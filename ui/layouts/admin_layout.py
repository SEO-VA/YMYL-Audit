#!/usr/bin/env python3
"""
Admin Layout for YMYL Audit Tool
Handles two-step process with detailed insights
"""

import streamlit as st
import asyncio
import concurrent.futures
from datetime import datetime
from typing import Dict, Any
from utils.feature_registry import FeatureRegistry
from core.analyzer import analyze_content
from core.reporter import generate_word_report
from utils.helpers import safe_log

class AdminLayout:
    """Admin layout with two-step detailed process"""
    
    def __init__(self):
        """Initialize admin layout"""
        self.current_step = self._get_current_step()
    
    def render(self, selected_feature: str):
        """Render admin interface for selected feature"""
        
        # Get feature handler
        try:
            feature_handler = FeatureRegistry.get_handler(selected_feature)
        except ValueError as e:
            st.error(f"❌ {str(e)}")
            return
        
        # Main content columns
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if self.current_step == 1:
                self._render_step1_extraction(feature_handler)
            elif self.current_step == 2:
                self._render_step2_analysis(feature_handler)
        
        with col2:
            self._render_step_indicator()
            self._render_admin_controls(feature_handler)
    
    def _get_current_step(self) -> int:
        """Determine current step based on session state"""
        # Check if any feature has extracted content
        for key in st.session_state.keys():
            if key.endswith('_extracted_content') and st.session_state[key]:
                return 2
        return 1
    
    def _render_step1_extraction(self, feature_handler):
        """Render Step 1: Content Extraction"""
        st.subheader("📄 Step 1: Content Extraction")
        
        # Get input interface
        input_data = feature_handler.get_input_interface()
        
        # Extract button
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            extract_clicked = st.button(
                "📄 Extract Content",
                type="primary",
                use_container_width=True,
                disabled=not input_data.get('is_valid', False)
            )
        
        # Process extraction
        if extract_clicked:
            self._process_extraction(feature_handler, input_data)
    
    def _render_step2_analysis(self, feature_handler):
        """Render Step 2: AI Analysis"""
        st.markdown("---")
        st.subheader("🤖 Step 2: AI Analysis")
        
        # Get extracted content info
        extracted_content = feature_handler.get_extracted_content()
        source_info = feature_handler.get_source_info()
        casino_mode = feature_handler.get_session_data('casino_mode', False)
        
        if not extracted_content:
            st.error("❌ No extracted content found. Please restart extraction.")
            if st.button("🔄 Back to Step 1"):
                feature_handler.clear_session_data()
                st.rerun()
            return
        
        # Show analysis info
        col1, col2 = st.columns([2, 1])
        
        with col1:
            mode_text = "Casino Review" if casino_mode else "Regular Analysis"
            st.info(f"🎯 Ready to analyze: **{source_info}** ({mode_text})")
        
        with col2:
            if st.button("🗑️ Clear & Restart", help="Clear extracted content"):
                feature_handler.clear_session_data()
                st.rerun()
        
        # Show extraction details
        self._show_extraction_details(feature_handler, extracted_content)
        
        # Analysis button
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            analyze_clicked = st.button(
                "🚀 Run AI Analysis",
                type="primary",
                use_container_width=True
            )
        
        # Process analysis
        if analyze_clicked:
            self._process_ai_analysis(extracted_content, casino_mode, source_info)
    
    def _process_extraction(self, feature_handler, input_data: Dict[str, Any]):
        """Process content extraction"""
        
        with st.status("Extracting content...") as status:
            # Validate input
            is_valid, error_msg = feature_handler.validate_input(input_data)
            if not is_valid:
                st.error(f"❌ Validation failed: {error_msg}")
                return
            
            # Extract content
            success, extracted_content, error = feature_handler.extract_content(input_data)
            
            if not success:
                st.error(f"❌ Extraction failed: {error}")
                return
            
            # Store results
            feature_handler.set_session_data('extracted_content', extracted_content)
            feature_handler.set_session_data('source_info', 
                feature_handler.get_source_description(input_data))
            feature_handler.set_session_data('casino_mode', 
                input_data.get('casino_mode', False))
            
            status.update(label="✅ Content extracted successfully!", state="complete")
        
        st.rerun()  # Refresh to show step 2
    
    def _show_extraction_details(self, feature_handler, extracted_content: str):
        """Show detailed extraction info for admin"""
        st.markdown("### 🔍 Admin: Extraction Details")
        
        # Get metrics
        metrics = feature_handler.get_extraction_metrics(extracted_content)
        
        # Show metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Big Chunks", metrics.get('big_chunks', 'N/A'))
        with col2:
            st.metric("Small Chunks", metrics.get('small_chunks', 'N/A'))
        with col3:
            st.metric("JSON Size", f"{metrics.get('json_size', 0):,} chars")
        
        # Show structured content preview
        with st.expander("👁️ View Extracted Content Structure"):
            try:
                import json
                content_data = json.loads(extracted_content)
                big_chunks = content_data.get('big_chunks', [])
                
                for i, chunk in enumerate(big_chunks, 1):
                    st.markdown(f"**📦 Big Chunk {i}:**")
                    small_chunks = chunk.get('small_chunks', [])
                    
                    for j, small_chunk in enumerate(small_chunks[:3], 1):
                        preview = small_chunk[:150] + "..." if len(small_chunk) > 150 else small_chunk
                        st.text(f"  {j}. {preview}")
                    
                    if len(small_chunks) > 3:
                        st.text(f"  ... and {len(small_chunks) - 3} more chunks")
                    st.markdown("---")
                    
            except json.JSONDecodeError:
                st.error("❌ Could not parse JSON")
        
        # Show raw JSON
        with st.expander("🤖 JSON Data Sent to AI"):
            st.code(extracted_content, language='json')
    
    def _process_ai_analysis(self, extracted_content: str, casino_mode: bool, source_info: str):
        """Process AI analysis with admin details"""
        
        try:
            # Run analysis
            with st.status("Running AI analysis...") as status:
                
                async def run_analysis():
                    return await analyze_content(extracted_content, casino_mode)
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(run_analysis()))
                    analysis_result = future.result(timeout=300)
                
                status.update(label="✅ Analysis complete!", state="complete")
            
            if not analysis_result or not analysis_result.get('success'):
                error_msg = analysis_result.get('error', 'Unknown error')
                st.error(f"❌ AI analysis failed: {error_msg}")
                return
            
            # Generate report
            with st.status("Generating Word report..."):
                word_bytes = generate_word_report(
                    analysis_result['report'],
                    f"YMYL Report - {source_info}",
                    casino_mode
                )
            
            st.success("✅ Analysis complete!")
            
            # Show admin analysis results
            self._show_analysis_results(analysis_result, word_bytes)
            
            # Download
            self._show_download(word_bytes)
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            safe_log(f"Analysis error: {e}")
    
    def _show_analysis_results(self, analysis_result: Dict[str, Any], word_bytes: bytes):
        """Show analysis results for admin"""
        st.markdown("### 📊 Analysis Results")
        
        # Metrics
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Processing Time", f"{analysis_result.get('processing_time', 0):.1f}s")
        with col2:
            ai_response = analysis_result.get('ai_response', [])
            violations = sum(1 for section in ai_response 
                            if section.get('violations') != "no violation found" 
                            and section.get('violations')) if isinstance(ai_response, list) else 0
            st.metric("Violations Found", violations)
        
        # Show markdown report
        st.markdown("### 📄 Generated Report")
        st.markdown(analysis_result.get('report', ''))
        
        # Raw AI response
        with st.expander("🤖 View Raw AI Response"):
            st.json(analysis_result.get('ai_response', {}))
    
    def _show_download(self, word_bytes: bytes):
        """Show download button"""
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ymyl_report_{timestamp}.docx"
        
        st.download_button(
            label="📄 Download Report",
            data=word_bytes,
            file_name=filename,
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            type="primary"
        )
    
    def _render_step_indicator(self):
        """Render step progress indicator"""
        st.markdown("### 📋 Progress")
        
        # Step indicators
        if self.current_step >= 1:
            st.success("✅ Step 1: Content Extraction")
        else:
            st.info("1️⃣ Step 1: Content Extraction")
        
        if self.current_step >= 2:
            st.success("✅ Step 2: AI Analysis")
        else:
            st.info("2️⃣ Step 2: AI Analysis")
        
        st.markdown("---")
    
    def _render_admin_controls(self, feature_handler):
        """Render admin-specific controls"""
        st.markdown("### 🛠️ Admin Controls")
        
        # Feature info
        feature_name = feature_handler.get_feature_name()
        st.info(f"**Feature**: {feature_name}")
        
        # Step info
        if self.current_step == 1:
            st.markdown("**Current**: Content extraction phase")
            st.markdown("**Next**: AI analysis with detailed metrics")
        else:
            st.markdown("**Current**: AI analysis phase")
            st.markdown("**Available**: Detailed processing insights")
        
        st.markdown("---")
        
        # Reset button
        if st.button("🔄 Reset Everything", help="Clear all data and start fresh"):
            # Clear all session data for all features
            keys_to_remove = [k for k in st.session_state.keys() 
                            if any(k.startswith(prefix) for prefix in 
                                  ['url_analysis_', 'html_analysis_'])]
            for key in keys_to_remove:
                del st.session_state[key]
            st.rerun()