#!/usr/bin/env python3
"""
User Layout for YMYL Audit Tool - FIXED VERSION
Handles simple one-step process with report display and persistent state
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

class UserLayout:
    """Simple user layout with one-step process and report display"""
    
    def render(self, selected_feature: str, casino_mode: bool = False):
        """Render user interface for selected feature"""
        
        # Get feature handler
        try:
            feature_handler = FeatureRegistry.get_handler(selected_feature)
        except ValueError as e:
            st.error(f"❌ {str(e)}")
            return
        
        # Check if we have analysis results stored
        analysis_key = f"user_analysis_{selected_feature}"
        if st.session_state.get(f'{analysis_key}_complete'):
            self._show_results_with_report(analysis_key)
        else:
            # Main content
            self._render_analysis_interface(feature_handler, analysis_key, casino_mode)
    
    def _render_analysis_interface(self, feature_handler, analysis_key: str, casino_mode: bool):
        """Render simple analysis interface with emergency stop support"""
        
        # Check processing state
        is_processing = st.session_state.get('is_processing', False)
        
        # Get input interface (disabled if processing)
        input_data = feature_handler.get_input_interface(disabled=is_processing)
        # Override casino mode with global setting
        input_data['casino_mode'] = casino_mode
        
        # Single analyze button
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            analyze_clicked = st.button(
                "🚀 Analyze Content",
                type="primary",
                use_container_width=True,
                disabled=not input_data.get('is_valid', False) or is_processing
            )
        
        # Process full analysis
        if analyze_clicked:
            st.session_state['is_processing'] = True
            st.rerun()
            
        # Process analysis if button was clicked
        if st.session_state.get('is_processing') and not st.session_state.get('stop_processing'):
            self._process_full_analysis_with_stop(feature_handler, input_data, analysis_key)
    
    def _show_results_with_report(self, analysis_key: str):
        """Show results with markdown preview and download"""
        st.success("✅ **Analysis Complete!**")
        
        # Get stored data
        markdown_report = st.session_state.get(f'{analysis_key}_report')
        word_bytes = st.session_state.get(f'{analysis_key}_word_bytes')
        source_info = st.session_state.get(f'{analysis_key}_source_info', 'Analysis')
        
        # FIRST show download and action buttons
        # Download button with unique key
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ymyl_report_{timestamp}.docx"
        
        col1, col2 = st.columns(2)
        
        with col1:
            if word_bytes:
                st.download_button(
                    label="📄 Download Word Report",
                    data=word_bytes,
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    type="primary",
                    use_container_width=True,
                    key=f"download_{analysis_key}_{timestamp}"  # Unique key prevents reset
                )
        
        with col2:
            if st.button("🔄 Analyze Another", use_container_width=True, key=f"new_analysis_{analysis_key}"):
                # Clear stored results for this analysis type
                keys_to_clear = [k for k in st.session_state.keys() if k.startswith(analysis_key)]
                for key in keys_to_clear:
                    del st.session_state[key]
                st.rerun()
        
        # Info about import
        st.info("💡 **Tip**: The Word document imports perfectly into Google Docs!")
        
        # THEN display the markdown report
        if markdown_report:
            st.markdown("### 📄 YMYL Compliance Report")
            st.markdown(markdown_report)
    
    def _process_full_analysis_with_stop(self, feature_handler, input_data: Dict[str, Any], analysis_key: str):
        """Process complete analysis in one step with emergency stop support"""
        
        try:
            # Step 1: Content Extraction
            with st.status("Extracting content...") as status:
                # Check for stop signal
                if st.session_state.get('stop_processing'):
                    st.session_state['is_processing'] = False
                    st.session_state['stop_processing'] = False
                    return
                
                # Validate input
                is_valid, error_msg = feature_handler.validate_input(input_data)
                if not is_valid:
                    st.error(f"❌ Validation failed: {error_msg}")
                    st.session_state['is_processing'] = False
                    return
                
                # Extract content
                success, extracted_content, error = feature_handler.extract_content(input_data)
                
                if not success:
                    st.error(f"❌ Extraction failed: {error}")
                    st.session_state['is_processing'] = False
                    return
                
                # Check for stop signal
                if st.session_state.get('stop_processing'):
                    st.session_state['is_processing'] = False
                    st.session_state['stop_processing'] = False
                    return
                
                status.update(label="Content extracted, running AI analysis...", state="running")
                
                # Step 2: AI Analysis
                casino_mode = input_data.get('casino_mode', False)
                
                async def run_analysis():
                    return await analyze_content(extracted_content, casino_mode)
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(run_analysis()))
                    analysis_result = future.result(timeout=300)
                
                # Check for stop signal
                if st.session_state.get('stop_processing'):
                    st.session_state['is_processing'] = False
                    st.session_state['stop_processing'] = False
                    return
                
                if not analysis_result or not analysis_result.get('success'):
                    error_msg = analysis_result.get('error', 'Unknown error')
                    st.error(f"❌ AI analysis failed: {error_msg}")
                    st.session_state['is_processing'] = False
                    return
                
                status.update(label="Generating Word report...", state="running")
                
                # Step 3: Generate Report
                source_info = feature_handler.get_source_description(input_data)
                word_bytes = generate_word_report(
                    analysis_result['report'],
                    f"YMYL Report - {source_info}",
                    casino_mode
                )
                
                status.update(label="✅ Analysis complete!", state="complete")
            
            # Store results in session state with unique keys to prevent conflicts
            st.session_state[f'{analysis_key}_complete'] = True
            st.session_state[f'{analysis_key}_report'] = analysis_result['report']
            st.session_state[f'{analysis_key}_word_bytes'] = word_bytes
            st.session_state[f'{analysis_key}_source_info'] = source_info
            st.session_state[f'{analysis_key}_processing_time'] = analysis_result.get('processing_time', 0)
            
            # Clear processing state
            st.session_state['is_processing'] = False
            
            # Log success
            safe_log(f"User analysis completed successfully for {source_info}")
            
            # Rerun to show results
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            safe_log(f"Full analysis error: {e}")
            st.session_state['is_processing'] = False