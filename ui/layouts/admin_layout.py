#!/usr/bin/env python3
"""
Admin Layout for YMYL Audit Tool - Multi-File Support with Debug Mode
Handles single or multiple files with enhanced debugging capabilities
"""

import streamlit as st
import asyncio
import concurrent.futures
import json
from datetime import datetime
from typing import Dict, Any, List
from utils.feature_registry import FeatureRegistry
from core.analyzer import analyze_content
from core.reporter import generate_word_report
from utils.helpers import safe_log

class AdminLayout:
    """Admin layout with single/multi-file processing and debug capabilities"""
    
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
        # Check for single file extraction
        for key in st.session_state.keys():
            if key.endswith('_extracted_content') and st.session_state[key]:
                return 2
        
        # Check for multi-file extraction
        for key in st.session_state.keys():
            if key.startswith('admin_multi_') and key.endswith('_extracted') and st.session_state[key]:
                return 2
        
        return 1
    
    def _render_step1_extraction(self, feature_handler):
        """Render Step 1: Content Extraction (single or multi-file)"""
        st.subheader("📄 Step 1: Content Extraction")
        
        # Get input interface
        input_data = feature_handler.get_input_interface()
        
        # Show file information
        is_multi_file = feature_handler.is_multi_file_input(input_data) if hasattr(feature_handler, 'is_multi_file_input') else False
        
        if is_multi_file and hasattr(feature_handler, 'get_file_list'):
            file_list = feature_handler.get_file_list(input_data)
            if file_list:
                st.info(f"📁 **Multi-file extraction**: {len(file_list)} files selected")
                with st.expander("📋 View File List"):
                    for i, filename in enumerate(file_list, 1):
                        st.text(f"{i}. {filename}")
        
        # Extract button
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            button_text = "📄 Extract All Files" if is_multi_file else "📄 Extract Content"
            extract_clicked = st.button(
                button_text,
                type="primary",
                use_container_width=True,
                disabled=not input_data.get('is_valid', False)
            )
        
        # Process extraction
        if extract_clicked:
            if is_multi_file:
                self._process_multi_file_extraction(feature_handler, input_data)
            else:
                self._process_single_file_extraction(feature_handler, input_data)
    
    def _render_step2_analysis(self, feature_handler):
        """Render Step 2: Multi-Audit AI Analysis"""
        st.markdown("---")
        st.subheader("🤖 Step 2: Multi-Audit AI Analysis")
        
        # Determine if we have single or multi-file extraction
        is_multi_extraction = self._has_multi_file_extraction()
        
        if is_multi_extraction:
            self._render_multi_file_analysis_step(feature_handler)
        else:
            self._render_single_file_analysis_step(feature_handler)
    
    def _has_multi_file_extraction(self) -> bool:
        """Check if we have multi-file extraction"""
        return any(key.startswith('admin_multi_') and key.endswith('_extracted') 
                  for key in st.session_state.keys() if st.session_state.get(key))
    
    def _render_single_file_analysis_step(self, feature_handler):
        """Render analysis step for single file (existing logic)"""
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
            st.info(f"🎯 Ready for multi-audit analysis: **{source_info}** ({mode_text})")
        
        with col2:
            if st.button("🗑️ Clear & Restart", help="Clear extracted content"):
                feature_handler.clear_session_data()
                st.rerun()
        
        # Show extraction details
        self._show_single_file_extraction_details(feature_handler, extracted_content)
        
        # Debug mode toggle
        debug_mode = st.checkbox(
            "🐛 Enable Debug Mode",
            value=True,
            help="Show individual audit reports and detailed metrics",
            key="admin_debug_mode_single"
        )
        
        # Analysis button
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            analyze_clicked = st.button(
                "🚀 Run 5-Audit Analysis",
                type="primary",
                use_container_width=True
            )
        
        # Process analysis
        if analyze_clicked:
            self._process_single_file_ai_analysis(extracted_content, casino_mode, source_info, debug_mode)
    
    def _render_multi_file_analysis_step(self, feature_handler):
        """Render analysis step for multiple files"""
        # Get multi-file extraction data
        extracted_files = self._get_multi_file_extracted_data()
        
        if not extracted_files:
            st.error("❌ No extracted files found. Please restart extraction.")
            if st.button("🔄 Back to Step 1"):
                self._clear_multi_file_extraction()
                st.rerun()
            return
        
        # Show analysis info
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.info(f"🎯 Ready for multi-file analysis: **{len(extracted_files)} files**")
        
        with col2:
            if st.button("🗑️ Clear & Restart", help="Clear all extracted content"):
                self._clear_multi_file_extraction()
                st.rerun()
        
        # Show multi-file extraction details
        self._show_multi_file_extraction_details(extracted_files)
        
        # Debug mode toggle (affects ALL files)
        debug_mode = st.checkbox(
            "🐛 Enable Debug Mode (All Files)",
            value=True,
            help="Show individual audit reports for each file",
            key="admin_debug_mode_multi"
        )
        
        if debug_mode:
            st.info("🐛 **Debug Mode Enabled**: Individual audit reports will be shown for each file")
        
        # Analysis button
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            analyze_clicked = st.button(
                f"🚀 Run 5-Audit Analysis ({len(extracted_files)} files)",
                type="primary",
                use_container_width=True
            )
        
        # Process analysis
        if analyze_clicked:
            casino_mode = st.session_state.get('admin_multi_casino_mode', False)
            self._process_multi_file_ai_analysis(extracted_files, casino_mode, debug_mode)
    
    def _process_single_file_extraction(self, feature_handler, input_data: Dict[str, Any]):
        """Process single file extraction (existing logic)"""
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
        
        st.rerun()
    
    def _process_multi_file_extraction(self, feature_handler, input_data: Dict[str, Any]):
        """Process multi-file extraction"""
        with st.status("Extracting content from multiple files...") as status:
            # Validate input
            is_valid, error_msg = feature_handler.validate_input(input_data)
            if not is_valid:
                st.error(f"❌ Validation failed: {error_msg}")
                return
            
            # Extract content from all files
            success, extracted_content, error = feature_handler.extract_content(input_data)
            
            if not success:
                st.error(f"❌ Multi-file extraction failed: {error}")
                return
            
            # Parse and store multi-file data
            try:
                multi_content = json.loads(extracted_content)
                files_data = multi_content.get('files', {})
                
                # Store each file's extracted content
                for filename, file_content in files_data.items():
                    st.session_state[f'admin_multi_{filename}_extracted'] = file_content
                    st.session_state[f'admin_multi_{filename}_filename'] = filename
                
                # Store global info
                st.session_state['admin_multi_extraction_complete'] = True
                st.session_state['admin_multi_casino_mode'] = input_data.get('casino_mode', False)
                st.session_state['admin_multi_file_count'] = len(files_data)
                
                status.update(label=f"✅ Successfully extracted {len(files_data)} files!", state="complete")
                
            except Exception as e:
                st.error(f"❌ Failed to parse multi-file content: {str(e)}")
                return
        
        st.rerun()
    
    def _get_multi_file_extracted_data(self) -> Dict[str, str]:
        """Get extracted data for all files"""
        extracted_files = {}
        
        for key in st.session_state.keys():
            if key.startswith('admin_multi_') and key.endswith('_extracted'):
                filename_key = key.replace('_extracted', '_filename')
                filename = st.session_state.get(filename_key, key[12:-10])  # Fallback to derived name
                extracted_files[filename] = st.session_state[key]
        
        return extracted_files
    
    def _show_single_file_extraction_details(self, feature_handler, extracted_content: str):
        """Show extraction details for single file (existing logic)"""
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
        
        # Show content preview
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
    
    def _show_multi_file_extraction_details(self, extracted_files: Dict[str, str]):
        """Show extraction details for multiple files"""
        st.markdown("### 🔍 Admin: Multi-File Extraction Details")
        
        # Overall metrics
        total_files = len(extracted_files)
        total_size = sum(len(content) for content in extracted_files.values())
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Files", total_files)
        with col2:
            st.metric("Combined Size", f"{total_size:,} chars")
        with col3:
            avg_size = total_size // total_files if total_files > 0 else 0
            st.metric("Average Size", f"{avg_size:,} chars")
        
        # Individual file details
        with st.expander("📁 Individual File Details"):
            for filename, content in extracted_files.items():
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**📄 {filename}**")
                
                with col2:
                    st.text(f"{len(content):,} chars")
                
                # Show content preview
                try:
                    content_data = json.loads(content)
                    big_chunks = content_data.get('big_chunks', [])
                    st.text(f"  {len(big_chunks)} sections extracted")
                except:
                    st.text("  Content structure analysis failed")
                
                st.markdown("---")
    
    def _process_single_file_ai_analysis(self, extracted_content: str, casino_mode: bool, source_info: str, debug_mode: bool):
        """Process single file AI analysis (existing logic enhanced)"""
        
        try:
            with st.status("Running 5 parallel AI audits...") as status:
                
                async def run_single_analysis():
                    return await analyze_content(extracted_content, casino_mode, debug_mode=debug_mode)
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(run_single_analysis()))
                    analysis_result = future.result(timeout=300)
                
                status.update(label="✅ Multi-audit analysis complete!", state="complete")
            
            if not analysis_result or not analysis_result.get('success'):
                error_msg = analysis_result.get('error', 'Unknown error')
                st.error(f"❌ Multi-audit analysis failed: {error_msg}")
                return
            
            # Generate report
            with st.status("Generating comprehensive report..."):
                word_bytes = generate_word_report(
                    analysis_result['report'],
                    f"YMYL Multi-Audit Report - {source_info}",
                    casino_mode
                )
            
            st.success("✅ Multi-audit analysis complete!")
            
            # Show results based on debug mode
            if debug_mode and analysis_result.get('debug_mode'):
                self._show_debug_analysis_results(analysis_result, word_bytes)
            else:
                self._show_standard_analysis_results(analysis_result, word_bytes)
            
            # Download
            self._show_download(word_bytes, "admin_single")
            
        except Exception as e:
            st.error(f"❌ Multi-audit analysis failed: {str(e)}")
            safe_log(f"Admin single file analysis error: {e}")
    
    def _process_multi_file_ai_analysis(self, extracted_files: Dict[str, str], casino_mode: bool, debug_mode: bool):
        """Process multi-file AI analysis in parallel"""
        
        try:
            with st.status(f"Running 5-audit analysis on {len(extracted_files)} files...") as status:
                
                # Initialize session state for tracking
                for filename in extracted_files.keys():
                    st.session_state[f'admin_multi_{filename}_analysis_status'] = 'processing'
                    st.session_state[f'admin_multi_{filename}_start_time'] = datetime.now()
                
                async def process_all_files():
                    tasks = []
                    for filename, content in extracted_files.items():
                        task = self._analyze_admin_file(filename, content, casino_mode, debug_mode)
                        tasks.append(task)
                    
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    return results
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(process_all_files()))
                    results = future.result(timeout=600)  # 10 minutes total
                
                status.update(label="✅ All files analyzed!", state="complete")
            
            # Show multi-file results
            self._show_multi_file_analysis_results(extracted_files, debug_mode)
            
        except Exception as e:
            st.error(f"❌ Multi-file analysis failed: {str(e)}")
            safe_log(f"Admin multi-file analysis error: {e}")
    
    async def _analyze_admin_file(self, filename: str, content: str, casino_mode: bool, debug_mode: bool):
        """Analyze single file for admin with debug info"""
        
        try:
            analysis_result = await analyze_content(content, casino_mode, debug_mode=debug_mode)
            
            if analysis_result and analysis_result.get('success'):
                # Generate report
                word_bytes = generate_word_report(
                    analysis_result['report'],
                    f"YMYL Multi-Audit Report - {filename}",
                    casino_mode
                )
                
                # Store results
                st.session_state[f'admin_multi_{filename}_analysis_status'] = 'complete'
                st.session_state[f'admin_multi_{filename}_analysis_result'] = analysis_result
                st.session_state[f'admin_multi_{filename}_word_bytes'] = word_bytes
                
                safe_log(f"Admin analysis completed for {filename}")
                
            else:
                error_msg = analysis_result.get('error', 'Unknown error') if analysis_result else 'Analysis failed'
                st.session_state[f'admin_multi_{filename}_analysis_status'] = 'failed'
                st.session_state[f'admin_multi_{filename}_error'] = error_msg
                safe_log(f"Admin analysis failed for {filename}: {error_msg}")
                
        except Exception as e:
            st.session_state[f'admin_multi_{filename}_analysis_status'] = 'failed'
            st.session_state[f'admin_multi_{filename}_error'] = str(e)
            safe_log(f"Admin analysis exception for {filename}: {str(e)}")
    
    def _show_debug_analysis_results(self, analysis_result: Dict[str, Any], word_bytes: bytes):
        """Show debug analysis results with individual audit reports"""
        try:
            from ui.debug_components import show_debug_results
            show_debug_results(analysis_result, word_bytes)
        except ImportError:
            st.warning("⚠️ Debug components not available. Showing standard results.")
            self._show_standard_analysis_results(analysis_result, word_bytes)
    
    def _show_standard_analysis_results(self, analysis_result: Dict[str, Any], word_bytes: bytes):
        """Show standard analysis results for admin"""
        st.markdown("### 📊 Multi-Audit Analysis Results")
        
        # Enhanced metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Processing Time", f"{analysis_result.get('processing_time', 0):.1f}s")
        with col2:
            st.metric("Total Violations Found", analysis_result.get('total_violations_found', 0))
        with col3:
            st.metric("After Deduplication", analysis_result.get('unique_violations', 0))
        with col4:
            total = analysis_result.get('total_violations_found', 0)
            unique = analysis_result.get('unique_violations', 0)
            if total > 0:
                efficiency = ((total - unique) / total) * 100
                st.metric("Duplicates Removed", f"{efficiency:.1f}%")
            else:
                st.metric("Duplicates Removed", "0%")
        
        # Show final report
        st.markdown("### 📄 Final Multi-Audit Report")
        st.markdown(analysis_result.get('report', ''))
    
    def _show_multi_file_analysis_results(self, extracted_files: Dict[str, str], debug_mode: bool):
        """Show analysis results for multiple files"""
        st.success("✅ **Multi-File Analysis Complete!**")
        
        # Summary metrics
        total_files = len(extracted_files)
        completed_files = sum(1 for filename in extracted_files.keys() 
                             if st.session_state.get(f'admin_multi_{filename}_analysis_status') == 'complete')
        failed_files = total_files - completed_files
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Files", total_files)
        with col2:
            st.metric("Completed", completed_files)
        with col3:
            st.metric("Failed", failed_files)
        
        # Individual file results
        st.markdown("### 📁 Individual File Results")
        
        for filename in extracted_files.keys():
            self._show_admin_file_result(filename, debug_mode)
    
    def _show_admin_file_result(self, filename: str, debug_mode: bool):
        """Show admin result for individual file"""
        
        status = st.session_state.get(f'admin_multi_{filename}_analysis_status', 'unknown')
        analysis_result = st.session_state.get(f'admin_multi_{filename}_analysis_result')
        word_bytes = st.session_state.get(f'admin_multi_{filename}_word_bytes')
        error = st.session_state.get(f'admin_multi_{filename}_error')
        
        # File header
        if status == 'complete':
            st.success(f"✅ **{filename}**")
        elif status == 'failed':
            st.error(f"❌ **{filename}** - {error}")
        else:
            st.info(f"🔄 **{filename}** - {status}")
        
        if status == 'complete' and analysis_result:
            
            # Show metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                processing_time = analysis_result.get('processing_time', 0)
                st.metric("Processing Time", f"{processing_time:.1f}s")
            with col2:
                total_violations = analysis_result.get('total_violations_found', 0)
                st.metric("Total Violations", total_violations)
            with col3:
                unique_violations = analysis_result.get('unique_violations', 0)
                st.metric("After Dedup", unique_violations)
            
            # Download button
            if word_bytes:
                clean_filename = filename.replace('.html', '').replace('.htm', '')
                download_filename = f"{clean_filename}_audit_report.docx"
                
                st.download_button(
                    label=f"📄 Download {filename} Report",
                    data=word_bytes,
                    file_name=download_filename,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    key=f"admin_download_{filename}"
                )
            
            # Debug results if enabled
            if debug_mode and analysis_result.get('debug_mode'):
                with st.expander(f"🐛 Debug Details - {filename}"):
                    try:
                        from ui.debug_components import show_debug_results
                        show_debug_results(analysis_result, word_bytes)
                    except ImportError:
                        st.warning("⚠️ Debug components not available")
                        st.json(analysis_result.get('ai_response', {}))
        
        st.markdown("---")
    
    def _show_download(self, word_bytes: bytes, prefix: str):
        """Show download button"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ymyl_multi_audit_report_{timestamp}.docx"
        
        st.download_button(
            label="📄 Download Multi-Audit Report",
            data=word_bytes,
            file_name=filename,
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            type="primary"
        )
    
    def _clear_multi_file_extraction(self):
        """Clear multi-file extraction data"""
        keys_to_clear = [k for k in st.session_state.keys() if k.startswith('admin_multi_')]
        for key in keys_to_clear:
            del st.session_state[key]
    
    def _render_step_indicator(self):
        """Render step progress indicator"""
        st.markdown("### 📋 Progress")
        
        if self.current_step >= 1:
            st.success("✅ Step 1: Content Extraction")
        else:
            st.info("1️⃣ Step 1: Content Extraction")
        
        if self.current_step >= 2:
            st.success("✅ Step 2: Multi-Audit Analysis")
        else:
            st.info("2️⃣ Step 2: Multi-Audit Analysis")
        
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
            st.markdown("**Supports**: Single or multi-file (max 5)")
        else:
            st.markdown("**Current**: Multi-audit analysis phase")
            st.markdown("**Available**: Debug mode + individual reports")
        
        # Multi-audit info
        st.markdown("### ℹ️ Multi-Audit System")
        st.markdown("""
        - **5 Parallel Audits**: Higher accuracy through redundancy
        - **Multi-File Support**: Up to 5 files simultaneously
        - **Debug Mode**: Individual audit breakdowns per file
        - **Processing Time**: 2-4 minutes per file
        """)
        
        st.markdown("---")
        
        # Reset button
        if st.button("🔄 Reset Everything", help="Clear all data and start fresh"):
            # Clear all session data
            keys_to_clear = [k for k in st.session_state.keys() 
                            if any(k.startswith(prefix) for prefix in 
                                  ['url_analysis_', 'html_analysis_', 'admin_multi_'])]
            for key in keys_to_clear:
                del st.session_state[key]
            st.rerun()