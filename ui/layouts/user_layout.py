#!/usr/bin/env python3
"""
User Layout for YMYL Audit Tool - Multi-File Processing Support
Handles single file OR multiple files (up to 5) with parallel processing
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

class UserLayout:
    """User layout with single and multi-file processing capabilities"""
    
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
        
        # Check for single file results
        if st.session_state.get(f'{analysis_key}_complete'):
            self._show_single_file_results(analysis_key)
            return
        
        # Check for multi-file results
        multi_results = self._get_multi_file_results()
        if multi_results:
            self._show_multi_file_results(multi_results)
            return
        
        # Main content - input interface
        self._render_analysis_interface(feature_handler, analysis_key, casino_mode)
    
    def _get_multi_file_results(self) -> Dict[str, Any]:
        """Get multi-file results from session state"""
        multi_results = {}
        for key in st.session_state.keys():
            if key.startswith('multi_') and key.endswith('_status'):
                filename = key[6:-7]  # Remove 'multi_' and '_status'
                status = st.session_state[key]
                
                multi_results[filename] = {
                    'status': status,
                    'word_bytes': st.session_state.get(f'multi_{filename}_word_bytes'),
                    'report': st.session_state.get(f'multi_{filename}_report'),
                    'processing_time': st.session_state.get(f'multi_{filename}_processing_time'),
                    'error': st.session_state.get(f'multi_{filename}_error')
                }
        
        return multi_results if multi_results else None
    
    def _render_analysis_interface(self, feature_handler, analysis_key: str, casino_mode: bool):
        """Render analysis interface with single/multi-file support"""
        
        # Check processing state
        is_processing = st.session_state.get('is_processing', False)
        
        # Get input interface (disabled if processing)
        input_data = feature_handler.get_input_interface(disabled=is_processing)
        # Override casino mode with global setting
        input_data['casino_mode'] = casino_mode
        
        # Determine if this is multi-file
        is_multi_file = feature_handler.is_multi_file_input(input_data) if hasattr(feature_handler, 'is_multi_file_input') else False
        
        # Show file info if multi-file
        if is_multi_file and hasattr(feature_handler, 'get_file_list'):
            file_list = feature_handler.get_file_list(input_data)
            if file_list:
                st.info(f"📁 **{len(file_list)} files selected**: {', '.join(file_list)}")
        
        # Single analyze button
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            button_text = "🚀 Analyze All Files" if is_multi_file else "🚀 Analyze Content"
            analyze_clicked = st.button(
                button_text,
                type="primary",
                use_container_width=True,
                disabled=not input_data.get('is_valid', False) or is_processing
            )
        
        # Process analysis
        if analyze_clicked:
            st.session_state['is_processing'] = True
            st.rerun()
            
        # Process analysis if button was clicked
        if st.session_state.get('is_processing') and not st.session_state.get('stop_processing'):
            if is_multi_file:
                self._process_multi_file_analysis(feature_handler, input_data, analysis_key)
            else:
                self._process_single_file_analysis(feature_handler, input_data, analysis_key)
    
    def _process_single_file_analysis(self, feature_handler, input_data: Dict[str, Any], analysis_key: str):
        """Process single file analysis (existing logic)"""
        
        try:
            with st.status("Running multi-audit analysis...") as status:
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
                
                status.update(label="Content extracted, running 5 parallel AI audits...", state="running")
                
                # AI Analysis
                casino_mode = input_data.get('casino_mode', False)
                
                async def run_single_analysis():
                    return await analyze_content(extracted_content, casino_mode, debug_mode=False)
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(run_single_analysis()))
                    analysis_result = future.result(timeout=300)
                
                # Check for stop signal
                if st.session_state.get('stop_processing'):
                    st.session_state['is_processing'] = False
                    st.session_state['stop_processing'] = False
                    return
                
                if not analysis_result or not analysis_result.get('success'):
                    error_msg = analysis_result.get('error', 'Unknown error')
                    st.error(f"❌ Multi-audit analysis failed: {error_msg}")
                    st.session_state['is_processing'] = False
                    return
                
                status.update(label="Generating comprehensive report...", state="running")
                
                # Generate Report
                source_info = feature_handler.get_source_description(input_data)
                word_bytes = generate_word_report(
                    analysis_result['report'],
                    f"YMYL Multi-Audit Report - {source_info}",
                    casino_mode
                )
                
                status.update(label="✅ Multi-audit analysis complete!", state="complete")
            
            # Store single file results
            st.session_state[f'{analysis_key}_complete'] = True
            st.session_state[f'{analysis_key}_report'] = analysis_result['report']
            st.session_state[f'{analysis_key}_word_bytes'] = word_bytes
            st.session_state[f'{analysis_key}_source_info'] = source_info
            st.session_state[f'{analysis_key}_processing_time'] = analysis_result.get('processing_time', 0)
            
            # Clear processing state
            st.session_state['is_processing'] = False
            
            # Log success
            safe_log(f"Single-file analysis completed: {source_info}")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Single-file analysis failed: {str(e)}")
            safe_log(f"Single-file analysis error: {e}")
            st.session_state['is_processing'] = False
    
    def _process_multi_file_analysis(self, feature_handler, input_data: Dict[str, Any], analysis_key: str):
        """Process multiple files in parallel"""
        
        try:
            with st.status("Processing multiple files...") as status:
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
                
                # Extract content from all files
                success, extracted_content, error = feature_handler.extract_content(input_data)
                
                if not success:
                    st.error(f"❌ Extraction failed: {error}")
                    st.session_state['is_processing'] = False
                    return
                
                # Parse multi-file content
                try:
                    multi_content = json.loads(extracted_content)
                    files_data = multi_content.get('files', {})
                except Exception as e:
                    st.error(f"❌ Failed to parse multi-file content: {str(e)}")
                    st.session_state['is_processing'] = False
                    return
                
                status.update(label=f"Starting parallel analysis of {len(files_data)} files...", state="running")
                
                # Initialize session state for all files
                for filename in files_data.keys():
                    st.session_state[f'multi_{filename}_status'] = 'processing'
                    st.session_state[f'multi_{filename}_start_time'] = datetime.now()
                
                # Process all files in parallel
                casino_mode = input_data.get('casino_mode', False)
                
                async def process_all_files():
                    tasks = []
                    for filename, file_content in files_data.items():
                        task = self._analyze_single_file(filename, file_content, casino_mode)
                        tasks.append(task)
                    
                    # Wait for all files to complete
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    return results
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(process_all_files()))
                    results = future.result(timeout=600)  # 10 minutes for multiple files
                
                status.update(label="✅ All files processed!", state="complete")
            
            # Clear processing state
            st.session_state['is_processing'] = False
            
            # Log completion
            completed_count = sum(1 for filename in files_data.keys() 
                                 if st.session_state.get(f'multi_{filename}_status') == 'complete')
            safe_log(f"Multi-file analysis completed: {completed_count}/{len(files_data)} files successful")
            
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Multi-file analysis failed: {str(e)}")
            safe_log(f"Multi-file analysis error: {e}")
            st.session_state['is_processing'] = False
    
    async def _analyze_single_file(self, filename: str, file_content: str, casino_mode: bool):
        """Analyze a single file asynchronously"""
        
        try:
            # Run 5-audit analysis
            analysis_result = await analyze_content(file_content, casino_mode, debug_mode=False)
            
            if analysis_result and analysis_result.get('success'):
                # Generate report
                word_bytes = generate_word_report(
                    analysis_result['report'],
                    f"YMYL Multi-Audit Report - {filename}",
                    casino_mode
                )
                
                # Store results
                st.session_state[f'multi_{filename}_status'] = 'complete'
                st.session_state[f'multi_{filename}_report'] = analysis_result['report']
                st.session_state[f'multi_{filename}_word_bytes'] = word_bytes
                st.session_state[f'multi_{filename}_processing_time'] = analysis_result.get('processing_time', 0)
                
                safe_log(f"Successfully processed {filename}")
                
            else:
                error_msg = analysis_result.get('error', 'Unknown error') if analysis_result else 'Analysis failed'
                st.session_state[f'multi_{filename}_status'] = 'failed'
                st.session_state[f'multi_{filename}_error'] = error_msg
                safe_log(f"Failed to process {filename}: {error_msg}")
                
        except Exception as e:
            st.session_state[f'multi_{filename}_status'] = 'failed'
            st.session_state[f'multi_{filename}_error'] = str(e)
            safe_log(f"Exception processing {filename}: {str(e)}")
    
    def _show_single_file_results(self, analysis_key: str):
        """Show single file results (existing logic)"""
        st.success("✅ **Multi-Audit Analysis Complete!**")
        
        # Get stored data
        markdown_report = st.session_state.get(f'{analysis_key}_report')
        word_bytes = st.session_state.get(f'{analysis_key}_word_bytes')
        source_info = st.session_state.get(f'{analysis_key}_source_info', 'Analysis')
        
        # Download and action buttons
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ymyl_multi_audit_report_{timestamp}.docx"
        
        col1, col2 = st.columns(2)
        
        with col1:
            if word_bytes:
                st.download_button(
                    label="📄 Download Multi-Audit Report",
                    data=word_bytes,
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    type="primary",
                    use_container_width=True,
                    key=f"download_{analysis_key}_{timestamp}"
                )
        
        with col2:
            if st.button("🔄 Analyze Another", use_container_width=True, key=f"new_analysis_{analysis_key}"):
                # Clear stored results
                keys_to_clear = [k for k in st.session_state.keys() if k.startswith(analysis_key)]
                for key in keys_to_clear:
                    del st.session_state[key]
                st.rerun()
        
        # Info
        st.info("💡 **Tip**: This report includes findings from 5 parallel AI audits with duplicate violations removed.")
        
        # Display report
        if markdown_report:
            st.markdown("### 📄 YMYL Multi-Audit Compliance Report")
            st.markdown(markdown_report)
    
    def _show_multi_file_results(self, multi_results: Dict[str, Any]):
        """Show multi-file results with individual downloads"""
        st.success("✅ **Multi-File Analysis Results**")
        
        # Summary metrics
        total_files = len(multi_results)
        completed_files = sum(1 for data in multi_results.values() if data['status'] == 'complete')
        failed_files = sum(1 for data in multi_results.values() if data['status'] == 'failed')
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Files", total_files)
        with col2:
            st.metric("Completed", completed_files)
        with col3:
            st.metric("Failed", failed_files)
        
        # Action buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🗂️ Download All Reports", use_container_width=True):
                self._download_all_reports(multi_results)
        with col2:
            if st.button("🔄 Start New Analysis", use_container_width=True):
                self._clear_multi_file_results()
                st.rerun()
        
        st.markdown("---")
        
        # Individual file results
        st.markdown("### 📁 Individual File Results")
        
        for filename, data in multi_results.items():
            self._show_individual_file_result(filename, data)
    
    def _show_individual_file_result(self, filename: str, data: Dict[str, Any]):
        """Show result for individual file"""
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if data['status'] == 'complete':
                processing_time = data.get('processing_time', 0)
                st.success(f"✅ **{filename}** - Completed in {processing_time:.1f}s")
            elif data['status'] == 'failed':
                error_msg = data.get('error', 'Unknown error')
                st.error(f"❌ **{filename}** - Failed: {error_msg}")
            elif data['status'] == 'processing':
                st.info(f"🔄 **{filename}** - Processing...")
        
        with col2:
            if data['status'] == 'complete' and data.get('word_bytes'):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                clean_filename = filename.replace('.html', '').replace('.htm', '')
                download_filename = f"{clean_filename}_audit_report.docx"
                
                st.download_button(
                    label="📄 Download",
                    data=data['word_bytes'],
                    file_name=download_filename,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    use_container_width=True,
                    key=f"download_{filename}_{timestamp}"
                )
    
    def _download_all_reports(self, multi_results: Dict[str, Any]):
        """Create ZIP of all completed reports"""
        import zipfile
        import io
        
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename, data in multi_results.items():
                if data['status'] == 'complete' and data.get('word_bytes'):
                    clean_filename = filename.replace('.html', '').replace('.htm', '')
                    docx_filename = f"{clean_filename}_audit_report.docx"
                    zip_file.writestr(docx_filename, data['word_bytes'])
        
        zip_buffer.seek(0)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"ymyl_multi_audit_reports_{timestamp}.zip"
        
        st.download_button(
            label="📦 Download ZIP of All Reports",
            data=zip_buffer.getvalue(),
            file_name=zip_filename,
            mime="application/zip",
            type="primary"
        )
    
    def _clear_multi_file_results(self):
        """Clear all multi-file results from session state"""
        keys_to_clear = [k for k in st.session_state.keys() if k.startswith('multi_')]
        for key in keys_to_clear:
            del st.session_state[key]