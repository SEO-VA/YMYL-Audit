#!/usr/bin/env python3
"""
YMYL Audit Tool - FINAL VERSION
Main application with HTML tip message and complete functionality
"""

import streamlit as st
from core.auth import check_authentication, logout, get_current_user
from utils.feature_registry import FeatureRegistry

# Configure Streamlit page
st.set_page_config(
    page_title="YMYL Audit Tool",
    page_icon="🔍",
    layout="centered"
)

def main():
    """Main application with improved state management and HTML tip"""
    
    # Check authentication
    if not check_authentication():
        return
    
    # Get current user
    current_user = get_current_user()
    is_admin = (current_user == 'admin')
    
    # Header with logout button
    col1, col2 = st.columns([4, 1])
    with col1:
        st.title("🔍 YMYL Audit Tool")
        st.markdown("**AI-powered YMYL compliance analysis for web content**")
    with col2:
        if st.button("🚪 Logout", key="main_logout"):
            logout()
            st.rerun()
    
    st.markdown("---")
    
    # Emergency stop button - always visible when process is running
    is_processing = st.session_state.get('is_processing', False)
    if is_processing:
        col1, col2, col3 = st.columns([2, 1, 2])
        with col2:
            if st.button("🛑 EMERGENCY STOP", type="secondary", use_container_width=True, key="emergency_stop"):
                # Clear processing state and any ongoing operations
                st.session_state['is_processing'] = False
                st.session_state['stop_processing'] = True
                st.error("⚠️ Process stopped by user")
                st.rerun()
    
    # Feature selection with radio buttons
    analysis_type = st.radio(
        "**Choose analysis type:**",
        ["🌐 URL Analysis", "📄 HTML Analysis"],
        horizontal=True,
        key="main_analysis_type",
        disabled=is_processing
    )
    
    # Show tip for HTML Analysis (only when not processing)
    if analysis_type == "📄 HTML Analysis" and not is_processing:
        st.info("""
💡 **How to: Analyse content from draft document**

1. Create a copy of the draft document
2. Remove anything that is not part of the content to audit  
Note: You can leave images/screenshot in content body
3. Download the draft document as HTML
4. Click "Browse files" and upload downloaded document
5. Start the analysis by clicking on "🚀 Analyze Content"
        """)
    
    # Casino mode toggle - moved to top level
    casino_mode = st.checkbox(
        "🎰 Casino Review Mode",
        help="Use specialized AI assistant for gambling content analysis",
        key="global_casino_mode",
        disabled=is_processing
    )
    
    # Show sticky message when casino mode is enabled
    if casino_mode:
        st.success("🎰 **Casino Review Mode: ON** - Using specialized gambling content analysis")
    
    # Get appropriate feature handler
    try:
        available_features = FeatureRegistry.get_available_features()
        
        if not available_features:
            st.error("❌ No features registered")
            return
        
        # Map display names to feature keys
        if analysis_type == "🌐 URL Analysis":
            feature_key = "url_analysis"
        else:
            feature_key = "html_analysis"
        
        # Check if feature exists
        if feature_key not in available_features:
            st.error(f"❌ Feature '{feature_key}' not found")
            return
        
        feature_handler = FeatureRegistry.get_handler(feature_key)
        
        if is_admin:
            render_admin_interface(feature_handler, feature_key, casino_mode)
        else:
            render_user_interface(feature_handler, feature_key, casino_mode)
            
    except Exception as e:
        st.error(f"❌ Error loading feature: {str(e)}")

def render_admin_interface(feature_handler, feature_key: str, casino_mode: bool):
    """Admin interface with two steps and preview"""
    
    # Check processing state
    is_processing = st.session_state.get('is_processing', False)
    
    # Check if we have extracted content
    has_content = feature_handler.has_extracted_content()
    
    if not has_content:
        # Step 1: Extract content
        st.subheader("Step 1: Extract Content")
        
        # Get input interface (disabled if processing)
        input_data = feature_handler.get_input_interface(disabled=is_processing)
        # Override casino mode with global setting
        input_data['casino_mode'] = casino_mode
        
        # Extract button
        extract_button = st.button(
            "📄 Extract Content", 
            type="primary", 
            disabled=not input_data.get('is_valid') or is_processing,
            key="admin_extract"
        )
        
        if extract_button:
            st.session_state['is_processing'] = True
            st.rerun()
            
        # Process extraction if button was clicked
        if st.session_state.get('is_processing') and not st.session_state.get('stop_processing'):
            process_extraction_admin(feature_handler, input_data, casino_mode)
    
    else:
        # Step 2: Show preview and analyze
        st.subheader("Step 2: Review & Analyze")
        
        # Show admin preview
        show_admin_preview(feature_handler)
        
        # Action buttons
        col1, col2 = st.columns([1, 1])
        with col1:
            analyze_button = st.button(
                "🚀 Run AI Analysis", 
                type="primary", 
                disabled=is_processing,
                key="admin_analyze"
            )
            if analyze_button:
                st.session_state['is_processing'] = True
                st.rerun()
                
        with col2:
            if st.button("🗑️ Clear & Restart", disabled=is_processing, key="admin_clear"):
                feature_handler.clear_session_data()
                st.rerun()
        
        # Process analysis if button was clicked
        if st.session_state.get('is_processing') and not st.session_state.get('stop_processing'):
            process_analysis_admin(feature_handler, feature_key, casino_mode)

def render_user_interface(feature_handler, feature_key: str, casino_mode: bool):
    """Simple user interface with report display"""
    from ui.layouts.user_layout import UserLayout
    
    layout = UserLayout()
    layout.render(feature_key, casino_mode)

def process_extraction_admin(feature_handler, input_data, casino_mode):
    """Process extraction with emergency stop support"""
    try:
        with st.status("Extracting content...") as status:
            # Check for stop signal
            if st.session_state.get('stop_processing'):
                st.session_state['is_processing'] = False
                st.session_state['stop_processing'] = False
                return
            
            success, extracted_content, error = feature_handler.extract_content(input_data)
            
            # Check for stop signal again
            if st.session_state.get('stop_processing'):
                st.session_state['is_processing'] = False
                st.session_state['stop_processing'] = False
                return
            
            if success:
                # Save data
                feature_handler.set_session_data('extracted_content', extracted_content)
                feature_handler.set_session_data('source_info', feature_handler.get_source_description(input_data))
                feature_handler.set_session_data('casino_mode', casino_mode)
                
                status.update(label="✅ Content extracted successfully!", state="complete")
                st.session_state['is_processing'] = False
                st.rerun()
            else:
                st.error(f"❌ {error}")
                st.session_state['is_processing'] = False
                
    except Exception as e:
        st.error(f"❌ Extraction failed: {str(e)}")
        st.session_state['is_processing'] = False

def process_analysis_admin(feature_handler, feature_key, casino_mode):
    """Process analysis with emergency stop support"""
    try:
        extracted_content = feature_handler.get_extracted_content()
        source_info = feature_handler.get_source_info()
        
        with st.status("Running AI analysis...") as status:
            # Check for stop signal
            if st.session_state.get('stop_processing'):
                st.session_state['is_processing'] = False
                st.session_state['stop_processing'] = False
                return
            
            analysis_result = run_ai_analysis(extracted_content, casino_mode)
            
            # Check for stop signal
            if st.session_state.get('stop_processing'):
                st.session_state['is_processing'] = False
                st.session_state['stop_processing'] = False
                return
            
            if analysis_result and analysis_result.get('success'):
                status.update(label="Generating report...", state="running")
                word_bytes = generate_report(analysis_result, source_info, casino_mode)
                
                status.update(label="✅ Analysis complete!", state="complete")
                st.session_state['is_processing'] = False
                
                st.success("✅ Analysis complete!")
                
                # Show markdown report in admin interface
                st.markdown("### 📄 Generated Report")
                st.markdown(analysis_result['report'])
                
                # Show admin results
                show_admin_results(analysis_result)
                
                # Download
                show_download(word_bytes, f"admin_{feature_key}")
            else:
                st.error("❌ Analysis failed")
                st.session_state['is_processing'] = False
                
    except Exception as e:
        st.error(f"❌ Analysis failed: {str(e)}")
        st.session_state['is_processing'] = False

def show_admin_preview(feature_handler):
    """Show content preview for admin"""
    extracted_content = feature_handler.get_extracted_content()
    source_info = feature_handler.get_source_info()
    
    st.info(f"**Source**: {source_info}")
    
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
    
    # Content preview
    with st.expander("👁️ View Full Extracted Content"):
        st.text_area(
            "Complete Extracted Content:",
            value=extracted_content,
            height=400,
            key="admin_content_preview"
        )

def show_admin_results(analysis_result):
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

def run_ai_analysis(extracted_content, casino_mode):
    """Run AI analysis"""
    import asyncio
    import concurrent.futures
    from core.analyzer import analyze_content
    
    try:
        async def run_analysis():
            return await analyze_content(extracted_content, casino_mode)
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(lambda: asyncio.run(run_analysis()))
            return future.result(timeout=300)
            
    except Exception as e:
        st.error(f"Analysis error: {str(e)}")
        return None

def generate_report(analysis_result, source_info, casino_mode):
    """Generate Word report"""
    from core.reporter import generate_word_report
    
    return generate_word_report(
        analysis_result['report'],
        f"YMYL Report - {source_info}",
        casino_mode
    )

def show_download(word_bytes, prefix: str):
    """Show download button with unique key"""
    from datetime import datetime
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ymyl_report_{timestamp}.docx"
    
    st.download_button(
        label="📄 Download Report",
        data=word_bytes,
        file_name=filename,
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        type="primary",
        key=f"download_{prefix}_{timestamp}"  # Unique key prevents UI reset
    )

if __name__ == "__main__":
    main()