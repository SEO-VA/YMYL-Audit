#!/usr/bin/env python3
"""
YMYL Audit Tool - 5-AUDIT WORKFLOW WITH MULTI-FILE SUPPORT
Main application with single and multi-file processing capabilities
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
    """Main application with single and multi-file workflow support"""
    
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
        if is_admin:
            st.markdown("**AI-powered YMYL compliance analysis with 5 parallel audits** (*Admin Mode*)")
        else:
            st.markdown("**AI-powered YMYL compliance analysis with 5 parallel audits**")
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
    
    # Show tips based on analysis type and user mode
    if not is_processing:
        if analysis_type == "📄 HTML Analysis":
            if is_admin:
                st.info("""
💡 **Admin HTML Analysis**

**Single File**: Upload one HTML file for detailed analysis with debug options
**Multi-File**: Upload up to 5 HTML files for bulk processing with individual debug reports
                """)
            else:
                st.info("""
💡 **HTML Analysis**

**Single File**: Upload one HTML file for analysis  
**Multi-File**: Upload up to 5 HTML files - each gets processed in parallel with individual reports
                """)
        else:
            st.info("""
💡 **URL Analysis**

Enter a webpage URL for comprehensive YMYL compliance analysis with 5 parallel AI audits
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
    
    # Show multi-audit system info
    if not is_processing:
        if is_admin:
            st.info("🔍 **Multi-Audit System**: 5 parallel AI audits with smart deduplication. Admin mode includes debug capabilities and detailed metrics.")
        else:
            st.info("🔍 **Multi-Audit System**: 5 parallel AI audits with smart deduplication for higher accuracy. Processing takes 2-4 minutes per file.")
    
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
    """Admin interface with enhanced multi-file capabilities"""
    from ui.layouts.admin_layout import AdminLayout
    
    layout = AdminLayout()
    layout.render(feature_key)
    
    # Note: casino_mode is handled within the layout via global session state

def render_user_interface(feature_handler, feature_key: str, casino_mode: bool):
    """User interface with multi-file support"""
    from ui.layouts.user_layout import UserLayout
    
    layout = UserLayout()
    layout.render(feature_key, casino_mode)

def process_extraction_admin(feature_handler, input_data, casino_mode):
    """Process extraction with emergency stop support (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All processing logic has been moved to the respective layouts
    pass

def process_analysis_admin(feature_handler, feature_key, casino_mode):
    """Process analysis with emergency stop support (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All processing logic has been moved to the respective layouts
    pass

def show_admin_normal_results(analysis_result, word_bytes, feature_key):
    """Show normal admin results (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All results display logic has been moved to the respective layouts
    pass

def show_admin_preview(feature_handler):
    """Show content preview for admin (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All preview logic has been moved to the respective layouts
    pass

def show_admin_results(analysis_result):
    """Show analysis results for admin (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All results display logic has been moved to the respective layouts
    pass

def run_multi_audit_analysis(extracted_content, casino_mode, debug_mode=False):
    """Run 5-audit analysis using the new analyzer (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All analysis logic has been moved to the respective layouts
    pass

def generate_report(analysis_result, source_info, casino_mode):
    """Generate Word report (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All report generation logic has been moved to the respective layouts
    pass

def show_download(word_bytes, prefix: str):
    """Show download button with unique key (legacy - now handled in layout)"""
    # This function is kept for backward compatibility
    # All download logic has been moved to the respective layouts
    pass

if __name__ == "__main__":
    main()