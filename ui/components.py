#!/usr/bin/env python3
"""
UI Components for YMYL Audit Tool
Reusable Streamlit UI components
"""

import streamlit as st
import time
from datetime import datetime
from typing import Tuple, Dict, Any
from core.auth import get_current_user

def create_header():
    """Create the main page header"""
    # Main title
    st.title("🔍 YMYL Audit Tool")
    st.markdown("**AI-powered YMYL compliance analysis for web content**")
    
    # User info in header
    current_user = get_current_user()
    if current_user != 'Anonymous':
        col1, col2 = st.columns([3, 1])
        with col2:
            st.markdown(f"**👤 {current_user}**")
    
    st.markdown("---")

def create_url_input(two_step_mode: bool = False) -> Tuple[str, bool, bool]:
    """
    Create URL input section with casino mode toggle
    
    Args:
        two_step_mode: Whether to show extract button instead of analyze button
    
    Returns:
        Tuple of (url, casino_mode, button_clicked)
    """
    st.subheader("📝 Content Analysis")
    
    # URL input
    col1, col2 = st.columns([2, 1])
    
    with col1:
        url = st.text_input(
            "Enter the URL to analyze:",
            placeholder="https://example.com/page-to-analyze",
            help="Enter the full URL including http:// or https://",
            key="url_input"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)  # Spacing
        casino_mode = st.checkbox(
            "🎰 Casino Review Mode",
            help="Use specialized AI assistant for gambling content analysis",
            key="casino_mode"
        )
    
    # Button section
    col1, col2, col3 = st.columns([2, 1, 2])
    
    with col2:
        if two_step_mode:
            # Admin mode - Extract button
            button_clicked = st.button(
                "📄 Extract Content",
                type="primary",
                use_container_width=True,
                help="Extract and structure content from URL",
                key="extract_button",
                disabled=not url or not url.strip()
            )
        else:
            # Regular mode - Analyze button  
            button_clicked = st.button(
                "🚀 Analyze Content",
                type="primary",
                use_container_width=True,
                help="Extract content and analyze for YMYL compliance",
                key="analyze_button",
                disabled=not url or not url.strip()
            )
    
    # Show URL validation
    if url and not _is_valid_url(url):
        st.warning("⚠️ Please enter a valid URL (must include http:// or https://)")
    
    return url.strip() if url else "", casino_mode, button_clicked

def create_fake_progress(total_steps: int = 5) -> Tuple[Any, Any, callable]:
    """
    Create fake progress bar components
    
    Args:
        total_steps: Number of progress steps
        
    Returns:
        Tuple of (progress_bar, status_text, update_function)
    """
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    def update_progress(step: int, message: str):
        """Update progress display"""
        progress = min(step / total_steps, 1.0)
        progress_bar.progress(progress)
        status_text.text(f"🔄 {message}")
    
    return progress_bar, status_text, update_progress

def create_results_display(analysis_result: Dict[str, Any], word_bytes: bytes, filename: str):
    """
    Simple results display with just download button
    
    Args:
        analysis_result: Results from AI analysis
        word_bytes: Word document bytes
        filename: Filename for download
    """
    # Simple download button
    st.download_button(
        label="📄 Download Word Report",
        data=word_bytes,
        file_name=filename,
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        help="Download YMYL compliance report as Word document",
        type="primary",
        use_container_width=True
    )
    
    st.info("💡 **Tip**: The Word document imports perfectly into Google Docs!")

def create_loading_animation(message: str = "Processing..."):
    """
    Create a simple loading animation
    
    Args:
        message: Loading message to display
    """
    placeholder = st.empty()
    
    loading_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    for i in range(10):  # Show for ~2 seconds
        char = loading_chars[i % len(loading_chars)]
        placeholder.text(f"{char} {message}")
        time.sleep(0.2)
    
    placeholder.empty()

def create_error_display(error_message: str, show_details: bool = False):
    """
    Create standardized error display
    
    Args:
        error_message: Main error message
        show_details: Whether to show technical details
    """
    st.error(f"❌ {error_message}")
    
    if show_details:
        with st.expander("🔧 Technical Details"):
            st.text(error_message)
            st.markdown("**Troubleshooting:**")
            st.markdown("""
            1. Check your internet connection
            2. Verify the URL is accessible
            3. Try again in a few minutes
            4. Contact support if the problem persists
            """)

def create_info_panel():
    """Create informational panel with usage instructions"""
    with st.sidebar:
        st.markdown("### ℹ️ How to Use")
        
        st.markdown("""
        **Step-by-step:**
        
        1️⃣ **Enter URL** - Paste the webpage URL you want to analyze
        
        2️⃣ **Choose Mode** - Select regular or casino review mode
        
        3️⃣ **Click Analyze** - AI will process the content (takes 2-5 minutes)
        
        4️⃣ **Download Report** - Get professionally formatted Word document
        
        5️⃣ **Import to Google Docs** - Upload the Word file to Google Drive
        """)
        
        st.markdown("### 🎯 Features")
        st.markdown("""
        - **Structured Analysis**: Content organized by sections
        - **YMYL Compliance**: Checks against guidelines
        - **Casino Mode**: Specialized gambling content review  
        - **Word Export**: Professional document formatting
        - **Google Docs Ready**: Perfect import compatibility
        """)
        
        st.markdown("### ⚡ Tips")
        st.markdown("""
        - Analysis takes 2-5 minutes for thorough review
        - Casino mode uses specialized gambling guidelines
        - Word documents preserve all formatting in Google Docs
        - Refresh page to start fresh analysis
        """)

def _is_valid_url(url: str) -> bool:
    """
    Basic URL validation
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL appears valid
    """
    if not url:
        return False
    
    url = url.strip().lower()
    return url.startswith(('http://', 'https://')) and '.' in url

def show_configuration_status():
    """Show configuration validation status in sidebar"""
    from config.settings import validate_configuration
    
    with st.sidebar:
        st.markdown("### 🔧 System Status")
        
        try:
            is_valid, errors = validate_configuration()
            
            if is_valid:
                st.success("✅ Configuration OK")
            else:
                st.error("❌ Configuration Issues")
                for error in errors:
                    st.text(f"• {error}")
                    
        except Exception as e:
            st.error(f"❌ Config check failed: {str(e)}")

def create_simple_metrics(metrics: Dict[str, Any]):
    """
    Create simple metrics display
    
    Args:
        metrics: Dictionary of metric names and values
    """
    if not metrics:
        return
    
    # Display metrics in columns
    metric_items = list(metrics.items())
    num_metrics = len(metric_items)
    
    if num_metrics <= 3:
        cols = st.columns(num_metrics)
    else:
        # Split into multiple rows
        cols = st.columns(3)
    
    for i, (key, value) in enumerate(metric_items):
        col_index = i % len(cols)
        
        with cols[col_index]:
            # Format value
            if isinstance(value, float):
                formatted_value = f"{value:.2f}"
            elif isinstance(value, int):
                formatted_value = f"{value:,}"
            else:
                formatted_value = str(value)
            
            # Format key
            formatted_key = key.replace('_', ' ').title()
            
            st.metric(formatted_key, formatted_value)

def create_status_indicator(status: str, message: str = ""):
    """
    Create status indicator with appropriate styling
    
    Args:
        status: Status type (success, error, warning, info)
        message: Status message
    """
    if status == "success":
        st.success(f"✅ {message}")
    elif status == "error":
        st.error(f"❌ {message}")
    elif status == "warning":
        st.warning(f"⚠️ {message}")
    elif status == "info":
        st.info(f"ℹ️ {message}")
    else:
        st.text(f"• {message}")

def format_timestamp(timestamp: float = None) -> str:
    """
    Format timestamp for display
    
    Args:
        timestamp: Unix timestamp (current time if None)
        
    Returns:
        Formatted timestamp string
    """
    if timestamp is None:
        timestamp = time.time()
    
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")
