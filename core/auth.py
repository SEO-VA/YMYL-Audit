#!/usr/bin/env python3
"""
Authentication module for YMYL Audit Tool
Simple username/password authentication using Streamlit secrets
"""

import streamlit as st
import time
from utils.helpers import safe_log

def check_authentication() -> bool:
    """
    Check if user is authenticated, show login form if not
    
    Returns:
        bool: True if authenticated, False otherwise
    """
    
    # Initialize session state
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = None
    
    # If already authenticated, return True
    if st.session_state.authenticated:
        return True
    
    # Show login form
    return show_login_form()

def show_login_form() -> bool:
    """
    Display login form and handle authentication
    
    Returns:
        bool: True if login successful, False otherwise
    """
    
    st.markdown("# 🔐 YMYL Audit Tool")
    st.markdown("### Please log in to continue")
    
    # Get user credentials from secrets
    try:
        users = st.secrets["auth"]["users"]
    except (KeyError, FileNotFoundError):
        st.error("❌ **Configuration Error**: Authentication not configured properly.")
        
        with st.expander("🔧 Setup Instructions"):
            st.markdown("""
            **Configure authentication in `.streamlit/secrets.toml`:**
            
            ```toml
            [auth]
            users = { admin = "password", user2 = "pass2" }
            ```
            """)
        return False
    
    # Login form
    with st.form("login_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        
        with col1:
            username = st.text_input("👤 Username", placeholder="Enter username")
        
        with col2:
            password = st.text_input("🔑 Password", type="password", placeholder="Enter password")
        
        login_button = st.form_submit_button("🚀 Login", type="primary", use_container_width=True)
        
        if login_button:
            return handle_login(username, password, users)
    
    return False

def handle_login(username: str, password: str, users: dict) -> bool:
    """
    Handle login attempt
    
    Args:
        username: Entered username
        password: Entered password  
        users: Dictionary of valid users from secrets
        
    Returns:
        bool: True if login successful
    """
    
    if not username or not password:
        st.error("❌ Please enter both username and password")
        return False
    
    # Check credentials
    if username in users and password == users[username]:
        # Successful login
        st.session_state.authenticated = True
        st.session_state.username = username
        
        st.success(f"✅ Welcome, {username}!")
        safe_log(f"User {username} logged in successfully")
        
        time.sleep(0.5)  # Brief pause for UX
        st.rerun()
        return True
    else:
        # Failed login
        st.error("❌ Invalid username or password")
        safe_log(f"Failed login attempt for username: {username}")
        time.sleep(1)  # Prevent rapid retry
        return False

def logout():
    """Log out the current user"""
    
    username = st.session_state.get('username', 'Unknown')
    
    # Clear session state
    st.session_state.authenticated = False
    st.session_state.username = None
    
    safe_log(f"User {username} logged out")
    st.success("👋 Logged out successfully!")

def get_current_user() -> str:
    """
    Get the currently authenticated username
    
    Returns:
        str: Username or 'Anonymous' if not authenticated
    """
    return st.session_state.get('username', 'Anonymous')

def is_authenticated() -> bool:
    """
    Check if user is currently authenticated
    
    Returns:
        bool: True if authenticated
    """
    return st.session_state.get('authenticated', False)
