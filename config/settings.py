#!/usr/bin/env python3
"""
Configuration settings for YMYL Audit Tool
Manages settings and Streamlit secrets access
"""

import streamlit as st
from typing import Dict, Any
from utils.helpers import safe_log

# Default settings
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_CONTENT_LENGTH = 1000000  # 1MB
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
DEFAULT_AI_TIMEOUT = 300  # 5 minutes
DEFAULT_MAX_AI_CONTENT = 2000000  # 2MB

def get_openai_api_key() -> str:
    """
    Get OpenAI API key from Streamlit secrets
    
    Returns:
        API key string
        
    Raises:
        KeyError: If API key not found in secrets
    """
    try:
        return st.secrets["openai_api_key"]
    except KeyError:
        safe_log("OpenAI API key not found in secrets")
        raise KeyError("OpenAI API key not configured in secrets.toml")

def get_assistant_ids() -> Dict[str, str]:
    """
    Get assistant IDs from Streamlit secrets
    
    Returns:
        Dictionary with regular and casino assistant IDs
        
    Raises:
        KeyError: If assistant IDs not found in secrets
    """
    try:
        return {
            'regular': st.secrets["regular_assistant_id"],
            'casino': st.secrets["casino_assistant_id"]
        }
    except KeyError as e:
        safe_log(f"Assistant ID not found in secrets: {e}")
        raise KeyError(f"Assistant IDs not configured in secrets: {e}")

def get_request_settings() -> Dict[str, Any]:
    """
    Get HTTP request settings
    
    Returns:
        Dictionary with request configuration
    """
    return {
        'timeout': DEFAULT_TIMEOUT,
        'max_content_length': DEFAULT_MAX_CONTENT_LENGTH,
        'user_agent': DEFAULT_USER_AGENT
    }

def get_ai_settings() -> Dict[str, Any]:
    """
    Get AI analysis settings
    
    Returns:
        Dictionary with AI configuration
    """
    try:
        assistant_ids = get_assistant_ids()
        api_key = get_openai_api_key()
        
        return {
            'api_key': api_key,
            'regular_assistant_id': assistant_ids['regular'],
            'casino_assistant_id': assistant_ids['casino'],
            'timeout': DEFAULT_AI_TIMEOUT,
            'max_content_size': DEFAULT_MAX_AI_CONTENT
        }
    except KeyError as e:
        safe_log(f"AI settings configuration error: {e}")
        raise

def validate_configuration() -> tuple[bool, list]:
    """
    Validate that all required configuration is present
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    try:
        # Check OpenAI API key
        api_key = get_openai_api_key()
        if not api_key or not api_key.startswith('sk-'):
            errors.append("Invalid OpenAI API key format")
    except KeyError:
        errors.append("OpenAI API key not configured")
    
    try:
        # Check assistant IDs
        assistant_ids = get_assistant_ids()
        
        if not assistant_ids['regular'] or not assistant_ids['regular'].startswith('asst_'):
            errors.append("Invalid regular assistant ID format")
            
        if not assistant_ids['casino'] or not assistant_ids['casino'].startswith('asst_'):
            errors.append("Invalid casino assistant ID format")
            
    except KeyError:
        errors.append("Assistant IDs not configured")
    
    try:
        # Check auth configuration - your format
        users = st.secrets["auth"]["users"]
        if not isinstance(users, dict) or len(users) == 0:
            errors.append("No users configured for authentication")
    except KeyError:
        errors.append("Authentication not configured")
    
    is_valid = len(errors) == 0
    
    if is_valid:
        safe_log("Configuration validation passed")
    else:
        safe_log(f"Configuration validation failed: {errors}")
    
    return is_valid, errors

def get_secrets_template() -> str:
    """
    Get template for secrets.toml configuration - updated with both assistant IDs
    
    Returns:
        Template string for secrets.toml file
    """
    return """# YMYL Audit Tool Configuration - Updated Format

# OpenAI Configuration
openai_api_key = "sk-your-openai-api-key-here"
regular_assistant_id = "asst_your-regular-assistant-id-here"
casino_assistant_id = "asst_your-casino-assistant-id-here"

# Authentication - Your Current Format
[auth.users]
seoapp = "your-seoapp-password"
admin = "your-admin-password"
"""

def display_configuration_help():
    """Display configuration help in Streamlit"""
    st.error("❌ **Configuration Error**: Required settings not found")
    
    with st.expander("🔧 Configuration Instructions"):
        st.markdown("""
        **Create `.streamlit/secrets.toml` file with:**
        """)
        
        st.code(get_secrets_template(), language='toml')
        
        st.markdown("""
        **Required values:**
        
        1. **OpenAI API Key**: Get from https://platform.openai.com/api-keys
        2. **Assistant IDs**: Create YMYL compliance assistants in OpenAI platform
        3. **User Authentication**: Set username/password pairs for app access
        
        **For Streamlit Cloud deployment:**
        - Paste the secrets in your app's "Advanced settings" → "Secrets" field
        """)

# Constants for external use
TIMEOUT = DEFAULT_TIMEOUT
MAX_CONTENT_LENGTH = DEFAULT_MAX_CONTENT_LENGTH
AI_TIMEOUT = DEFAULT_AI_TIMEOUT
MAX_AI_CONTENT_SIZE = DEFAULT_MAX_AI_CONTENT
USER_AGENT = DEFAULT_USER_AGENT
