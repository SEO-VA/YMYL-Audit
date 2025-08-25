#!/usr/bin/env python3
"""
URL Analysis Feature for YMYL Audit Tool - Updated Version
Handles URL-based content analysis without individual casino mode toggle
"""

import streamlit as st
from typing import Dict, Any, Tuple, Optional
from features.base_feature import BaseAnalysisFeature
from core.extractor import extract_url_content
from utils.helpers import validate_url, safe_log

class URLAnalysisFeature(BaseAnalysisFeature):
    """Feature for analyzing content from web URLs"""
    
    def get_feature_name(self) -> str:
        """Get display name for this feature"""
        return "URL Analysis"
    
    def get_input_interface(self, disabled: bool = False) -> Dict[str, Any]:
        """Render simple URL input interface without casino toggle"""
        
        # URL input
        url = st.text_input(
            "**Enter URL:**",
            placeholder="https://example.com/page",
            key=self.get_session_key("url_input"),
            disabled=disabled
        )
        
        # Simple validation
        is_valid = bool(url and url.strip() and validate_url(url.strip()))
        
        if url and not is_valid:
            st.error("❌ Please enter a valid URL")
        
        return {
            'url': url.strip() if url else "",
            'is_valid': is_valid,
            'error_message': "" if is_valid else "Valid URL required"
        }
    
    def validate_input(self, input_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate URL input"""
        url = input_data.get('url', '').strip()
        
        if not url:
            return False, "URL is required"
        
        if not validate_url(url):
            return False, "Invalid URL format"
        
        return True, ""
    
    def extract_content(self, input_data: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
        """Extract content from URL"""
        url = input_data['url']
        
        safe_log(f"Starting URL content extraction from: {url}")
        
        try:
            # Use existing extractor
            success, extracted_content, error = extract_url_content(url)
            
            if success:
                safe_log(f"URL extraction successful: {len(extracted_content):,} characters")
                return True, extracted_content, None
            else:
                safe_log(f"URL extraction failed: {error}")
                return False, None, error
                
        except Exception as e:
            error_msg = f"Unexpected error during URL extraction: {str(e)}"
            safe_log(error_msg)
            return False, None, error_msg
    
    def get_progress_steps(self) -> list:
        """Get URL-specific progress steps"""
        return [
            "Connecting to URL",
            "Downloading content",
            "Parsing HTML structure", 
            "Extracting text content",
            "Organizing by sections"
        ]
    
    def get_source_description(self, input_data: Dict[str, Any]) -> str:
        """Get description of the content source"""
        url = input_data.get('url', '')
        try:
            from utils.helpers import extract_domain
            domain = extract_domain(url)
            return f"URL: {domain}" if domain else f"URL: {url}"
        except Exception:
            return f"URL: {url}"