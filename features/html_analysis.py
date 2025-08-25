#!/usr/bin/env python3
"""
HTML Analysis Feature for YMYL Audit Tool - Updated Version
Handles HTML file and ZIP archive content analysis without individual casino mode toggle
"""

import streamlit as st
import zipfile
import io
from typing import Dict, Any, Tuple, Optional
from features.base_feature import BaseAnalysisFeature
from core.html_extractor import extract_html_content
from utils.helpers import safe_log

class HTMLAnalysisFeature(BaseAnalysisFeature):
    """Feature for analyzing content from HTML files or ZIP archives"""
    
    def get_feature_name(self) -> str:
        """Get display name for this feature"""
        return "HTML Analysis"
    
    def get_input_interface(self, disabled: bool = False) -> Dict[str, Any]:
        """Render simple HTML input interface without casino toggle"""
        
        # Simple input method selection with Upload HTML/ZIP as default
        input_method = st.selectbox(
            "**Input method:**",
            ["📁 Upload HTML/ZIP", "📝 Paste HTML"],
            key=self.get_session_key("input_method"),
            disabled=disabled
        )
        
        # Input interface based on method
        input_data = {'input_method': input_method}
        
        if input_method == "📝 Paste HTML":
            input_data.update(self._render_simple_html_interface(disabled))
        else:
            input_data.update(self._render_simple_zip_interface(disabled))
        
        return input_data
    
    def _render_simple_html_interface(self, disabled: bool = False) -> Dict[str, Any]:
        """Simple HTML paste interface"""
        html_content = st.text_area(
            "**HTML Content:**",
            height=150,
            placeholder="<html><body>Your content...</body></html>",
            key=self.get_session_key("html_content"),
            disabled=disabled
        )
        
        # Simple validation
        is_valid = bool(html_content and html_content.strip() and len(html_content.strip()) > 10)
        
        return {
            'html_content': html_content.strip() if html_content else "",
            'is_valid': is_valid,
            'error_message': "" if is_valid else "HTML content required",
            'source_type': 'html_paste'
        }
    
    def _render_simple_zip_interface(self, disabled: bool = False) -> Dict[str, Any]:
        """Simple ZIP/HTML upload interface"""
        uploaded_file = st.file_uploader(
            "**Upload HTML or ZIP file:**",
            type=['zip', 'html', 'htm'],
            key=self.get_session_key("zip_file"),
            disabled=disabled,
            help="Upload a single HTML file or a ZIP containing one HTML file"
        )
        
        # Validation
        is_valid = uploaded_file is not None
        error_message = ""
        html_content = ""
        
        if uploaded_file:
            try:
                if uploaded_file.name.lower().endswith('.zip'):
                    zip_bytes = uploaded_file.getvalue()
                    is_valid, html_content, error_message = self._validate_zip_file(zip_bytes)
                else:
                    # Direct HTML file
                    html_content = uploaded_file.getvalue().decode('utf-8', errors='ignore')
                    is_valid, error_message = self._validate_html_content(html_content)
                
                if not is_valid:
                    st.error(f"❌ {error_message}")
                    
            except Exception as e:
                is_valid = False
                error_message = f"Error reading file: {str(e)}"
                st.error(f"❌ {error_message}")
        
        return {
            'zip_file': uploaded_file,
            'html_content': html_content,
            'is_valid': is_valid,
            'error_message': error_message,
            'source_type': 'file_upload'
        }
    
    def _is_valid_html(self, html_content: str) -> bool:
        """Basic HTML validation"""
        if not html_content or len(html_content.strip()) < 10:
            return False
        
        html_lower = html_content.lower().strip()
        
        # Check for basic HTML structure
        has_html_tag = '<html' in html_lower and '</html>' in html_lower
        has_body_tag = '<body' in html_lower and '</body>' in html_lower
        has_content = len(html_content.strip()) > 50
        
        return has_html_tag or has_body_tag or has_content
    
    def _validate_zip_file(self, zip_bytes: bytes) -> Tuple[bool, str, str]:
        """Validate ZIP file and extract HTML content"""
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zip_file:
                # Get file list
                file_list = zip_file.namelist()
                
                # Filter HTML files
                html_files = [f for f in file_list 
                             if f.lower().endswith(('.html', '.htm')) 
                             and not f.startswith('__MACOSX/')]
                
                if len(html_files) == 0:
                    return False, "", "No HTML files found in ZIP archive"
                
                if len(html_files) > 1:
                    return False, "", f"Multiple HTML files found ({len(html_files)}). ZIP must contain exactly one HTML file"
                
                # Extract HTML content
                html_file = html_files[0]
                html_content = zip_file.read(html_file).decode('utf-8', errors='ignore')
                
                # Validate HTML content
                if not self._is_valid_html(html_content):
                    return False, "", "HTML file contains invalid or incomplete content"
                
                # Check size
                if len(html_content) > 5 * 1024 * 1024:  # 5MB limit
                    return False, "", f"HTML file too large: {len(html_content):,} characters (max: 5MB)"
                
                return True, html_content, ""
                
        except zipfile.BadZipFile:
            return False, "", "Invalid or corrupted ZIP file"
        except UnicodeDecodeError:
            return False, "", "HTML file contains invalid character encoding"
        except Exception as e:
            return False, "", f"Error processing ZIP file: {str(e)}"
    
    def validate_input(self, input_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate HTML input"""
        html_content = input_data.get('html_content', '').strip()
        
        if not html_content:
            return False, "HTML content is required"
        
        if len(html_content) < 10:
            return False, "HTML content is too short"
        
        if len(html_content) > 5 * 1024 * 1024:  # 5MB limit
            return False, f"HTML content is too large: {len(html_content):,} characters (max: 5MB)"
        
        if not self._is_valid_html(html_content):
            return False, "HTML content appears to be invalid"
        
        return True, ""
    
    def extract_content(self, input_data: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
        """Extract content from HTML"""
        html_content = input_data['html_content']
        source_type = input_data.get('source_type', 'unknown')
        
        safe_log(f"Starting HTML content extraction ({source_type}, {len(html_content):,} chars)")
        
        try:
            # Use HTML extractor
            success, extracted_content, error = extract_html_content(html_content)
            
            if success:
                safe_log(f"HTML extraction successful: {len(extracted_content):,} characters")
                return True, extracted_content, None
            else:
                safe_log(f"HTML extraction failed: {error}")
                return False, None, error
                
        except Exception as e:
            error_msg = f"Unexpected error during HTML extraction: {str(e)}"
            safe_log(error_msg)
            return False, None, error_msg
    
    def get_progress_steps(self) -> list:
        """Get HTML-specific progress steps"""
        return [
            "Validating HTML content",
            "Parsing HTML structure", 
            "Extracting text content",
            "Processing tables and lists",
            "Organizing by sections"
        ]
    
    def _validate_html_content(self, html_content: str) -> Tuple[bool, str]:
        """Validate direct HTML content"""
        if not self._is_valid_html(html_content):
            return False, "HTML file contains invalid or incomplete content"
        
        if len(html_content) > 5 * 1024 * 1024:  # 5MB limit
            return False, f"HTML file too large: {len(html_content):,} characters (max: 5MB)"
        
        return True, ""
    
    def get_source_description(self, input_data: Dict[str, Any]) -> str:
        """Get description of the content source"""
        source_type = input_data.get('source_type', 'unknown')
        
        if source_type == 'html_paste':
            return "HTML (pasted content)"
        elif source_type == 'file_upload':
            uploaded_file = input_data.get('zip_file')
            if uploaded_file:
                return f"File: {uploaded_file.name}"
            return "Uploaded file"
        else:
            return "HTML content"