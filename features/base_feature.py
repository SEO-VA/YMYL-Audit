#!/usr/bin/env python3
"""
Base Feature Interface for YMYL Audit Tool
Defines common interface for all analysis features
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional
import streamlit as st
from datetime import datetime

class BaseAnalysisFeature(ABC):
    """Base class for all analysis features"""
    
    def __init__(self):
        """Initialize base feature"""
        self.feature_id = self.__class__.__name__.lower().replace('analysisfeature', '').replace('feature', '')
        self.session_key_prefix = f"{self.feature_id}_"
    
    @abstractmethod
    def get_input_interface(self) -> Dict[str, Any]:
        """
        Render input interface and return input data
        
        Returns:
            Dict containing input data and validation status
        """
        pass
    
    @abstractmethod
    def extract_content(self, input_data: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Extract content from input
        
        Args:
            input_data: Input data from get_input_interface
            
        Returns:
            Tuple of (success, extracted_content_json, error_message)
        """
        pass
    
    @abstractmethod
    def get_feature_name(self) -> str:
        """Get display name for this feature"""
        pass
    
    def supports_casino_mode(self) -> bool:
        """Whether this feature supports casino-specific analysis"""
        return True
    
    def get_session_key(self, key: str) -> str:
        """Get prefixed session state key"""
        return f"{self.session_key_prefix}{key}"
    
    def set_session_data(self, key: str, value: Any):
        """Set data in session state with feature prefix"""
        session_key = self.get_session_key(key)
        st.session_state[session_key] = value
    
    def get_session_data(self, key: str, default: Any = None) -> Any:
        """Get data from session state with feature prefix"""
        session_key = self.get_session_key(key)
        return st.session_state.get(session_key, default)
    
    def clear_session_data(self, key: str = None):
        """Clear session data for this feature"""
        if key:
            session_key = self.get_session_key(key)
            if session_key in st.session_state:
                del st.session_state[session_key]
        else:
            # Clear all feature data
            keys_to_remove = [k for k in st.session_state.keys() 
                            if k.startswith(self.session_key_prefix)]
            for key in keys_to_remove:
                del st.session_state[key]
    
    def show_casino_mode_toggle(self) -> bool:
        """Show casino mode toggle if supported"""
        if not self.supports_casino_mode():
            return False
        
        # Use a simpler key to avoid conflicts
        key = f"casino_mode_{self.feature_id}"
        
        return st.checkbox(
            "🎰 Casino Review Mode",
            help="Use specialized AI assistant for gambling content analysis",
            key=key
        )
    
    def validate_input(self, input_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate input data
        
        Args:
            input_data: Input data to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Default validation - override in subclasses
        if not input_data:
            return False, "No input data provided"
        return True, ""
    
    def get_progress_steps(self) -> list:
        """Get list of progress steps for this feature"""
        return [
            "Validating input",
            "Extracting content", 
            "Structuring data",
            "Preparing for analysis"
        ]
    
    def show_extraction_status(self, extracted_content: str, source_info: str):
        """Show extraction status and preview"""
        st.success("✅ Content extracted successfully!")
        
        # Store in session
        self.set_session_data('extracted_content', extracted_content)
        self.set_session_data('source_info', source_info)
        self.set_session_data('extraction_time', datetime.now().isoformat())
        
        # Show preview info
        st.info(f"💡 Content ready for AI analysis from: **{source_info}**")
    
    def get_extraction_metrics(self, extracted_content: str) -> Dict[str, Any]:
        """Get metrics about extracted content"""
        try:
            import json
            content_data = json.loads(extracted_content)
            big_chunks = content_data.get('big_chunks', [])
            
            total_small_chunks = sum(len(chunk.get('small_chunks', [])) for chunk in big_chunks)
            
            return {
                'big_chunks': len(big_chunks),
                'small_chunks': total_small_chunks,
                'json_size': len(extracted_content),
                'content_size_mb': len(extracted_content) / (1024 * 1024)
            }
        except Exception:
            return {
                'json_size': len(extracted_content),
                'content_size_mb': len(extracted_content) / (1024 * 1024)
            }
    
    def create_clear_button(self, button_text: str = "🗑️ Clear & Restart") -> bool:
        """Create clear button and handle clearing"""
        if st.button(button_text, help="Clear extracted content and start over"):
            self.clear_session_data()
            st.rerun()
            return True
        return False
    
    def has_extracted_content(self) -> bool:
        """Check if content has been extracted"""
        return self.get_session_data('extracted_content') is not None
    
    def get_extracted_content(self) -> Optional[str]:
        """Get extracted content from session"""
        return self.get_session_data('extracted_content')
    
    def get_source_info(self) -> str:
        """Get source information from session"""
        return self.get_session_data('source_info', 'Unknown source')
    
    def show_input_validation_error(self, error_message: str):
        """Show input validation error"""
        st.error(f"❌ {error_message}")
    
    def show_extraction_error(self, error_message: str):
        """Show content extraction error"""  
        st.error(f"❌ Extraction failed: {error_message}")
        
        with st.expander("🔧 Troubleshooting"):
            st.markdown("""
            **Common issues:**
            - Check your input format and content
            - Ensure content is not too large
            - Try again in a few moments
            - Contact support if problem persists
            """)
