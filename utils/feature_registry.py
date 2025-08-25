#!/usr/bin/env python3
"""
Feature Registry for YMYL Audit Tool
Manages dynamic loading and registration of analysis features
"""

from typing import Dict, Any, Type
from utils.helpers import safe_log

class FeatureRegistry:
    """Central registry for managing analysis features"""
    
    _features = {}
    _handlers = {}
    
    @classmethod
    def register_feature(cls, feature_id: str, feature_config: Dict[str, Any], handler_class: Type):
        """
        Register a new feature
        
        Args:
            feature_id: Unique feature identifier
            feature_config: Feature configuration and metadata
            handler_class: Handler class for the feature
        """
        cls._features[feature_id] = feature_config
        cls._handlers[feature_id] = handler_class
        safe_log(f"Registered feature: {feature_id}")
    
    @classmethod
    def get_available_features(cls) -> Dict[str, Dict[str, Any]]:
        """Get all available features with their metadata"""
        return cls._features.copy()
    
    @classmethod
    def get_handler(cls, feature_id: str):
        """
        Get handler instance for a feature
        
        Args:
            feature_id: Feature identifier
            
        Returns:
            Handler instance
        """
        if feature_id not in cls._handlers:
            raise ValueError(f"Unknown feature: {feature_id}")
        
        handler_class = cls._handlers[feature_id]
        return handler_class()
    
    @classmethod
    def is_feature_available(cls, feature_id: str) -> bool:
        """Check if a feature is available"""
        return feature_id in cls._features
    
    @classmethod
    def get_feature_config(cls, feature_id: str) -> Dict[str, Any]:
        """Get configuration for a specific feature"""
        return cls._features.get(feature_id, {})


# Auto-register available features
def _register_default_features():
    """Register default features with better error handling"""
    
    # URL Analysis Feature
    try:
        from features.url_analysis import URLAnalysisFeature
        FeatureRegistry.register_feature(
            'url_analysis',
            {
                'display_name': '🌐 URL Analysis',
                'description': 'Analyze content from web URLs',
                'supports_casino_mode': True,
                'input_types': ['url'],
                'version': '1.0'
            },
            URLAnalysisFeature
        )
        safe_log("Successfully registered URL Analysis feature")
    except ImportError as e:
        safe_log(f"URL Analysis feature not available: {e}")
    except Exception as e:
        safe_log(f"Error registering URL Analysis feature: {e}")
    
    # HTML Analysis Feature  
    try:
        from features.html_analysis import HTMLAnalysisFeature
        FeatureRegistry.register_feature(
            'html_analysis',
            {
                'display_name': '📄 HTML Analysis', 
                'description': 'Analyze HTML files or ZIP archives',
                'supports_casino_mode': True,
                'input_types': ['html', 'zip'],
                'version': '1.0'
            },
            HTMLAnalysisFeature
        )
        safe_log("Successfully registered HTML Analysis feature")
    except ImportError as e:
        safe_log(f"HTML Analysis feature not available: {e}")
    except Exception as e:
        safe_log(f"Error registering HTML Analysis feature: {e}")

# Initialize features on module load with error handling
try:
    _register_default_features()
    safe_log(f"Feature registration complete. Available features: {len(FeatureRegistry.get_available_features())}")
except Exception as e:
    safe_log(f"Critical error during feature registration: {e}")
