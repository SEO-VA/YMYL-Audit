#!/usr/bin/env python3
"""
Helper utilities for YMYL Audit Tool
Common utility functions used across the application
"""

import logging
import time
import re
from datetime import datetime
from typing import Any, Optional, Dict

# Setup simple logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def safe_log(message: str, level: str = "INFO"):
    """
    Safely log a message
    
    Args:
        message: Message to log
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    try:
        log_level = getattr(logging, level.upper(), logging.INFO)
        logger.log(log_level, message)
    except Exception:
        # Fallback to print if logging fails
        print(f"[{level}] {message}")

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes / (1024**2):.1f} MB"
    else:
        return f"{size_bytes / (1024**3):.1f} GB"

def clean_text(text: str) -> str:
    """
    Clean text content by removing extra whitespace and special characters
    
    Args:
        text: Raw text to clean
        
    Returns:
        Cleaned text
    """
    if not text:
        return ""
    
    # Remove extra whitespace
    cleaned = re.sub(r'\s+', ' ', text.strip())
    
    # Remove control characters but keep newlines and tabs
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', cleaned)
    
    return cleaned.strip()

def validate_url(url: str) -> bool:
    """
    Basic URL validation
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL appears valid
    """
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    
    # Basic pattern check
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))

def safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert value to integer
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
        
    Returns:
        Integer value or default
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Safely convert value to float
    
    Args:
        value: Value to convert  
        default: Default value if conversion fails
        
    Returns:
        Float value or default
    """
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate text to specified length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated text
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def get_timestamp() -> str:
    """
    Get current timestamp as formatted string
    
    Returns:
        Formatted timestamp
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def measure_execution_time(func):
    """
    Decorator to measure function execution time
    
    Args:
        func: Function to measure
        
    Returns:
        Decorated function
    """
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        execution_time = end_time - start_time
        safe_log(f"{func.__name__} executed in {execution_time:.3f} seconds")
        
        return result
    
    return wrapper

def create_safe_filename(text: str, max_length: int = 50) -> str:
    """
    Create safe filename from text
    
    Args:
        text: Text to convert to filename
        max_length: Maximum filename length
        
    Returns:
        Safe filename
    """
    if not text:
        return "untitled"
    
    # Remove/replace unsafe characters
    safe_text = re.sub(r'[^\w\s-]', '', text)  # Keep alphanumeric, spaces, hyphens
    safe_text = re.sub(r'\s+', '_', safe_text)  # Replace spaces with underscores
    safe_text = safe_text.lower().strip('_')
    
    # Truncate if too long
    if len(safe_text) > max_length:
        safe_text = safe_text[:max_length].rstrip('_')
    
    return safe_text or "untitled"

def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from URL
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain string or None if invalid
    """
    try:
        if not validate_url(url):
            return None
        
        # Remove protocol
        domain = re.sub(r'^https?://', '', url)
        
        # Remove path, query, fragment
        domain = domain.split('/')[0]
        domain = domain.split('?')[0]
        domain = domain.split('#')[0]
        
        # Remove port
        domain = domain.split(':')[0]
        
        return domain.lower()
        
    except Exception:
        return None

def format_duration(seconds: float) -> str:
    """
    Format duration in human readable format
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.1f}s"
    else:
        hours = int(seconds // 3600)
        remaining_minutes = int((seconds % 3600) // 60)
        return f"{hours}h {remaining_minutes}m"

def dict_get_nested(data: Dict, key_path: str, default: Any = None) -> Any:
    """
    Get nested dictionary value using dot notation
    
    Args:
        data: Dictionary to search
        key_path: Dot-separated key path (e.g., "user.profile.name")
        default: Default value if key not found
        
    Returns:
        Value at key path or default
    """
    try:
        keys = key_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
        
    except Exception:
        return default

def is_development_mode() -> bool:
    """
    Check if running in development mode
    
    Returns:
        True if in development mode
    """
    import os
    return os.environ.get('STREAMLIT_ENV', '').lower() == 'development'

# Error handling utilities
class SafeExecutor:
    """Context manager for safe code execution with logging"""
    
    def __init__(self, operation_name: str, reraise: bool = False):
        self.operation_name = operation_name
        self.reraise = reraise
        self.success = False
        self.error = None
    
    def __enter__(self):
        safe_log(f"Starting operation: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.success = True
            safe_log(f"Operation completed successfully: {self.operation_name}")
        else:
            self.success = False
            self.error = str(exc_val)
            safe_log(f"Operation failed: {self.operation_name} - {exc_val}", "ERROR")
            
            if self.reraise:
                return False  # Re-raise the exception
            else:
                return True   # Suppress the exception

# Convenience function for common safe execution pattern
def safe_execute(func, *args, operation_name: str = None, default_return=None, **kwargs):
    """
    Safely execute a function with error logging
    
    Args:
        func: Function to execute
        *args: Function arguments
        operation_name: Name for logging
        default_return: Value to return on error
        **kwargs: Function keyword arguments
        
    Returns:
        Function result or default_return on error
    """
    op_name = operation_name or func.__name__
    
    try:
        safe_log(f"Executing: {op_name}")
        result = func(*args, **kwargs)
        safe_log(f"Success: {op_name}")
        return result
        
    except Exception as e:
        safe_log(f"Error in {op_name}: {str(e)}", "ERROR")
        return default_return
