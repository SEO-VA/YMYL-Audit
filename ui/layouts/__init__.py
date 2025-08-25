# ui/layouts/__init__.py  
"""
UI Layouts package for YMYL Audit Tool
Contains layout implementations for different user types
"""

from .admin_layout import AdminLayout
from .user_layout import UserLayout

__all__ = ['AdminLayout', 'UserLayout']
