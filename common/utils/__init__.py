"""
Utility modules for the custom VPN system.
Includes configuration, logging, and permissions handling.
"""

from common.utils.config import ConfigManager
from common.utils.logging_setup import setup_logging
from common.utils.permissions import check_admin_privileges, elevate_privileges

__all__ = [
    'ConfigManager',
    'setup_logging',
    'check_admin_privileges',
    'elevate_privileges'
]
