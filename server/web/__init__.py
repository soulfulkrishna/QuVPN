"""
Web interface package for the VPN server.
Provides a web-based UI for managing the VPN server.
"""

from server.web.app import app, initialize_web_app, start_web_server

__all__ = ['app', 'initialize_web_app', 'start_web_server']
