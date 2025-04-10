"""
Platform-specific implementations for the VPN client.
Provides abstractions for TUN interfaces and routing on different platforms.
"""

import platform

# Export appropriate platform-specific modules
if platform.system() == 'Windows':
    from client.platform.windows import TunInterface, setup_routing, register_as_service
else:
    from client.platform.linux import TunInterface, setup_routing, install_service

