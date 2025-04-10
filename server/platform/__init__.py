"""
Platform-specific implementations for the VPN server.
Provides abstractions for TUN interfaces and routing on different platforms.
"""

import platform

# Export appropriate platform-specific modules
if platform.system() == 'Windows':
    from server.platform.windows import TunInterface, setup_routing, create_tap_device
else:
    from server.platform.linux import TunInterface, setup_routing, setup_nat
