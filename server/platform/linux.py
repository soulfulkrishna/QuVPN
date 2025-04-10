"""
Linux-specific implementations for TUN interface and routing.
Provides Linux platform support for the VPN server.
"""
import os
import sys
import fcntl
import struct
import logging
import subprocess
import ipaddress
import time
from typing import Optional, Tuple, Dict, Any, List

logger = logging.getLogger("linux")

# Constants for TUN setup
TUNSETIFF = 0x400454ca
TUNSETOWNER = 0x400454cc
TUNSETGROUP = 0x400454ce
TUNSETPERSIST = 0x400454cb
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class TunInterface:
    """
    TUN interface implementation for Linux
    """
    
    def __init__(self, name: str = "vpn0", mtu: int = 1400):
        """
        Initialize TUN interface
        
        Args:
            name: Interface name
            mtu: Maximum Transmission Unit
        """
        self.name = name
        self.mtu = mtu
        self.fd = None
    
    def setup(self) -> bool:
        """
        Set up the TUN interface
        
        Returns:
            True if setup successful, False otherwise
        """
        try:
            logger.info(f"Setting up TUN interface: {self.name}")
            
            # Open the TUN/TAP device
            self.fd = open("/dev/net/tun", "rb+")
            
            # Set up the TUN device with the specified name
            ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.fd, TUNSETIFF, ifr)
            
            # Set persistence
            fcntl.ioctl(self.fd, TUNSETPERSIST, 1)
            
            # Set MTU
            subprocess.check_call(["ip", "link", "set", "dev", self.name, "mtu", str(self.mtu)])
            
            # Set interface up
            subprocess.check_call(["ip", "link", "set", "dev", self.name, "up"])
            
            logger.info(f"TUN interface {self.name} set up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set up TUN interface: {e}")
            self.close()
            return False
    
    def read(self, size: int) -> bytes:
        """
        Read data from the TUN interface
        
        Args:
            size: Maximum size to read
            
        Returns:
            Read data as bytes
        """
        if not self.fd:
            logger.error("Cannot read: TUN interface not initialized")
            return b''
            
        try:
            return self.fd.read(size)
        except (OSError, IOError) as e:
            logger.error(f"Failed to read from TUN interface: {e}")
            return b''
    
    def write(self, data: bytes) -> int:
        """
        Write data to the TUN interface
        
        Args:
            data: Data to write
            
        Returns:
            Number of bytes written
        """
        if not self.fd:
            logger.error("Cannot write: TUN interface not initialized")
            return 0
            
        try:
            self.fd.write(data)
            self.fd.flush()
            return len(data)
        except (OSError, IOError) as e:
            logger.error(f"Failed to write to TUN interface: {e}")
            return 0
    
    def close(self) -> None:
        """Close the TUN interface"""
        logger.info(f"Closing TUN interface: {self.name}")
        
        try:
            # If interface is still up, bring it down
            try:
                subprocess.check_call(["ip", "link", "set", "dev", self.name, "down"])
            except:
                pass
                
            # Remove persistence if the file descriptor is still valid
            if self.fd:
                try:
                    fcntl.ioctl(self.fd, TUNSETPERSIST, 0)
                except:
                    pass
                    
                self.fd.close()
                self.fd = None
                
        except Exception as e:
            logger.error(f"Error while closing TUN interface: {e}")


def setup_routing(tun_interface: str, server_ip: str, vpn_subnet: str) -> Tuple[bool, str]:
    """
    Set up routing for the VPN on Linux
    
    Args:
        tun_interface: TUN interface name
        server_ip: VPN server IP address
        vpn_subnet: VPN subnet in CIDR notation
        
    Returns:
        Tuple of (success, message)
    """
    logger.info(f"Setting up routing for VPN on interface {tun_interface}")
    
    try:
        # Parse the VPN subnet
        network = ipaddress.IPv4Network(vpn_subnet)
        
        # Configure IP for the VPN interface
        subprocess.check_call(["ip", "addr", "add", f"{server_ip}/{network.prefixlen}", "dev", tun_interface])
        
        # Enable IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        
        logger.info(f"Routing set up successfully for {vpn_subnet} through {tun_interface}")
        return True, "Routing configured successfully"
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set up routing: {e}")
        return False, f"Command failed: {e}"
        
    except Exception as e:
        logger.error(f"Error setting up routing: {e}")
        return False, f"Error: {str(e)}"


def setup_nat(tun_interface: str, external_interface: str, vpn_subnet: str) -> Tuple[bool, str]:
    """
    Set up NAT for the VPN on Linux
    
    Args:
        tun_interface: TUN interface name
        external_interface: External interface name (for internet access)
        vpn_subnet: VPN subnet in CIDR notation
        
    Returns:
        Tuple of (success, message)
    """
    logger.info(f"Setting up NAT for VPN traffic from {tun_interface} to {external_interface}")
    
    try:
        # Set up iptables for NAT
        # Allow forwarding
        subprocess.check_call([
            "iptables", "-A", "FORWARD", "-i", tun_interface, "-o", 
            external_interface, "-s", vpn_subnet, "-j", "ACCEPT"
        ])
        
        # Allow established connections
        subprocess.check_call([
            "iptables", "-A", "FORWARD", "-i", external_interface, "-o", 
            tun_interface, "-d", vpn_subnet, "-m", "state", "--state", 
            "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ])
        
        # Set up NAT
        subprocess.check_call([
            "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", 
            external_interface, "-s", vpn_subnet, "-j", "MASQUERADE"
        ])
        
        logger.info(f"NAT set up successfully for {vpn_subnet}")
        return True, "NAT configured successfully"
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set up NAT: {e}")
        return False, f"Command failed: {e}"
        
    except Exception as e:
        logger.error(f"Error setting up NAT: {e}")
        return False, f"Error: {str(e)}"


def install_service(service_name: str, executable_path: str, description: str = None) -> Tuple[bool, str]:
    """
    Install the VPN server as a systemd service
    
    Args:
        service_name: Service name
        executable_path: Path to the executable
        description: Service description
        
    Returns:
        Tuple of (success, message)
    """
    if not description:
        description = "Custom Post-Quantum VPN Server"
        
    logger.info(f"Installing systemd service: {service_name}")
    
    service_path = f"/etc/systemd/system/{service_name}.service"
    
    try:
        # Create service file
        service_content = f"""[Unit]
Description={description}
After=network.target

[Service]
ExecStart={executable_path}
Restart=on-failure
RestartSec=5s
Type=simple
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""
        
        # Write service file
        with open(service_path, "w") as f:
            f.write(service_content)
            
        # Reload systemd
        subprocess.check_call(["systemctl", "daemon-reload"])
        
        # Enable service to start on boot
        subprocess.check_call(["systemctl", "enable", service_name])
        
        logger.info(f"Service {service_name} installed successfully")
        return True, f"Service {service_name} installed"
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install service: {e}")
        return False, f"Failed to install service: {e}"
        
    except Exception as e:
        logger.error(f"Error installing service: {e}")
        return False, f"Error: {str(e)}"
