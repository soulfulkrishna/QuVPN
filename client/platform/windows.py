"""
Windows-specific implementations for TUN interface and routing.
Provides Windows platform support for the VPN system.
"""
import os
import sys
import subprocess
import logging
import time
import ipaddress
import ctypes
import winreg
from typing import Optional, Tuple, Dict, Any, List

# Try to import Windows-specific libraries
try:
    import win32file
    import win32event
    import win32con
    import pywintypes
except ImportError:
    raise ImportError("pywin32 library is required for Windows support. Please install it with: pip install pywin32")

logger = logging.getLogger("windows")


class TunInterface:
    """
    TUN interface implementation for Windows using WinTUN or TAP-Windows adapters
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
        self.handle = None
        self.overlapped_read = None
        self.overlapped_write = None
        self.read_buffer = win32file.AllocateReadBuffer(65536)
        self.adapter_id = None
        self.device_path = None
        self.adapter_index = None
        self.iface_index = None

    def _find_tap_adapter(self) -> Optional[str]:
        """
        Find existing TAP Windows adapter
        
        Returns:
            Device path if found, None otherwise
        """
        try:
            # Open network adapters key
            adapters_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            )
            
            adapter_index = 0
            while True:
                try:
                    adapter_key_name = winreg.EnumKey(adapters_key, adapter_index)
                    adapter_key = winreg.OpenKey(adapters_key, adapter_key_name)
                    
                    try:
                        component_id = winreg.QueryValueEx(adapter_key, "ComponentId")[0]
                        if component_id.startswith("tap") or component_id.startswith("wintun"):
                            device_id = winreg.QueryValueEx(adapter_key, "NetCfgInstanceId")[0]
                            device_path = r"\\.\Global\{%s}.tap" % device_id
                            device_name = winreg.QueryValueEx(adapter_key, "NetConnectionID")[0]
                            logger.info(f"Found TAP adapter: {device_name} at {device_path}")
                            self.adapter_id = device_id
                            winreg.CloseKey(adapter_key)
                            winreg.CloseKey(adapters_key)
                            return device_path
                    except (WindowsError, FileNotFoundError):
                        pass
                    finally:
                        winreg.CloseKey(adapter_key)
                        
                    adapter_index += 1
                except WindowsError:
                    break
                    
            winreg.CloseKey(adapters_key)
            return None
            
        except Exception as e:
            logger.error(f"Failed to find TAP adapter: {e}")
            return None

    def _get_adapter_index(self) -> Optional[int]:
        """
        Get the adapter index from the adapter name
        
        Returns:
            Adapter index if found, None otherwise
        """
        try:
            # Use netsh to get interface information
            output = subprocess.check_output(
                ["netsh", "interface", "show", "interface", self.name],
                universal_newlines=True
            )
            
            # Parse the output to find the interface index
            lines = output.splitlines()
            for line in lines:
                if self.name in line:
                    parts = line.split()
                    try:
                        return int(parts[0])
                    except (ValueError, IndexError):
                        pass
                        
            return None
            
        except Exception as e:
            logger.error(f"Failed to get adapter index: {e}")
            return None
            
    def setup(self) -> bool:
        """
        Set up the TUN interface
        
        Returns:
            True if setup successful, False otherwise
        """
        try:
            logger.info(f"Setting up TUN interface: {self.name}")
            
            # Find existing TAP adapter
            self.device_path = self._find_tap_adapter()
            if not self.device_path:
                logger.error("No TAP adapter found, please install a TAP driver")
                return False
            
            # Open device
            self.handle = win32file.CreateFile(
                self.device_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,  # No sharing
                None,  # Default security
                win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
                None  # No template
            )
            
            # Initialize overlapped structures for async I/O
            self.overlapped_read = pywintypes.OVERLAPPED()
            self.overlapped_read.hEvent = win32event.CreateEvent(None, True, False, None)
            
            self.overlapped_write = pywintypes.OVERLAPPED()
            self.overlapped_write.hEvent = win32event.CreateEvent(None, True, False, None)
            
            # Set interface name if needed
            try:
                current_name = self._get_interface_name()
                if current_name and current_name != self.name:
                    logger.info(f"Renaming interface from {current_name} to {self.name}")
                    subprocess.check_call(
                        ["netsh", "interface", "set", "interface", 
                         "name=" + current_name, "newname=" + self.name]
                    )
            except Exception as e:
                logger.warning(f"Failed to rename interface: {e}")
            
            # Set the interface to up state
            subprocess.check_call(
                ["netsh", "interface", "set", "interface", self.name, "admin=enabled"]
            )
            
            # Get adapter index
            self.adapter_index = self._get_adapter_index()
            if not self.adapter_index:
                logger.warning("Could not determine adapter index")
                
            logger.info(f"TUN interface {self.name} set up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set up TUN interface: {e}")
            self.close()
            return False
    
    def _get_interface_name(self) -> Optional[str]:
        """
        Get the current interface name associated with the adapter ID
        
        Returns:
            Interface name if found, None otherwise
        """
        try:
            if not self.adapter_id:
                return None
                
            # Find the interface name for this adapter ID
            output = subprocess.check_output(
                ["netsh", "interface", "show", "interface"],
                universal_newlines=True
            )
            
            # Then try to correlate with registry
            key_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{" + self.adapter_id + r"}\Connection"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                name = winreg.QueryValueEx(key, "Name")[0]
                winreg.CloseKey(key)
                return name
            except (WindowsError, FileNotFoundError):
                pass
                
            return None
            
        except Exception as e:
            logger.error(f"Failed to get interface name: {e}")
            return None
    
    def read(self, size: int) -> bytes:
        """
        Read data from the TUN interface
        
        Args:
            size: Maximum size to read
            
        Returns:
            Read data as bytes
        """
        if not self.handle:
            logger.error("Cannot read: TUN interface not initialized")
            return b''
            
        try:
            # Start asynchronous read
            win32file.ReadFile(self.handle, self.read_buffer, self.overlapped_read)
            
            # Wait for completion with timeout
            result = win32event.WaitForSingleObject(self.overlapped_read.hEvent, 1000)
            
            if result == win32event.WAIT_OBJECT_0:
                # Read completed, get the result
                bytes_read = win32file.GetOverlappedResult(self.handle, self.overlapped_read, False)
                if bytes_read > 0:
                    return bytes(self.read_buffer[:bytes_read])
            elif result == win32event.WAIT_TIMEOUT:
                # Read timed out, cancel it
                win32file.CancelIo(self.handle)
                win32event.ResetEvent(self.overlapped_read.hEvent)
                
            return b''
            
        except Exception as e:
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
        if not self.handle:
            logger.error("Cannot write: TUN interface not initialized")
            return 0
            
        try:
            # Start asynchronous write
            win32file.WriteFile(self.handle, data, self.overlapped_write)
            
            # Wait for completion with timeout
            result = win32event.WaitForSingleObject(self.overlapped_write.hEvent, 1000)
            
            if result == win32event.WAIT_OBJECT_0:
                # Write completed, get the result
                bytes_written = win32file.GetOverlappedResult(self.handle, self.overlapped_write, False)
                return bytes_written
            elif result == win32event.WAIT_TIMEOUT:
                # Write timed out, cancel it
                win32file.CancelIo(self.handle)
                win32event.ResetEvent(self.overlapped_write.hEvent)
                
            return 0
            
        except Exception as e:
            logger.error(f"Failed to write to TUN interface: {e}")
            return 0
    
    def close(self) -> None:
        """Close the TUN interface"""
        logger.info(f"Closing TUN interface: {self.name}")
        
        try:
            # Close overlapped event handles
            if self.overlapped_read and self.overlapped_read.hEvent:
                win32file.CloseHandle(self.overlapped_read.hEvent)
                self.overlapped_read = None
                
            if self.overlapped_write and self.overlapped_write.hEvent:
                win32file.CloseHandle(self.overlapped_write.hEvent)
                self.overlapped_write = None
                
            # Close device handle
            if self.handle:
                win32file.CloseHandle(self.handle)
                self.handle = None
                
        except Exception as e:
            logger.error(f"Error while closing TUN interface: {e}")


def setup_routing(tun_interface: str, server_ip: str, vpn_subnet: str) -> Tuple[bool, str]:
    """
    Set up routing for the VPN on Windows
    
    Args:
        tun_interface: TUN interface name
        server_ip: VPN server IP address
        vpn_subnet: VPN subnet in CIDR notation
        
    Returns:
        Tuple of (success, message)
    """
    logger.info(f"Setting up routing for VPN on interface {tun_interface}")
    
    try:
        # Get interface index
        output = subprocess.check_output(
            ["netsh", "interface", "show", "interface", tun_interface],
            universal_newlines=True
        )
        
        iface_index = None
        lines = output.splitlines()
        for line in lines:
            if tun_interface in line:
                parts = line.split()
                try:
                    iface_index = parts[0]
                    break
                except (ValueError, IndexError):
                    pass
                    
        if not iface_index:
            return False, f"Could not find interface index for {tun_interface}"
            
        # Set interface metric
        subprocess.check_call(
            ["netsh", "interface", "ip", "set", "interface", 
             iface_index, "metric=1"]
        )
        
        # Configure IP for the VPN interface
        # Parse the VPN subnet to get an IP
        network = ipaddress.IPv4Network(vpn_subnet)
        client_ip = str(network[1])  # Use the first usable IP in the subnet
        subnet_mask = str(network.netmask)
        
        # Configure IP address
        subprocess.check_call(
            ["netsh", "interface", "ip", "set", "address", 
             f"name={tun_interface}", "static", client_ip, subnet_mask]
        )
        
        # Add route for VPN subnet through the TUN interface
        subprocess.check_call(
            ["route", "add", vpn_subnet, client_ip, "metric", "1"]
        )
        
        # Make sure server traffic doesn't go through the VPN
        subprocess.check_call(
            ["route", "add", server_ip, "mask", "255.255.255.255", 
             "default", "metric", "1"]
        )
        
        logger.info(f"Routing set up successfully for {vpn_subnet} through {tun_interface}")
        return True, "Routing configured successfully"
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set up routing: {e}")
        return False, f"Command failed: {e}"
        
    except Exception as e:
        logger.error(f"Error setting up routing: {e}")
        return False, f"Error: {str(e)}"


def register_as_service(service_name: str, executable_path: str, display_name: str = None) -> Tuple[bool, str]:
    """
    Register the VPN client as a Windows service
    
    Args:
        service_name: Service name
        executable_path: Path to the executable
        display_name: Display name (defaults to service_name)
        
    Returns:
        Tuple of (success, message)
    """
    if display_name is None:
        display_name = service_name
        
    logger.info(f"Registering Windows service: {service_name}")
    
    try:
        # Check if the service already exists
        check_result = subprocess.run(
            ["sc", "query", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        if check_result.returncode == 0:
            # Service exists, try to update it
            logger.info(f"Service {service_name} already exists, updating")
            
            subprocess.check_call(
                ["sc", "config", service_name,
                 f"binPath= \"{executable_path}\"",
                 "start= auto",
                 f"DisplayName= \"{display_name}\""]
            )
            
            return True, f"Service {service_name} updated"
            
        else:
            # Create new service
            subprocess.check_call(
                ["sc", "create", service_name,
                 f"binPath= \"{executable_path}\"",
                 "start= auto",
                 f"DisplayName= \"{display_name}\""]
            )
            
            # Set description
            subprocess.check_call(
                ["sc", "description", service_name, 
                 "\"Custom Post-Quantum VPN Client\""]
            )
            
            # Set recovery options
            subprocess.check_call(
                ["sc", "failure", service_name, 
                 "reset= 86400", "actions= restart/60000/restart/60000/restart/60000"]
            )
            
            logger.info(f"Service {service_name} registered successfully")
            return True, f"Service {service_name} registered"
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to register service: {e}")
        return False, f"Failed to register service: {e}"
        
    except Exception as e:
        logger.error(f"Error registering service: {e}")
        return False, f"Error: {str(e)}"
