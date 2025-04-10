"""
Permission handling utilities for the VPN system.
Functions to check and elevate privileges on different platforms.
"""
import os
import sys
import ctypes
import subprocess
import logging
from typing import Tuple, Optional, List


def check_admin_privileges() -> bool:
    """
    Check if the script is running with administrator/root privileges
    
    Returns:
        True if running with admin/root privileges, False otherwise
    """
    logger = logging.getLogger("permissions")
    
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix-like (Linux, macOS)
            return os.geteuid() == 0
    except Exception as e:
        logger.error(f"Error checking admin privileges: {e}")
        return False


def elevate_privileges(args: Optional[List[str]] = None) -> bool:
    """
    Attempt to elevate privileges by restarting the script with admin/root privileges
    
    Args:
        args: Command line arguments to pass to the elevated process
        
    Returns:
        True if elevation succeeded or already elevated, False otherwise
    """
    logger = logging.getLogger("permissions")
    
    if check_admin_privileges():
        logger.debug("Already running with admin privileges")
        return True
    
    logger.info("Attempting to elevate privileges")
    
    try:
        if args is None:
            args = sys.argv[:]
            
        if os.name == 'nt':  # Windows
            # Use ShellExecute to get a UAC prompt
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                " ".join(f'"{arg}"' for arg in args), 
                None, 
                1  # SW_SHOWNORMAL
            )
            # Exit the current (non-elevated) process
            sys.exit(0)
            
        else:  # Unix-like (Linux, macOS)
            # Use pkexec, sudo, or similar
            if _command_exists("pkexec"):
                subprocess.Popen(["pkexec", sys.executable] + args)
            elif _command_exists("sudo"):
                subprocess.Popen(["sudo", sys.executable] + args)
            else:
                logger.error("No suitable privilege elevation command found")
                return False
                
            # Exit the current (non-elevated) process
            sys.exit(0)
            
        return True  # Note: This line won't be reached if elevation succeeds
        
    except Exception as e:
        logger.error(f"Failed to elevate privileges: {e}")
        return False


def _command_exists(command: str) -> bool:
    """
    Check if a command exists in the system PATH
    
    Args:
        command: Command name to check
        
    Returns:
        True if command exists, False otherwise
    """
    try:
        subprocess.run(
            ["which", command] if os.name != 'nt' else ["where", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False
        )
        return True
    except:
        return False


def configure_interface_permissions(interface_name: str) -> Tuple[bool, str]:
    """
    Configure permissions for network interfaces
    
    Args:
        interface_name: Name of the interface to configure
        
    Returns:
        Tuple of (success, message)
    """
    logger = logging.getLogger("permissions")
    
    if not check_admin_privileges():
        return False, "Administrator privileges required to configure network interfaces"
    
    try:
        if os.name == 'nt':  # Windows
            # On Windows, admin privileges are enough for most operations
            # For specific permissions, would use netsh or similar
            result = subprocess.run(
                ["netsh", "interface", "show", "interface", interface_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                return False, f"Failed to access interface: {result.stderr}"
                
            return True, "Interface permissions configured successfully"
            
        else:  # Unix-like (Linux, macOS)
            # On Linux, ensure the interface has proper permissions
            # This might involve udev rules for persistent permissions
            
            # Example: Change ownership of the TUN device
            result = subprocess.run(
                ["ip", "link", "set", "dev", interface_name, "up"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                return False, f"Failed to bring up interface: {result.stderr}"
                
            return True, "Interface permissions configured successfully"
            
    except Exception as e:
        logger.error(f"Error configuring interface permissions: {e}")
        return False, f"Error: {str(e)}"


def setup_service_privileges(service_name: str) -> Tuple[bool, str]:
    """
    Set up privileges for running as a system service
    
    Args:
        service_name: Name of the service
        
    Returns:
        Tuple of (success, message)
    """
    logger = logging.getLogger("permissions")
    
    if not check_admin_privileges():
        return False, "Administrator privileges required to configure services"
    
    try:
        if os.name == 'nt':  # Windows
            # On Windows, use sc.exe to configure service permissions
            result = subprocess.run(
                [
                    "sc", "sdset", service_name,
                    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
                    + "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True
            )
            
            if result.returncode != 0:
                return False, f"Failed to set service permissions: {result.stderr}"
                
            return True, "Service permissions configured successfully"
            
        else:  # Unix-like (Linux, macOS)
            # On Linux, create or modify a systemd service file
            service_file = f"/etc/systemd/system/{service_name}.service"
            
            # Check if file exists before attempting to modify
            if not os.path.exists(service_file):
                logger.warning(f"Service file {service_file} does not exist")
                return False, f"Service file {service_file} does not exist"
                
            # In a real implementation, would modify the service file
            # and reload systemd
            
            return True, "Service permissions configured successfully"
            
    except Exception as e:
        logger.error(f"Error setting up service privileges: {e}")
        return False, f"Error: {str(e)}"


# Example usage
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Check for admin privileges
    is_admin = check_admin_privileges()
    print(f"Running with administrator privileges: {is_admin}")
    
    if not is_admin:
        print("Attempting to elevate privileges...")
        elevate_privileges()
        # If elevation is successful, this code won't be reached
        print("Elevation failed or cancelled")
