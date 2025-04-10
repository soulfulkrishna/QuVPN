"""
VPN client implementation.
Establishes and maintains secure VPN connections to the server.
"""
import os
import sys
import time
import signal
import platform
import ipaddress
import logging
import threading
import queue
from typing import Optional, Dict, Any, Tuple, List

from common.networking.tunnel import TunnelClient, TunnelConfig
from common.networking.packet import IPPacket
from common.utils.config import ConfigManager
from common.utils.logging_setup import setup_logging
from common.utils.permissions import check_admin_privileges, elevate_privileges

# Platform-specific imports
if platform.system() == 'Windows':
    from client.platform.windows import TunInterface, setup_routing
else:
    from client.platform.linux import TunInterface, setup_routing


class VPNClient:
    """
    Main VPN client class
    """
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the VPN client
        
        Args:
            config_path: Path to the configuration file
        """
        # Set up logging
        self.logger = setup_logging(
            app_name="vpn_client",
            log_level="INFO",
            log_file="vpn_client.log"
        )
        
        # Load configuration
        self.logger.info("Initializing VPN client")
        self.config_manager = ConfigManager(config_path)
        
        # Get configuration values
        self.server_address = self.config_manager.get("client.server_address", "127.0.0.1")
        self.server_port = self.config_manager.get("client.server_port", 8000)
        protocol = self.config_manager.get("client.protocol", "tcp")
        
        # Set up tunnel mode
        self.tunnel_mode = TunnelConfig.MODE_TCP if protocol.lower() == "tcp" else TunnelConfig.MODE_UDP
        
        # Initialize components
        self.tunnel = TunnelClient(
            mode=self.tunnel_mode,
            log_traffic=self.config_manager.get("client.log_traffic", False)
        )
        
        self.tun_interface: Optional[TunInterface] = None
        self.keepalive_event = threading.Event()
        self.connected = False
        self.running = False
        
        # Status reporting
        self.status_queue = queue.Queue()
        self.last_status = {}
    
    def start(self) -> bool:
        """
        Start the VPN client
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            self.logger.warning("VPN client already running")
            return False
            
        self.logger.info("Starting VPN client")
        
        # Check privileges
        if not check_admin_privileges():
            self.logger.warning("Admin privileges required to create TUN interface")
            if not elevate_privileges():
                self.logger.error("Failed to elevate privileges, cannot create TUN interface")
                self._update_status("error", "Failed to acquire admin privileges")
                return False
        
        try:
            # Create TUN interface
            self.tun_interface = TunInterface(
                name=self.config_manager.get("client.tun_name", "vpn0"),
                mtu=self.config_manager.get("networking.mtu", 1400)
            )
            
            # Set up interface
            self.logger.info("Setting up TUN interface")
            success = self.tun_interface.setup()
            if not success:
                self.logger.error("Failed to set up TUN interface")
                self._update_status("error", "Failed to set up TUN interface")
                return False
                
            # Connect tunnel
            self.logger.info(f"Connecting to server: {self.server_address}:{self.server_port}")
            self._update_status("connecting", f"Connecting to {self.server_address}:{self.server_port}")
            
            success = self.tunnel.connect((self.server_address, self.server_port), 
                                        timeout=self.config_manager.get("client.connect_timeout", 10.0))
            
            if not success:
                self.logger.error("Failed to connect to VPN server")
                self._update_status("error", "Failed to connect to VPN server")
                return False
                
            # Set TUN interface for tunnel
            self.tunnel.set_tun_interface(self.tun_interface)
            
            # Start TUN reader thread
            self.running = True
            self.connected = True
            
            self.tun_reader_thread = threading.Thread(target=self._tun_reader_thread)
            self.tun_reader_thread.daemon = True
            self.tun_reader_thread.start()
            
            # Start keepalive thread
            self.keepalive_thread = threading.Thread(target=self._keepalive_thread)
            self.keepalive_thread.daemon = True
            self.keepalive_thread.start()
            
            # Set up routing
            self.logger.info("Setting up routing")
            success, message = setup_routing(
                tun_interface=self.tun_interface.name,
                server_ip=self.server_address,
                vpn_subnet=self.config_manager.get("networking.subnet", "10.0.0.0/24")
            )
            
            if not success:
                self.logger.error(f"Failed to set up routing: {message}")
                self._update_status("warning", f"Connected, but routing failed: {message}")
            else:
                self.logger.info("Routing set up successfully")
                
            self._update_status("connected", "Connected to VPN server")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting VPN client: {e}")
            self._update_status("error", f"Error starting VPN client: {str(e)}")
            self.stop()
            return False
    
    def stop(self) -> None:
        """Stop the VPN client"""
        if not self.running:
            return
            
        self.logger.info("Stopping VPN client")
        self.running = False
        self.connected = False
        
        # Set keepalive event to stop the thread
        self.keepalive_event.set()
        
        # Disconnect tunnel
        try:
            if self.tunnel:
                self.tunnel.disconnect()
                self.tunnel.cleanup()
        except Exception as e:
            self.logger.error(f"Error disconnecting tunnel: {e}")
        
        # Clean up TUN interface
        try:
            if self.tun_interface:
                self.tun_interface.close()
                self.tun_interface = None
        except Exception as e:
            self.logger.error(f"Error closing TUN interface: {e}")
        
        self._update_status("disconnected", "Disconnected from VPN server")
        self.logger.info("VPN client stopped")
    
    def restart(self) -> bool:
        """
        Restart the VPN client
        
        Returns:
            True if restarted successfully, False otherwise
        """
        self.logger.info("Restarting VPN client")
        self.stop()
        time.sleep(1)  # Give time for cleanup
        return self.start()
    
    def _tun_reader_thread(self) -> None:
        """Thread for reading packets from the TUN interface"""
        self.logger.info("TUN reader thread started")
        
        buffer_size = self.config_manager.get("networking.buffer_size", 2048)
        
        while self.running and self.tun_interface:
            try:
                # Read packet from TUN interface
                packet = self.tun_interface.read(buffer_size)
                
                if not packet:
                    continue
                
                # Send to tunnel
                if self.connected:
                    # Parse as IP packet for logging
                    try:
                        ip_packet = IPPacket.from_bytes(packet)
                        if self.config_manager.get("client.log_traffic", False):
                            self.logger.debug(
                                f"Sending packet: {ip_packet.src_ip} -> {ip_packet.dst_ip}, "
                                f"Protocol: {ip_packet.protocol}, Length: {len(packet)} bytes"
                            )
                    except Exception:
                        # Not critical if we can't parse for logging
                        pass
                        
                    # Send through tunnel
                    self.tunnel.send_ip_packet(packet)
                    
            except Exception as e:
                self.logger.error(f"Error in TUN reader thread: {e}")
                if not self.running:
                    break
        
        self.logger.info("TUN reader thread stopped")
    
    def _keepalive_thread(self) -> None:
        """Thread for monitoring connection status"""
        self.logger.info("Keepalive thread started")
        
        check_interval = self.config_manager.get("client.keepalive_interval", 5)
        max_failures = self.config_manager.get("client.max_failures", 3)
        failures = 0
        
        while self.running and not self.keepalive_event.is_set():
            try:
                # Check if tunnel is connected
                if not self.tunnel.connected:
                    failures += 1
                    self.logger.warning(f"Tunnel disconnected, failure count: {failures}")
                    
                    if failures >= max_failures:
                        self.logger.error("Too many connection failures, reconnecting")
                        self._update_status("reconnecting", "Connection lost, reconnecting")
                        self.restart()
                        failures = 0
                else:
                    # Reset failure count on success
                    failures = 0
                    
                # Wait for next check
                self.keepalive_event.wait(check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in keepalive thread: {e}")
                if not self.running:
                    break
        
        self.logger.info("Keepalive thread stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the VPN client
        
        Returns:
            Dictionary with status information
        """
        try:
            # Get updated status from queue
            while not self.status_queue.empty():
                self.last_status = self.status_queue.get_nowait()
        except:
            pass
            
        # Add additional status information
        current_status = self.last_status.copy()
        current_status.update({
            "running": self.running,
            "connected": self.connected,
            "server": f"{self.server_address}:{self.server_port}",
            "protocol": "TCP" if self.tunnel_mode == TunnelConfig.MODE_TCP else "UDP",
            "timestamp": time.time()
        })
        
        return current_status
    
    def _update_status(self, status: str, message: str) -> None:
        """
        Update the client status
        
        Args:
            status: Status code
            message: Status message
        """
        status_update = {
            "status": status,
            "message": message,
            "timestamp": time.time()
        }
        
        self.status_queue.put(status_update)
        self.last_status = status_update
        
        self.logger.info(f"Status update: {status} - {message}")
    
    def set_server(self, address: str, port: int) -> None:
        """
        Change the server address and port
        
        Args:
            address: Server address
            port: Server port
        """
        if self.connected:
            self.logger.warning("Cannot change server while connected, disconnect first")
            return
            
        self.server_address = address
        self.server_port = port
        
        # Update configuration
        self.config_manager.set("client.server_address", address)
        self.config_manager.set("client.server_port", port)
        self.config_manager.save()
        
        self.logger.info(f"Server changed to {address}:{port}")


# Signal handler for graceful shutdown
def signal_handler(signum, frame):
    """Handle termination signals"""
    global client
    logging.info(f"Received signal {signum}, shutting down")
    if client:
        client.stop()
    sys.exit(0)


# Global client instance for signal handling
client = None

# Main client function
def main() -> int:
    """
    Main entry point for VPN client
    
    Returns:
        Exit code
    """
    global client
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create client
    client = VPNClient()
    
    # Start client
    if not client.start():
        logging.error("Failed to start VPN client")
        return 1
        
    # Run until terminated
    try:
        logging.info("VPN client running, press Ctrl+C to stop")
        while client.running:
            time.sleep(1)
    except:
        pass
    finally:
        # Ensure client is stopped
        client.stop()
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
