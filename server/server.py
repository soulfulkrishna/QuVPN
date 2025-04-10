"""
VPN server implementation.
Manages client connections and routes traffic between VPN clients and the internet.
"""
import os
import sys
import time
import signal
import logging
import threading
import ipaddress
import platform
import queue
from typing import Dict, Any, Optional, List, Tuple, Set

from common.networking.tunnel import TunnelServer, TunnelConfig
from common.networking.packet import IPPacket
from common.utils.config import ConfigManager
from common.utils.logging_setup import setup_logging
from common.utils.permissions import check_admin_privileges, elevate_privileges
from server.auth.user_manager import UserManager

# Platform-specific imports
if platform.system() == 'Windows':
    import win32file
    import win32event
    from server.platform.windows import TunInterface, setup_routing, create_tap_device
else:
    from server.platform.linux import TunInterface, setup_routing, setup_nat


class VPNServer:
    """
    Main VPN server class
    """
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the VPN server
        
        Args:
            config_path: Path to the configuration file
        """
        # Set up logging
        self.logger = setup_logging(
            app_name="vpn_server",
            log_level="INFO",
            log_file="vpn_server.log"
        )
        
        # Load configuration
        self.logger.info("Initializing VPN server")
        self.config_manager = ConfigManager(config_path)
        
        # Get configuration values
        self.bind_address = self.config_manager.get("server.bind_address", "0.0.0.0")
        self.bind_port = self.config_manager.get("server.bind_port", 8000)
        protocol = self.config_manager.get("server.protocol", "tcp")
        
        # Set up tunnel mode
        self.tunnel_mode = TunnelConfig.MODE_TCP if protocol.lower() == "tcp" else TunnelConfig.MODE_UDP
        
        # Initialize components
        self.tunnel_server = TunnelServer(
            mode=self.tunnel_mode,
            log_traffic=self.config_manager.get("server.log_traffic", False)
        )
        
        # Initialize user manager
        user_db_path = self.config_manager.get("server.user_db_path", "users.db")
        self.user_manager = UserManager(user_db_path)
        
        # Initialize TUN interface
        self.tun_interface = None
        
        # Tracking connected clients
        self.clients = {}  # addr -> client_info
        self.client_lock = threading.RLock()
        
        # Stats
        self.stats = {
            "bytes_in": 0,
            "bytes_out": 0,
            "packets_in": 0,
            "packets_out": 0,
            "start_time": 0,
            "client_count": 0
        }
        
        # Status
        self.running = False
        self.status_queue = queue.Queue()
        
        # Server information
        vpn_subnet = self.config_manager.get("networking.subnet", "10.0.0.0/24")
        self.vpn_network = ipaddress.IPv4Network(vpn_subnet)
        self.ip_pool = list(self.vpn_network.hosts())
        self.ip_pool = self.ip_pool[1:]  # Skip the first IP (usually the server)
        self.allocated_ips = set()
    
    def start(self) -> bool:
        """
        Start the VPN server
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            self.logger.warning("VPN server already running")
            return False
            
        self.logger.info("Starting VPN server")
        
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
                name=self.config_manager.get("server.tun_name", "vpn0"),
                mtu=self.config_manager.get("networking.mtu", 1400)
            )
            
            # Set up interface
            self.logger.info("Setting up TUN interface")
            success = self.tun_interface.setup()
            if not success:
                self.logger.error("Failed to set up TUN interface")
                self._update_status("error", "Failed to set up TUN interface")
                return False
                
            # Set up routing
            self.logger.info("Setting up routing")
            server_ip = str(self.vpn_network[1])  # First IP in the subnet
            vpn_subnet = str(self.vpn_network)
            
            success, message = setup_routing(
                tun_interface=self.tun_interface.name,
                server_ip=server_ip,
                vpn_subnet=vpn_subnet
            )
            
            if not success:
                self.logger.error(f"Failed to set up routing: {message}")
                self._update_status("warning", f"Started, but routing failed: {message}")
            else:
                self.logger.info("Routing set up successfully")
            
            # Set up NAT if on Linux
            if platform.system() != 'Windows':
                # External interface for outbound traffic
                ext_iface = self._get_default_interface()
                if ext_iface:
                    success, message = setup_nat(self.tun_interface.name, ext_iface, vpn_subnet)
                    if not success:
                        self.logger.error(f"Failed to set up NAT: {message}")
                    else:
                        self.logger.info(f"NAT set up successfully: {message}")
            
            # Start TUN reader thread
            self.running = True
            self.stats["start_time"] = time.time()
            
            self.tun_reader_thread = threading.Thread(target=self._tun_reader_thread)
            self.tun_reader_thread.daemon = True
            self.tun_reader_thread.start()
            
            # Start tunnel server
            success = self.tunnel_server.start((self.bind_address, self.bind_port))
            if not success:
                self.logger.error("Failed to start tunnel server")
                self.running = False
                self._update_status("error", "Failed to start tunnel server")
                return False
                
            self._update_status("running", f"Server running on {self.bind_address}:{self.bind_port}")
            self.logger.info(f"VPN server started on {self.bind_address}:{self.bind_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting VPN server: {e}")
            self._update_status("error", f"Error starting VPN server: {str(e)}")
            self.stop()
            return False
    
    def stop(self) -> None:
        """Stop the VPN server"""
        if not self.running:
            return
            
        self.logger.info("Stopping VPN server")
        self.running = False
        
        # Disconnect all clients
        with self.client_lock:
            for client_addr in list(self.clients.keys()):
                try:
                    self.disconnect_client(client_addr)
                except:
                    pass
        
        # Stop tunnel server
        try:
            if self.tunnel_server:
                self.tunnel_server.cleanup()
        except Exception as e:
            self.logger.error(f"Error stopping tunnel server: {e}")
        
        # Clean up TUN interface
        try:
            if self.tun_interface:
                self.tun_interface.close()
                self.tun_interface = None
        except Exception as e:
            self.logger.error(f"Error closing TUN interface: {e}")
        
        self._update_status("stopped", "Server stopped")
        self.logger.info("VPN server stopped")
    
    def restart(self) -> bool:
        """
        Restart the VPN server
        
        Returns:
            True if restarted successfully, False otherwise
        """
        self.logger.info("Restarting VPN server")
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
                
                # Update stats
                self.stats["bytes_out"] += len(packet)
                self.stats["packets_out"] += 1
                
                # Parse the packet to get destination
                try:
                    ip_packet = IPPacket.from_bytes(packet)
                    
                    # Find the client that should receive this packet based on destination IP
                    dst_ip = ip_packet.dst_ip
                    client_addr = self._find_client_by_ip(dst_ip)
                    
                    if client_addr:
                        # Forward the packet to the client
                        self.tunnel_server._send_to_client(client_addr, packet)
                    else:
                        # No client found for this IP
                        if self.config_manager.get("server.log_traffic", False):
                            self.logger.debug(f"No client found for packet to {dst_ip}")
                            
                except Exception as e:
                    self.logger.error(f"Error parsing or forwarding packet: {e}")
                    
            except Exception as e:
                self.logger.error(f"Error in TUN reader thread: {e}")
                if not self.running:
                    break
        
        self.logger.info("TUN reader thread stopped")
    
    def _get_default_interface(self) -> Optional[str]:
        """
        Get the default network interface
        
        Returns:
            Interface name if found, None otherwise
        """
        try:
            if platform.system() == 'Windows':
                # On Windows, use netsh to get the interface information
                result = subprocess.check_output(
                    ["netsh", "interface", "show", "interface"],
                    universal_newlines=True
                )
                
                # Parse the output to find the connected external interface
                lines = result.splitlines()
                for line in lines:
                    if "Connected" in line and "Loopback" not in line and self.tun_interface.name not in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            return parts[3]  # Interface name
                            
                return None
                
            else:
                # On Linux, use the route command
                import subprocess
                result = subprocess.check_output(
                    ["ip", "route", "show", "default"],
                    universal_newlines=True
                )
                
                # Parse the output
                if "dev" in result:
                    parts = result.split()
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
                        
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting default interface: {e}")
            return None
    
    def _find_client_by_ip(self, ip: str) -> Optional[Tuple[str, int]]:
        """
        Find a client by its assigned IP address
        
        Args:
            ip: IP address to look for
            
        Returns:
            Client address tuple if found, None otherwise
        """
        with self.client_lock:
            for client_addr, client_info in self.clients.items():
                if client_info.get("assigned_ip") == ip:
                    return client_addr
                    
        return None
    
    def _allocate_client_ip(self) -> Optional[str]:
        """
        Allocate an IP address for a new client
        
        Returns:
            IP address if available, None otherwise
        """
        with self.client_lock:
            for ip in self.ip_pool:
                ip_str = str(ip)
                if ip_str not in self.allocated_ips:
                    self.allocated_ips.add(ip_str)
                    return ip_str
                    
        return None
    
    def _release_client_ip(self, ip: str) -> None:
        """
        Release an allocated IP address
        
        Args:
            ip: IP address to release
        """
        with self.client_lock:
            if ip in self.allocated_ips:
                self.allocated_ips.remove(ip)
    
    def _update_tunnel_server(self) -> None:
        """Update the tunnel server to handle VPN traffic"""
        # Override the TunnelServer's _route_ip_packet method to handle VPN routing
        def route_ip_packet(client_addr, packet):
            """
            Route an IP packet to its destination
            
            Args:
                client_addr: The client's address
                packet: The IP packet to route
            """
            # First check if this client is authenticated
            with self.client_lock:
                if client_addr not in self.clients:
                    self.logger.warning(f"Received packet from unauthenticated client: {client_addr}")
                    return
                    
                # Get client information
                client_info = self.clients[client_addr]
                if not client_info.get("authenticated", False):
                    self.logger.warning(f"Received packet from client not yet authenticated: {client_addr}")
                    return
            
            # Update stats
            self.stats["bytes_in"] += len(packet.to_bytes())
            self.stats["packets_in"] += 1
            
            # Get source and destination
            src_ip = packet.src_ip
            dst_ip = packet.dst_ip
            
            # Check if destination is in our VPN subnet
            if ipaddress.IPv4Address(dst_ip) in self.vpn_network:
                # Packet is for another VPN client or the server itself
                # Write to TUN interface to handle internal routing
                if self.tun_interface:
                    self.tun_interface.write(packet.to_bytes())
            else:
                # Packet is for outside the VPN
                # Check if the client is allowed to access the internet
                if client_info.get("allow_internet", True):
                    # Write to TUN interface for outbound routing
                    if self.tun_interface:
                        self.tun_interface.write(packet.to_bytes())
                else:
                    self.logger.warning(f"Client {client_addr} attempted internet access but is not allowed")
        
        # Patch the tunnel server
        self.tunnel_server._route_ip_packet = route_ip_packet.__get__(self.tunnel_server, TunnelServer)
        
        # Also patch the process_client_kyber_init to handle authentication
        original_process_kyber = self.tunnel_server._process_client_kyber_init
        
        def process_client_kyber_init(client_addr, data):
            """
            Process a Kyber initialization request and handle authentication
            
            Args:
                client_addr: The client's address
                data: The client's Kyber public key
            """
            self.logger.info(f"New client connection from {client_addr}")
            
            # Register new client
            with self.client_lock:
                # Allocate IP
                assigned_ip = self._allocate_client_ip()
                if not assigned_ip:
                    self.logger.error(f"No IP addresses available for client {client_addr}")
                    # Disconnect the client
                    self.tunnel_server._remove_client(client_addr)
                    return
                
                # Initialize client info
                self.clients[client_addr] = {
                    "assigned_ip": assigned_ip,
                    "connected_time": time.time(),
                    "authenticated": False,  # Will be set to True after auth
                    "username": None,
                    "allow_internet": True,
                    "bytes_in": 0,
                    "bytes_out": 0
                }
                
                # Update stats
                self.stats["client_count"] = len(self.clients)
            
            # Continue with the original Kyber key exchange
            original_process_kyber(client_addr, data)
            
            # Send client configuration
            self._send_client_config(client_addr)
        
        self.tunnel_server._process_client_kyber_init = process_client_kyber_init.__get__(self.tunnel_server, TunnelServer)
    
    def _send_client_config(self, client_addr: Tuple[str, int]) -> None:
        """
        Send configuration to a connected client
        
        Args:
            client_addr: Client address
        """
        with self.client_lock:
            if client_addr not in self.clients:
                return
                
            client_info = self.clients[client_addr]
            assigned_ip = client_info["assigned_ip"]
            
            # Create configuration message
            config = {
                "assigned_ip": assigned_ip,
                "subnet": str(self.vpn_network),
                "dns": self.config_manager.get("networking.dns_servers", ["8.8.8.8"]),
                "routes": self.config_manager.get("networking.routes", []),
                "mtu": self.config_manager.get("networking.mtu", 1400)
            }
            
            # Encode as JSON
            import json
            config_msg = f"CONFIG:{json.dumps(config)}"
            
            # Send as control message
            self.tunnel_server.send_control_message(client_addr, config_msg)
            self.logger.info(f"Sent configuration to client {client_addr}: IP={assigned_ip}")
    
    def authenticate_client(self, client_addr: Tuple[str, int], username: str, authenticated: bool = True) -> None:
        """
        Mark a client as authenticated
        
        Args:
            client_addr: Client address
            username: Username
            authenticated: True if authentication successful
        """
        with self.client_lock:
            if client_addr not in self.clients:
                return
                
            self.clients[client_addr]["authenticated"] = authenticated
            self.clients[client_addr]["username"] = username
            
            if authenticated:
                self.logger.info(f"Client {client_addr} authenticated as {username}")
            else:
                self.logger.warning(f"Client {client_addr} failed authentication as {username}")
    
    def disconnect_client(self, client_addr: Tuple[str, int]) -> None:
        """
        Disconnect a client
        
        Args:
            client_addr: Client address
        """
        with self.client_lock:
            if client_addr not in self.clients:
                return
                
            # Get client info for logging
            client_info = self.clients[client_addr]
            assigned_ip = client_info.get("assigned_ip")
            username = client_info.get("username")
            
            # Release the IP
            if assigned_ip:
                self._release_client_ip(assigned_ip)
                
            # Remove from clients list
            del self.clients[client_addr]
            
            # Update stats
            self.stats["client_count"] = len(self.clients)
            
            # Log disconnection
            log_msg = f"Client {client_addr}"
            if username:
                log_msg += f" ({username})"
            log_msg += " disconnected"
            self.logger.info(log_msg)
            
        # Remove from tunnel server's clients
        self.tunnel_server._remove_client(client_addr)
    
    def broadcast_message(self, message: str) -> None:
        """
        Broadcast a message to all connected clients
        
        Args:
            message: Message to broadcast
        """
        control_msg = f"BROADCAST:{message}"
        self.tunnel_server.broadcast(control_msg.encode('utf-8'), TunnelConfig.CMD_CONTROL)
        self.logger.info(f"Broadcast message to all clients: {message}")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current server status
        
        Returns:
            Dictionary with status information
        """
        uptime = 0
        if self.stats["start_time"] > 0:
            uptime = time.time() - self.stats["start_time"]
            
        status = {
            "running": self.running,
            "bind_address": self.bind_address,
            "bind_port": self.bind_port,
            "protocol": "TCP" if self.tunnel_mode == TunnelConfig.MODE_TCP else "UDP",
            "uptime": uptime,
            "client_count": self.stats["client_count"],
            "bytes_in": self.stats["bytes_in"],
            "bytes_out": self.stats["bytes_out"],
            "packets_in": self.stats["packets_in"],
            "packets_out": self.stats["packets_out"],
            "timestamp": time.time()
        }
        
        # Add connected clients info
        clients_info = []
        with self.client_lock:
            for client_addr, client_info in self.clients.items():
                clients_info.append({
                    "address": f"{client_addr[0]}:{client_addr[1]}",
                    "ip": client_info.get("assigned_ip", "unknown"),
                    "username": client_info.get("username", "anonymous"),
                    "connected_time": client_info.get("connected_time", 0),
                    "authenticated": client_info.get("authenticated", False)
                })
                
        status["clients"] = clients_info
        
        # Add last status update if available
        try:
            while not self.status_queue.empty():
                last_status = self.status_queue.get_nowait()
                status.update(last_status)
        except:
            pass
            
        return status
    
    def _update_status(self, status: str, message: str) -> None:
        """
        Update the server status
        
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
        self.logger.info(f"Status update: {status} - {message}")
    
    def get_client_by_username(self, username: str) -> Optional[Tuple[str, int]]:
        """
        Find a client by username
        
        Args:
            username: Username to find
            
        Returns:
            Client address if found, None otherwise
        """
        with self.client_lock:
            for client_addr, client_info in self.clients.items():
                if client_info.get("username") == username:
                    return client_addr
                    
        return None
    
    def set_client_internet_access(self, client_addr: Tuple[str, int], allowed: bool) -> None:
        """
        Set whether a client can access the internet
        
        Args:
            client_addr: Client address
            allowed: True to allow internet access
        """
        with self.client_lock:
            if client_addr not in self.clients:
                return
                
            self.clients[client_addr]["allow_internet"] = allowed
            
            # Notify the client
            msg = "INTERNET:ALLOWED" if allowed else "INTERNET:BLOCKED"
            self.tunnel_server.send_control_message(client_addr, msg)
            
            username = self.clients[client_addr].get("username", "unknown")
            self.logger.info(f"Internet access for client {username} set to {allowed}")


# Signal handler for graceful shutdown
def signal_handler(signum, frame):
    """Handle termination signals"""
    global server
    logging.info(f"Received signal {signum}, shutting down")
    if server:
        server.stop()
    sys.exit(0)


# Global server instance for signal handling
server = None

# Main server function
def main() -> int:
    """
    Main entry point for VPN server
    
    Returns:
        Exit code
    """
    global server
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create server
    server = VPNServer()
    
    # Initialize server
    server._update_tunnel_server()
    
    # Start server
    if not server.start():
        logging.error("Failed to start VPN server")
        return 1
        
    # Run until terminated
    try:
        logging.info("VPN server running, press Ctrl+C to stop")
        while server.running:
            time.sleep(1)
    except:
        pass
    finally:
        # Ensure server is stopped
        server.stop()
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
