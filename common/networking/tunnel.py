"""
Tunneling implementation for the custom VPN system.
Handles creation and management of secure tunnels for IP traffic.
"""
import os
import socket
import select
import ssl
import struct
import time
import logging
import threading
import queue
from typing import Dict, Tuple, List, Optional, Union, Any

from common.crypto.kyber import Kyber
from common.crypto.aes import AESCipher
from common.networking.packet import IPPacket, PacketFragmenter


class TunnelConfig:
    """Configuration settings for the tunnel"""
    # TLS settings
    CERT_PATH = "certs/cert.pem"
    KEY_PATH = "certs/key.pem"
    
    # Tunnel protocol constants
    PACKET_HEADER_SIZE = 8  # bytes
    MAX_PACKET_SIZE = 1500  # Maximum packet size including header
    KEEPALIVE_INTERVAL = 30  # seconds
    
    # Tunnel operation modes
    MODE_TCP = 0
    MODE_UDP = 1
    
    # Tunnel protocol commands
    CMD_DATA = 0
    CMD_CONTROL = 1
    CMD_KYBER_INIT = 2
    CMD_KYBER_RESPONSE = 3
    CMD_KEEPALIVE = 4
    CMD_DISCONNECT = 5


class TunnelEndpoint:
    """
    Base class for both client and server tunnel endpoints
    """
    def __init__(self, mode: int = TunnelConfig.MODE_TCP,
                log_traffic: bool = False):
        """
        Initialize the tunnel endpoint
        
        Args:
            mode: TunnelConfig.MODE_TCP or TunnelConfig.MODE_UDP
            log_traffic: Whether to log traffic details
        """
        self.mode = mode
        self.log_traffic = log_traffic
        self.running = False
        self.connected = False
        self.connection = None
        self.remote_address = None
        
        # Encryption
        self.session_key = None
        self.kyber_keys = None
        
        # Packet processing
        self.fragmenter = PacketFragmenter()
        self.recv_buffer = bytearray()
        self.send_queue = queue.Queue()
        
        # Setup logging
        self.logger = logging.getLogger("tunnel")
    
    def _create_socket(self) -> socket.socket:
        """Create appropriate socket based on mode"""
        if self.mode == TunnelConfig.MODE_TCP:
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def _wrap_socket_with_tls(self, sock: socket.socket, 
                             server_side: bool = False) -> ssl.SSLSocket:
        """
        Wrap socket with TLS
        
        Args:
            sock: The socket to wrap
            server_side: True if server, False if client
            
        Returns:
            SSL wrapped socket
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH 
                                           if server_side 
                                           else ssl.Purpose.SERVER_AUTH)
        
        if server_side:
            context.load_cert_chain(certfile=TunnelConfig.CERT_PATH, 
                                   keyfile=TunnelConfig.KEY_PATH)
        else:
            # For client, normally we'd verify cert but disable for testing
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        return context.wrap_socket(sock, server_side=server_side)
    
    def _initialize_kyber(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Initialize Kyber key exchange
        
        Returns:
            Tuple of (public_key, private_key)
        """
        self.logger.info("Initializing Kyber key exchange")
        return Kyber.keygen()
    
    def _pack_tunnel_packet(self, data: bytes, command: int = TunnelConfig.CMD_DATA) -> bytes:
        """
        Pack data with tunnel header
        
        Args:
            data: The payload data
            command: The command type
            
        Returns:
            Packet with tunnel header
        """
        # Header format: [COMMAND:1][LENGTH:3][SEQUENCE:4]
        sequence = int(time.time() * 1000) & 0xFFFFFFFF  # Use timestamp as sequence
        length = len(data)
        
        if length > 0xFFFFFF:  # 3 bytes max for length
            raise ValueError(f"Packet too large: {length} bytes")
        
        header = struct.pack("!BL", 
                           (command & 0xFF), 
                           (length << 8) | (sequence & 0xFFFFFFFF))
        
        return header + data
    
    def _unpack_tunnel_packet(self, packet: bytes) -> Tuple[int, bytes]:
        """
        Unpack a tunnel packet
        
        Args:
            packet: The raw packet data
            
        Returns:
            Tuple of (command, payload)
        """
        if len(packet) < TunnelConfig.PACKET_HEADER_SIZE:
            raise ValueError(f"Packet too small: {len(packet)} bytes")
            
        header = packet[:TunnelConfig.PACKET_HEADER_SIZE]
        payload = packet[TunnelConfig.PACKET_HEADER_SIZE:]
        
        command = header[0]
        # Extract length (3 bytes) and sequence (4 bytes) if needed
        
        return command, payload
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data for transmission
        
        Args:
            data: Raw data to encrypt
            
        Returns:
            Encrypted data
        """
        if not self.session_key:
            raise ValueError("No session key established")
            
        return AESCipher.encrypt_packet(data, self.session_key)
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """
        Decrypt received data
        
        Args:
            data: Encrypted data
            
        Returns:
            Decrypted data
        """
        if not self.session_key:
            raise ValueError("No session key established")
            
        return AESCipher.decrypt_packet(data, self.session_key)
    
    def send_packet(self, packet: Union[bytes, IPPacket], 
                   command: int = TunnelConfig.CMD_DATA) -> bool:
        """
        Send a packet through the tunnel
        
        Args:
            packet: The packet data or IPPacket object
            command: Command type
            
        Returns:
            True if successful, False otherwise
        """
        if not self.connected:
            self.logger.error("Cannot send packet: tunnel not connected")
            return False
            
        # Convert IPPacket to bytes if needed
        if isinstance(packet, IPPacket):
            packet_data = packet.to_bytes()
        else:
            packet_data = packet
            
        # Fragment if needed
        max_payload = TunnelConfig.MAX_PACKET_SIZE - TunnelConfig.PACKET_HEADER_SIZE
        
        if len(packet_data) > max_payload:
            fragments = self.fragmenter.fragment(packet_data, max_payload)
            for fragment in fragments:
                self._queue_packet(fragment, command)
        else:
            self._queue_packet(packet_data, command)
            
        return True
    
    def _queue_packet(self, data: bytes, command: int) -> None:
        """
        Queue a packet for sending
        
        Args:
            data: The packet data
            command: Command type
        """
        # Encrypt if not a control command
        if command == TunnelConfig.CMD_DATA and self.session_key:
            data = self._encrypt_data(data)
            
        # Pack with tunnel header
        packet = self._pack_tunnel_packet(data, command)
        
        # Add to send queue
        self.send_queue.put(packet)
    
    def _handle_packet(self, packet: bytes) -> None:
        """
        Process a received packet
        
        Args:
            packet: The raw packet data
        """
        try:
            command, payload = self._unpack_tunnel_packet(packet)
            
            if command == TunnelConfig.CMD_DATA:
                # Decrypt data packet
                if self.session_key:
                    try:
                        payload = self._decrypt_data(payload)
                        self._process_data_packet(payload)
                    except Exception as e:
                        self.logger.error(f"Failed to decrypt packet: {e}")
                else:
                    self.logger.warning("Received data packet but no session key established")
                    
            elif command == TunnelConfig.CMD_CONTROL:
                self._process_control_packet(payload)
                
            elif command == TunnelConfig.CMD_KYBER_INIT:
                self._process_kyber_init(payload)
                
            elif command == TunnelConfig.CMD_KYBER_RESPONSE:
                self._process_kyber_response(payload)
                
            elif command == TunnelConfig.CMD_KEEPALIVE:
                self._process_keepalive()
                
            elif command == TunnelConfig.CMD_DISCONNECT:
                self.logger.info("Received disconnect command")
                self.disconnect()
                
            else:
                self.logger.warning(f"Unknown command: {command}")
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
    
    def _process_data_packet(self, data: bytes) -> None:
        """
        Process a data packet (to be implemented by subclasses)
        
        Args:
            data: The decrypted packet data
        """
        raise NotImplementedError("Subclasses must implement _process_data_packet")
    
    def _process_control_packet(self, data: bytes) -> None:
        """
        Process a control packet (to be implemented by subclasses)
        
        Args:
            data: The control packet data
        """
        raise NotImplementedError("Subclasses must implement _process_control_packet")
    
    def _process_kyber_init(self, data: bytes) -> None:
        """
        Process a Kyber initialization packet (to be implemented by subclasses)
        
        Args:
            data: The Kyber initialization data
        """
        raise NotImplementedError("Subclasses must implement _process_kyber_init")
    
    def _process_kyber_response(self, data: bytes) -> None:
        """
        Process a Kyber response packet (to be implemented by subclasses)
        
        Args:
            data: The Kyber response data
        """
        raise NotImplementedError("Subclasses must implement _process_kyber_response")
    
    def _process_keepalive(self) -> None:
        """Process a keepalive packet"""
        # Respond to keepalive with a keepalive
        self.send_packet(b'', TunnelConfig.CMD_KEEPALIVE)
        
    def _sender_thread(self) -> None:
        """Thread for sending packets"""
        while self.running:
            try:
                # Get packet with timeout to allow for thread termination
                packet = self.send_queue.get(timeout=1.0)
                
                if self.connection:
                    if self.mode == TunnelConfig.MODE_TCP:
                        self.connection.sendall(packet)
                    else:
                        self.connection.sendto(packet, self.remote_address)
                        
                    if self.log_traffic:
                        self.logger.debug(f"Sent packet: {len(packet)} bytes")
                
                self.send_queue.task_done()
                
            except queue.Empty:
                continue
                
            except Exception as e:
                self.logger.error(f"Error in sender thread: {e}")
                if not self.running:
                    break
    
    def _receiver_thread(self) -> None:
        """Thread for receiving packets - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement _receiver_thread")
    
    def _keepalive_thread(self) -> None:
        """Thread for sending keepalive packets"""
        while self.running and self.connected:
            try:
                # Send keepalive packet
                self.send_packet(b'', TunnelConfig.CMD_KEEPALIVE)
                
                # Sleep for the keepalive interval
                time.sleep(TunnelConfig.KEEPALIVE_INTERVAL)
                
            except Exception as e:
                self.logger.error(f"Error in keepalive thread: {e}")
                if not self.running:
                    break
    
    def disconnect(self) -> None:
        """Disconnect the tunnel"""
        if self.connected:
            try:
                # Send disconnect command
                self.send_packet(b'', TunnelConfig.CMD_DISCONNECT)
                
                # Close connection
                if self.connection:
                    self.connection.close()
                    self.connection = None
                    
            except Exception as e:
                self.logger.error(f"Error during disconnect: {e}")
                
            finally:
                self.connected = False
                self.session_key = None
                self.logger.info("Tunnel disconnected")
    
    def cleanup(self) -> None:
        """Clean up resources"""
        self.running = False
        self.disconnect()


class TunnelClient(TunnelEndpoint):
    """
    Client-side implementation of the tunnel
    """
    def __init__(self, mode: int = TunnelConfig.MODE_TCP,
                log_traffic: bool = False):
        """
        Initialize the tunnel client
        
        Args:
            mode: TunnelConfig.MODE_TCP or TunnelConfig.MODE_UDP
            log_traffic: Whether to log traffic details
        """
        super().__init__(mode, log_traffic)
        self.tun_interface = None
        
        # Threads
        self.sender_thread = None
        self.receiver_thread = None
        self.keepalive_thread = None
    
    def connect(self, server_address: Tuple[str, int], timeout: float = 10.0) -> bool:
        """
        Connect to the tunnel server
        
        Args:
            server_address: Tuple of (host, port)
            timeout: Connection timeout in seconds
            
        Returns:
            True if connection successful, False otherwise
        """
        if self.connected:
            self.logger.warning("Already connected, disconnecting first")
            self.disconnect()
            
        try:
            self.logger.info(f"Connecting to server at {server_address}")
            
            # Create socket
            sock = self._create_socket()
            sock.settimeout(timeout)
            
            # Connect
            if self.mode == TunnelConfig.MODE_TCP:
                sock.connect(server_address)
                
                # Wrap with TLS
                self.connection = self._wrap_socket_with_tls(sock)
            else:
                # For UDP, just store the connection and address
                self.connection = sock
                self.remote_address = server_address
            
            # Start threads
            self.running = True
            self.connected = True
            
            self.sender_thread = threading.Thread(target=self._sender_thread)
            self.receiver_thread = threading.Thread(target=self._receiver_thread)
            self.keepalive_thread = threading.Thread(target=self._keepalive_thread)
            
            self.sender_thread.daemon = True
            self.receiver_thread.daemon = True
            self.keepalive_thread.daemon = True
            
            self.sender_thread.start()
            self.receiver_thread.start()
            self.keepalive_thread.start()
            
            # Initiate Kyber key exchange
            self._initiate_kyber_exchange()
            
            self.logger.info("Connected to server")
            return True
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            self.cleanup()
            return False
    
    def _initiate_kyber_exchange(self) -> None:
        """Initiate Kyber key exchange with the server"""
        try:
            # Generate Kyber keypair
            public_key, private_key = self._initialize_kyber()
            self.kyber_keys = private_key
            
            # Serialize public key (simplified)
            # In a real implementation, we'd properly serialize the public key components
            serialized_pk = str(public_key).encode()
            
            # Send to server
            self.send_packet(serialized_pk, TunnelConfig.CMD_KYBER_INIT)
            self.logger.info("Sent Kyber public key to server")
            
        except Exception as e:
            self.logger.error(f"Kyber initialization failed: {e}")
            self.disconnect()
    
    def _process_kyber_response(self, data: bytes) -> None:
        """
        Process a Kyber response from the server
        
        Args:
            data: The ciphertext from the server
        """
        try:
            self.logger.info("Received Kyber response from server")
            
            # In a real implementation, we would:
            # 1. Deserialize the ciphertext
            # 2. Decrypt it using our private key
            # 3. Derive the session key
            
            # Simplified for demonstration
            # Assume data contains the ciphertext
            ciphertext = data
            
            # Decrypt using Kyber
            private_key = self.kyber_keys
            shared_secret = Kyber.decapsulate(ciphertext, private_key)
            
            # Derive AES key
            salt = ciphertext[:16]  # Use part of ciphertext as salt
            self.session_key, _ = AESCipher.derive_key_from_shared_secret(shared_secret, salt)
            
            self.logger.info("Key exchange completed, secure session established")
            
        except Exception as e:
            self.logger.error(f"Kyber response processing failed: {e}")
            self.disconnect()
    
    def _process_control_packet(self, data: bytes) -> None:
        """
        Process a control packet from the server
        
        Args:
            data: The control packet data
        """
        # Parse control messages from server
        try:
            # Simple text-based control protocol for now
            control_msg = data.decode('utf-8')
            self.logger.info(f"Received control message: {control_msg}")
            
            # Handle specific control messages
            if control_msg.startswith("CONFIG:"):
                # Process configuration update
                pass
                
            elif control_msg.startswith("ROUTE:"):
                # Process routing update
                pass
                
            else:
                self.logger.warning(f"Unknown control message: {control_msg}")
                
        except Exception as e:
            self.logger.error(f"Failed to process control packet: {e}")
    
    def _process_data_packet(self, data: bytes) -> None:
        """
        Process a data packet from the server
        
        Args:
            data: The decrypted packet data
        """
        try:
            # Check if this is a fragment
            if self.fragmenter.is_fragment(data):
                # Process fragment, get complete packet if available
                complete_packet = self.fragmenter.process_fragment(data)
                if not complete_packet:
                    # Fragments still being collected
                    return
                data = complete_packet
            
            # Parse as an IP packet
            ip_packet = IPPacket.from_bytes(data)
            
            if self.log_traffic:
                self.logger.debug(
                    f"Received IP packet: {ip_packet.src_ip} -> {ip_packet.dst_ip}, "
                    f"Protocol: {ip_packet.protocol}, Length: {len(data)} bytes"
                )
            
            # Write to TUN interface if available
            if self.tun_interface:
                self.tun_interface.write(data)
                
        except Exception as e:
            self.logger.error(f"Failed to process data packet: {e}")
    
    def _receiver_thread(self) -> None:
        """Thread for receiving packets from the server"""
        while self.running and self.connected:
            try:
                if self.mode == TunnelConfig.MODE_TCP:
                    # TCP mode - receive stream
                    data = self.connection.recv(4096)
                    if not data:
                        self.logger.warning("Server closed connection")
                        self.disconnect()
                        break
                        
                    # Add to buffer and process complete packets
                    self.recv_buffer.extend(data)
                    self._process_buffer()
                    
                else:
                    # UDP mode - receive datagrams
                    data, addr = self.connection.recvfrom(4096)
                    if addr != self.remote_address:
                        self.logger.warning(f"Received packet from unknown address: {addr}")
                        continue
                        
                    # Process the packet
                    self._handle_packet(data)
                    
            except socket.timeout:
                continue
                
            except ConnectionResetError:
                self.logger.warning("Connection reset by server")
                self.disconnect()
                break
                
            except Exception as e:
                self.logger.error(f"Error in receiver thread: {e}")
                if not self.running:
                    break
    
    def _process_buffer(self) -> None:
        """
        Process the receive buffer (for TCP mode)
        Extracts complete packets from the buffer and processes them
        """
        while len(self.recv_buffer) >= TunnelConfig.PACKET_HEADER_SIZE:
            # Parse header to get packet length
            header = self.recv_buffer[:TunnelConfig.PACKET_HEADER_SIZE]
            command = header[0]
            length_bytes = header[1:4]
            length = int.from_bytes(length_bytes, byteorder='big')
            
            # Check if we have a complete packet
            total_length = TunnelConfig.PACKET_HEADER_SIZE + length
            if len(self.recv_buffer) < total_length:
                # Incomplete packet, wait for more data
                break
                
            # Extract the packet
            packet = bytes(self.recv_buffer[:total_length])
            del self.recv_buffer[:total_length]
            
            # Process the packet
            self._handle_packet(packet)
    
    def set_tun_interface(self, tun_interface) -> None:
        """
        Set the TUN interface for sending/receiving IP packets
        
        Args:
            tun_interface: The TUN interface object
        """
        self.tun_interface = tun_interface
    
    def send_ip_packet(self, packet_data: bytes) -> bool:
        """
        Send an IP packet through the tunnel
        
        Args:
            packet_data: Raw IP packet data
            
        Returns:
            True if successful, False otherwise
        """
        return self.send_packet(packet_data)


class TunnelServer(TunnelEndpoint):
    """
    Server-side implementation of the tunnel
    """
    def __init__(self, mode: int = TunnelConfig.MODE_TCP,
                log_traffic: bool = False):
        """
        Initialize the tunnel server
        
        Args:
            mode: TunnelConfig.MODE_TCP or TunnelConfig.MODE_UDP
            log_traffic: Whether to log traffic details
        """
        super().__init__(mode, log_traffic)
        
        self.server_socket = None
        self.clients = {}  # client_address -> client_connection
        self.client_buffers = {}  # client_address -> buffer
        self.client_keys = {}  # client_address -> session_key
        
        # Threads
        self.accept_thread = None
        self.sender_thread = None
        self.receiver_thread = None
    
    def start(self, bind_address: Tuple[str, int], backlog: int = 5) -> bool:
        """
        Start the tunnel server
        
        Args:
            bind_address: Tuple of (host, port) to bind to
            backlog: Connection backlog for TCP
            
        Returns:
            True if server started successfully, False otherwise
        """
        try:
            self.logger.info(f"Starting tunnel server on {bind_address}")
            
            # Create server socket
            self.server_socket = self._create_socket()
            
            # Set socket options
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind
            self.server_socket.bind(bind_address)
            
            # For TCP, listen for connections
            if self.mode == TunnelConfig.MODE_TCP:
                self.server_socket.listen(backlog)
            
            self.running = True
            
            # Start threads
            if self.mode == TunnelConfig.MODE_TCP:
                self.accept_thread = threading.Thread(target=self._accept_thread)
                self.accept_thread.daemon = True
                self.accept_thread.start()
            else:
                # UDP mode - just start receiver thread
                self.receiver_thread = threading.Thread(target=self._receiver_thread)
                self.receiver_thread.daemon = True
                self.receiver_thread.start()
            
            self.sender_thread = threading.Thread(target=self._sender_thread)
            self.sender_thread.daemon = True
            self.sender_thread.start()
            
            self.logger.info("Tunnel server started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            self.cleanup()
            return False
    
    def _accept_thread(self) -> None:
        """Thread for accepting client connections (TCP mode)"""
        while self.running:
            try:
                # Accept connection
                client_sock, client_addr = self.server_socket.accept()
                
                # Wrap with TLS
                client_connection = self._wrap_socket_with_tls(client_sock, server_side=True)
                
                self.logger.info(f"Client connected: {client_addr}")
                
                # Add to clients
                self.clients[client_addr] = client_connection
                self.client_buffers[client_addr] = bytearray()
                
                # Start a dedicated receiver thread for this client
                client_thread = threading.Thread(
                    target=self._client_receiver_thread,
                    args=(client_connection, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                self.logger.error(f"Error accepting connection: {e}")
                if not self.running:
                    break
    
    def _client_receiver_thread(self, client_connection: ssl.SSLSocket, 
                              client_addr: Tuple[str, int]) -> None:
        """
        Thread for receiving data from a specific TCP client
        
        Args:
            client_connection: The client's SSL socket
            client_addr: The client's address
        """
        while self.running and client_addr in self.clients:
            try:
                # Receive data
                data = client_connection.recv(4096)
                if not data:
                    self.logger.info(f"Client disconnected: {client_addr}")
                    self._remove_client(client_addr)
                    break
                
                # Add to buffer and process
                self.client_buffers[client_addr].extend(data)
                self._process_client_buffer(client_addr)
                
            except ConnectionResetError:
                self.logger.warning(f"Connection reset by client: {client_addr}")
                self._remove_client(client_addr)
                break
                
            except Exception as e:
                self.logger.error(f"Error receiving from client {client_addr}: {e}")
                if not self.running or client_addr not in self.clients:
                    break
    
    def _process_client_buffer(self, client_addr: Tuple[str, int]) -> None:
        """
        Process the receive buffer for a specific client (TCP mode)
        
        Args:
            client_addr: The client's address
        """
        buffer = self.client_buffers.get(client_addr)
        if not buffer:
            return
            
        while len(buffer) >= TunnelConfig.PACKET_HEADER_SIZE:
            # Parse header to get packet length
            header = buffer[:TunnelConfig.PACKET_HEADER_SIZE]
            command = header[0]
            length_bytes = header[1:4]
            length = int.from_bytes(length_bytes, byteorder='big')
            
            # Check if we have a complete packet
            total_length = TunnelConfig.PACKET_HEADER_SIZE + length
            if len(buffer) < total_length:
                # Incomplete packet, wait for more data
                break
                
            # Extract the packet
            packet = bytes(buffer[:total_length])
            del buffer[:total_length]
            
            # Process the packet
            self._handle_client_packet(client_addr, packet)
    
    def _handle_client_packet(self, client_addr: Tuple[str, int], packet: bytes) -> None:
        """
        Process a packet from a client
        
        Args:
            client_addr: The client's address
            packet: The raw packet data
        """
        try:
            command, payload = self._unpack_tunnel_packet(packet)
            
            if command == TunnelConfig.CMD_DATA:
                # Decrypt data packet if we have a session key
                session_key = self.client_keys.get(client_addr)
                if session_key:
                    try:
                        payload = AESCipher.decrypt_packet(payload, session_key)
                        self._process_client_data(client_addr, payload)
                    except Exception as e:
                        self.logger.error(f"Failed to decrypt packet from {client_addr}: {e}")
                else:
                    self.logger.warning(f"Received data packet from {client_addr} but no session key established")
                    
            elif command == TunnelConfig.CMD_CONTROL:
                self._process_client_control(client_addr, payload)
                
            elif command == TunnelConfig.CMD_KYBER_INIT:
                self._process_client_kyber_init(client_addr, payload)
                
            elif command == TunnelConfig.CMD_KEEPALIVE:
                # Send keepalive response
                self._send_to_client(client_addr, b'', TunnelConfig.CMD_KEEPALIVE)
                
            elif command == TunnelConfig.CMD_DISCONNECT:
                self.logger.info(f"Client {client_addr} requested disconnect")
                self._remove_client(client_addr)
                
            else:
                self.logger.warning(f"Unknown command {command} from client {client_addr}")
                
        except Exception as e:
            self.logger.error(f"Error handling packet from {client_addr}: {e}")
    
    def _process_client_data(self, client_addr: Tuple[str, int], data: bytes) -> None:
        """
        Process a data packet from a client
        
        Args:
            client_addr: The client's address
            data: The decrypted packet data
        """
        try:
            # Check if this is a fragment
            if self.fragmenter.is_fragment(data):
                # Process fragment, get complete packet if available
                complete_packet = self.fragmenter.process_fragment(data)
                if not complete_packet:
                    # Fragments still being collected
                    return
                data = complete_packet
            
            # Parse as an IP packet
            ip_packet = IPPacket.from_bytes(data)
            
            if self.log_traffic:
                self.logger.debug(
                    f"Received IP packet from {client_addr}: "
                    f"{ip_packet.src_ip} -> {ip_packet.dst_ip}, "
                    f"Protocol: {ip_packet.protocol}, Length: {len(data)} bytes"
                )
            
            # Process the IP packet (e.g., route to destination)
            # This would be implemented by a subclass for specific routing logic
            self._route_ip_packet(client_addr, ip_packet)
            
        except Exception as e:
            self.logger.error(f"Failed to process data packet from {client_addr}: {e}")
    
    def _route_ip_packet(self, client_addr: Tuple[str, int], packet: IPPacket) -> None:
        """
        Route an IP packet to its destination
        
        Args:
            client_addr: The client's address
            packet: The IP packet to route
        """
        # This is a placeholder for actual routing logic
        # In a real VPN, this would forward the packet to the internet or other clients
        pass
    
    def _process_client_control(self, client_addr: Tuple[str, int], data: bytes) -> None:
        """
        Process a control packet from a client
        
        Args:
            client_addr: The client's address
            data: The control packet data
        """
        try:
            # Simple text-based control protocol for now
            control_msg = data.decode('utf-8')
            self.logger.info(f"Received control message from {client_addr}: {control_msg}")
            
            # Handle specific control messages
            if control_msg.startswith("ROUTE_REQUEST:"):
                # Handle route request
                pass
                
            elif control_msg.startswith("STATUS:"):
                # Handle status update
                pass
                
            else:
                self.logger.warning(f"Unknown control message from {client_addr}: {control_msg}")
                
        except Exception as e:
            self.logger.error(f"Failed to process control packet from {client_addr}: {e}")
    
    def _process_client_kyber_init(self, client_addr: Tuple[str, int], data: bytes) -> None:
        """
        Process a Kyber initialization request from a client
        
        Args:
            client_addr: The client's address
            data: The client's Kyber public key
        """
        try:
            self.logger.info(f"Received Kyber initialization from {client_addr}")
            
            # In a real implementation, we would:
            # 1. Deserialize the client's public key
            # 2. Generate a random secret
            # 3. Encapsulate the secret using the client's public key
            # 4. Derive our session key from the secret
            # 5. Send the ciphertext to the client
            
            # Simplified for demonstration
            # Assume data contains the serialized public key
            
            # Parse client's public key
            # For demonstration, assume it's in a simple format
            client_pk = eval(data.decode())
            
            # Generate shared secret and encapsulate
            ciphertext, shared_secret = Kyber.encapsulate(client_pk)
            
            # Derive AES key
            salt = os.urandom(16)
            session_key, _ = AESCipher.derive_key_from_shared_secret(shared_secret, salt)
            
            # Store the session key for this client
            self.client_keys[client_addr] = session_key
            
            # Send the ciphertext to the client
            response = salt + ciphertext
            self._send_to_client(client_addr, response, TunnelConfig.CMD_KYBER_RESPONSE)
            
            self.logger.info(f"Completed key exchange with {client_addr}")
            
        except Exception as e:
            self.logger.error(f"Kyber initialization with {client_addr} failed: {e}")
    
    def _send_to_client(self, client_addr: Tuple[str, int], data: bytes, 
                      command: int = TunnelConfig.CMD_DATA) -> bool:
        """
        Send data to a specific client
        
        Args:
            client_addr: The client's address
            data: The data to send
            command: The command type
            
        Returns:
            True if successful, False otherwise
        """
        if client_addr not in self.clients:
            self.logger.warning(f"Cannot send to {client_addr}: client not connected")
            return False
            
        # Encrypt if it's a data packet and we have a session key
        if command == TunnelConfig.CMD_DATA and client_addr in self.client_keys:
            try:
                data = AESCipher.encrypt_packet(data, self.client_keys[client_addr])
            except Exception as e:
                self.logger.error(f"Failed to encrypt packet to {client_addr}: {e}")
                return False
                
        # Pack with tunnel header
        packet = self._pack_tunnel_packet(data, command)
        
        try:
            client = self.clients[client_addr]
            
            if self.mode == TunnelConfig.MODE_TCP:
                client.sendall(packet)
            else:
                self.server_socket.sendto(packet, client_addr)
                
            if self.log_traffic:
                self.logger.debug(f"Sent packet to {client_addr}: {len(packet)} bytes")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending to {client_addr}: {e}")
            self._remove_client(client_addr)
            return False
    
    def _remove_client(self, client_addr: Tuple[str, int]) -> None:
        """
        Remove a client from the active clients list
        
        Args:
            client_addr: The client's address
        """
        if client_addr in self.clients:
            try:
                self.clients[client_addr].close()
            except:
                pass
                
            del self.clients[client_addr]
            
            if client_addr in self.client_buffers:
                del self.client_buffers[client_addr]
                
            if client_addr in self.client_keys:
                del self.client_keys[client_addr]
                
            self.logger.info(f"Client {client_addr} removed")
    
    def _receiver_thread(self) -> None:
        """Thread for receiving packets (UDP mode)"""
        if self.mode != TunnelConfig.MODE_UDP:
            return
            
        self.server_socket.settimeout(1.0)
        
        while self.running:
            try:
                # Receive datagram
                data, client_addr = self.server_socket.recvfrom(4096)
                
                # Process the packet
                self._handle_client_packet(client_addr, data)
                
                # Add to clients list if new
                if client_addr not in self.clients:
                    self.clients[client_addr] = None  # No actual connection object for UDP
                    self.logger.info(f"New UDP client: {client_addr}")
                    
            except socket.timeout:
                continue
                
            except Exception as e:
                self.logger.error(f"Error in UDP receiver thread: {e}")
                if not self.running:
                    break
    
    def broadcast(self, data: bytes, command: int = TunnelConfig.CMD_DATA) -> None:
        """
        Broadcast data to all connected clients
        
        Args:
            data: The data to broadcast
            command: The command type
        """
        # Get copy of client list to avoid modification during iteration
        clients = list(self.clients.keys())
        
        for client_addr in clients:
            self._send_to_client(client_addr, data, command)
    
    def send_control_message(self, client_addr: Tuple[str, int], message: str) -> bool:
        """
        Send a control message to a specific client
        
        Args:
            client_addr: The client's address
            message: The control message
            
        Returns:
            True if successful, False otherwise
        """
        return self._send_to_client(client_addr, message.encode('utf-8'), 
                                 TunnelConfig.CMD_CONTROL)
    
    def cleanup(self) -> None:
        """Clean up resources"""
        self.running = False
        
        # Close all client connections
        for client_addr in list(self.clients.keys()):
            self._remove_client(client_addr)
            
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
            
        self.logger.info("Tunnel server cleaned up")


# Example usage
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example server
    server = TunnelServer(mode=TunnelConfig.MODE_TCP, log_traffic=True)
    server.start(('0.0.0.0', 8080))
    
    try:
        # Keep the server running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        server.cleanup()
