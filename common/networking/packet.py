"""
IP packet handling and fragmentation for the VPN tunnel.
Provides classes for parsing, manipulating, and fragmenting IP packets.
"""
import socket
import struct
import hashlib
import time
from typing import Dict, List, Tuple, Optional


class IPPacket:
    """
    Class for parsing and manipulating IP packets
    """
    def __init__(self, version: int = 4, header_length: int = 5, tos: int = 0,
                total_length: int = 0, identification: int = 0,
                flags: int = 0, fragment_offset: int = 0,
                ttl: int = 64, protocol: int = 0,
                checksum: int = 0, src_ip: str = "0.0.0.0",
                dst_ip: str = "0.0.0.0", options: bytes = b'',
                payload: bytes = b''):
        """
        Initialize an IP packet with the given parameters
        
        Args:
            version: IP version (4 or 6)
            header_length: Header length in 32-bit words
            tos: Type of Service
            total_length: Total packet length in bytes
            identification: Packet identification
            flags: Fragmentation flags
            fragment_offset: Fragmentation offset
            ttl: Time to Live
            protocol: Protocol (e.g., TCP=6, UDP=17)
            checksum: Header checksum
            src_ip: Source IP address
            dst_ip: Destination IP address
            options: IP options
            payload: Packet payload
        """
        self.version = version
        self.header_length = header_length
        self.tos = tos
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.options = options
        self.payload = payload
        
        # Calculate total length if not specified
        if self.total_length == 0:
            self.total_length = self.header_length * 4 + len(self.payload)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'IPPacket':
        """
        Create an IP packet from raw bytes
        
        Args:
            data: Raw packet data
            
        Returns:
            IPPacket object
        """
        if len(data) < 20:
            raise ValueError("Packet too small to be a valid IP packet")
            
        # Parse IP header
        header = data[:20]
        version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum = struct.unpack('!BBHHHBBH', header[:12])
        src_ip, dst_ip = struct.unpack('!4s4s', header[12:20])
        
        # Extract version and header length
        version = (version_ihl >> 4) & 0xF
        header_length = version_ihl & 0xF
        
        # Extract flags and fragment offset
        flags = (flags_offset >> 13) & 0x7
        fragment_offset = flags_offset & 0x1FFF
        
        # Convert IP addresses
        src_ip = socket.inet_ntoa(src_ip)
        dst_ip = socket.inet_ntoa(dst_ip)
        
        # Extract options and payload
        header_bytes = header_length * 4
        options = data[20:header_bytes] if header_bytes > 20 else b''
        payload = data[header_bytes:total_length] if total_length <= len(data) else data[header_bytes:]
        
        return cls(
            version=version,
            header_length=header_length,
            tos=tos,
            total_length=total_length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            src_ip=src_ip,
            dst_ip=dst_ip,
            options=options,
            payload=payload
        )
    
    def to_bytes(self) -> bytes:
        """
        Convert the packet to bytes
        
        Returns:
            Raw packet data
        """
        # Build the header
        version_ihl = (self.version << 4) | self.header_length
        flags_offset = (self.flags << 13) | self.fragment_offset
        
        # Convert IP addresses
        src_ip = socket.inet_aton(self.src_ip)
        dst_ip = socket.inet_aton(self.dst_ip)
        
        # Calculate checksum if not specified
        checksum = self.checksum
        if checksum == 0:
            # Build header without checksum
            header = struct.pack('!BBHHHBBH4s4s',
                               version_ihl, self.tos, self.total_length,
                               self.identification, flags_offset,
                               self.ttl, self.protocol, 0,
                               src_ip, dst_ip)
            
            # Calculate checksum
            checksum = self._calculate_checksum(header)
        
        # Build final header
        header = struct.pack('!BBHHHBBH4s4s',
                           version_ihl, self.tos, self.total_length,
                           self.identification, flags_offset,
                           self.ttl, self.protocol, checksum,
                           src_ip, dst_ip)
        
        # Add options and payload
        return header + self.options + self.payload
    
    def _calculate_checksum(self, header: bytes) -> int:
        """
        Calculate the IP header checksum
        
        Args:
            header: Header bytes with checksum field set to 0
            
        Returns:
            Calculated checksum
        """
        # Sum all 16-bit words
        words = [header[i:i+2] for i in range(0, len(header), 2)]
        sum = 0
        
        for word in words:
            if len(word) == 2:
                sum += int.from_bytes(word, byteorder='big')
            else:
                # Last byte if odd length
                sum += word[0] << 8
        
        # Add the carry
        sum = (sum & 0xFFFF) + (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16)
        
        # Take one's complement
        return (~sum) & 0xFFFF
    
    def get_protocol_name(self) -> str:
        """
        Get the name of the protocol
        
        Returns:
            Protocol name
        """
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            50: "ESP",
            51: "AH",
            58: "ICMPv6"
        }
        
        return protocols.get(self.protocol, f"Unknown ({self.protocol})")
    
    def __str__(self) -> str:
        """
        String representation of the packet
        
        Returns:
            Formatted string with packet details
        """
        return (
            f"IPv{self.version} Packet:\n"
            f"  {self.src_ip} -> {self.dst_ip}\n"
            f"  Protocol: {self.get_protocol_name()}\n"
            f"  Length: {self.total_length} bytes\n"
            f"  TTL: {self.ttl}\n"
            f"  ID: {self.identification}\n"
            f"  Flags: {self.flags}, Offset: {self.fragment_offset}\n"
            f"  Payload: {len(self.payload)} bytes"
        )


class PacketFragmenter:
    """
    Class for fragmenting and reassembling IP packets
    """
    # Fragment header format:
    # [MARKER:2][ID:4][TOTAL_FRAGMENTS:1][FRAGMENT_INDEX:1][FRAGMENT_DATA...]
    FRAGMENT_MARKER = b'\xF7\xF7'
    FRAGMENT_HEADER_SIZE = 8  # bytes
    
    def __init__(self, fragment_timeout: int = 30):
        """
        Initialize the packet fragmenter
        
        Args:
            fragment_timeout: Time in seconds after which incomplete fragments are discarded
        """
        self.fragment_buffer = {}  # id -> {index -> (data, timestamp)}
        self.fragment_timeout = fragment_timeout
    
    def is_fragment(self, data: bytes) -> bool:
        """
        Check if data is a fragment
        
        Args:
            data: The data to check
            
        Returns:
            True if data is a fragment
        """
        return len(data) >= self.FRAGMENT_HEADER_SIZE and data[:2] == self.FRAGMENT_MARKER
    
    def fragment(self, data: bytes, max_fragment_size: int) -> List[bytes]:
        """
        Fragment a packet into smaller chunks
        
        Args:
            data: The packet data to fragment
            max_fragment_size: Maximum size of each fragment
            
        Returns:
            List of fragment data
        """
        if max_fragment_size <= self.FRAGMENT_HEADER_SIZE:
            raise ValueError("Max fragment size too small")
        
        # Generate a random ID for this fragmentation
        fragment_id = int(time.time() * 1000).to_bytes(4, byteorder='big')
        
        # Calculate maximum payload size per fragment
        max_payload = max_fragment_size - self.FRAGMENT_HEADER_SIZE
        
        # Calculate number of fragments needed
        num_fragments = (len(data) + max_payload - 1) // max_payload
        
        fragments = []
        for i in range(num_fragments):
            # Get fragment data
            start = i * max_payload
            end = min(start + max_payload, len(data))
            fragment_data = data[start:end]
            
            # Create fragment header
            header = (
                self.FRAGMENT_MARKER +
                fragment_id +
                bytes([num_fragments]) +
                bytes([i])
            )
            
            # Combine header and data
            fragment = header + fragment_data
            fragments.append(fragment)
        
        return fragments
    
    def process_fragment(self, fragment: bytes) -> Optional[bytes]:
        """
        Process a received fragment
        
        Args:
            fragment: The fragment data
            
        Returns:
            Complete packet data if all fragments received, None otherwise
        """
        if len(fragment) < self.FRAGMENT_HEADER_SIZE:
            return None
            
        if fragment[:2] != self.FRAGMENT_MARKER:
            return None
            
        # Extract fragment information
        fragment_id = fragment[2:6]
        total_fragments = fragment[6]
        fragment_index = fragment[7]
        fragment_data = fragment[self.FRAGMENT_HEADER_SIZE:]
        
        # Convert fragment ID to string for dictionary key
        id_key = fragment_id.hex()
        
        # Add to buffer
        if id_key not in self.fragment_buffer:
            self.fragment_buffer[id_key] = {}
            
        self.fragment_buffer[id_key][fragment_index] = (fragment_data, time.time())
        
        # Check if we have all fragments
        fragments = self.fragment_buffer[id_key]
        if len(fragments) == total_fragments:
            # Reassemble the packet
            packet = b''
            for i in range(total_fragments):
                if i in fragments:
                    packet += fragments[i][0]
                else:
                    # Missing fragment
                    return None
                    
            # Clear this set of fragments
            del self.fragment_buffer[id_key]
            
            return packet
            
        # Clean up old fragments
        self._cleanup_old_fragments()
        
        # Still waiting for more fragments
        return None
    
    def _cleanup_old_fragments(self) -> None:
        """Clean up fragments that have timed out"""
        now = time.time()
        ids_to_remove = []
        
        for id_key, fragments in self.fragment_buffer.items():
            indices_to_remove = []
            
            for index, (_, timestamp) in fragments.items():
                if now - timestamp > self.fragment_timeout:
                    indices_to_remove.append(index)
                    
            for index in indices_to_remove:
                del fragments[index]
                
            if not fragments:
                ids_to_remove.append(id_key)
                
        for id_key in ids_to_remove:
            del self.fragment_buffer[id_key]


# Example usage
if __name__ == "__main__":
    # Create a sample IP packet
    packet = IPPacket(
        version=4,
        protocol=6,  # TCP
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        payload=b"Sample TCP payload" * 50  # Make it large enough to fragment
    )
    
    # Convert to bytes
    packet_bytes = packet.to_bytes()
    print(f"Original packet size: {len(packet_bytes)} bytes")
    
    # Fragment the packet
    fragmenter = PacketFragmenter()
    fragments = fragmenter.fragment(packet_bytes, 200)
    print(f"Split into {len(fragments)} fragments")
    
    # Reconstruct from fragments
    for i, fragment in enumerate(fragments):
        print(f"Processing fragment {i+1}/{len(fragments)}")
        result = fragmenter.process_fragment(fragment)
        if result:
            print("Packet reassembled")
            reassembled = IPPacket.from_bytes(result)
            print(f"Reassembled packet: {reassembled}")
            break
    else:
        print("Failed to reassemble packet")
