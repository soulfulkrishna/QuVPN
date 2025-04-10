"""
Test program for verifying OTP encryption within the tunnel.
This simulates sending packets through the tunnel with OTP encryption enabled.
"""
import logging
import os
import time
import json
from common.crypto.otp import OTPCipher
from common.crypto.aes import AESCipher
from common.networking.packet import IPPacket, IPProtocol

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('tunnel_otp_test')

def simulate_tunnel_encryption(data, use_otp=True):
    """
    Simulates the tunnel encryption process
    
    Args:
        data: The data to encrypt
        use_otp: Whether to use OTP encryption
        
    Returns:
        Tuple of (encrypted_data, session_key, metadata)
    """
    # Generate a session key (simulating what would happen after Kyber exchange)
    session_key = AESCipher.generate_key()
    logger.info(f"Session key: {base64.b64encode(session_key).decode()}")
    
    if use_otp:
        # Apply OTP encryption
        encrypted_data, metadata = OTPCipher.encrypt(data)
        
        # Store the OTP metadata with the packet
        # Format: [OTP_FLAG (1)] [META_LEN (2)] [METADATA (JSON)] [ENCRYPTED_DATA]
        meta_json = json.dumps(metadata).encode('utf-8')
        meta_len = len(meta_json).to_bytes(2, byteorder='big')
        packet = b'\x01' + meta_len + meta_json + encrypted_data
        
        logger.info(f"OTP-encrypted packet size: {len(packet)} bytes")
        return packet, session_key, metadata
    else:
        # Use only AES
        encrypted_data = AESCipher.encrypt_packet(data, session_key)
        logger.info(f"AES-only encrypted packet size: {len(encrypted_data)} bytes")
        return encrypted_data, session_key, None

def simulate_tunnel_decryption(data, session_key, use_otp=True):
    """
    Simulates the tunnel decryption process
    
    Args:
        data: The encrypted data
        session_key: The session key for AES
        use_otp: Whether to use OTP decryption
        
    Returns:
        Decrypted data
    """
    if use_otp and data[0] == 0x01:
        # Extract metadata
        meta_len = int.from_bytes(data[1:3], byteorder='big')
        meta_json = data[3:3+meta_len]
        encrypted_data = data[3+meta_len:]
        
        # Parse metadata
        metadata = json.loads(meta_json.decode('utf-8'))
        logger.info(f"OTP metadata: {metadata}")
        
        # Decrypt with OTP
        return OTPCipher.decrypt(encrypted_data, metadata)
    else:
        # Standard AES decryption
        return AESCipher.decrypt_packet(data, session_key)

def test_tunnel_packet_transmission():
    """
    Test full packet encryption/decryption through the tunnel
    """
    logger.info("Testing tunnel packet transmission with OTP...")
    
    # Create a simulated IP packet
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"
    protocol = IPProtocol.TCP
    ttl = 64
    payload = b"This is test packet data that would normally be TCP/IP payload"
    
    packet = IPPacket(src_ip, dst_ip, protocol, ttl, payload)
    packet_bytes = packet.to_bytes()
    
    logger.info(f"Original packet: {src_ip} -> {dst_ip}, Protocol: {protocol}, Data length: {len(payload)}")
    
    # Test both with and without OTP
    for use_otp in [True, False]:
        logger.info(f"\nTesting with OTP {'enabled' if use_otp else 'disabled'}")
        
        # Simulate sender encryption
        encrypted, session_key, metadata = simulate_tunnel_encryption(packet_bytes, use_otp)
        
        # Simulate transmission delay
        time.sleep(0.1)
        
        # Simulate receiver decryption
        decrypted = simulate_tunnel_decryption(encrypted, session_key, use_otp)
        
        # Verify
        if packet_bytes == decrypted:
            logger.info("✓ Tunnel transmission successful - packet intact")
        else:
            logger.error("✗ Tunnel transmission failed - packet corrupted")
            logger.error(f"Original length: {len(packet_bytes)}, Decrypted length: {len(decrypted)}")
    
    print()

def test_large_packet_handling():
    """
    Test handling of large packets with OTP
    """
    logger.info("Testing large packet handling with OTP...")
    
    # Create packets of increasing size
    sizes = [100, 1000, 10000, 65000]  # Up to ~64KB
    
    for size in sizes:
        # Create random packet data
        packet_data = os.urandom(size)
        logger.info(f"\nTesting packet size: {size} bytes")
        
        # Encrypt with OTP
        encrypted, session_key, metadata = simulate_tunnel_encryption(packet_data, use_otp=True)
        
        # Decrypt
        decrypted = simulate_tunnel_decryption(encrypted, session_key, use_otp=True)
        
        # Verify
        if packet_data == decrypted:
            logger.info(f"✓ Size {size}: Packet successfully processed")
        else:
            logger.error(f"✗ Size {size}: Packet corrupted")
            logger.error(f"Original length: {len(packet_data)}, Decrypted length: {len(decrypted)}")
    
    print()

if __name__ == "__main__":
    print("-" * 60)
    print("TESTING TUNNEL OTP ENCRYPTION")
    print("-" * 60)
    
    # Import base64 here to avoid polluting global namespace
    import base64
    
    # Run tests
    test_tunnel_packet_transmission()
    test_large_packet_handling()
    
    print("All tunnel OTP tests completed!")