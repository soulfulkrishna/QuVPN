"""
AES encryption module for data packet encryption in the VPN system.
Uses PyCryptodome for AES implementation.
"""
import os
import base64
import hashlib
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    """
    AES encryption/decryption utility class.
    Provides methods for encrypting and decrypting data using AES-GCM.
    """
    
    @staticmethod
    def generate_key(length: int = 32) -> bytes:
        """
        Generate a secure random AES key.
        
        Args:
            length: Key length in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256)
            
        Returns:
            Random key bytes
        """
        return os.urandom(length)
    
    @staticmethod
    def derive_key_from_shared_secret(shared_secret: bytes, salt: Optional[bytes] = None, 
                                      key_length: int = 32) -> Tuple[bytes, bytes]:
        """
        Derive an AES key from a shared secret (e.g., from Kyber KEM).
        
        Args:
            shared_secret: The shared secret from key exchange
            salt: Optional salt for key derivation, generated if None
            key_length: Length of the derived key in bytes
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
            
        # Use HKDF or PBKDF2 for proper key derivation
        # This is a simplified version using SHA-256
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            shared_secret, 
            salt, 
            100000,  # High iteration count for security
            dklen=key_length
        )
        
        return key, salt
    
    @staticmethod
    def encrypt_gcm(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-GCM mode with authentication.
        
        Args:
            plaintext: Data to encrypt
            key: AES key (should be 16, 24, or 32 bytes)
            
        Returns:
            Tuple of (ciphertext, nonce, tag)
        """
        # Generate random nonce (IV)
        nonce = os.urandom(12)  # 96 bits is recommended for GCM
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt and get authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        return ciphertext, nonce, tag
    
    @staticmethod
    def decrypt_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-GCM mode with authentication verification.
        
        Args:
            ciphertext: Encrypted data
            key: AES key used for encryption
            nonce: Nonce (IV) used during encryption
            tag: Authentication tag
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If authentication fails
        """
        # Create cipher for decryption
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt and verify
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext
    
    @staticmethod
    def encrypt_cbc(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-CBC mode.
        
        Args:
            plaintext: Data to encrypt
            key: AES key (should be 16, 24, or 32 bytes)
            
        Returns:
            Tuple of (ciphertext, iv)
        """
        # Generate random IV
        iv = os.urandom(16)  # 128 bits for CBC
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the plaintext to a multiple of the block size
        padded_plaintext = pad(plaintext, AES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_plaintext)
        
        return ciphertext, iv
    
    @staticmethod
    def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt data using AES-CBC mode.
        
        Args:
            ciphertext: Encrypted data
            key: AES key used for encryption
            iv: Initialization vector used during encryption
            
        Returns:
            Decrypted plaintext
        """
        # Create cipher for decryption
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        return plaintext
    
    @staticmethod
    def encrypt_packet(packet_data: bytes, key: bytes, use_gcm: bool = True) -> bytes:
        """
        Encrypt a data packet for the VPN tunnel.
        
        Args:
            packet_data: Raw packet data
            key: AES key
            use_gcm: Use GCM mode for authentication if True, otherwise use CBC
            
        Returns:
            Formatted encrypted packet with metadata
        """
        if use_gcm:
            ciphertext, nonce, tag = AESCipher.encrypt_gcm(packet_data, key)
            # Format: [mode_byte (1)] [nonce_len (1)] [nonce] [tag_len (1)] [tag] [ciphertext]
            packet = b'\x01' + bytes([len(nonce)]) + nonce + bytes([len(tag)]) + tag + ciphertext
        else:
            ciphertext, iv = AESCipher.encrypt_cbc(packet_data, key)
            # Format: [mode_byte (1)] [iv_len (1)] [iv] [ciphertext]
            packet = b'\x00' + bytes([len(iv)]) + iv + ciphertext
            
        return packet
    
    @staticmethod
    def decrypt_packet(encrypted_packet: bytes, key: bytes) -> bytes:
        """
        Decrypt a data packet from the VPN tunnel.
        
        Args:
            encrypted_packet: Formatted encrypted packet
            key: AES key
            
        Returns:
            Decrypted packet data
            
        Raises:
            ValueError: If packet format is invalid or authentication fails
        """
        # Extract mode
        if not encrypted_packet:
            raise ValueError("Empty packet")
            
        mode = encrypted_packet[0]
        
        if mode == 0x01:  # GCM mode
            # Extract nonce
            nonce_len = encrypted_packet[1]
            nonce = encrypted_packet[2:2+nonce_len]
            
            # Extract tag
            tag_pos = 2 + nonce_len
            tag_len = encrypted_packet[tag_pos]
            tag = encrypted_packet[tag_pos+1:tag_pos+1+tag_len]
            
            # Extract ciphertext
            ciphertext = encrypted_packet[tag_pos+1+tag_len:]
            
            # Decrypt
            return AESCipher.decrypt_gcm(ciphertext, key, nonce, tag)
        
        elif mode == 0x00:  # CBC mode
            # Extract IV
            iv_len = encrypted_packet[1]
            iv = encrypted_packet[2:2+iv_len]
            
            # Extract ciphertext
            ciphertext = encrypted_packet[2+iv_len:]
            
            # Decrypt
            return AESCipher.decrypt_cbc(ciphertext, key, iv)
        
        else:
            raise ValueError(f"Unknown encryption mode: {mode}")


# Example usage
if __name__ == "__main__":
    # Generate an AES key
    key = AESCipher.generate_key()
    print(f"AES Key: {base64.b64encode(key).decode()}")
    
    # Example data
    data = b"This is a sample packet to be encrypted for the VPN tunnel"
    
    # Encrypt using GCM
    encrypted_packet = AESCipher.encrypt_packet(data, key, use_gcm=True)
    print(f"Encrypted packet size: {len(encrypted_packet)} bytes")
    
    # Decrypt
    decrypted_data = AESCipher.decrypt_packet(encrypted_packet, key)
    print(f"Decrypted data: {decrypted_data.decode()}")
    
    # Verify
    print(f"Data intact: {data == decrypted_data}")
    
    # Derive key from shared secret
    shared_secret = os.urandom(32)  # Simulate Kyber output
    derived_key, salt = AESCipher.derive_key_from_shared_secret(shared_secret)
    print(f"Derived key: {base64.b64encode(derived_key).decode()}")
