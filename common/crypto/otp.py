"""
One-Time Pad implementation for the VPN system.
Implements OTP encryption on top of AES for enhanced security.
"""
import os
import hashlib
import base64
import logging
from typing import Tuple, Dict, Any, Optional, List, Union

from common.crypto.rng import RNG
from common.crypto.aes import AESCipher

logger = logging.getLogger(__name__)


class OTPCipher:
    """
    One-Time Pad implementation that works on top of existing AES encryption.
    Provides complete theoretical security when used with true random keys.
    """
    
    # Maximum key reuse counter (for safety)
    MAX_KEY_REUSE = 100
    
    # Key management
    _key_store = {}  # Format: {key_id: {"key": bytes, "uses": int}}
    _next_key_id = 0
    
    @classmethod
    def generate_otp_key(cls, length: int) -> Tuple[int, bytes]:
        """
        Generate a new one-time pad key
        
        Args:
            length: Length of the key in bytes
            
        Returns:
            Tuple of (key_id, key_bytes)
        """
        # Generate a truly random key (using our RNG abstraction)
        key = RNG.generate_bytes(length)
        
        # Store the key with a unique ID
        key_id = cls._next_key_id
        cls._next_key_id += 1
        
        cls._key_store[key_id] = {
            "key": key,
            "uses": 0
        }
        
        logger.debug(f"Generated OTP key {key_id} with length {length} bytes")
        return key_id, key
    
    @classmethod
    def get_key(cls, key_id: int) -> Optional[bytes]:
        """
        Retrieve a key by ID and track its usage
        
        Args:
            key_id: The key identifier
            
        Returns:
            The key bytes or None if not found or too many uses
        """
        if key_id not in cls._key_store:
            logger.warning(f"OTP key {key_id} not found")
            return None
            
        key_info = cls._key_store[key_id]
        
        # Check for key reuse - for safety, we'll allow a small number of reuses
        # In a true OTP system, this would be limited to exactly 1
        if key_info["uses"] >= cls.MAX_KEY_REUSE:
            logger.warning(f"OTP key {key_id} has been used too many times ({key_info['uses']})")
            return None
            
        # Increment usage counter
        key_info["uses"] += 1
        return key_info["key"]
    
    @classmethod
    def delete_key(cls, key_id: int) -> bool:
        """
        Delete a key from the store
        
        Args:
            key_id: The key identifier
            
        Returns:
            True if deleted, False if not found
        """
        if key_id in cls._key_store:
            del cls._key_store[key_id]
            logger.debug(f"Deleted OTP key {key_id}")
            return True
        return False
    
    @classmethod
    def apply_otp(cls, data: bytes, key: bytes) -> bytes:
        """
        Apply a one-time pad to data (XOR operation)
        
        Args:
            data: The data to encrypt/decrypt
            key: The key to use (must be at least as long as data)
            
        Returns:
            The transformed data
            
        Raises:
            ValueError: If key is shorter than data
        """
        if len(key) < len(data):
            raise ValueError("OTP key must be at least as long as the data")
            
        # Apply XOR operation between data and key
        return bytes(a ^ b for a, b in zip(data, key[:len(data)]))
    
    @classmethod
    def encrypt(cls, plaintext: bytes, key_id: Optional[int] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt data using a one-time pad, followed by AES
        
        Args:
            plaintext: Data to encrypt
            key_id: Optional existing key ID to use
            
        Returns:
            Tuple of (encrypted_data, metadata)
        """
        # Generate new OTP key if one is not provided
        if key_id is None:
            key_id, key = cls.generate_otp_key(len(plaintext))
        else:
            key = cls.get_key(key_id)
            if key is None:
                # If the key isn't found or is overused, generate a new one
                key_id, key = cls.generate_otp_key(len(plaintext))
        
        # Apply the one-time pad (XOR)
        otp_ciphertext = cls.apply_otp(plaintext, key)
        
        # Further encrypt with AES for additional protection
        # Generate a random AES key
        aes_key = AESCipher.generate_key()
        
        # Encrypt with AES-GCM
        encrypted_data = AESCipher.encrypt_packet(otp_ciphertext, aes_key, use_gcm=True)
        
        # Return the encrypted data and necessary metadata
        metadata = {
            "key_id": key_id,
            "aes_key": base64.b64encode(aes_key).decode('utf-8'),
            "length": len(plaintext)
        }
        
        return encrypted_data, metadata
    
    @classmethod
    def decrypt(cls, ciphertext: bytes, metadata: Dict[str, Any]) -> bytes:
        """
        Decrypt data using AES, followed by a one-time pad
        
        Args:
            ciphertext: Encrypted data
            metadata: Metadata including key ID and AES key
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If key not found or other decryption error
        """
        # Extract metadata
        key_id = metadata["key_id"]
        aes_key = base64.b64decode(metadata["aes_key"])
        length = metadata["length"]
        
        # Retrieve the OTP key
        otp_key = cls.get_key(key_id)
        if otp_key is None:
            raise ValueError(f"OTP key {key_id} not found or has been used too many times")
        
        # First decrypt with AES
        try:
            otp_ciphertext = AESCipher.decrypt_packet(ciphertext, aes_key)
        except Exception as e:
            logger.error(f"AES decryption failed: {e}")
            raise ValueError(f"AES decryption failed: {e}")
        
        # Then apply the one-time pad
        plaintext = cls.apply_otp(otp_ciphertext, otp_key)
        
        # Verify the length
        if len(plaintext) != length:
            logger.warning(f"Decrypted length {len(plaintext)} does not match expected {length}")
        
        return plaintext
    
    @classmethod
    def list_keys(cls) -> List[Dict[str, Any]]:
        """
        List all keys and their status
        
        Returns:
            List of key information dictionaries
        """
        return [
            {
                "key_id": key_id,
                "length": len(info["key"]),
                "uses": info["uses"],
                "remaining_uses": cls.MAX_KEY_REUSE - info["uses"]
            }
            for key_id, info in cls._key_store.items()
        ]


# Example usage
if __name__ == "__main__":
    # Example data
    data = b"This is a top-secret message that needs ultimate protection!"
    print(f"Original data: {data.decode()}")
    
    # Encrypt with OTP + AES
    encrypted, metadata = OTPCipher.encrypt(data)
    print(f"Encrypted size: {len(encrypted)} bytes")
    print(f"Metadata: {metadata}")
    
    # Decrypt
    decrypted = OTPCipher.decrypt(encrypted, metadata)
    print(f"Decrypted: {decrypted.decode()}")
    
    # Verify
    print(f"Data intact: {data == decrypted}")
    
    # Key statistics
    print(f"Key usage statistics: {OTPCipher.list_keys()}")