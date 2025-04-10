"""
Test program for the OTP encryption layer implemented for the VPN tunnel.
Verifies that the one-time pad encryption works properly, both alone and with AES.
"""
import os
import base64
import logging
from common.crypto.otp import OTPCipher

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('otp_test')

def test_otp_encryption():
    """
    Test one-time pad encryption and decryption
    """
    logger.info("Testing OTP encryption and decryption...")
    
    # Test data
    data_samples = [
        b"This is a short message",
        b"This is a longer message with some numbers 12345 and special characters !@#$%",
        os.urandom(1000)  # Random binary data of 1KB
    ]
    
    for i, data in enumerate(data_samples):
        logger.info(f"Test #{i+1} - Data length: {len(data)} bytes")
        if len(data) < 100:
            logger.info(f"Sample data: {data}")
        
        # Encrypt with OTP
        encrypted, metadata = OTPCipher.encrypt(data)
        
        logger.info(f"Encrypted size: {len(encrypted)} bytes")
        logger.info(f"Metadata: {metadata}")
        
        # Decrypt
        decrypted = OTPCipher.decrypt(encrypted, metadata)
        
        # Verify
        if data == decrypted:
            logger.info("✓ Decryption successful - data intact")
        else:
            logger.error("✗ Decryption failed - data corrupted")
            if len(data) < 100:
                logger.error(f"Original : {data}")
                logger.error(f"Decrypted: {decrypted}")
        
        print()

def test_key_reuse_limit():
    """
    Test the key reuse limit feature
    """
    logger.info("Testing key reuse limit...")
    
    # Create data and encrypt it
    test_data = b"Test message for key reuse"
    encrypted, metadata = OTPCipher.encrypt(test_data)
    key_id = metadata["key_id"]
    
    logger.info(f"Original key_id: {key_id}")
    
    # Try to reuse the key more times than allowed
    max_reuse = OTPCipher.MAX_KEY_REUSE
    logger.info(f"Max allowed reuses: {max_reuse}")
    
    for i in range(max_reuse + 5):
        try:
            # Get the key - this should increment the usage counter
            key = OTPCipher.get_key(key_id)
            
            if key:
                logger.info(f"Usage #{i+1}: Key access successful")
            else:
                logger.info(f"Usage #{i+1}: Key access denied (used too many times)")
                
        except Exception as e:
            logger.error(f"Error on usage #{i+1}: {e}")
    
    print()

def test_key_management():
    """
    Test key creation, listing and deletion
    """
    logger.info("Testing key management...")
    
    # List initial keys
    keys = OTPCipher.list_keys()
    logger.info(f"Initial keys: {len(keys)}")
    
    # Generate several keys of different sizes
    key_sizes = [16, 32, 64, 128, 256]
    key_ids = []
    
    for size in key_sizes:
        key_id, _ = OTPCipher.generate_otp_key(size)
        key_ids.append(key_id)
        logger.info(f"Generated key ID {key_id} with size {size} bytes")
    
    # List keys after generation
    keys = OTPCipher.list_keys()
    logger.info(f"Keys after generation: {len(keys)}")
    for key_info in keys:
        logger.info(f"  Key {key_info['key_id']}: {key_info['length']} bytes, {key_info['uses']} uses")
    
    # Delete keys
    for key_id in key_ids:
        success = OTPCipher.delete_key(key_id)
        logger.info(f"Deleted key {key_id}: {success}")
    
    # List keys after deletion
    keys = OTPCipher.list_keys()
    logger.info(f"Keys after deletion: {len(keys)}")
    
    print()

if __name__ == "__main__":
    print("-" * 60)
    print("TESTING ONE-TIME PAD IMPLEMENTATION")
    print("-" * 60)
    
    # Run tests
    test_otp_encryption()
    test_key_reuse_limit()
    test_key_management()
    
    print("All tests completed!")