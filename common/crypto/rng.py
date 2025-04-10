"""
Random Number Generation module for the VPN cryptography.
Provides an abstraction over random number sources to enable future QRNG integration.
"""
import os
import secrets
from typing import Optional, List, Union
import enum
import logging

logger = logging.getLogger(__name__)


class RNGSource(enum.Enum):
    """Enumeration of available random number sources"""
    SYSTEM_PRNG = 0  # Default OS randomness source
    QUANTUM_RNG = 1  # Reserved for future QRNG hardware


class RandomGenerator:
    """
    Random Number Generator class that abstracts different sources.
    Currently using PRNG, with hooks for future QRNG integration.
    """

    _instance = None  # Singleton instance
    _source = RNGSource.SYSTEM_PRNG  # Default source
    _qrng_driver = None  # Reserved for future QRNG device driver

    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super(RandomGenerator, cls).__new__(cls)
        return cls._instance

    @classmethod
    def get_source(cls) -> RNGSource:
        """Get the current random number source"""
        return cls._source

    @classmethod
    def set_source(cls, source: RNGSource, driver_config: Optional[dict] = None) -> bool:
        """
        Set the random number source to use
        
        Args:
            source: The source type to use
            driver_config: Optional configuration for hardware sources
            
        Returns:
            True if successful, False otherwise
        """
        if source == RNGSource.SYSTEM_PRNG:
            cls._source = source
            return True
            
        elif source == RNGSource.QUANTUM_RNG:
            # Here we would initialize QRNG hardware if available
            # For now, log a warning and fall back to PRNG
            logger.warning("QRNG requested but hardware not available. Using PRNG instead.")
            cls._source = RNGSource.SYSTEM_PRNG
            return False
            
        return False

    @classmethod
    def generate_bytes(cls, length: int) -> bytes:
        """
        Generate random bytes
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes
        """
        if cls._source == RNGSource.SYSTEM_PRNG:
            return os.urandom(length)
        elif cls._source == RNGSource.QUANTUM_RNG and cls._qrng_driver:
            # In the future, call QRNG hardware driver here
            # For now, fall back to PRNG
            logger.debug("Using PRNG as fallback for QRNG (not yet implemented)")
            return os.urandom(length)
        
        # Default fallback
        return os.urandom(length)

    @classmethod
    def generate_int(cls, min_value: int, max_value: int) -> int:
        """
        Generate a random integer in range [min_value, max_value]
        
        Args:
            min_value: Minimum value (inclusive)
            max_value: Maximum value (inclusive)
            
        Returns:
            Random integer
        """
        if cls._source == RNGSource.SYSTEM_PRNG:
            return secrets.randbelow(max_value - min_value + 1) + min_value
        elif cls._source == RNGSource.QUANTUM_RNG and cls._qrng_driver:
            # In the future, call QRNG hardware driver here
            # For now, fall back to PRNG
            return secrets.randbelow(max_value - min_value + 1) + min_value
        
        # Default fallback
        return secrets.randbelow(max_value - min_value + 1) + min_value

    @classmethod
    def generate_token(cls, length: int = 32) -> str:
        """
        Generate a secure random token
        
        Args:
            length: Token length in bytes
            
        Returns:
            Hex-encoded token string
        """
        if cls._source == RNGSource.SYSTEM_PRNG:
            return secrets.token_hex(length)
        elif cls._source == RNGSource.QUANTUM_RNG and cls._qrng_driver:
            # In the future, format bytes from QRNG as hex
            # For now, fall back to PRNG
            return secrets.token_hex(length)
        
        # Default fallback
        return secrets.token_hex(length)


# Global instance for easy access
RNG = RandomGenerator()


# Example usage
if __name__ == "__main__":
    print(f"Current RNG source: {RNG.get_source().name}")
    print(f"Random bytes: {RNG.generate_bytes(16).hex()}")
    print(f"Random integer (1-100): {RNG.generate_int(1, 100)}")
    print(f"Random token: {RNG.generate_token(16)}")