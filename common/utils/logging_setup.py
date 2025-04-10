"""
Logging configuration for the VPN system.
Sets up logging with file and console handlers.
"""
import os
import logging
import logging.handlers
import sys
from typing import Optional, Dict, Any


def setup_logging(
    app_name: str,
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_to_console: bool = True,
    log_format: Optional[str] = None,
    max_size: int = 10485760,  # 10 MB
    backup_count: int = 5,
    include_process_info: bool = False
) -> logging.Logger:
    """
    Configure logging for the application
    
    Args:
        app_name: Name of the application (prefix for logger)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (None for no file logging)
        log_to_console: Whether to log to console
        log_format: Custom log format (None for default)
        max_size: Maximum log file size in bytes
        backup_count: Number of backup log files
        include_process_info: Include process ID and thread name in logs
        
    Returns:
        Configured logger
    """
    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger(app_name)
    logger.setLevel(numeric_level)
    
    # Clear existing handlers to avoid duplicate logging
    logger.handlers = []
    
    # Determine log format
    if not log_format:
        if include_process_info:
            log_format = '%(asctime)s - %(name)s - [%(process)d:%(threadName)s] - %(levelname)s - %(message)s'
        else:
            log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    formatter = logging.Formatter(log_format)
    
    # Add console handler if requested
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # Add file handler if log file specified
    if log_file:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size,
                backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            logger.info(f"Logging to file: {log_file}")
        except Exception as e:
            logger.error(f"Failed to setup file logging: {e}")
    
    # Log initial message
    logger.info(f"Logging initialized for {app_name} at level {log_level}")
    
    return logger


class LogManager:
    """
    Manager for coordinating logging across components
    """
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log manager
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.loggers = {}
        
        # Configure root logger
        log_level = config.get("log_level", "INFO")
        log_file = config.get("log_file", None)
        log_to_console = config.get("log_to_console", True)
        
        self.root_logger = setup_logging(
            app_name="vpn",
            log_level=log_level,
            log_file=log_file,
            log_to_console=log_to_console,
            include_process_info=True
        )
        
        self.loggers["root"] = self.root_logger
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger by name
        
        Args:
            name: Logger name
            
        Returns:
            Logger instance
        """
        if name in self.loggers:
            return self.loggers[name]
        
        # Create a new logger as a child of the root logger
        logger = logging.getLogger(f"vpn.{name}")
        self.loggers[name] = logger
        
        return logger
    
    def set_log_level(self, level: str, logger_name: Optional[str] = None) -> None:
        """
        Set the log level for a specific logger or all loggers
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            logger_name: Logger name (None for all loggers)
        """
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        
        if logger_name and logger_name in self.loggers:
            # Set for specific logger
            self.loggers[logger_name].setLevel(numeric_level)
            self.root_logger.info(f"Set log level for {logger_name} to {level}")
        else:
            # Set for all loggers
            for name, logger in self.loggers.items():
                logger.setLevel(numeric_level)
            self.root_logger.info(f"Set log level for all loggers to {level}")
    
    def update_config(self, config: Dict[str, Any]) -> None:
        """
        Update logging configuration
        
        Args:
            config: New configuration dictionary
        """
        self.config.update(config)
        
        # Apply new configuration
        log_level = self.config.get("log_level", "INFO")
        self.set_log_level(log_level)
        
        # TODO: Add functionality to change log file dynamically if needed
        
        self.root_logger.info(f"Logging configuration updated: level={log_level}")


# Example usage
if __name__ == "__main__":
    # Setup basic logging
    logger = setup_logging("vpn_test", log_level="DEBUG", log_file="vpn_test.log")
    
    # Log some messages
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Create a log manager
    config = {
        "log_level": "INFO",
        "log_file": "vpn.log",
        "log_to_console": True
    }
    
    log_manager = LogManager(config)
    
    # Get component loggers
    tunnel_logger = log_manager.get_logger("tunnel")
    crypto_logger = log_manager.get_logger("crypto")
    
    # Log from different components
    tunnel_logger.info("Tunnel initialized")
    crypto_logger.info("Cryptography module initialized")
    
    # Change log level for a specific component
    log_manager.set_log_level("DEBUG", "tunnel")
    tunnel_logger.debug("This debug message should appear")
    crypto_logger.debug("This debug message should NOT appear")
