"""
Configuration management for the VPN system.
Handles reading, writing, and validating configuration from JSON files.
"""
import os
import json
import shutil
import logging
from typing import Dict, Any, Optional, List, Union


class ConfigManager:
    """
    Configuration manager for VPN settings
    """
    DEFAULT_CONFIG_PATH = "config.json"
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager
        
        Args:
            config_path: Path to the configuration file (None for default)
        """
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.config = {}
        self.logger = logging.getLogger("config")
        
        # Load existing config or create default
        self.load()
    
    def load(self) -> bool:
        """
        Load configuration from file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                    self.logger.info(f"Configuration loaded from {self.config_path}")
                    return True
            else:
                self.logger.warning(f"Configuration file {self.config_path} not found, creating default")
                self.config = self._create_default_config()
                self.save()
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self.config = self._create_default_config()
            return False
    
    def save(self) -> bool:
        """
        Save configuration to file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create backup if file exists
            if os.path.exists(self.config_path):
                backup_path = f"{self.config_path}.bak"
                shutil.copy2(self.config_path, backup_path)
                self.logger.debug(f"Created backup of configuration at {backup_path}")
            
            # Save configuration
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
                
            self.logger.info(f"Configuration saved to {self.config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            return False
    
    def _create_default_config(self) -> Dict[str, Any]:
        """
        Create default configuration
        
        Returns:
            Default configuration dictionary
        """
        return {
            "version": "1.0.0",
            "client": {
                "server_address": "127.0.0.1",
                "server_port": 8000,
                "protocol": "tcp",
                "autostart": False,
                "reconnect_attempts": 3,
                "reconnect_delay": 5,
                "log_level": "INFO",
                "log_file": "vpn_client.log",
                "ui": {
                    "theme": "dark",
                    "show_notifications": True,
                    "minimize_to_tray": True
                }
            },
            "server": {
                "bind_address": "0.0.0.0",
                "bind_port": 8000,
                "protocol": "tcp",
                "max_clients": 10,
                "log_level": "INFO",
                "log_file": "vpn_server.log",
                "user_db_path": "users.db",
                "certificate": {
                    "cert_file": "certs/cert.pem",
                    "key_file": "certs/key.pem",
                    "generate_if_missing": True
                }
            },
            "networking": {
                "mtu": 1400,
                "dns_servers": ["8.8.8.8", "8.8.4.4"],
                "subnet": "10.0.0.0/24",
                "keepalive_interval": 30,
                "reconnect_timeout": 60
            },
            "security": {
                "cipher": "AES-256-GCM",
                "use_kyber": True,
                "use_dilithium": True,
                "packet_signing": True,
                "forward_secrecy": True,
                "connection_timeout": 300
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value
        
        Args:
            key: Configuration key (dot notation for nested keys)
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value
        
        Args:
            key: Configuration key (dot notation for nested keys)
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to the nested dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        # Set the value
        config[keys[-1]] = value
    
    def update(self, config_dict: Dict[str, Any]) -> None:
        """
        Update multiple configuration values
        
        Args:
            config_dict: Dictionary of configuration values to update
        """
        self._recursive_update(self.config, config_dict)
    
    def _recursive_update(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """
        Recursively update nested dictionaries
        
        Args:
            target: Target dictionary to update
            source: Source dictionary with updates
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                # Recursively update nested dictionary
                self._recursive_update(target[key], value)
            else:
                # Update or add the value
                target[key] = value
    
    def validate(self, schema: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Validate the configuration against a schema
        
        Args:
            schema: Validation schema (None for default)
            
        Returns:
            List of validation errors (empty if valid)
        """
        # Simple validation for required fields
        errors = []
        
        # Basic validation for common fields
        if not schema:
            # Check client configuration
            client = self.get('client', {})
            if not client.get('server_address'):
                errors.append("Client server_address is required")
            if not isinstance(client.get('server_port'), int):
                errors.append("Client server_port must be an integer")
                
            # Check server configuration
            server = self.get('server', {})
            if not isinstance(server.get('bind_port'), int):
                errors.append("Server bind_port must be an integer")
                
            # Check networking configuration
            networking = self.get('networking', {})
            if not isinstance(networking.get('mtu'), int):
                errors.append("Networking mtu must be an integer")
        
        return errors
    
    def export_config(self, output_path: str) -> bool:
        """
        Export configuration to a file
        
        Args:
            output_path: Path to export to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            self.logger.info(f"Configuration exported to {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export configuration: {e}")
            return False
    
    def import_config(self, input_path: str, merge: bool = False) -> bool:
        """
        Import configuration from a file
        
        Args:
            input_path: Path to import from
            merge: True to merge with existing config, False to replace
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(input_path, 'r') as f:
                imported_config = json.load(f)
                
            if merge:
                self.update(imported_config)
            else:
                self.config = imported_config
                
            self.logger.info(f"Configuration imported from {input_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to import configuration: {e}")
            return False


# Example usage
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create config manager
    config = ConfigManager("example_config.json")
    
    # Get values
    server_address = config.get("client.server_address")
    port = config.get("server.bind_port")
    
    print(f"Server address: {server_address}")
    print(f"Server port: {port}")
    
    # Set values
    config.set("client.server_address", "vpn.example.com")
    config.set("client.server_port", 443)
    
    # Save
    config.save()
    
    # Validate
    errors = config.validate()
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"- {error}")
    else:
        print("Configuration is valid")
