"""
User authentication and management for the VPN system.
Handles user registration, authentication, and database storage.
"""
import os
import sqlite3
import hashlib
import secrets
import logging
import time
import json
from typing import Dict, Any, Optional, List, Tuple

from common.crypto.dilithium import Dilithium


class UserManager:
    """
    User authentication and management
    """
    
    def __init__(self, db_path: str = "users.db"):
        """
        Initialize the user manager
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.logger = logging.getLogger("user_manager")
        
        # Ensure the database exists
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the database schema if not already created"""
        try:
            # Ensure the directory exists
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir)
                
            # Create tables
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                created_at INTEGER NOT NULL,
                last_login INTEGER,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            )
            ''')
            
            # User profiles table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id INTEGER PRIMARY KEY,
                full_name TEXT,
                settings TEXT,
                allowed_ips TEXT,
                max_bandwidth INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            ''')
            
            # Sessions table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            ''')
            
            # Public keys table for Dilithium certificates
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS public_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_type TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                is_revoked INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            ''')
            
            # Connection logs table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS connection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                ip_address TEXT,
                connected_at INTEGER NOT NULL,
                disconnected_at INTEGER,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                assigned_ip TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            ''')
            
            conn.commit()
            conn.close()
            
            # Create admin user if no users exist
            if self.count_users() == 0:
                self.create_user(
                    username="admin",
                    password="admin123",  # Should be changed immediately
                    email="admin@example.com",
                    is_admin=True
                )
                self.logger.warning("Created default admin user (admin/admin123) - CHANGE PASSWORD IMMEDIATELY")
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password securely
        
        Args:
            password: The password to hash
            
        Returns:
            Secure hash of the password
        """
        # Generate a random salt
        salt = secrets.token_hex(16)
        
        # Hash the password with the salt
        hash_obj = hashlib.sha3_512((password + salt).encode())
        password_hash = hash_obj.hexdigest()
        
        # Return salt:hash format
        return f"{salt}:{password_hash}"
    
    def verify_password(self, stored_hash: str, password: str) -> bool:
        """
        Verify a password against a stored hash
        
        Args:
            stored_hash: The stored password hash (salt:hash)
            password: The password to verify
            
        Returns:
            True if the password matches, False otherwise
        """
        # Split the stored hash into salt and hash
        try:
            salt, hash_value = stored_hash.split(':', 1)
            
            # Hash the input password with the salt
            hash_obj = hashlib.sha3_512((password + salt).encode())
            password_hash = hash_obj.hexdigest()
            
            # Compare the hashes
            return password_hash == hash_value
        except:
            return False
    
    def create_user(self, username: str, password: str, email: Optional[str] = None,
                   is_admin: bool = False) -> Optional[int]:
        """
        Create a new user
        
        Args:
            username: Username
            password: Password
            email: Email address
            is_admin: True if the user should be an admin
            
        Returns:
            User ID if successful, None otherwise
        """
        try:
            # Check if username already exists
            if self.get_user_by_username(username) is not None:
                self.logger.warning(f"Username '{username}' already exists")
                return None
                
            # Hash the password
            password_hash = self.hash_password(password)
            
            # Insert the user
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO users (username, password_hash, email, created_at, is_admin, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, email, int(time.time()), 1 if is_admin else 0, 1))
            
            user_id = cursor.lastrowid
            
            # Create empty profile
            cursor.execute('''
            INSERT INTO user_profiles (user_id, settings)
            VALUES (?, ?)
            ''', (user_id, json.dumps({})))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Created user '{username}' with ID {user_id}")
            return user_id
            
        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user
        
        Args:
            username: Username
            password: Password
            
        Returns:
            User information if authentication successful, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch the user
            cursor.execute('''
            SELECT id, username, password_hash, email, created_at, last_login, is_admin, is_active
            FROM users
            WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            
            if not user:
                self.logger.warning(f"Authentication failed: User '{username}' not found")
                return None
                
            # Convert to dict
            user_dict = dict(user)
            
            # Check if user is active
            if not user_dict['is_active']:
                self.logger.warning(f"Authentication failed: User '{username}' is disabled")
                return None
                
            # Verify the password
            if not self.verify_password(user_dict['password_hash'], password):
                self.logger.warning(f"Authentication failed: Invalid password for user '{username}'")
                return None
                
            # Update last login time
            cursor.execute('''
            UPDATE users
            SET last_login = ?
            WHERE id = ?
            ''', (int(time.time()), user_dict['id']))
            
            conn.commit()
            
            # Fetch user profile
            cursor.execute('''
            SELECT * FROM user_profiles
            WHERE user_id = ?
            ''', (user_dict['id'],))
            
            profile = cursor.fetchone()
            
            if profile:
                profile_dict = dict(profile)
                user_dict['profile'] = profile_dict
                
                # Parse JSON settings if present
                if profile_dict.get('settings'):
                    try:
                        user_dict['settings'] = json.loads(profile_dict['settings'])
                    except:
                        user_dict['settings'] = {}
            
            conn.close()
            
            self.logger.info(f"User '{username}' authenticated successfully")
            return user_dict
            
        except Exception as e:
            self.logger.error(f"Error authenticating user: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get a user by username
        
        Args:
            username: Username
            
        Returns:
            User information if found, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, username, email, created_at, last_login, is_admin, is_active
            FROM users
            WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            
            if not user:
                return None
                
            user_dict = dict(user)
            
            # Fetch user profile
            cursor.execute('''
            SELECT * FROM user_profiles
            WHERE user_id = ?
            ''', (user_dict['id'],))
            
            profile = cursor.fetchone()
            
            if profile:
                profile_dict = dict(profile)
                user_dict['profile'] = profile_dict
                
                # Parse JSON settings if present
                if profile_dict.get('settings'):
                    try:
                        user_dict['settings'] = json.loads(profile_dict['settings'])
                    except:
                        user_dict['settings'] = {}
            
            conn.close()
            return user_dict
            
        except Exception as e:
            self.logger.error(f"Error getting user by username: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a user by ID
        
        Args:
            user_id: User ID
            
        Returns:
            User information if found, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, username, email, created_at, last_login, is_admin, is_active
            FROM users
            WHERE id = ?
            ''', (user_id,))
            
            user = cursor.fetchone()
            
            if not user:
                return None
                
            user_dict = dict(user)
            
            # Fetch user profile
            cursor.execute('''
            SELECT * FROM user_profiles
            WHERE user_id = ?
            ''', (user_dict['id'],))
            
            profile = cursor.fetchone()
            
            if profile:
                profile_dict = dict(profile)
                user_dict['profile'] = profile_dict
                
                # Parse JSON settings if present
                if profile_dict.get('settings'):
                    try:
                        user_dict['settings'] = json.loads(profile_dict['settings'])
                    except:
                        user_dict['settings'] = {}
            
            conn.close()
            return user_dict
            
        except Exception as e:
            self.logger.error(f"Error getting user by ID: {e}")
            return None
    
    def count_users(self) -> int:
        """
        Count the number of users in the database
        
        Returns:
            User count
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM users')
            count = cursor.fetchone()[0]
            
            conn.close()
            return count
            
        except Exception as e:
            self.logger.error(f"Error counting users: {e}")
            return 0
    
    def list_users(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """
        List all users
        
        Args:
            active_only: Only return active users
            
        Returns:
            List of user information
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if active_only:
                cursor.execute('''
                SELECT id, username, email, created_at, last_login, is_admin, is_active
                FROM users
                WHERE is_active = 1
                ORDER BY username
                ''')
            else:
                cursor.execute('''
                SELECT id, username, email, created_at, last_login, is_admin, is_active
                FROM users
                ORDER BY username
                ''')
            
            users = cursor.fetchall()
            users_list = [dict(user) for user in users]
            
            conn.close()
            return users_list
            
        except Exception as e:
            self.logger.error(f"Error listing users: {e}")
            return []
    
    def update_user(self, user_id: int, data: Dict[str, Any]) -> bool:
        """
        Update user information
        
        Args:
            user_id: User ID
            data: Dictionary of fields to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build update query
            update_fields = []
            params = []
            
            if 'username' in data:
                update_fields.append('username = ?')
                params.append(data['username'])
                
            if 'email' in data:
                update_fields.append('email = ?')
                params.append(data['email'])
                
            if 'password' in data:
                password_hash = self.hash_password(data['password'])
                update_fields.append('password_hash = ?')
                params.append(password_hash)
                
            if 'is_admin' in data:
                update_fields.append('is_admin = ?')
                params.append(1 if data['is_admin'] else 0)
                
            if 'is_active' in data:
                update_fields.append('is_active = ?')
                params.append(1 if data['is_active'] else 0)
                
            if not update_fields:
                return False
                
            # Add user_id to params
            params.append(user_id)
            
            # Execute update
            cursor.execute(f'''
            UPDATE users
            SET {', '.join(update_fields)}
            WHERE id = ?
            ''', params)
            
            # Update profile if provided
            if 'profile' in data:
                profile = data['profile']
                
                profile_fields = []
                profile_params = []
                
                if 'full_name' in profile:
                    profile_fields.append('full_name = ?')
                    profile_params.append(profile['full_name'])
                    
                if 'settings' in profile:
                    profile_fields.append('settings = ?')
                    profile_params.append(json.dumps(profile['settings']))
                    
                if 'allowed_ips' in profile:
                    profile_fields.append('allowed_ips = ?')
                    profile_params.append(profile['allowed_ips'])
                    
                if 'max_bandwidth' in profile:
                    profile_fields.append('max_bandwidth = ?')
                    profile_params.append(profile['max_bandwidth'])
                    
                if profile_fields:
                    # Add user_id to params
                    profile_params.append(user_id)
                    
                    # Execute update
                    cursor.execute(f'''
                    UPDATE user_profiles
                    SET {', '.join(profile_fields)}
                    WHERE user_id = ?
                    ''', profile_params)
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Updated user with ID {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating user: {e}")
            return False
    
    def delete_user(self, user_id: int) -> bool:
        """
        Delete a user
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get username for logging
            cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()
            if not result:
                self.logger.warning(f"User with ID {user_id} not found")
                return False
                
            username = result[0]
            
            # Start transaction
            conn.execute('BEGIN TRANSACTION')
            
            # Delete from all related tables
            cursor.execute('DELETE FROM public_keys WHERE user_id = ?', (user_id,))
            cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            cursor.execute('DELETE FROM user_profiles WHERE user_id = ?', (user_id,))
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Deleted user '{username}' with ID {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting user: {e}")
            return False
    
    def create_session(self, user_id: int, ip_address: Optional[str] = None, 
                      user_agent: Optional[str] = None, 
                      expires_in: int = 86400) -> Optional[str]:
        """
        Create a new session for a user
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
            expires_in: Session expiration time in seconds
            
        Returns:
            Session token if successful, None otherwise
        """
        try:
            # Generate a random token
            token = secrets.token_hex(32)
            
            # Calculate expiration time
            created_at = int(time.time())
            expires_at = created_at + expires_in
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO sessions (user_id, token, created_at, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, token, created_at, expires_at, ip_address, user_agent))
            
            conn.commit()
            conn.close()
            
            return token
            
        except Exception as e:
            self.logger.error(f"Error creating session: {e}")
            return None
    
    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a session token
        
        Args:
            token: Session token
            
        Returns:
            User information if session is valid, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get the session
            cursor.execute('''
            SELECT user_id, created_at, expires_at, ip_address
            FROM sessions
            WHERE token = ?
            ''', (token,))
            
            session = cursor.fetchone()
            
            if not session:
                return None
                
            session_dict = dict(session)
            
            # Check if session has expired
            if session_dict['expires_at'] < time.time():
                # Remove expired session
                cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
                conn.commit()
                return None
                
            # Get the user
            user_id = session_dict['user_id']
            cursor.execute('''
            SELECT id, username, email, is_admin, is_active
            FROM users
            WHERE id = ?
            ''', (user_id,))
            
            user = cursor.fetchone()
            
            if not user:
                return None
                
            user_dict = dict(user)
            
            # Check if user is still active
            if not user_dict['is_active']:
                return None
                
            # Add session information to user dict
            user_dict['session'] = session_dict
            
            conn.close()
            return user_dict
            
        except Exception as e:
            self.logger.error(f"Error validating session: {e}")
            return None
    
    def invalidate_session(self, token: str) -> bool:
        """
        Invalidate a session token
        
        Args:
            token: Session token
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error invalidating session: {e}")
            return False
    
    def log_connection(self, user_id: Optional[int], ip_address: str, assigned_ip: str) -> Optional[int]:
        """
        Log a new connection
        
        Args:
            user_id: User ID or None if anonymous
            ip_address: Client IP address
            assigned_ip: Assigned VPN IP address
            
        Returns:
            Log entry ID if successful, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO connection_logs (user_id, ip_address, connected_at, assigned_ip)
            VALUES (?, ?, ?, ?)
            ''', (user_id, ip_address, int(time.time()), assigned_ip))
            
            log_id = cursor.lastrowid
            
            conn.commit()
            conn.close()
            
            return log_id
            
        except Exception as e:
            self.logger.error(f"Error logging connection: {e}")
            return None
    
    def log_disconnection(self, log_id: int, bytes_sent: int, bytes_received: int) -> bool:
        """
        Update a connection log with disconnection information
        
        Args:
            log_id: Log entry ID
            bytes_sent: Bytes sent
            bytes_received: Bytes received
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            UPDATE connection_logs
            SET disconnected_at = ?, bytes_sent = ?, bytes_received = ?
            WHERE id = ?
            ''', (int(time.time()), bytes_sent, bytes_received, log_id))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error logging disconnection: {e}")
            return False
    
    def register_public_key(self, user_id: int, key_type: str, public_key: str, 
                           expires_in: Optional[int] = None) -> Optional[int]:
        """
        Register a public key for a user
        
        Args:
            user_id: User ID
            key_type: Key type (e.g., "dilithium")
            public_key: Public key data
            expires_in: Expiration time in seconds from now, or None for no expiration
            
        Returns:
            Key ID if successful, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            created_at = int(time.time())
            expires_at = None
            if expires_in is not None:
                expires_at = created_at + expires_in
                
            cursor.execute('''
            INSERT INTO public_keys (user_id, key_type, public_key, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ''', (user_id, key_type, public_key, created_at, expires_at))
            
            key_id = cursor.lastrowid
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Registered {key_type} public key for user {user_id}")
            return key_id
            
        except Exception as e:
            self.logger.error(f"Error registering public key: {e}")
            return None
    
    def verify_signature(self, username: str, message: bytes, signature: bytes) -> bool:
        """
        Verify a user's signature using their Dilithium public key
        
        Args:
            username: Username
            message: Message to verify
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Get the user
            user = self.get_user_by_username(username)
            if not user:
                return False
                
            # Get the user's public key
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT public_key
            FROM public_keys
            WHERE user_id = ? AND key_type = 'dilithium' AND is_revoked = 0
            ORDER BY created_at DESC
            LIMIT 1
            ''', (user['id'],))
            
            key_record = cursor.fetchone()
            
            if not key_record:
                return False
                
            # Deserialize public key
            public_key = eval(key_record['public_key'])
            
            # Verify signature
            return Dilithium.verify(message, signature, public_key)
            
        except Exception as e:
            self.logger.error(f"Error verifying signature: {e}")
            return False


# Test function
def main():
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create user manager
    user_manager = UserManager("test_users.db")
    
    # Test user creation
    user_id = user_manager.create_user("testuser", "password123", "test@example.com")
    if user_id:
        print(f"Created user with ID: {user_id}")
    
    # Test authentication
    user = user_manager.authenticate_user("testuser", "password123")
    if user:
        print(f"Authenticated user: {user['username']}")
    else:
        print("Authentication failed")
    
    # Test getting user by username
    user = user_manager.get_user_by_username("testuser")
    if user:
        print(f"Got user by username: {user['username']}")
    
    # Test listing users
    users = user_manager.list_users()
    print(f"User count: {len(users)}")


if __name__ == "__main__":
    main()
