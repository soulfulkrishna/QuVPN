"""
Web interface for the VPN server.
Provides a user-friendly interface for user management and monitoring.
"""
import os
import sys
import time
import logging
import json
import ipaddress
import threading
from typing import Optional, Dict, Any, List

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

# Import VPN server components
from server.server import VPNServer
from server.auth.user_manager import UserManager
from common.utils.config import ConfigManager
from common.utils.logging_setup import setup_logging

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())

# Global instance of VPN server
vpn_server = None
config_manager = None
user_manager = None

# Set up logging
logger = setup_logging(
    app_name="web_interface",
    log_level="INFO",
    log_file="vpn_web.log"
)


def initialize_web_app(server_instance: Optional[VPNServer] = None,
                      config_path: Optional[str] = None) -> None:
    """
    Initialize the web application with VPN server instance and configuration
    
    Args:
        server_instance: Optional existing VPN server instance
        config_path: Path to the configuration file
    """
    global vpn_server, config_manager, user_manager
    
    # Initialize configuration
    config_manager = ConfigManager(config_path)
    
    # Initialize user manager
    user_db_path = config_manager.get("server.user_db_path", "users.db")
    user_manager = UserManager(user_db_path)
    
    # Use existing server instance or create a new one
    if server_instance:
        vpn_server = server_instance
    else:
        vpn_server = VPNServer(config_manager.config_path)
        # Initialize tunnel behavior
        vpn_server._update_tunnel_server()


@app.before_request
def check_auth():
    """Ensure user is authenticated for protected routes"""
    public_routes = ['login', 'static', 'register']
    if request.endpoint not in public_routes and 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))


@app.route('/')
def index():
    """Main dashboard page"""
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
            
        user = user_manager.authenticate_user(username, password)
        
        if user:
            # Set session data
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            # Create a session token
            token = user_manager.create_session(
                user_id=user['id'],
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            if token:
                session['token'] = token
                
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Log out the current user"""
    if 'token' in session:
        user_manager.invalidate_session(session['token'])
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    # Check if registration is enabled in config
    if not config_manager.get('server.allow_registration', False):
        if 'is_admin' not in session or not session['is_admin']:
            flash('Registration is currently disabled', 'danger')
            return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        email = request.form.get('email')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('register.html')
            
        if password != password_confirm:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
            
        # Check if username already exists
        existing_user = user_manager.get_user_by_username(username)
        if existing_user:
            flash('Username already exists', 'danger')
            return render_template('register.html')
            
        # Create the user
        user_id = user_manager.create_user(
            username=username,
            password=password,
            email=email
        )
        
        if user_id:
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Failed to create user', 'danger')
    
    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    """Main dashboard"""
    server_status = vpn_server.get_status() if vpn_server else {}
    
    # Get user info if logged in
    user = None
    if 'user_id' in session:
        user = user_manager.get_user_by_id(session['user_id'])
    
    return render_template(
        'dashboard.html',
        server_status=server_status,
        user=user,
        config=config_manager.config
    )


@app.route('/api/server/status')
def server_status():
    """API endpoint to get server status"""
    if not vpn_server:
        return jsonify({'error': 'Server not initialized'}), 500
        
    return jsonify(vpn_server.get_status())


@app.route('/api/server/control', methods=['POST'])
def server_control():
    """API endpoint to control the server"""
    if 'is_admin' not in session or not session['is_admin']:
        return jsonify({'error': 'Admin privileges required'}), 403
        
    if not vpn_server:
        return jsonify({'error': 'Server not initialized'}), 500
        
    action = request.json.get('action')
    
    if action == 'start':
        success = vpn_server.start()
        return jsonify({'success': success})
        
    elif action == 'stop':
        vpn_server.stop()
        return jsonify({'success': True})
        
    elif action == 'restart':
        success = vpn_server.restart()
        return jsonify({'success': success})
        
    return jsonify({'error': 'Invalid action'}), 400


@app.route('/api/users')
def list_users():
    """API endpoint to list users"""
    if 'is_admin' not in session or not session['is_admin']:
        return jsonify({'error': 'Admin privileges required'}), 403
        
    users = user_manager.list_users(active_only=False)
    return jsonify(users)


@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
def user_management(user_id):
    """API endpoint to manage users"""
    if 'is_admin' not in session or not session['is_admin']:
        return jsonify({'error': 'Admin privileges required'}), 403
        
    # Get user
    if request.method == 'GET':
        user = user_manager.get_user_by_id(user_id)
        if user:
            return jsonify(user)
        else:
            return jsonify({'error': 'User not found'}), 404
            
    # Update user
    elif request.method == 'PUT':
        data = request.json
        success = user_manager.update_user(user_id, data)
        return jsonify({'success': success})
        
    # Delete user
    elif request.method == 'DELETE':
        success = user_manager.delete_user(user_id)
        return jsonify({'success': success})
        
    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/clients')
def list_clients():
    """API endpoint to list connected clients"""
    if not vpn_server:
        return jsonify({'error': 'Server not initialized'}), 500
        
    status = vpn_server.get_status()
    return jsonify(status.get('clients', []))


@app.route('/api/clients/<string:client_addr>', methods=['POST'])
def client_management(client_addr):
    """API endpoint to manage connected clients"""
    if 'is_admin' not in session or not session['is_admin']:
        return jsonify({'error': 'Admin privileges required'}), 403
        
    if not vpn_server:
        return jsonify({'error': 'Server not initialized'}), 500
        
    action = request.json.get('action')
    
    # Parse client address (host:port format)
    try:
        host, port = client_addr.split(':')
        client_addr_tuple = (host, int(port))
    except:
        return jsonify({'error': 'Invalid client address format'}), 400
        
    # Disconnect client
    if action == 'disconnect':
        vpn_server.disconnect_client(client_addr_tuple)
        return jsonify({'success': True})
        
    # Set internet access
    elif action == 'set_internet_access':
        allowed = request.json.get('allowed', True)
        vpn_server.set_client_internet_access(client_addr_tuple, allowed)
        return jsonify({'success': True})
        
    return jsonify({'error': 'Invalid action'}), 400


@app.route('/api/config', methods=['GET', 'PUT'])
def manage_config():
    """API endpoint to get or update configuration"""
    if 'is_admin' not in session or not session['is_admin']:
        return jsonify({'error': 'Admin privileges required'}), 403
        
    # Get configuration
    if request.method == 'GET':
        return jsonify(config_manager.config)
        
    # Update configuration
    elif request.method == 'PUT':
        config_update = request.json
        config_manager.update(config_update)
        success = config_manager.save()
        return jsonify({'success': success})
        
    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/broadcast', methods=['POST'])
def broadcast_message():
    """API endpoint to broadcast a message to all clients"""
    if 'is_admin' not in session or not session['is_admin']:
        return jsonify({'error': 'Admin privileges required'}), 403
        
    if not vpn_server:
        return jsonify({'error': 'Server not initialized'}), 500
        
    message = request.json.get('message')
    if not message:
        return jsonify({'error': 'Message is required'}), 400
        
    vpn_server.broadcast_message(message)
    return jsonify({'success': True})


def start_web_server(host: str = '0.0.0.0', port: int = 5000, 
                    server_instance: Optional[VPNServer] = None,
                    config_path: Optional[str] = None) -> None:
    """
    Start the web server
    
    Args:
        host: Host to bind to
        port: Port to bind to
        server_instance: Optional existing VPN server instance
        config_path: Path to the configuration file
    """
    # Initialize web app with server instance and configuration
    initialize_web_app(server_instance, config_path)
    
    # Start Flask application
    app.run(host=host, port=port, debug=True)


# Main entry point
if __name__ == '__main__':
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='VPN Web Interface')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--config', help='Path to configuration file')
    args = parser.parse_args()
    
    # Start web server
    start_web_server(args.host, args.port, config_path=args.config)
