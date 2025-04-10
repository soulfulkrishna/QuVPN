"""
Route definitions for the Post-Quantum VPN Web Interface.
Includes user authentication, dashboard, and administration routes.
"""
import os
import json
import logging
from datetime import datetime, timedelta
import secrets
from functools import wraps

from flask import render_template, redirect, url_for, flash, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError

from app import app, db
from models import User, UserSession, VPNClient

# Set up logging
logger = logging.getLogger(__name__)

# Add current year to all templates via context processor
@app.context_processor
def inject_current_year():
    return dict(current_year=datetime.now().year)

# Helper function to generate tokens
def generate_token():
    """Generate a secure random token for session management"""
    return secrets.token_hex(32)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check if user is admin
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin privileges required to access this page.', 'danger')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    """Main landing page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        
        # Find user by username
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # User authentication successful
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            
            # Update last login time
            user.last_login = datetime.utcnow()
            
            # Create user session
            token = generate_token()
            expires_at = datetime.utcnow() + timedelta(days=30 if remember else 1)
            
            user_session = UserSession(
                user_id=user.id,
                token=token,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                expires_at=expires_at
            )
            
            try:
                db.session.add(user_session)
                db.session.commit()
                session['token'] = token
                
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
                
            except SQLAlchemyError as e:
                db.session.rollback()
                logger.error(f"Database error during login: {str(e)}")
                flash('An error occurred during login. Please try again.', 'danger')
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout route"""
    if 'token' in session:
        # Invalidate the session token
        user_session = UserSession.query.filter_by(token=session['token']).first()
        if user_session:
            user_session.is_active = False
            try:
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
    
    # Clear the session
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    # Check if registration is allowed
    # You can add a config check here to disable registration
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        # Validate form inputs
        if not username or not email or not password or not password_confirm:
            flash('All fields are required', 'danger')
            return render_template('register.html')
            
        if password != password_confirm:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
            
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return render_template('register.html')
            
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html')
            
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        # First user is an admin
        if User.query.count() == 0:
            user.is_admin = True
            
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during registration: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page"""
    # Get the current user
    user = User.query.get(session['user_id'])
    
    if not user:
        session.clear()
        flash('User not found', 'danger')
        return redirect(url_for('login'))
    
    # Get server status and statistics
    # For now, we'll use a placeholder, but this would be replaced
    # with actual calls to the VPN server's status API
    server_status = {
        'running': True,
        'bind_address': '0.0.0.0',
        'bind_port': 8000,
        'protocol': 'TCP',
        'uptime': 3600,  # 1 hour in seconds
        'client_count': 2,
        'bytes_in': 1024 * 1024 * 10,  # 10 MB
        'bytes_out': 1024 * 1024 * 5,  # 5 MB
        'packets_in': 10000,
        'packets_out': 8000,
        'timestamp': datetime.utcnow().timestamp(),
        'clients': [
            {
                'username': 'alice',
                'address': '192.168.1.100:52341',
                'ip': '10.0.0.2',
                'connected_time': (datetime.utcnow() - timedelta(minutes=30)).timestamp(),
                'authenticated': True
            },
            {
                'username': 'bob',
                'address': '192.168.1.101:45211',
                'ip': '10.0.0.3',
                'connected_time': (datetime.utcnow() - timedelta(minutes=15)).timestamp(),
                'authenticated': True
            }
        ]
    }
    
    # Get configuration
    # This would also come from the VPN server's configuration
    config = {
        'server': {
            'bind_address': '0.0.0.0',
            'bind_port': 8000,
            'protocol': 'tcp',
            'max_clients': 10
        },
        'networking': {
            'subnet': '10.0.0.0/24',
            'mtu': 1400,
            'dns_servers': ['8.8.8.8', '8.8.4.4'],
            'keepalive_interval': 30
        }
    }
    
    return render_template(
        'dashboard.html',
        user=user,
        server_status=server_status,
        config=config
    )

# API Endpoints
@app.route('/api/users')
@admin_required
def api_list_users():
    """API endpoint to list all users"""
    users = User.query.all()
    user_list = []
    
    for user in users:
        user_list.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'is_active': user.is_active,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else None,
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
        })
    
    return jsonify(user_list)

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def api_user_management(user_id):
    """API endpoint for user management"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get user details
    if request.method == 'GET':
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'is_active': user.is_active,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else None,
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
        })
    
    # Update user
    elif request.method == 'PUT':
        data = request.json
        
        # Update fields
        if 'email' in data:
            user.email = data['email']
        
        if 'is_admin' in data:
            user.is_admin = bool(data['is_admin'])
        
        if 'is_active' in data:
            user.is_active = bool(data['is_active'])
        
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        try:
            db.session.commit()
            return jsonify({'success': True})
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during user update: {str(e)}")
            return jsonify({'error': 'Database error'}), 500
    
    # Delete user
    elif request.method == 'DELETE':
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'success': True})
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during user deletion: {str(e)}")
            return jsonify({'error': 'Database error'}), 500
    
    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/profile', methods=['GET', 'PUT'])
@login_required
def api_profile():
    """API endpoint for user profile management"""
    user = User.query.get(session['user_id'])
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get profile
    if request.method == 'GET':
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else None,
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
        })
    
    # Update profile
    elif request.method == 'PUT':
        data = request.json
        
        # Update email
        if 'email' in data:
            # Check if email is already in use
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({'error': 'Email already in use'}), 400
            user.email = data['email']
        
        # Update password
        if 'password' in data and 'current_password' in data:
            if not user.check_password(data['current_password']):
                return jsonify({'error': 'Current password is incorrect'}), 401
            user.set_password(data['password'])
        
        try:
            db.session.commit()
            return jsonify({'success': True})
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during profile update: {str(e)}")
            return jsonify({'error': 'Database error'}), 500
    
    return jsonify({'error': 'Invalid request'}), 400

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return render_template('error.html', error_code=500, error_message='Internal server error'), 500

# Jinja custom filters can be added here if needed