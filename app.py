"""
Flask app initialization for the Post-Quantum VPN Web Interface.
This file is used as an entry point for the application.
"""
import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Initialize database
db = SQLAlchemy(model_class=Base)

# Initialize login manager
login_manager = LoginManager()
login_manager.login_view = 'login'

# Create the Flask application with the correct template and static folders
app = Flask(__name__, 
           static_folder='server/web/static',
           template_folder='server/web/templates')

# Configure the application
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())

# Use PostgreSQL database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with extensions
db.init_app(app)
login_manager.init_app(app)

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Import routes after app initialization to avoid circular imports
from routes import *

# Create database tables
with app.app_context():
    db.create_all()
    logger.info("Database tables created")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)