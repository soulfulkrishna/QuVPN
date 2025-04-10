"""
Flask app initialization for the Post-Quantum VPN Web Interface.
This file is used as an entry point for the application.
"""
import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Initialize database
db = SQLAlchemy(model_class=Base)

# Create the Flask application with the correct template and static folders
app = Flask(__name__, 
           static_folder='server/web/static',
           template_folder='server/web/templates')

# Configure the application
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///vpn.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Import routes after app initialization to avoid circular imports
from routes import *

# Create database tables
with app.app_context():
    db.create_all()
    logger.info("Database tables created")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)