#!/usr/bin/env python3
"""
Main entry point for Post-Quantum VPN system.
Provides command-line interfaces for server, client, and web interface.
"""
from app import app

# This will be imported by gunicorn
# The app variable is required for gunicorn to work

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)