# QuVPN Installation and Usage Guide

This document provides detailed instructions for installing and using QuVPN outside of the Replit environment. For a more comprehensive understanding of the system architecture and implementation details, please refer to the thesis document.

## System Requirements

### Server Requirements
- **Operating System**: Linux (Ubuntu 20.04+ or Debian 11+ recommended)
- **CPU**: 2+ cores (4+ recommended for multiple concurrent users)
- **RAM**: 2GB minimum (4GB+ recommended)
- **Storage**: 1GB free space for installation
- **Network**: Public IP address or proper port forwarding
- **Software**: Python 3.8+, PostgreSQL 12+

### Client Requirements
- **Operating System**: Windows 10/11 or Linux (any modern distribution)
- **CPU**: 1+ cores
- **RAM**: 1GB minimum
- **Storage**: 500MB free space
- **Software**: Python 3.8+
- **Privileges**: Administrator (Windows) or root (Linux) for TUN/TAP interface creation

## Server Installation

1. **Update your system and install prerequisites**:

   ```bash
   sudo apt update
   sudo apt upgrade -y
   sudo apt install -y python3 python3-pip python3-venv postgresql postgresql-contrib build-essential libffi-dev
   ```

2. **Create a virtual environment**:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/QuVPN.git
   cd QuVPN
   ```

4. **Install dependencies**:

   ```bash
   pip install -r github-requirements.txt
   ```

5. **Configure PostgreSQL**:

   ```bash
   sudo -u postgres psql
   ```

   In the PostgreSQL prompt:
   ```sql
   CREATE DATABASE vpn_database;
   CREATE USER vpn_user WITH ENCRYPTED PASSWORD 'your_secure_password';
   GRANT ALL PRIVILEGES ON DATABASE vpn_database TO vpn_user;
   \q
   ```

6. **Set environment variables**:

   Create a `.env` file in the project root:
   ```
   DATABASE_URL=postgresql://vpn_user:your_secure_password@localhost/vpn_database
   FLASK_SECRET_KEY=generate_a_secure_random_string_here
   ```

   Then load it:
   ```bash
   export $(cat .env | xargs)
   ```

7. **Initialize the database**:

   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

8. **Create an admin user**:

   ```bash
   python -c "from app import app, db; from models import User; app.app_context().push(); admin = User(username='admin', email='admin@example.com', is_admin=True); admin.set_password('secure_password'); db.session.add(admin); db.session.commit()"
   ```

9. **Configure firewall**:

   ```bash
   sudo ufw allow 5000/tcp  # Web interface
   sudo ufw allow 8080/tcp  # VPN server (TCP)
   sudo ufw allow 8080/udp  # VPN server (UDP)
   ```

10. **Set up IP forwarding** (enable the server to route traffic):

    ```bash
    sudo sh -c "echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf"
    sudo sysctl -p
    ```

11. **Create a systemd service for automatic startup**:

    Create a file at `/etc/systemd/system/quvpn.service`:
    ```
    [Unit]
    Description=QuVPN Server
    After=network.target postgresql.service

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/path/to/QuVPN
    EnvironmentFile=/path/to/QuVPN/.env
    ExecStart=/path/to/QuVPN/venv/bin/python main.py server --port 8080
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
    ```

    Create another file at `/etc/systemd/system/quvpn-web.service`:
    ```
    [Unit]
    Description=QuVPN Web Interface
    After=network.target postgresql.service

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/path/to/QuVPN
    EnvironmentFile=/path/to/QuVPN/.env
    ExecStart=/path/to/QuVPN/venv/bin/gunicorn --bind 0.0.0.0:5000 main:app
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
    ```

    Enable and start the services:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable quvpn.service quvpn-web.service
    sudo systemctl start quvpn.service quvpn-web.service
    ```

## Client Installation

### Linux Client

1. **Install prerequisites**:

   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv build-essential libffi-dev
   ```

2. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/QuVPN.git
   cd QuVPN
   ```

3. **Create a virtual environment**:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install dependencies**:

   ```bash
   pip install -r github-requirements.txt
   ```

5. **Run the client**:

   ```bash
   sudo ./venv/bin/python main.py client --server your.vpn.server.address --port 8080
   ```

### Windows Client

1. **Install Python**:
   Download and install Python 3.8 or higher from the [official website](https://www.python.org/downloads/windows/).
   Make sure to check "Add Python to PATH" during installation.

2. **Install Git**:
   Download and install Git from the [official website](https://git-scm.com/download/win).

3. **Clone the repository**:
   Open Command Prompt as Administrator and run:
   ```
   git clone https://github.com/yourusername/QuVPN.git
   cd QuVPN
   ```

4. **Create a virtual environment**:
   ```
   python -m venv venv
   venv\Scripts\activate
   ```

5. **Install dependencies**:
   ```
   pip install -r github-requirements.txt
   ```

6. **Install TAP Windows Adapter** (required for TUN/TAP interface):
   Download and install the TAP Windows adapter from the [OpenVPN website](https://openvpn.net/community-downloads/).

7. **Run the client**:
   ```
   python main.py client --server your.vpn.server.address --port 8080
   ```

## Web Interface Usage

The web interface provides a comprehensive management dashboard for the VPN system. Here's how to use it:

1. **Access the dashboard**:
   Open a web browser and navigate to `http://your.server.address:5000`

2. **Register a new account**:
   Click "Register" and create a user account.

3. **Log in to your account**:
   Enter your credentials and log in.

4. **Dashboard Overview**:
   The dashboard provides information about:
   - Connection status
   - Traffic statistics
   - Active sessions
   - Server performance

5. **Create VPN Connection Profile**:
   - Click "New Connection"
   - Enter a profile name
   - Select protocol (TCP/UDP)
   - Configure advanced settings if needed
   - Save the profile

6. **Connect using the client**:
   Use the client software with your account credentials to connect to the VPN.

## Administration

Admin users have additional capabilities:

1. **Access the admin panel**:
   Click "Admin" in the navigation menu (only visible to admin users).

2. **User Management**:
   - View all users
   - Edit user details
   - Enable/disable user accounts
   - Promote users to admin

3. **Server Management**:
   - Monitor server status
   - View active connections
   - Disconnect users
   - Update server settings

4. **System Logs**:
   - View connection logs
   - View error logs
   - Export logs for analysis

## Troubleshooting

### Common Server Issues

1. **Database Connection Failed**:
   - Verify PostgreSQL is running: `sudo systemctl status postgresql`
   - Check credentials in `.env` file
   - Ensure database user has proper permissions

2. **Permission Denied for TUN Interface**:
   - Ensure the server is running as root
   - Verify TUN/TAP module is loaded: `lsmod | grep tun`
   - If missing, load it: `sudo modprobe tun`

3. **Web Interface Not Accessible**:
   - Check if gunicorn is running: `sudo systemctl status quvpn-web.service`
   - Verify firewall allows port 5000: `sudo ufw status`
   - Check for binding errors in logs: `journalctl -u quvpn-web.service`

### Common Client Issues

1. **Connection Timeout**:
   - Verify server address and port
   - Check if server is running and accessible
   - Test with `telnet server_address 8080`

2. **TUN/TAP Interface Creation Failed**:
   - Ensure client is running with admin/root privileges
   - On Windows, verify TAP adapter is installed properly
   - On Linux, check if TUN module is loaded: `lsmod | grep tun`

3. **Authentication Failed**:
   - Verify username and password
   - Check if account is active in web interface
   - Verify the server logs for authentication errors

## Security Considerations

1. **Server Hardening**:
   - Use a dedicated server for the VPN
   - Keep the system updated
   - Use strong passwords
   - Consider adding a firewall with restrictive rules
   - Enable automatic security updates

2. **Key Management**:
   - Regularly update the FLASK_SECRET_KEY
   - Consider using a hardware security module for production
   - Implement key rotation for long-term keys

3. **Network Security**:
   - Place the server in a DMZ if available
   - Monitor for suspicious connection patterns
   - Implement rate limiting for authentication attempts

4. **Regulatory Compliance**:
   - Be aware of data retention requirements in your jurisdiction
   - Consider privacy implications of VPN traffic logging
   - Implement appropriate data protection measures

## Maintenance

1. **Regular Updates**:
   ```bash
   cd /path/to/QuVPN
   git pull
   source venv/bin/activate
   pip install -r github-requirements.txt
   sudo systemctl restart quvpn.service quvpn-web.service
   ```

2. **Database Backup**:
   ```bash
   sudo -u postgres pg_dump vpn_database > vpn_backup_$(date +%Y%m%d).sql
   ```

3. **Log Rotation**:
   Configure logrotate to manage your application logs:
   ```
   /path/to/QuVPN/logs/*.log {
       daily
       missingok
       rotate 14
       compress
       delaycompress
       notifempty
       create 0640 root root
   }
   ```

## Next Steps

After installation, consider exploring these advanced features:

1. **Integration with external authentication systems** (LDAP, OAuth)
2. **Setting up redundant VPN servers** for high availability
3. **Implementing traffic shaping** for bandwidth management
4. **Adding custom security plugins** for enhanced protection
5. **Setting up monitoring and alerting** for server health