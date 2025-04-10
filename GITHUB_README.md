# QuVPN - Post-Quantum VPN System

A Python-based custom VPN system using post-quantum cryptography with CRYSTAL-Kyber and Dilithium, supporting both Windows and Linux platforms.

![Quantum VPN](generated-icon.png)

## Features

- **Post-Quantum Cryptography Implementation:**
  - CRYSTAL-Kyber for key exchange
  - Dilithium for certificate exchange
  - AES-256-GCM for data encryption
- **Secure Tunnel Architecture:**
  - Custom HTTPS TLS-Socket tunneling mechanism
  - Robust packet fragmentation and forwarding
  - TCP and UDP protocol support
- **User Management:**
  - Authentication system
  - Role-based permission system
  - User registration and management
- **Web Administration Interface:**
  - Dashboard with real-time statistics
  - Client monitoring
  - Configuration management
- **Cross-Platform Support:**
  - Windows implementation with WinTUN adapters
  - Linux implementation with native TUN interfaces
- **Enhanced Security Features:**
  - Perfect forward secrecy
  - Firewall capabilities
  - Traffic filtering
- **Enterprise-Ready:**
  - Comprehensive logging
  - Windows service / Linux daemon support
  - Administrator privileges handling

## System Requirements

- Python 3.8 or later
- PyCryptodome for AES implementation
- Flask for web interface
- SQLAlchemy for database management
- Pywin32 for Windows platform support (Windows only)

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/soulfulkrishna/QuVPN.git
   cd QuVPN
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Initialize the database:
   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

4. Start the web interface:
   ```bash
   python main.py
   ```

## Architecture

The QuVPN system consists of three main components:

1. **VPN Server:** Manages client connections and routes traffic between VPN clients and the internet.
2. **VPN Client:** Establishes and maintains secure VPN connections to the server.
3. **Web Interface:** Provides a user-friendly UI for managing the VPN server and monitoring clients.

### Directory Structure

```
QuVPN/
├── client/               # VPN client components
│   ├── platform/         # Platform-specific implementations
│   ├── ui/               # User interface components
│   └── client.py         # Main client implementation
├── common/               # Shared components
│   ├── crypto/           # Cryptography implementations
│   ├── networking/       # Networking components
│   └── utils/            # Utility functions
├── server/               # VPN server components
│   ├── auth/             # Authentication modules
│   ├── platform/         # Platform-specific implementations
│   ├── web/              # Web interface
│   └── server.py         # Main server implementation
└── main.py               # Entry point
```

## Post-Quantum Cryptography

QuVPN uses NIST's post-quantum cryptography standardization candidates:

- **CRYSTAL-Kyber:** A lattice-based key encapsulation mechanism (KEM) that is designed to be secure against both classical and quantum computer attacks.
- **Dilithium:** A lattice-based digital signature scheme resistant to quantum attacks.

These algorithms provide protection against future quantum computing threats while maintaining good performance on current hardware.

## Usage

### Running the VPN Server

```bash
python -m main server --config config.json
```

### Running the Web Interface

```bash
python -m main web --host 0.0.0.0 --port 5000
```

### Running the VPN Client

```bash
python -m main client --config client_config.json
```

### Running the GUI Client

```bash
python -m main client --gui
```

## Security Considerations

- QuVPN is designed with security in mind but should undergo a thorough security audit before deployment in high-security environments.
- The system provides a framework for implementing post-quantum cryptography but is intended for educational and research purposes.
- Always keep the software updated to incorporate the latest security improvements.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NIST for the post-quantum cryptography standardization process
- The cryptography research community for their work on quantum-resistant algorithms