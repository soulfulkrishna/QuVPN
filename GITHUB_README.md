# QuVPN: Post-Quantum Virtual Private Network

QuVPN is a custom Python-based VPN system utilizing post-quantum cryptography with CRYSTAL-Kyber and Dilithium algorithms. It features dual-layer encryption with AES-256 and One-Time Pad (OTP) implementation.

## Features

- **Post-Quantum Security**: Uses NIST PQC finalists CRYSTAL-Kyber for key exchange and CRYSTAL-Dilithium for digital signatures
- **Dual-Layer Encryption**: AES-256 with an additional one-time pad layer for enhanced security
- **Cross-Platform Support**: Compatible with both Windows and Linux
- **Protocol Support**: Implements both TCP and UDP VPN tunneling
- **Web Interface**: Flask-based administration dashboard for user management
- **Perfect Forward Secrecy**: Ensures sessions remain secure even if long-term keys are compromised

## Repository Structure

```
.
├── client/                # Client-side implementation
│   ├── platform/          # Platform-specific code (Windows, Linux)
│   └── ui/                # User interface components
├── common/                # Shared code between client and server
│   ├── crypto/            # Cryptographic implementations
│   ├── networking/        # Networking and tunnel code
│   └── utils/             # Utility functions
├── server/                # Server-side implementation
│   ├── auth/              # Authentication services
│   ├── platform/          # Platform-specific server code
│   └── web/               # Web interface
└── docs/                  # Documentation
```

## Installation

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- Administrative privileges (required for TUN/TAP interfaces)

### Server Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/QuVPN.git
   cd QuVPN
   ```

2. Install dependencies:
   ```
   pip install -r github-requirements.txt
   ```

3. Set up the PostgreSQL database:
   ```
   createdb vpn_database
   ```

4. Configure environment variables:
   ```
   export DATABASE_URL=postgresql://username:password@localhost/vpn_database
   export FLASK_SECRET_KEY=your_secure_random_key
   ```

5. Initialize the database:
   ```
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

6. Start the server:
   ```
   python main.py server --port 8080
   ```

7. Start the web interface:
   ```
   gunicorn --bind 0.0.0.0:5000 main:app
   ```

### Client Setup

1. Install dependencies:
   ```
   pip install -r github-requirements.txt
   ```

2. Run the client (as administrator/root):
   ```
   sudo python main.py client --server your.vpn.server.address --port 8080
   ```

## Web Interface

The web interface runs on port 5000 by default and provides:

- User registration and login
- VPN connection management
- Traffic statistics
- Administrative functions

Access it at `http://localhost:5000` after starting the server.

## Security Features

- **Quantum-Resistant Algorithms**: CRYSTAL-Kyber and Dilithium implementation
- **Dual-Layer Encryption**: AES-256-GCM plus One-Time Pad
- **Perfect Forward Secrecy**: Ephemeral keys for each session
- **Secure Authentication**: Multi-factor capability and robust session management
- **Certificate Verification**: Using Dilithium signatures for verification

## Technical Documentation

For complete technical details, compile the provided thesis document:

```
./compile_thesis.sh
```

This will generate a comprehensive PDF that explains all aspects of the code implementation.

## Development

### Running Tests

```
# Run cryptography tests
python -m common.crypto.test_otp
python -m common.crypto.test_tunnel_otp

# Run unit tests
python -m unittest discover
```

### Adding New Features

1. Create a new branch for your feature
2. Implement tests to verify functionality
3. Ensure cross-platform compatibility
4. Submit a pull request

## License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## Disclaimer

This software is provided for educational and research purposes. Before using in production environments, conduct a thorough security review and consider regulatory compliance requirements.