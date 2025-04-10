# Post-Quantum VPN

A Python-based custom VPN system using post-quantum cryptography with CRYSTAL-Kyber and Dilithium, supporting both Windows and Linux.

## Features

- Post-quantum cryptography implementation:
  - CRYSTAL-Kyber for key exchange
  - Dilithium for certificate exchange
  - AES-256-GCM for data encryption
- Secure tunnel following HTTPS TLS-Socket mechanism
- IP packet fragmentation and forwarding
- User management system with authentication
- Web-based administration interface
- Cross-platform support (Windows and Linux)
- Both TCP and UDP protocol support
- Perfect forward secrecy
- Comprehensive logging
- JSON configuration
- Enterprise features (Windows service, admin privileges handling)

## Requirements

- Python 3.8 or later
- PyCryptodome for AES implementation
- Flask for web interface (optional)
- Pywin32 for Windows support (Windows only)

## Installation

### From Source

1. Clone the repository:
   ```
   git clone https://github.com/pqvpn/pq-vpn.git
   cd pq-vpn
   ```

2. Install dependencies:
   