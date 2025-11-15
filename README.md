# SecureChat - Cryptographic Secure Messaging System

**Course:** Information Security (Fall 2025)  
**University:** FAST-NUCES  
**GitHub Repository:** https://github.com/laiba54678/securechat-skeleton


## 📋 Overview

SecureChat is a console-based secure messaging system implementing full CIANR (Confidentiality, Integrity, Authenticity, Non-Repudiation, Reliability) using:
- **PKI**: X.509 certificates with Root CA
- **Encryption**: AES-128 in CBC mode with PKCS#7 padding
- **Key Exchange**: Diffie-Hellman (2048-bit MODP group)
- **Signatures**: RSA with PSS padding
- **Hashing**: SHA-256

## 🏗️ System Architecture
```
┌─────────────┐                      ┌─────────────┐
│   CLIENT    │◄────────────────────►│   SERVER    │
│             │   Mutual TLS Auth    │             │
│  • Client   │   DH Key Exchange    │  • Server   │
│    Cert     │   AES-128 Encrypted  │    Cert     │
│  • Private  │   RSA Signatures     │  • MySQL DB │
│    Key      │   Transcripts        │  • Logs     │
└─────────────┘                      └─────────────┘
```

## 🔒 Security Features

### Phase 1: Control Plane (Certificate Validation)
- Mutual certificate exchange
- CA signature verification
- Expiry and validity checks
- Hostname/CN validation

### Phase 2: Authentication
- Salted password hashing (SHA-256)
- Encrypted credential transmission
- MySQL secure storage
- Session logging

### Phase 3: Key Agreement
- Diffie-Hellman key exchange
- RFC 3526 2048-bit MODP group
- SHA-256 key derivation (truncated to 16 bytes)

### Phase 4: Data Plane (Encrypted Messaging)
- AES-128 CBC encryption with PKCS#7 padding
- Per-message RSA signatures
- Sequence number replay protection
- Timestamp freshness validation

### Phase 5: Teardown (Non-Repudiation)
- Append-only transcripts
- SHA-256 transcript hashing
- RSA-signed session receipts
- Offline verification support

## 📁 Project Structure
```
securechat-skeleton/
├── certs/                    # Certificates (gitignored)
├── src/
│   ├── server.py            # Chat server
│   ├── client.py            # Chat client
│   └── utils/
│       ├── crypto_utils.py  # Crypto operations
│       ├── cert_validator.py # Certificate validation
│       └── db_utils.py      # Database operations
├── scripts/
│   ├── gen_ca.py            # Generate Root CA
│   ├── gen_cert.py          # Generate certificates
│   └── verify_receipt.py    # Verify transcripts
├── tests/
│   └── test_invalid_cert.py # Certificate tests
├── transcripts/             # Chat transcripts (gitignored)
├── logs/                    # System logs
├── .env                     # Configuration (gitignored)
├── .env.example             # Configuration template
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🚀 Installation & Setup.

### Prerequisites
- Python 3.8+
- MySQL 8.0+
- Git

### Step 1: Clone Repository
```bash
git clone https://github.com/laiba54678/securechat-skeleton

cd securechat-skeleton
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Setup MySQL Database
```sql
CREATE DATABASE securechat_db;
CREATE USER 'securechat_user'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON securechat_db.* TO 'securechat_user'@'localhost';
FLUSH PRIVILEGES;

USE securechat_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

CREATE TABLE session_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_end TIMESTAMP NULL,
    client_cert_fingerprint VARCHAR(64)
);
```

### Step 4: Configure Environment
```bash
cp .env.example .env
# Edit .env with your MySQL credentials
```

### Step 5: Generate Certificates
```bash
# Generate Root CA
python scripts/gen_ca.py

# Generate Server Certificate
python scripts/gen_cert.py --type server --name localhost

# Generate Client Certificate
python scripts/gen_cert.py --type client --name client_user
```

## 🎮 Usage

### Start Server
```bash
python src/server.py
```

Expected output:
```
[+] Server certificate and key loaded
[+] Certificate validator initialized
[+] Connected to MySQL database: securechat_db

[*] Secure Chat Server started on 0.0.0.0:5555
[*] Waiting for client connection...
```

### Start Client (in another terminal)
```bash
python src/client.py
```

Follow prompts to:
1. Register or login
2. Send encrypted messages
3. Type `quit` to end session

## 🧪 Testing

### Test Certificate Validation
```bash
python tests/test_invalid_cert.py
```

Tests:
- ✅ Valid certificate acceptance
- ❌ Self-signed certificate rejection
- ❌ Expired certificate rejection
- ❌ Not-yet-valid certificate rejection

### Verify Transcripts
```bash
# Verify message signatures
python scripts/verify_receipt.py transcript transcripts/client_testuser_*.txt certs/client_cert.pem

# Verify session receipt
python scripts/verify_receipt.py receipt transcripts/client_receipt_*.json transcripts/client_testuser_*.txt certs/client_cert.pem

# Test tamper detection
python scripts/verify_receipt.py tamper transcripts/client_testuser_*.txt certs/client_cert.pem
```

## 📊 Wireshark Analysis

### Capture Traffic
1. Start Wireshark
2. Capture on loopback interface (lo or Loopback)
3. Apply filter: `tcp.port == 5555`
4. Run server and client
5. Save capture as `.pcapng`

### Verify Encryption
- All messages are base64-encoded JSON
- Ciphertext is encrypted (no plaintext visible)
- Signatures are present on all messages

## 📝 Message Protocol

### Control Plane
```json
{"type": "hello", "client_cert": "...", "nonce": "..."}
{"type": "server_hello", "server_cert": "...", "nonce": "..."}
```

### Authentication
```json
{"type": "register", "data": "<encrypted>"}
{"type": "login", "data": "<encrypted>"}
```

### Key Exchange
```json
{"type": "dh_client", "g": 2, "p": "...", "A": "..."}
{"type": "dh_server", "B": "..."}
```

### Data Plane
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1705234567890,
  "ct": "<base64_ciphertext>",
  "sig": "<base64_signature>"
}
```

### Teardown
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 5,
  "transcript_sha256": "...",
  "sig": "<base64_signature>"
}
```

## 🔐 Security Analysis

| Goal | Implementation | Attack Prevention |
|------|----------------|-------------------|
| **Confidentiality** | AES-128 CBC + PKCS#7 | Eavesdropping |
| **Integrity** | SHA-256 + RSA signatures | Tampering, Modification |
| **Authenticity** | X.509 certificates + CA | Impersonation, MITM |
| **Non-Repudiation** | Signed transcripts + receipts | Denial of communication |
| **Replay Protection** | Sequence numbers + timestamps | Replay attacks |

## 🐛 Troubleshooting

### Import Errors
```bash
# Make sure you're in the project root
cd securechat-skeleton

# Install dependencies
pip install -r requirements.txt
```

### MySQL Connection Failed
```bash
# Check MySQL is running
# Windows:
net start MySQL80

# Check credentials in .env file
DB_USER=securechat_user
DB_PASSWORD=SecurePass123!
```

### Certificate Not Found
```bash
# Generate all certificates
python scripts/gen_ca.py
python scripts/gen_cert.py --type server --name localhost
python scripts/gen_cert.py --type client --name client_user

# Verify they exist
dir certs
```

## 📚 References

- RFC 3526 - Diffie-Hellman Groups
- RFC 5280 - X.509 Certificate Profiles
- NIST SP 800-38A - Block Cipher Modes
- PKCS#7 - Cryptographic Message Syntax

## 👤 Author

**Your Name**  
Roll Number: 22i-2359
FAST-NUCES Islamabad

## 📄 License

Educational project for Information Security course.