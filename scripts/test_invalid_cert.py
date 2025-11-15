#!/usr/bin/env python3
"""
tests/test_invalid_cert.py
Test certificate validation by creating invalid certificates
Tests: self-signed, expired, wrong CA
"""

import sys
import os
import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from utils.cert_validator import CertificateValidator

def create_self_signed_cert():
    """Create a self-signed certificate (not signed by our CA)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Fake Certificate"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    return cert.public_bytes(serialization.Encoding.PEM)

def create_expired_cert(ca_cert, ca_key):
    """Create an expired certificate"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Expired Certificate"),
    ])
    
    # Create cert that expired yesterday
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=365))
        .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    return cert.public_bytes(serialization.Encoding.PEM)

def create_not_yet_valid_cert(ca_cert, ca_key):
    """Create a certificate that's not yet valid"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Future Certificate"),
    ])
    
    # Create cert that won't be valid until tomorrow
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    return cert.public_bytes(serialization.Encoding.PEM)

def load_ca():
    """Load CA certificate and key"""
    ca_cert_path = "certs/ca_cert.pem"
    ca_key_path = "certs/ca_key.pem"
    
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key

def run_tests():
    """Run all certificate validation tests"""
    
    print("=" * 60)
    print("Certificate Validation Tests")
    print("=" * 60)
    print()
    
    # Check if CA exists
    if not os.path.exists("certs/ca_cert.pem"):
        print("[!] Error: CA certificate not found!")
        print("    Run 'python scripts/gen_ca.py' first")
        sys.exit(1)
    
    # Check if client cert exists
    if not os.path.exists("certs/client_cert.pem"):
        print("[!] Error: Client certificate not found!")
        print("    Run 'python scripts/gen_cert.py --type client --name client_user' first")
        sys.exit(1)
    
    # Load CA
    ca_cert, ca_key = load_ca()
    
    # Initialize validator
    validator = CertificateValidator("certs/ca_cert.pem")
    
    # Test 1: Valid Certificate
    print("[TEST 1] Valid Certificate (should pass)")
    with open("certs/client_cert.pem", "rb") as f:
        valid_cert = f.read()
    
    is_valid, error = validator.validate_certificate(valid_cert)
    if is_valid:
        print("[✓] PASS: Valid certificate accepted")
    else:
        print(f"[✗] FAIL: Valid certificate rejected - {error}")
    print()
    
    # Test 2: Self-Signed Certificate
    print("[TEST 2] Self-Signed Certificate (should fail)")
    self_signed = create_self_signed_cert()
    is_valid, error = validator.validate_certificate(self_signed)
    if not is_valid and "Signature verification failed" in str(error):
        print("[✓] PASS: Self-signed certificate rejected")
        print(f"    Error: {error}")
    else:
        print("[✗] FAIL: Self-signed certificate accepted!")
    print()
    
    # Test 3: Expired Certificate
    print("[TEST 3] Expired Certificate (should fail)")
    expired = create_expired_cert(ca_cert, ca_key)
    is_valid, error = validator.validate_certificate(expired)
    if not is_valid and "expired" in str(error).lower():
        print("[✓] PASS: Expired certificate rejected")
        print(f"    Error: {error}")
    else:
        print("[✗] FAIL: Expired certificate accepted!")
    print()
    
    # Test 4: Not-Yet-Valid Certificate
    print("[TEST 4] Not-Yet-Valid Certificate (should fail)")
    not_yet_valid = create_not_yet_valid_cert(ca_cert, ca_key)
    is_valid, error = validator.validate_certificate(not_yet_valid)
    if not is_valid and "not yet valid" in str(error).lower():
        print("[✓] PASS: Not-yet-valid certificate rejected")
        print(f"    Error: {error}")
    else:
        print("[✗] FAIL: Not-yet-valid certificate accepted!")
    print()
    
    print("=" * 60)
    print("[SUCCESS] All certificate validation tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()