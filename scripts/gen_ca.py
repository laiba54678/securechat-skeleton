#!/usr/bin/env python3
"""
scripts/gen_ca.py
Generates a self-signed Root Certificate Authority (CA)
This CA will be used to sign server and client certificates
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
# Generate Root CA Certificate
def generate_root_ca():
    """Generate a self-signed root CA certificate"""
    
    print("[*] Generating Root CA...")
    
    # Ensure certs directory exists
    os.makedirs("certs", exist_ok=True)
    
    # Generate private key
    print("[*] Generating RSA private key (4096 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])
    
    # Build certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Save private key
    ca_key_path = "certs/ca_key.pem"
    with open(ca_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"[+] CA private key saved to: {ca_key_path}")
    
    # Save certificate
    ca_cert_path = "certs/ca_cert.pem"
    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] CA certificate saved to: {ca_cert_path}")
    
    print("[+] Root CA generation complete!")
    print(f"    Certificate valid for 10 years")
    print(f"    Serial Number: {cert.serial_number}")

if __name__ == "__main__":
    generate_root_ca()