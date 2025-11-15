#!/usr/bin/env python3
"""
scripts/gen_cert.py
Generates RSA X.509 certificates for server and client, signed by Root CA
Usage: python scripts/gen_cert.py --type [server|client] --name [hostname/username]
"""

import os
import sys
import argparse
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def load_ca():
    """Load CA certificate and private key"""
    ca_cert_path = "certs/ca_cert.pem"
    ca_key_path = "certs/ca_key.pem"
    
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        print("[!] Error: CA certificate or key not found!")
        print("    Run 'python scripts/gen_ca.py' first to generate the CA")
        sys.exit(1)
    
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key

def generate_certificate(cert_type, name):
    """Generate a certificate signed by the CA"""
    
    print(f"[*] Generating {cert_type} certificate for: {name}")
    
    # Ensure certs directory exists
    os.makedirs("certs", exist_ok=True)
    
    # Load CA
    ca_cert, ca_key = load_ca()
    
    # Generate private key for this certificate
    print(f"[*] Generating RSA private key (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    if cert_type == "server":
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        
        # Add Subject Alternative Name for server
        san = x509.SubjectAlternativeName([
            x509.DNSName(name),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ])
        
    else:  # client
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Client"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        
        san = None
    
    # Build certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    
    # Add SAN for server certificates
    if san:
        cert_builder = cert_builder.add_extension(san, critical=False)
    
    # Add Extended Key Usage
    if cert_type == "server":
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
    else:
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
    
    # Sign certificate with CA
    cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_filename = f"certs/{cert_type}_key.pem"
    with open(key_filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"[+] Private key saved to: {key_filename}")
    
    # Save certificate
    cert_filename = f"certs/{cert_type}_cert.pem"
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved to: {cert_filename}")
    
    print(f"[+] {cert_type.capitalize()} certificate generation complete!")
    print(f"    Valid for 1 year")
    print(f"    Serial Number: {cert.serial_number}")

def main():
    parser = argparse.ArgumentParser(description="Generate certificates signed by CA")
    parser.add_argument("--type", required=True, choices=["server", "client"],
                        help="Certificate type: server or client")
    parser.add_argument("--name", required=True,
                        help="Common Name (hostname for server, username for client)")
    
    args = parser.parse_args()
    
    generate_certificate(args.type, args.name)

if __name__ == "__main__":
    main()