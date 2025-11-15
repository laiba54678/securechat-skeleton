#!/usr/bin/env python3
"""
src/utils/cert_validator.py
Certificate validation utilities for mutual TLS authentication
Validates: signature chain, expiry, hostname/CN, trusted CA
verifies X.509 certificates
"""

# FIX 1: Import 'UTC' from datetime and 'padding'
from datetime import datetime, UTC
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding # <-- ADDED THIS
from cryptography.exceptions import InvalidSignature
from datetime import UTC
class CertificateValidator:
    """Validates X.509 certificates against trusted CA"""
    
    def __init__(self, ca_cert_path: str):
        """
        Initialize validator with CA certificate
        
        Args:
            ca_cert_path: Path to CA certificate PEM file
        """
        with open(ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(
                f.read(), 
                default_backend()
            )
        self.ca_public_key = self.ca_cert.public_key()
    
    def validate_certificate(self, cert_pem: bytes, expected_cn: str = None) -> tuple:
        """
        Validate a certificate
        
        Args:
            cert_pem: Certificate in PEM format (bytes)
            expected_cn: Expected Common Name (optional)
        
        Returns:
            (is_valid: bool, error_message: str or None)
        """
        try:
            # Load certificate
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Check 1: Verify signature (signed by our CA)
            try:
                # FIX 2: The verify call was wrong. It needs 4 arguments:
                # 1. The signature
                # 2. The data that was signed
                # 3. The padding (which is PKCS1v15 by default)
                # 4. The algorithm (which the cert itself tells us)
                self.ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),  # <-- ADDED PADDING
                    cert.signature_hash_algorithm # <-- ADDED ALGORITHM
                )
            except InvalidSignature:
                return False, "BAD_CERT: Signature verification failed (not signed by trusted CA)"
            except Exception as e:
                return False, f"BAD_CERT: Signature verification error: {str(e)}"
            
            # Check 2: Verify certificate is currently valid (not expired, not before valid date)
            now = datetime.now(UTC)
            
            # Use the timezone-AWARE properties of the certificate
            if now < cert.not_valid_before_utc:
                return False, f"BAD_CERT: Certificate not yet valid (valid from {cert.not_valid_before_utc})"
            
            if now > cert.not_valid_after_utc:
                return False, f"BAD_CERT: Certificate expired (expired on {cert.not_valid_after_utc})"
            
            # Check 3: Verify Common Name if specified
            if expected_cn:
                cert_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                if cert_cn != expected_cn:
                    return False, f"BAD_CERT: Common Name mismatch (expected: {expected_cn}, got: {cert_cn})"
            
            # Check 4: Verify it's not a CA certificate (unless we're validating the CA itself)
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                if basic_constraints.ca:
                    # This is a CA cert - only valid if it's our root CA
                    if cert.subject != self.ca_cert.subject:
                        return False, "BAD_CERT: Certificate is a CA but not our trusted CA"
            except x509.ExtensionNotFound:
                pass  # No basic constraints extension
            
            # All checks passed
            return True, None
            
        except Exception as e:
            return False, f"BAD_CERT: Certificate parsing error: {str(e)}"
    
    def get_certificate_info(self, cert_pem: bytes) -> dict:
        """
        Extract information from certificate
        
        Args:
            cert_pem: Certificate in PEM format (bytes)
        
        Returns:
            Dictionary with certificate information
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Extract Common Name
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            
            # Extract organization
            try:
                org = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
            except IndexError:
                org = "N/A"
            
            # Get fingerprint
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            
            return {
                "common_name": cn,
                "organization": org,
                "serial_number": cert.serial_number,
                "not_valid_before": cert.not_valid_before,
                "not_valid_after": cert.not_valid_after,
                "fingerprint": fingerprint,
                "issuer_cn": cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            }
        except Exception as e:
            return {"error": str(e)}