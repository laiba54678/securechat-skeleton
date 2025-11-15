#!/usr/bin/env python3
"""
src/utils/crypto_utils.py
Core cryptographic utilities for SecureChat system
Handles: AES encryption, RSA signatures, DH key exchange, SHA-256 hashing
"""

import os
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# ===== AES-128 Encryption/Decryption (Block Cipher with PKCS#7 Padding) =====

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES key
    
    Returns:
        iv + ciphertext (iv is first 16 bytes)
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Apply PKCS#7 padding
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV + ciphertext
    return iv + ciphertext

def aes_decrypt(ciphertext_with_iv: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in CBC mode and remove PKCS#7 padding
    
    Args:
        ciphertext_with_iv: IV + ciphertext (first 16 bytes are IV)
        key: 16-byte AES key
    
    Returns:
        Decrypted plaintext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Extract IV and ciphertext
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    
    # Decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext

# ===== RSA Signatures =====

def rsa_sign(data: bytes, private_key) -> bytes:
    """
    Sign data using RSA private key
    
    Args:
        data: Data to sign
        private_key: RSA private key object
    
    Returns:
        Digital signature
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify RSA signature
    
    Args:
        data: Original data
        signature: Signature to verify
        public_key: RSA public key object
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ===== Diffie-Hellman Key Exchange =====

# RFC 3526 2048-bit MODP Group
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2

def dh_generate_keypair():
    """
    Generate Diffie-Hellman keypair
    
    Returns:
        (private_key, public_key)
    """
    # Generate random private key (256 bits)
    private_key = secrets.randbits(256)
    # Compute public key: g^private mod p
    public_key = pow(DH_GENERATOR, private_key, DH_PRIME)
    return private_key, public_key

def dh_compute_shared_secret(private_key: int, peer_public_key: int) -> int:
    """
    Compute Diffie-Hellman shared secret
    
    Args:
        private_key: Own private key
        peer_public_key: Peer's public key
    
    Returns:
        Shared secret: peer_public^private mod p
    """
    return pow(peer_public_key, private_key, DH_PRIME)

def derive_aes_key_from_shared_secret(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret
    
    Args:
        shared_secret: DH shared secret integer
    
    Returns:
        16-byte AES key
    """
    # Convert shared secret to bytes (big-endian)
    shared_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    # Hash with SHA-256 and truncate to 16 bytes
    hash_digest = hashlib.sha256(shared_bytes).digest()
    aes_key = hash_digest[:16]
    
    return aes_key

# ===== SHA-256 Hashing =====

def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash
    
    Args:
        data: Data to hash
    
    Returns:
        32-byte hash digest
    """
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hex string
    
    Args:
        data: Data to hash
    
    Returns:
        64-character hex string
    """
    return hashlib.sha256(data).hexdigest()

# ===== Password Hashing =====

def hash_password(password: str, salt: bytes) -> str:
    """
    Hash password with salt using SHA-256
    
    Args:
        password: Password string
        salt: Random salt bytes
    
    Returns:
        Hex string of hash(salt || password)
    """
    combined = salt + password.encode('utf-8')
    return hashlib.sha256(combined).hexdigest()

def generate_salt(length: int = 16) -> bytes:
    """
    Generate cryptographically secure random salt
    
    Args:
        length: Length of salt in bytes (default: 16)
    
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)

# ===== Utility Functions =====

def load_private_key(filepath: str):
    """Load RSA private key from PEM file"""
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def load_certificate(filepath: str):
    """Load X.509 certificate from PEM file"""
    from cryptography import x509
    with open(filepath, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def get_certificate_fingerprint(cert) -> str:
    """Get SHA-256 fingerprint of certificate"""
    return cert.fingerprint(hashes.SHA256()).hex()