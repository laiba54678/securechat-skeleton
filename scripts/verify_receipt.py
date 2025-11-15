#!/usr/bin/env python3
"""
scripts/verify_receipt.py
Offline verification of session receipts and transcripts
Verifies: message signatures, transcript hash, session receipt signature
"""

import sys
import json
import base64
import os

# Add parent directory to path to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.crypto_utils import sha256_hash, rsa_verify, load_certificate

def verify_transcript(transcript_path, cert_path):
    """
    Verify all message signatures in a transcript
    
    Args:
        transcript_path: Path to transcript file
        cert_path: Path to certificate used to sign messages
    
    Returns:
        (total_messages, valid_count, invalid_count)
    """
    print(f"[*] Verifying transcript: {transcript_path}")
    print(f"[*] Using certificate: {cert_path}")
    print()
    
    # Load certificate
    cert = load_certificate(cert_path)
    public_key = cert.public_key()
    
    valid_count = 0
    invalid_count = 0
    
    with open(transcript_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                # Parse transcript line: seqno|timestamp|ct|sig|fingerprint
                parts = line.split('|')
                if len(parts) != 5:
                    print(f"[!] Line {line_num}: Invalid format")
                    invalid_count += 1
                    continue
                
                seqno, timestamp, ct_b64, sig_b64, fingerprint = parts
                
                # Decode signature and ciphertext
                sig = base64.b64decode(sig_b64)
                ct = base64.b64decode(ct_b64)
                
                # Recompute digest: SHA256(seqno || timestamp || ciphertext)
                digest_data = f"{seqno}|{timestamp}".encode() + ct
                digest = sha256_hash(digest_data)
                
                # Verify signature
                is_valid = rsa_verify(digest, sig, public_key)
                
                if is_valid:
                    print(f"[✓] Line {line_num} (seqno={seqno}): Signature VALID")
                    valid_count += 1
                else:
                    print(f"[✗] Line {line_num} (seqno={seqno}): Signature INVALID")
                    invalid_count += 1
                    
            except Exception as e:
                print(f"[!] Line {line_num}: Error - {str(e)}")
                invalid_count += 1
    
    print()
    print(f"[*] Verification complete:")
    print(f"    Valid signatures:   {valid_count}")
    print(f"    Invalid signatures: {invalid_count}")
    print()
    
    if invalid_count == 0:
        print("[SUCCESS] All message signatures are valid!")
    else:
        print(f"[FAILURE] {invalid_count} message(s) have invalid signatures!")
    
    return valid_count + invalid_count, valid_count, invalid_count

def verify_receipt(receipt_path, transcript_path, cert_path):
    """
    Verify a session receipt against its transcript
    
    Args:
        receipt_path: Path to receipt JSON file
        transcript_path: Path to transcript file
        cert_path: Path to certificate used to sign receipt
    """
    print(f"[*] Verifying session receipt: {receipt_path}")
    print(f"[*] Against transcript: {transcript_path}")
    print()
    
    # Load receipt
    with open(receipt_path, 'r') as f:
        receipt = json.load(f)
    
    print(f"[*] Receipt details:")
    print(f"    Peer: {receipt['peer']}")
    print(f"    Sequence range: {receipt['first_seq']} - {receipt['last_seq']}")
    print(f"    Claimed transcript hash: {receipt['transcript_sha256']}")
    print()
    
    # Compute transcript hash
    with open(transcript_path, 'rb') as f:
        transcript_data = f.read()
    
    computed_hash = sha256_hash(transcript_data).hex()
    print(f"[*] Computed transcript hash: {computed_hash}")
    
    # Compare hashes
    if computed_hash == receipt['transcript_sha256']:
        print("[✓] Transcript hash matches")
    else:
        print("[✗] Transcript hash MISMATCH!")
        print("[FAILURE] Receipt verification failed!")
        return
    
    # Verify receipt signature
    cert = load_certificate(cert_path)
    public_key = cert.public_key()
    
    # The signature is over the transcript hash
    sig = base64.b64decode(receipt['sig'])
    hash_bytes = bytes.fromhex(receipt['transcript_sha256'])
    
    is_valid = rsa_verify(hash_bytes, sig, public_key)
    
    if is_valid:
        print("[✓] Receipt signature VALID")
        print()
        print("[SUCCESS] Session receipt is authentic and verifiable!")
    else:
        print("[✗] Receipt signature INVALID")
        print()
        print("[FAILURE] Receipt verification failed!")

def tamper_test(transcript_path, cert_path):
    """
    Test tamper detection by modifying a transcript
    
    Args:
        transcript_path: Path to transcript file
        cert_path: Path to certificate
    """
    print("[*] Testing tamper detection...")
    
    # Create a tampered copy
    tampered_path = transcript_path.replace('.txt', '_TAMPERED.txt')
    
    with open(transcript_path, 'r') as f:
        lines = f.readlines()
    
    if len(lines) > 0:
        # Tamper with first line by changing ciphertext
        parts = lines[0].strip().split('|')
        if len(parts) == 5:
            # Flip a byte in the ciphertext
            ct = base64.b64decode(parts[2])
            tampered_ct = bytearray(ct)
            tampered_ct[0] ^= 0xFF  # Flip all bits of first byte
            parts[2] = base64.b64encode(bytes(tampered_ct)).decode()
            lines[0] = '|'.join(parts) + '\n'
    
    with open(tampered_path, 'w') as f:
        f.writelines(lines)
    
    print(f"[*] Created tampered transcript: {tampered_path}")
    print()
    print("[*] Verifying tampered transcript (should fail):")
    
    # Verify tampered transcript
    total, valid, invalid = verify_transcript(tampered_path, cert_path)
    
    print()
    if invalid > 0:
        print(f"[✓] Tamper detection works! {invalid} invalid signature(s) detected")
    else:
        print("[✗] Tamper detection FAILED - all signatures still valid!")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Verify transcript:")
        print("    python scripts/verify_receipt.py transcript <transcript_file> <cert_file>")
        print()
        print("  Verify receipt:")
        print("    python scripts/verify_receipt.py receipt <receipt_file> <transcript_file> <cert_file>")
        print()
        print("  Test tamper detection:")
        print("    python scripts/verify_receipt.py tamper <transcript_file> <cert_file>")
        sys.exit(1)
    
    mode = sys.argv[1]
    
    if mode == "transcript":
        if len(sys.argv) != 4:
            print("Error: transcript mode requires 2 arguments")
            print("Usage: python scripts/verify_receipt.py transcript <transcript_file> <cert_file>")
            sys.exit(1)
        verify_transcript(sys.argv[2], sys.argv[3])
    
    elif mode == "receipt":
        if len(sys.argv) != 5:
            print("Error: receipt mode requires 3 arguments")
            print("Usage: python scripts/verify_receipt.py receipt <receipt_file> <transcript_file> <cert_file>")
            sys.exit(1)
        verify_receipt(sys.argv[2], sys.argv[3], sys.argv[4])
    
    elif mode == "tamper":
        if len(sys.argv) != 4:
            print("Error: tamper mode requires 2 arguments")
            print("Usage: python scripts/verify_receipt.py tamper <transcript_file> <cert_file>")
            sys.exit(1)
        tamper_test(sys.argv[2], sys.argv[3])
    
    else:
        print(f"Error: Unknown mode '{mode}'")
        print("Valid modes: transcript, receipt, tamper")
        sys.exit(1)

if __name__ == "__main__":
    main()