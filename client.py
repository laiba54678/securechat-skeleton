#!/usr/bin/env python3
"""
src/client.py
Secure Chat Client with mutual TLS authentication
Handles: certificate validation, registration/login, DH key exchange, encrypted messaging
"""

import socket
import json
import base64
import time
import os
import sys
from datetime import datetime
import getpass

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.crypto_utils import (
    aes_encrypt, aes_decrypt, rsa_sign, rsa_verify,
    dh_generate_keypair, dh_compute_shared_secret, derive_aes_key_from_shared_secret,
    sha256_hash, load_private_key, load_certificate, get_certificate_fingerprint,
    DH_PRIME, DH_GENERATOR
)
from utils.cert_validator import CertificateValidator

class SecureChatClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.sock = None
        
        # Load client certificate and private key
        self.client_cert_path = "certs/client_cert.pem"
        self.client_key_path = "certs/client_key.pem"
        self.ca_cert_path = "certs/ca_cert.pem"
        
        # Load keys
        self.private_key = load_private_key(self.client_key_path)
        self.certificate = load_certificate(self.client_cert_path)
        print("[+] Client certificate and key loaded")
        
        # Initialize certificate validator
        self.cert_validator = CertificateValidator(self.ca_cert_path)
        print("[+] Certificate validator initialized")
        
        # Session state
        self.server_cert = None
        self.server_public_key = None
        self.session_key = None
        self.temp_session_key = None
        self.username = None
        self.next_seqno = 1
        self.transcript = []
        
    def connect(self):
        """Connect to server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[+] Connected to server {self.host}:{self.port}\n")
    
    def send_message(self, msg_dict):
        """Send a JSON message"""
        msg_json = json.dumps(msg_dict)
        msg_bytes = msg_json.encode('utf-8')
        self.sock.sendall(msg_bytes + b'\n')
    
    def receive_message(self):
        """Receive a JSON message"""
        data = b''
        while b'\n' not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            data += chunk
        
        msg_json = data.decode('utf-8').strip()
        return json.loads(msg_json)
    
    def run(self):
        """Run the client"""
        try:
            self.connect()
            
            # Phase 1: Control Plane - Certificate Exchange
            print("=== CONTROL PLANE: Certificate Exchange ===")
            if not self.handle_certificate_exchange():
                print("[!] Certificate exchange failed")
                return
            
            # Phase 2: Authentication
            print("\n=== AUTHENTICATION: Registration/Login ===")
            if not self.handle_authentication():
                print("[!] Authentication failed")
                return
            
            # Phase 3: Key Agreement
            print("\n=== KEY AGREEMENT: Session Key Establishment ===")
            if not self.handle_key_agreement():
                print("[!] Key agreement failed")
                return
            
            # Phase 4: Data Plane - Messaging
            print("\n=== DATA PLANE: Encrypted Messaging ===")
            self.handle_messaging()
            
            # Phase 5: Teardown
            print("\n=== TEARDOWN: Non-Repudiation ===")
            self.handle_teardown()
            
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()
            print("\n[*] Disconnected from server")
    
    def handle_certificate_exchange(self):
        """Handle certificate exchange with server"""
        
        # Load client certificate
        with open(self.client_cert_path, 'r') as f:
            client_cert_pem = f.read()
        
        # Generate nonce
        client_nonce = os.urandom(16)
        
        # Send hello with certificate
        hello_msg = {
            "type": "hello",
            "client_cert": client_cert_pem,
            "nonce": base64.b64encode(client_nonce).decode()
        }
        self.send_message(hello_msg)
        print(f"[+] Sent hello with nonce: {client_nonce.hex()[:16]}...")
        
        # Receive server hello
        server_hello = self.receive_message()
        if server_hello['type'] != 'server_hello':
            print(f"[!] Expected 'server_hello', got '{server_hello['type']}'")
            return False
        
        server_cert_pem = server_hello['server_cert'].encode('utf-8')
        server_nonce = base64.b64decode(server_hello['nonce'])
        
        print(f"[+] Received server hello with nonce: {server_nonce.hex()[:16]}...")
        
        # Validate server certificate
        is_valid, error = self.cert_validator.validate_certificate(server_cert_pem, expected_cn="localhost")
        if not is_valid:
            print(f"[!] Server certificate validation failed: {error}")
            return False
        
        # Load server certificate
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        self.server_cert = x509.load_pem_x509_certificate(server_cert_pem, default_backend())
        self.server_public_key = self.server_cert.public_key()
        
        cert_info = self.cert_validator.get_certificate_info(server_cert_pem)
        print(f"[+] Server certificate validated:")
        print(f"    CN: {cert_info['common_name']}")
        print(f"    Fingerprint: {cert_info['fingerprint'][:16]}...")
        
        print("[+] Control plane complete: Certificates validated")
        return True
    
    def handle_authentication(self):
        """Handle registration or login"""
        
        # Receive temporary DH parameters
        dh_params = self.receive_message()
        if dh_params['type'] != 'dh_params':
            return False
        
        server_temp_public = dh_params['B']
        print("[+] Received temporary DH parameters")
        
        # Generate temporary DH keypair
        temp_dh_private, temp_dh_public = dh_generate_keypair()
        
        # Send client DH public key
        client_dh = {
            "type": "dh_client_auth",
            "A": temp_dh_public
        }
        self.send_message(client_dh)
        
        # Compute temporary shared secret
        temp_shared_secret = dh_compute_shared_secret(temp_dh_private, server_temp_public)
        self.temp_session_key = derive_aes_key_from_shared_secret(temp_shared_secret)
        print(f"[+] Temporary session key established: {self.temp_session_key.hex()[:16]}...")
        
        # Ask user: register or login?
        print("\n[?] Choose action:")
        print("    1. Register new account")
        print("    2. Login with existing account")
        
        choice = input("Enter choice (1/2): ").strip()
        
        if choice == '1':
            return self.handle_registration()
        elif choice == '2':
            return self.handle_login()
        else:
            print("[!] Invalid choice")
            return False
    
    def handle_registration(self):
        """Handle user registration"""
        print("\n--- Registration ---")
        
        email = input("Enter email: ").strip()
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        
        # Prepare registration data
        reg_data = {
            "email": email,
            "username": username,
            "password": password
        }
        
        # Encrypt registration data
        reg_json = json.dumps(reg_data).encode('utf-8')
        encrypted_data = aes_encrypt(reg_json, self.temp_session_key)
        
        # Send registration request
        reg_request = {
            "type": "register",
            "data": base64.b64encode(encrypted_data).decode()
        }
        self.send_message(reg_request)
        
        # Receive response
        response = self.receive_message()
        
        if response['success']:
            self.username = username
            print(f"[+] {response['message']}")
            return True
        else:
            print(f"[!] {response['message']}")
            return False
    
    def handle_login(self):
        """Handle user login"""
        print("\n--- Login ---")
        
        email = input("Enter email: ").strip()
        password = getpass.getpass("Enter password: ")
        
        # Prepare login data
        login_data = {
            "email": email,
            "password": password
        }
        
        # Encrypt login data
        login_json = json.dumps(login_data).encode('utf-8')
        encrypted_data = aes_encrypt(login_json, self.temp_session_key)
        
        # Send login request
        login_request = {
            "type": "login",
            "data": base64.b64encode(encrypted_data).decode()
        }
        self.send_message(login_request)
        
        # Receive response
        response = self.receive_message()
        
        if response['success']:
            self.username = response['username']
            print(f"[+] {response['message']}")
            return True
        else:
            print(f"[!] {response['message']}")
            return False
    
    def handle_key_agreement(self):
        """Handle DH key exchange for session"""
        
        # Generate DH keypair
        dh_private, dh_public = dh_generate_keypair()
        
        # Send client DH public key
        client_dh = {
            "type": "dh_client",
            "g": DH_GENERATOR,
            "p": DH_PRIME,
            "A": dh_public
        }
        self.send_message(client_dh)
        print("[+] Sent DH public key")
        
        # Receive server DH public key
        server_dh = self.receive_message()
        if server_dh['type'] != 'dh_server':
            return False
        
        server_public = server_dh['B']
        print("[+] Received server DH public key")
        
        # Compute shared secret
        shared_secret = dh_compute_shared_secret(dh_private, server_public)
        self.session_key = derive_aes_key_from_shared_secret(shared_secret)
        
        print(f"[+] Session key established: {self.session_key.hex()[:16]}...")
        return True
    
    def handle_messaging(self):
        """Handle encrypted messaging"""
        
        print(f"\n[*] Chat session active as: {self.username}")
        print("[*] Type your messages (or 'quit' to exit)\n")
        
        while True:
            # Get user input
            try:
                user_input = input(f"{self.username}> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            
            if not user_input.strip():
                continue
            
            if user_input.strip().lower() == 'quit':
                # Send quit message
                quit_msg = {"type": "quit"}
                self.send_message

                self.send_message(quit_msg)
                break
            
            # Encrypt message
            plaintext = user_input.encode('utf-8')
            ct = aes_encrypt(plaintext, self.session_key)
            
            # Create signature
            timestamp = int(time.time() * 1000)
            digest_data = f"{self.next_seqno}|{timestamp}".encode() + ct
            digest = sha256_hash(digest_data)
            sig = rsa_sign(digest, self.private_key)
            
            # Send encrypted message
            msg = {
                "type": "msg",
                "seqno": self.next_seqno,
                "ts": timestamp,
                "ct": base64.b64encode(ct).decode(),
                "sig": base64.b64encode(sig).decode()
            }
            self.send_message(msg)
            
            # Log to transcript
            cert_fingerprint = get_certificate_fingerprint(self.certificate)
            self.transcript.append(
                f"{self.next_seqno}|{timestamp}|{base64.b64encode(ct).decode()}|{base64.b64encode(sig).decode()}|{cert_fingerprint}"
            )
            
            # Receive server response
            response = self.receive_message()
            
            if response['type'] == 'error':
                print(f"[!] Error: {response['code']} - {response['message']}")
                if response['code'] in ['REPLAY', 'SIG_FAIL']:
                    break
                continue
            
            # Verify and decrypt server echo
            resp_seqno = response['seqno']
            resp_timestamp = response['ts']
            resp_ct_b64 = response['ct']
            resp_sig_b64 = response['sig']
            
            resp_ct = base64.b64decode(resp_ct_b64)
            resp_sig = base64.b64decode(resp_sig_b64)
            
            # Verify signature
            resp_digest_data = f"{resp_seqno}|{resp_timestamp}".encode() + resp_ct
            resp_digest = sha256_hash(resp_digest_data)
            
            if not rsa_verify(resp_digest, resp_sig, self.server_public_key):
                print("[!] Server response signature verification failed!")
                break
            
            # Decrypt response
            try:
                resp_plaintext = aes_decrypt(resp_ct, self.session_key).decode('utf-8')
                ts_str = datetime.fromtimestamp(resp_timestamp / 1000.0).strftime('%H:%M:%S')
                print(f"[{ts_str}] Server: {resp_plaintext}")
            except Exception as e:
                print(f"[!] Failed to decrypt server response: {str(e)}")
            
            # Increment sequence number
            self.next_seqno += 1
    
    def handle_teardown(self):
        """Handle session teardown and non-repudiation"""
        
        # Save transcript
        os.makedirs("transcripts", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        transcript_filename = f"transcripts/client_{self.username}_{timestamp}.txt"
        
        with open(transcript_filename, 'w') as f:
            for line in self.transcript:
                f.write(line + '\n')
        
        print(f"[+] Transcript saved: {transcript_filename}")
        
        # Compute transcript hash
        with open(transcript_filename, 'rb') as f:
            transcript_data = f.read()
        transcript_hash = sha256_hash(transcript_data)
        
        print(f"[+] Transcript hash: {transcript_hash.hex()[:32]}...")
        
        # Sign transcript hash (session receipt)
        receipt_sig = rsa_sign(transcript_hash, self.private_key)
        
        receipt = {
            "type": "receipt",
            "peer": "client",
            "first_seq": 1,
            "last_seq": self.next_seqno - 1,
            "transcript_sha256": transcript_hash.hex(),
            "sig": base64.b64encode(receipt_sig).decode()
        }
        
        # Save receipt
        receipt_filename = f"transcripts/client_receipt_{self.username}_{timestamp}.json"
        with open(receipt_filename, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[+] Session receipt saved: {receipt_filename}")
        
        # Send receipt to server
        self.send_message(receipt)
        print("[+] Session receipt sent to server")
        
        # Receive server receipt
        server_receipt = self.receive_message()
        if server_receipt and server_receipt['type'] == 'receipt':
            print("[+] Received server session receipt")
        
        print("[+] Teardown complete")

def main():
    client = SecureChatClient()
    client.run()

if __name__ == "__main__":
    main()