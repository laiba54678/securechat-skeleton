#!/usr/bin/env python3
"""
src/server.py
Secure Chat Server with mutual TLS authentication
Handles: certificate validation, registration, login, DH key exchange, encrypted messaging
implements session teardown with non-repudiation
"""

import socket
import json
import base64
import time
import os
import sys
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.crypto_utils import (
    aes_encrypt, aes_decrypt, rsa_sign, rsa_verify,
    dh_generate_keypair, dh_compute_shared_secret, derive_aes_key_from_shared_secret,
    sha256_hash, load_private_key, load_certificate, get_certificate_fingerprint,
    DH_PRIME, DH_GENERATOR
)
from utils.cert_validator import CertificateValidator
from utils.db_utils import DatabaseManager

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.sock = None
        self.conn = None
        
        # Load server certificate and private key
        self.server_cert_path = "certs/server_cert.pem"
        self.server_key_path = "certs/server_key.pem"
        self.ca_cert_path = "certs/ca_cert.pem"
        
        # Load keys
        self.private_key = load_private_key(self.server_key_path)
        self.certificate = load_certificate(self.server_cert_path)
        print("[+] Server certificate and key loaded")
        
        # Initialize certificate validator
        self.cert_validator = CertificateValidator(self.ca_cert_path)
        print("[+] Certificate validator initialized")
        
        # Initialize database
        self.db = DatabaseManager()
        
        # Session state
        self.client_cert = None
        self.client_public_key = None
        self.session_key = None
        self.temp_session_key = None  # For registration/login
        self.username = None
        self.next_seqno = 1
        self.transcript = []
        
    def start(self):
        """Start the server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        
        print(f"\n[*] Secure Chat Server started on {self.host}:{self.port}")
        print("[*] Waiting for client connection...")
        
        try:
            while True:
                self.conn, addr = self.sock.accept()
                print(f"\n[+] Client connected from {addr[0]}:{addr[1]}")
                
                try:
                    self.handle_client()
                except Exception as e:
                    print(f"[!] Error handling client: {str(e)}")
                    import traceback
                    traceback.print_exc()
                finally:
                    if self.conn:
                        self.conn.close()
                    # Reset session state
                    self.reset_session()
                    print("\n[*] Waiting for next client...")
        except KeyboardInterrupt:
            print("\n\n[*] Server shutting down...")
        finally:
            if self.sock:
                self.sock.close()
            self.db.close()
    
    def reset_session(self):
        """Reset session state between clients"""
        self.client_cert = None
        self.client_public_key = None
        self.session_key = None
        self.temp_session_key = None
        self.username = None
        self.next_seqno = 1
        self.transcript = []
    
    def send_message(self, msg_dict):
        """Send a JSON message"""
        msg_json = json.dumps(msg_dict)
        msg_bytes = msg_json.encode('utf-8')
        self.conn.sendall(msg_bytes + b'\n')
    
    def receive_message(self):
        """Receive a JSON message"""
        data = b''
        while b'\n' not in data:
            chunk = self.conn.recv(4096)
            if not chunk:
                return None
            data += chunk
        
        msg_json = data.decode('utf-8').strip()
        return json.loads(msg_json)
    
    def handle_client(self):
        """Handle a client connection"""
        
        # Phase 1: Control Plane - Certificate Exchange
        print("\n=== CONTROL PLANE: Certificate Exchange ===")
        if not self.handle_certificate_exchange():
            print("[!] Certificate exchange failed")
            return
        
        # Phase 2: Authentication - Registration or Login
        print("\n=== AUTHENTICATION: Registration/Login ===")
        if not self.handle_authentication():
            print("[!] Authentication failed")
            return
        
        # Phase 3: Key Agreement - DH Key Exchange
        print("\n=== KEY AGREEMENT: Session Key Establishment ===")
        if not self.handle_key_agreement():
            print("[!] Key agreement failed")
            return
        
        # Phase 4: Data Plane - Encrypted Messaging
        print("\n=== DATA PLANE: Encrypted Messaging ===")
        self.handle_messaging()
        
        # Phase 5: Teardown - Non-Repudiation
        print("\n=== TEARDOWN: Non-Repudiation ===")
        self.handle_teardown()
    
    def handle_certificate_exchange(self):
        """Handle certificate exchange and validation"""
        
        # Receive client hello with certificate
        client_hello = self.receive_message()
        if client_hello['type'] != 'hello':
            print(f"[!] Expected 'hello', got '{client_hello['type']}'")
            return False
        
        client_cert_pem = client_hello['client_cert'].encode('utf-8')
        client_nonce = base64.b64decode(client_hello['nonce'])
        
        print(f"[+] Received client hello with nonce: {client_nonce.hex()[:16]}...")
        
        # Validate client certificate
        is_valid, error = self.cert_validator.validate_certificate(client_cert_pem)
        if not is_valid:
            print(f"[!] Client certificate validation failed: {error}")
            self.send_message({"type": "error", "message": error})
            return False
        
        # Load client certificate
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        self.client_cert = x509.load_pem_x509_certificate(client_cert_pem, default_backend())
        self.client_public_key = self.client_cert.public_key()
        
        cert_info = self.cert_validator.get_certificate_info(client_cert_pem)
        print(f"[+] Client certificate validated:")
        print(f"    CN: {cert_info['common_name']}")
        print(f"    Fingerprint: {cert_info['fingerprint'][:16]}...")
        
        # Send server hello with certificate
        with open(self.server_cert_path, 'r') as f:
            server_cert_pem = f.read()
        
        server_nonce = os.urandom(16)
        server_hello = {
            "type": "server_hello",
            "server_cert": server_cert_pem,
            "nonce": base64.b64encode(server_nonce).decode()
        }
        self.send_message(server_hello)
        print(f"[+] Sent server hello with nonce: {server_nonce.hex()[:16]}...")
        
        print("[+] Control plane complete: Certificates validated")
        return True
    
    def handle_authentication(self):
        """Handle registration or login with temporary DH key"""
        
        # Generate temporary DH keypair for auth phase
        temp_dh_private, temp_dh_public = dh_generate_keypair()
        
        # Send temporary DH parameters
        dh_params = {
            "type": "dh_params",
            "g": DH_GENERATOR,
            "p": DH_PRIME,
            "B": temp_dh_public
        }
        self.send_message(dh_params)
        print("[+] Sent temporary DH parameters for authentication")
        
        # Receive client DH public key
        client_dh = self.receive_message()
        if client_dh['type'] != 'dh_client_auth':
            return False
        
        client_temp_public = client_dh['A']
        
        # Compute temporary shared secret
        temp_shared_secret = dh_compute_shared_secret(temp_dh_private, client_temp_public)
        self.temp_session_key = derive_aes_key_from_shared_secret(temp_shared_secret)
        print(f"[+] Temporary session key established: {self.temp_session_key.hex()[:16]}...")
        
        # Receive encrypted auth request (register or login)
        auth_request = self.receive_message()
        
        if auth_request['type'] == 'register':
            return self.handle_registration(auth_request)
        elif auth_request['type'] == 'login':
            return self.handle_login(auth_request)
        else:
            print(f"[!] Unknown auth type: {auth_request['type']}")
            return False
    
    def handle_registration(self, auth_request):
        """Handle user registration"""
        
        # Decrypt registration data
        encrypted_data = base64.b64decode(auth_request['data'])
        decrypted_json = aes_decrypt(encrypted_data, self.temp_session_key).decode('utf-8')
        reg_data = json.loads(decrypted_json)
        
        email = reg_data['email']
        username = reg_data['username']
        password = reg_data['password']
        
        print(f"[*] Registration request: {username} ({email})")
        
        # Register user in database
        success, message = self.db.register_user(email, username, password)
        
        if success:
            self.username = username
            print(f"[+] User '{username}' registered successfully")
            
            # Log session
            cert_fingerprint = get_certificate_fingerprint(self.client_cert)
            self.db.log_session(username, cert_fingerprint)
            
            # Send success response
            response = {"type": "register_response", "success": True, "message": message}
        else:
            print(f"[!] Registration failed: {message}")
            response = {"type": "register_response", "success": False, "message": message}
        
        self.send_message(response)
        return success
    
    def handle_login(self, auth_request):
        """Handle user login"""
        
        # Decrypt login data
        encrypted_data = base64.b64decode(auth_request['data'])
        decrypted_json = aes_decrypt(encrypted_data, self.temp_session_key).decode('utf-8')
        login_data = json.loads(decrypted_json)
        
        email = login_data['email']
        password = login_data['password']
        
        print(f"[*] Login request: {email}")
        
        # Verify credentials
        success, username, message = self.db.verify_login(email, password)
        
        if success:
            self.username = username
            print(f"[+] User '{username}' logged in successfully")
            
            # Log session
            cert_fingerprint = get_certificate_fingerprint(self.client_cert)
            self.db.log_session(username, cert_fingerprint)
            
            # Send success response
            response = {"type": "login_response", "success": True, "username": username, "message": message}
        else:
            print(f"[!] Login failed: {message}")
            response = {"type": "login_response", "success": False, "message": message}
        
        self.send_message(response)
        return success
    
    def handle_key_agreement(self):
        """Handle DH key exchange for session"""
        
        # Generate DH keypair
        dh_private, dh_public = dh_generate_keypair()
        
        # Receive client DH public key
        client_dh = self.receive_message()
        if client_dh['type'] != 'dh_client':
            return False
        
        client_public = client_dh['A']
        print(f"[+] Received client DH public key")
        
        # Send server DH public key
        server_dh = {
            "type": "dh_server",
            "B": dh_public
        }
        self.send_message(server_dh)
        print(f"[+] Sent server DH public key")
        
        # Compute shared secret
        shared_secret = dh_compute_shared_secret(dh_private, client_public)
        self.session_key = derive_aes_key_from_shared_secret(shared_secret)
        
        print(f"[+] Session key established: {self.session_key.hex()[:16]}...")
        return True
    
    def handle_messaging(self):
        """Handle encrypted message exchange"""
        
        print(f"[*] Chat session active with: {self.username}")
        print("[*] Waiting for messages (client will send 'quit' to end)...")
        
        while True:
            # Receive encrypted message
            msg = self.receive_message()
            
            if msg['type'] == 'quit':
                print("[*] Client requested to quit")
                break
            
            if msg['type'] != 'msg':
                print(f"[!] Unexpected message type: {msg['type']}")
                continue
            
            seqno = msg['seqno']
            timestamp = msg['ts']
            ct_b64 = msg['ct']
            sig_b64 = msg['sig']
            
            # Verify sequence number
            if seqno != self.next_seqno:
                print(f"[!] REPLAY: Expected seqno {self.next_seqno}, got {seqno}")
                error_msg = {
                    "type": "error",
                    "code": "REPLAY",
                    "message": f"Invalid sequence number"
                }
                self.send_message(error_msg)
                continue
            
            # Decode ciphertext and signature
            ct = base64.b64decode(ct_b64)
            sig = base64.b64decode(sig_b64)
            
            # Verify signature
            digest_data = f"{seqno}|{timestamp}".encode() + ct
            digest = sha256_hash(digest_data)
            
            if not rsa_verify(digest, sig, self.client_public_key):
                print(f"[!] SIG_FAIL: Message {seqno} signature verification failed")
                error_msg = {
                    "type": "error",
                    "code": "SIG_FAIL",
                    "message": "Signature verification failed"
                }
                self.send_message(error_msg)
                continue
            
            # Decrypt message
            try:
                plaintext = aes_decrypt(ct, self.session_key).decode('utf-8')
            except Exception as e:
                print(f"[!] Decryption failed: {str(e)}")
                continue
            
            # Log to transcript
            cert_fingerprint = get_certificate_fingerprint(self.client_cert)
            self.transcript.append(f"{seqno}|{timestamp}|{ct_b64}|{sig_b64}|{cert_fingerprint}")
            
            # Display message
            ts_str = datetime.fromtimestamp(timestamp / 1000.0).strftime('%H:%M:%S')
            print(f"[{ts_str}] {self.username}: {plaintext}")
            
            # Echo message back
            echo_plaintext = f"Server echo: {plaintext}"
            echo_ct = aes_encrypt(echo_plaintext.encode('utf-8'), self.session_key)
            
            # Sign echo message
            echo_timestamp = int(time.time() * 1000)
            echo_digest_data = f"{seqno}|{echo_timestamp}".encode() + echo_ct
            echo_digest = sha256_hash(echo_digest_data)
            echo_sig = rsa_sign(echo_digest, self.private_key)
            
            echo_msg = {
                "type": "msg",
                "seqno": seqno,
                "ts": echo_timestamp,
                "ct": base64.b64encode(echo_ct).decode(),
                "sig": base64.b64encode(echo_sig).decode()
            }
            self.send_message(echo_msg)
            
            # Increment sequence number
            self.next_seqno += 1
    
    def handle_teardown(self):
        """Handle session teardown and non-repudiation"""
        
        # Save transcript
        os.makedirs("transcripts", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        transcript_filename = f"transcripts/server_{self.username}_{timestamp}.txt"
        
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
            "peer": "server",
            "first_seq": 1,
            "last_seq": self.next_seqno - 1,
            "transcript_sha256": transcript_hash.hex(),
            "sig": base64.b64encode(receipt_sig).decode()
        }
        
        # Save receipt
        receipt_filename = f"transcripts/server_receipt_{self.username}_{timestamp}.json"
        with open(receipt_filename, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[+] Session receipt saved: {receipt_filename}")
        
        # Send receipt to client
        self.send_message(receipt)
        print("[+] Session receipt sent to client")
        
        # Receive client receipt
        client_receipt = self.receive_message()
        if client_receipt and client_receipt['type'] == 'receipt':
            print("[+] Received client session receipt")
        
        print("[+] Teardown complete")

def main():
    server = SecureChatServer()
    server.start()

if __name__ == "__main__":
    main()