#!/usr/bin/env python3
"""
src/utils/db_utils.py
MySQL database operations for user registration and authentication
Handles: user creation, credential storage, login verification\
            session logging
"""

import pymysql
import os
from dotenv import load_dotenv
from utils.crypto_utils import hash_password, generate_salt

# Load environment variables
load_dotenv()

class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self):
        """Initialize database connection"""
        self.connection = pymysql.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME'),
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        print(f"[+] Connected to MySQL database: {os.getenv('DB_NAME')}")
    
    def register_user(self, email: str, username: str, password: str) -> tuple:
        """
        Register a new user
        
        Args:
            email: User email
            username: Username
            password: Plain text password (will be hashed)
        
        Returns:
            (success: bool, message: str)
        """
        try:
            # Generate random salt
            salt = generate_salt(16)
            
            # Hash password with salt
            pwd_hash = hash_password(password, salt)
            
            # Insert into database
            with self.connection.cursor() as cursor:
                sql = """
                    INSERT INTO users (email, username, salt, pwd_hash)
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(sql, (email, username, salt, pwd_hash))
                self.connection.commit()
            
            return True, "Registration successful"
            
        except pymysql.IntegrityError as e:
            if "Duplicate entry" in str(e):
                if "username" in str(e):
                    return False, "Username already exists"
                elif "email" in str(e):
                    return False, "Email already registered"
            return False, f"Database error: {str(e)}"
        except Exception as e:
            return False, f"Registration error: {str(e)}"
    
    def verify_login(self, email: str, password: str) -> tuple:
        """
        Verify user login credentials
        
        Args:
            email: User email
            password: Plain text password
        
        Returns:
            (success: bool, username: str or None, message: str)
        """
        try:
            with self.connection.cursor() as cursor:
                # Retrieve user's salt and password hash
                sql = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
                cursor.execute(sql, (email,))
                result = cursor.fetchone()
                
                if not result:
                    return False, None, "Email not found"
                
                stored_hash = result['pwd_hash']
                salt = result['salt']
                username = result['username']
                
                # Hash provided password with stored salt
                computed_hash = hash_password(password, salt)
                
                # Constant-time comparison to prevent timing attacks
                if self._constant_time_compare(computed_hash, stored_hash):
                    # Update last login timestamp
                    update_sql = "UPDATE users SET last_login = NOW() WHERE email = %s"
                    cursor.execute(update_sql, (email,))
                    self.connection.commit()
                    
                    return True, username, "Login successful"
                else:
                    return False, None, "Incorrect password"
                    
        except Exception as e:
            return False, None, f"Login error: {str(e)}"
    
    def log_session(self, username: str, cert_fingerprint: str):
        """
        Log a new session
        
        Args:
            username: Username
            cert_fingerprint: Certificate fingerprint
        """
        try:
            with self.connection.cursor() as cursor:
                sql = """
                    INSERT INTO session_logs (username, client_cert_fingerprint)
                    VALUES (%s, %s)
                """
                cursor.execute(sql, (username, cert_fingerprint))
                self.connection.commit()
        except Exception as e:
            print(f"[!] Failed to log session: {str(e)}")
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("[*] Database connection closed")
    
    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks
        
        Args:
            a: First string
            b: Second string
        
        Returns:
            True if strings are equal
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0