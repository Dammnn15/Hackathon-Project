"""
User Authentication System
Handles user registration, login, and session management
"""
import sqlite3
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple

class AuthSystem:
    """Secure authentication system with user management"""
    
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self.sessions = {}  # session_token -> user_data
        self._init_database()
    
    def _init_database(self):
        """Initialize user database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        """)
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Login history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                success BOOLEAN NOT NULL,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        
        print("✅ Authentication database initialized")
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    
    def _generate_salt(self) -> str:
        """Generate random salt"""
        return secrets.token_hex(32)
    
    def _generate_session_token(self) -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(64)
    
    def register_user(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user
        
        Returns: (success, message)
        """
        # Validation
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        if '@' not in email:
            return False, "Invalid email address"
        
        # Check for SQL injection in username/email (extra security)
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/']
        if any(char in username for char in dangerous_chars):
            return False, "Username contains invalid characters"
        
        if any(char in email for char in dangerous_chars):
            return False, "Email contains invalid characters"
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", 
                         (username, email))
            if cursor.fetchone():
                conn.close()
                return False, "Username or email already exists"
            
            # Create user
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, salt)
                VALUES (?, ?, ?, ?)
            """, (username, email, password_hash, salt))
            
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            print(f"✅ User registered: {username} (ID: {user_id})")
            return True, "Registration successful"
            
        except Exception as e:
            print(f"❌ Registration error: {e}")
            return False, f"Registration failed: {str(e)}"
    
    def login(self, username: str, password: str, ip_address: str = "unknown", 
              user_agent: str = "unknown") -> Tuple[bool, Optional[str], str]:
        """
        Authenticate user and create session
        
        Returns: (success, session_token, message)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get user
            cursor.execute("""
                SELECT id, username, password_hash, salt, is_active, 
                       login_attempts, locked_until
                FROM users 
                WHERE username = ?
            """, (username,))
            
            user = cursor.fetchone()
            
            if not user:
                # Log failed attempt
                cursor.execute("""
                    INSERT INTO login_history (username, success, ip_address, reason)
                    VALUES (?, 0, ?, ?)
                """, (username, ip_address, "User not found"))
                conn.commit()
                conn.close()
                return False, None, "Invalid username or password"
            
            user_id, db_username, password_hash, salt, is_active, login_attempts, locked_until = user
            
            # Check if account is locked
            if locked_until:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < lock_time:
                    conn.close()
                    return False, None, f"Account locked until {lock_time.strftime('%H:%M:%S')}"
            
            # Check if account is active
            if not is_active:
                conn.close()
                return False, None, "Account is deactivated"
            
            # Verify password
            provided_hash = self._hash_password(password, salt)
            
            if provided_hash != password_hash:
                # Increment login attempts
                login_attempts += 1
                
                # Lock account after 5 failed attempts
                if login_attempts >= 5:
                    locked_until = datetime.now() + timedelta(minutes=15)
                    cursor.execute("""
                        UPDATE users 
                        SET login_attempts = ?, locked_until = ?
                        WHERE id = ?
                    """, (login_attempts, locked_until.isoformat(), user_id))
                    
                    cursor.execute("""
                        INSERT INTO login_history (user_id, username, success, ip_address, reason)
                        VALUES (?, ?, 0, ?, ?)
                    """, (user_id, username, ip_address, "Account locked after 5 failed attempts"))
                    conn.commit()
                    conn.close()
                    return False, None, "Too many failed attempts. Account locked for 15 minutes."
                else:
                    cursor.execute("""
                        UPDATE users 
                        SET login_attempts = ?
                        WHERE id = ?
                    """, (login_attempts, user_id))
                
                # Log failed attempt
                cursor.execute("""
                    INSERT INTO login_history (user_id, username, success, ip_address, reason)
                    VALUES (?, ?, 0, ?, ?)
                """, (user_id, username, ip_address, "Invalid password"))
                conn.commit()
                conn.close()
                return False, None, "Invalid username or password"
            
            # Successful login
            # Reset login attempts
            cursor.execute("""
                UPDATE users 
                SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (user_id,))
            
            # Create session
            session_token = self._generate_session_token()
            expires_at = datetime.now() + timedelta(hours=24)
            
            cursor.execute("""
                INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, session_token, expires_at.isoformat(), ip_address, user_agent))
            
            # Log successful login
            cursor.execute("""
                INSERT INTO login_history (user_id, username, success, ip_address, reason)
                VALUES (?, ?, 1, ?, ?)
            """, (user_id, username, ip_address, "Successful login"))
            
            conn.commit()
            conn.close()
            
            # Store in memory cache
            self.sessions[session_token] = {
                'user_id': user_id,
                'username': db_username,
                'expires_at': expires_at
            }
            
            print(f"✅ User logged in: {username} from {ip_address}")
            return True, session_token, "Login successful"
            
        except Exception as e:
            conn.close()
            print(f"❌ Login error: {e}")
            return False, None, f"Login failed: {str(e)}"
    
    def verify_session(self, session_token: str) -> Optional[Dict]:
        """
        Verify if session token is valid
        
        Returns: user_data if valid, None otherwise
        """
        # Check memory cache first
        if session_token in self.sessions:
            session_data = self.sessions[session_token]
            if datetime.now() < session_data['expires_at']:
                return session_data
            else:
                # Session expired
                del self.sessions[session_token]
                return None
        
        # Check database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT s.user_id, u.username, s.expires_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND u.is_active = 1
        """, (session_token,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        user_id, username, expires_at = result
        expires_time = datetime.fromisoformat(expires_at)
        
        if datetime.now() >= expires_time:
            # Session expired
            self.logout(session_token)
            return None
        
        # Cache in memory
        session_data = {
            'user_id': user_id,
            'username': username,
            'expires_at': expires_time
        }
        self.sessions[session_token] = session_data
        
        return session_data
    
    def logout(self, session_token: str) -> bool:
        """Logout user and invalidate session"""
        # Remove from memory
        if session_token in self.sessions:
            del self.sessions[session_token]
        
        # Remove from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
        conn.commit()
        conn.close()
        
        return True
    
    def get_user_info(self, user_id: int) -> Optional[Dict]:
        """Get user information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, email, created_at, last_login
            FROM users
            WHERE id = ?
        """, (user_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        return {
            'id': result[0],
            'username': result[1],
            'email': result[2],
            'created_at': result[3],
            'last_login': result[4]
        }
    
    def get_all_users(self) -> list:
        """Get list of all users (admin function)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, email, created_at, last_login, is_active
            FROM users
            ORDER BY created_at DESC
        """)
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'created_at': row[3],
                'last_login': row[4],
                'is_active': row[5]
            })
        
        conn.close()
        return users
    
    def get_login_history(self, user_id: Optional[int] = None, limit: int = 50) -> list:
        """Get login history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute("""
                SELECT username, success, ip_address, timestamp, reason
                FROM login_history
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (user_id, limit))
        else:
            cursor.execute("""
                SELECT username, success, ip_address, timestamp, reason
                FROM login_history
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        history = []
        for row in cursor.fetchall():
            history.append({
                'username': row[0],
                'success': bool(row[1]),
                'ip_address': row[2],
                'timestamp': row[3],
                'reason': row[4]
            })
        
        conn.close()
        return history


# Singleton instance
_auth_system = None

def get_auth_system() -> AuthSystem:
    global _auth_system
    if _auth_system is None:
        _auth_system = AuthSystem()
    return _auth_system

