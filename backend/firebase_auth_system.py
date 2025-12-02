"""
Firebase Authentication System
Uses Firebase Firestore for all data storage
"""
import secrets
from typing import Optional, Dict, Tuple
from firebase_data_manager import get_firebase_manager

class FirebaseAuthSystem:
    """Authentication system using Firebase Firestore"""
    
    def __init__(self):
        self.firebase = get_firebase_manager()
        self.sessions = {}  # In-memory cache for faster verification
        print("✅ Firebase Authentication System initialized")
    
    def register_user(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user in Firebase
        
        Returns: (success, message)
        """
        # Validation
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        if '@' not in email:
            return False, "Invalid email address"
        
        # Check for dangerous characters
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/']
        if any(char in username for char in dangerous_chars):
            return False, "Username contains invalid characters"
        
        if any(char in email for char in dangerous_chars):
            return False, "Email contains invalid characters"
        
        # Create user in Firebase
        return self.firebase.create_user(username, email, password)
    
    def login(self, username: str, password: str, ip_address: str = "unknown", 
              user_agent: str = "unknown") -> Tuple[bool, Optional[str], str]:
        """
        Authenticate user with Firebase
        
        Returns: (success, session_token, message)
        """
        # Verify credentials
        success, user_data = self.firebase.verify_user(username, password)
        
        if not success or not user_data:
            # Log failed attempt
            self.firebase.log_login_attempt(username, None, False, ip_address, "Invalid credentials")
            return False, None, "Invalid username or password"
        
        user_id = user_data['id']
        
        # Check if account is locked
        if user_data.get('locked_until'):
            lock_time = user_data['locked_until']
            self.firebase.log_login_attempt(username, user_id, False, ip_address, "Account locked")
            return False, None, f"Account locked. Try again later."
        
        # Check if account is active
        if not user_data.get('is_active', True):
            self.firebase.log_login_attempt(username, user_id, False, ip_address, "Account deactivated")
            return False, None, "Account is deactivated"
        
        # Generate session token
        session_token = secrets.token_urlsafe(64)
        
        # Create session in Firebase
        self.firebase.create_session(user_id, session_token, ip_address, user_agent)
        
        # Cache in memory
        self.sessions[session_token] = {
            'user_id': user_id,
            'username': user_data['username']
        }
        
        # Log successful login
        self.firebase.log_login_attempt(username, user_id, True, ip_address, "Successful login")
        
        print(f"✅ User logged in (Firebase): {username} from {ip_address}")
        return True, session_token, "Login successful"
    
    def verify_session(self, session_token: str) -> Optional[Dict]:
        """
        Verify if session token is valid
        
        Returns: user_data if valid, None otherwise
        """
        # Check memory cache first
        if session_token in self.sessions:
            cached_data = self.sessions[session_token]
            # Verify in Firebase to ensure it's still valid
            firebase_data = self.firebase.verify_session(session_token)
            if firebase_data:
                return firebase_data
            else:
                # Session expired or invalid
                del self.sessions[session_token]
                return None
        
        # Check Firebase
        session_data = self.firebase.verify_session(session_token)
        
        if session_data:
            # Cache in memory
            self.sessions[session_token] = session_data
            return session_data
        
        return None
    
    def logout(self, session_token: str) -> bool:
        """Logout user and invalidate session"""
        # Remove from memory cache
        if session_token in self.sessions:
            del self.sessions[session_token]
        
        # Remove from Firebase
        return self.firebase.delete_session(session_token)
    
    def get_user_info(self, user_id: str) -> Optional[Dict]:
        """Get user information from Firebase"""
        return self.firebase.get_user_by_id(user_id)
    
    def get_all_users(self) -> list:
        """Get list of all users from Firebase"""
        return self.firebase.get_all_users()
    
    def get_login_history(self, user_id: Optional[str] = None, limit: int = 50) -> list:
        """Get login history from Firebase"""
        return self.firebase.get_login_history(user_id, limit)


# Singleton instance
_firebase_auth_system = None

def get_firebase_auth_system() -> FirebaseAuthSystem:
    global _firebase_auth_system
    if _firebase_auth_system is None:
        _firebase_auth_system = FirebaseAuthSystem()
    return _firebase_auth_system

