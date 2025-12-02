"""
Firebase Data Manager
Stores all user authentication and security data in Firebase Firestore
"""
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timedelta
import hashlib
import secrets
import os
from typing import Optional, Dict, Tuple, List
from dotenv import load_dotenv

load_dotenv()

class FirebaseDataManager:
    """Manage all data in Firebase Firestore"""
    
    def __init__(self):
        self.db = None
        self._init_firebase()
    
    def _init_firebase(self):
        """Initialize Firebase connection"""
        try:
            # Check if Firebase is already initialized
            firebase_admin.get_app()
            print("✅ Firebase already initialized")
        except ValueError:
            # Initialize Firebase
            try:
                # Try environment variables first
                if os.getenv('FIREBASE_PROJECT_ID'):
                    cred_dict = {
                        "type": os.getenv('FIREBASE_TYPE'),
                        "project_id": os.getenv('FIREBASE_PROJECT_ID'),
                        "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
                        "private_key": os.getenv('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
                        "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
                        "client_id": os.getenv('FIREBASE_CLIENT_ID'),
                        "auth_uri": os.getenv('FIREBASE_AUTH_URI'),
                        "token_uri": os.getenv('FIREBASE_TOKEN_URI'),
                        "auth_provider_x509_cert_url": os.getenv('FIREBASE_AUTH_PROVIDER_CERT_URL'),
                        "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_CERT_URL'),
                        "universe_domain": os.getenv('FIREBASE_UNIVERSE_DOMAIN', 'googleapis.com')
                    }
                    cred = credentials.Certificate(cred_dict)
                    print("✅ Loading Firebase credentials from environment variables")
                else:
                    # Fallback to service account key file
                    cred = credentials.Certificate("serviceAccountKey.json")
                    print("✅ Loading Firebase credentials from serviceAccountKey.json")
                
                firebase_admin.initialize_app(cred)
                print("✅ Firebase initialized successfully")
            except Exception as e:
                print(f"❌ Firebase initialization error: {e}")
                raise
        
        self.db = firestore.client()
        print("✅ Firestore client connected")
    
    # ==================== USER MANAGEMENT ====================
    
    def create_user(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """
        Create a new user in Firebase
        
        Returns: (success, message)
        """
        try:
            # Check if user already exists
            users_ref = self.db.collection('users')
            
            # Check username
            username_query = users_ref.where('username', '==', username).limit(1).get()
            if len(list(username_query)) > 0:
                return False, "Username already exists"
            
            # Check email
            email_query = users_ref.where('email', '==', email).limit(1).get()
            if len(list(email_query)) > 0:
                return False, "Email already exists"
            
            # Generate salt and hash password
            salt = secrets.token_hex(32)
            password_hash = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
            
            # Create user document
            user_data = {
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'salt': salt,
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': None,
                'is_active': True,
                'login_attempts': 0,
                'locked_until': None
            }
            
            # Add to Firestore
            doc_ref = users_ref.add(user_data)
            user_id = doc_ref[1].id
            
            print(f"✅ User created in Firebase: {username} (ID: {user_id})")
            return True, "Registration successful"
            
        except Exception as e:
            print(f"❌ Error creating user: {e}")
            return False, f"Registration failed: {str(e)}"
    
    def verify_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """
        Verify user credentials
        
        Returns: (success, user_data)
        """
        try:
            users_ref = self.db.collection('users')
            query = users_ref.where('username', '==', username).limit(1).get()
            
            users_list = list(query)
            if len(users_list) == 0:
                return False, None
            
            user_doc = users_list[0]
            user_data = user_doc.to_dict()
            user_data['id'] = user_doc.id
            
            # Check if account is locked
            if user_data.get('locked_until'):
                lock_time = user_data['locked_until']
                if isinstance(lock_time, datetime) and datetime.now() < lock_time:
                    return False, None
            
            # Check if account is active
            if not user_data.get('is_active', True):
                return False, None
            
            # Verify password
            salt = user_data['salt']
            stored_hash = user_data['password_hash']
            provided_hash = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
            
            if provided_hash == stored_hash:
                # Reset login attempts on successful login
                user_doc.reference.update({
                    'login_attempts': 0,
                    'locked_until': None,
                    'last_login': firestore.SERVER_TIMESTAMP
                })
                return True, user_data
            else:
                # Increment login attempts
                login_attempts = user_data.get('login_attempts', 0) + 1
                update_data = {'login_attempts': login_attempts}
                
                # Lock account after 5 failed attempts
                if login_attempts >= 5:
                    locked_until = datetime.now() + timedelta(minutes=15)
                    update_data['locked_until'] = locked_until
                
                user_doc.reference.update(update_data)
                return False, None
                
        except Exception as e:
            print(f"❌ Error verifying user: {e}")
            return False, None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user data by ID"""
        try:
            doc_ref = self.db.collection('users').document(user_id)
            doc = doc_ref.get()
            
            if doc.exists:
                user_data = doc.to_dict()
                user_data['id'] = doc.id
                return user_data
            return None
        except Exception as e:
            print(f"❌ Error getting user: {e}")
            return None
    
    def get_all_users(self) -> List[Dict]:
        """Get all users"""
        try:
            users_ref = self.db.collection('users')
            docs = users_ref.order_by('created_at', direction=firestore.Query.DESCENDING).stream()
            
            users = []
            for doc in docs:
                user_data = doc.to_dict()
                user_data['id'] = doc.id
                users.append(user_data)
            
            return users
        except Exception as e:
            print(f"❌ Error getting users: {e}")
            return []
    
    # ==================== SESSION MANAGEMENT ====================
    
    def create_session(self, user_id: str, session_token: str, ip_address: str, user_agent: str) -> bool:
        """Create a new session"""
        try:
            expires_at = datetime.now() + timedelta(hours=24)
            
            session_data = {
                'user_id': user_id,
                'session_token': session_token,
                'created_at': firestore.SERVER_TIMESTAMP,
                'expires_at': expires_at,
                'ip_address': ip_address,
                'user_agent': user_agent
            }
            
            self.db.collection('sessions').add(session_data)
            print(f"✅ Session created in Firebase for user {user_id}")
            return True
        except Exception as e:
            print(f"❌ Error creating session: {e}")
            return False
    
    def verify_session(self, session_token: str) -> Optional[Dict]:
        """Verify if session is valid"""
        try:
            sessions_ref = self.db.collection('sessions')
            query = sessions_ref.where('session_token', '==', session_token).limit(1).get()
            
            sessions_list = list(query)
            if len(sessions_list) == 0:
                return None
            
            session_doc = sessions_list[0]
            session_data = session_doc.to_dict()
            
            # Check expiration
            expires_at = session_data['expires_at']
            if isinstance(expires_at, datetime) and datetime.now() >= expires_at:
                # Session expired, delete it
                session_doc.reference.delete()
                return None
            
            # Get user data
            user_data = self.get_user_by_id(session_data['user_id'])
            if user_data:
                return {
                    'user_id': session_data['user_id'],
                    'username': user_data['username'],
                    'expires_at': expires_at
                }
            return None
        except Exception as e:
            print(f"❌ Error verifying session: {e}")
            return None
    
    def delete_session(self, session_token: str) -> bool:
        """Delete a session (logout)"""
        try:
            sessions_ref = self.db.collection('sessions')
            query = sessions_ref.where('session_token', '==', session_token).limit(1).get()
            
            for doc in query:
                doc.reference.delete()
                print(f"✅ Session deleted from Firebase")
                return True
            return False
        except Exception as e:
            print(f"❌ Error deleting session: {e}")
            return False
    
    # ==================== LOGIN HISTORY ====================
    
    def log_login_attempt(self, username: str, user_id: Optional[str], success: bool, 
                         ip_address: str, reason: str) -> bool:
        """Log a login attempt"""
        try:
            log_data = {
                'username': username,
                'user_id': user_id,
                'success': success,
                'ip_address': ip_address,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'reason': reason
            }
            
            self.db.collection('login_history').add(log_data)
            return True
        except Exception as e:
            print(f"❌ Error logging login attempt: {e}")
            return False
    
    def get_login_history(self, user_id: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Get login history"""
        try:
            history_ref = self.db.collection('login_history')
            
            if user_id:
                query = history_ref.where('user_id', '==', user_id).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
            else:
                query = history_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
            
            docs = query.stream()
            
            history = []
            for doc in docs:
                entry = doc.to_dict()
                entry['id'] = doc.id
                history.append(entry)
            
            return history
        except Exception as e:
            print(f"❌ Error getting login history: {e}")
            return []
    
    # ==================== SECURITY VERDICTS ====================
    
    def save_verdict(self, verdict_data: Dict) -> str:
        """Save security verdict to Firebase"""
        try:
            verdict_data['timestamp'] = firestore.SERVER_TIMESTAMP
            doc_ref = self.db.collection('security_verdicts').add(verdict_data)
            verdict_id = doc_ref[1].id
            return verdict_id
        except Exception as e:
            print(f"❌ Error saving verdict: {e}")
            return "0"
    
    def get_recent_verdicts(self, limit: int = 50) -> List[Dict]:
        """Get recent security verdicts"""
        try:
            verdicts_ref = self.db.collection('security_verdicts')
            query = verdicts_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
            docs = query.stream()
            
            verdicts = []
            for doc in docs:
                verdict = doc.to_dict()
                verdict['id'] = doc.id
                verdicts.append(verdict)
            
            return verdicts
        except Exception as e:
            print(f"❌ Error getting verdicts: {e}")
            return []


# Singleton instance
_firebase_manager = None

def get_firebase_manager() -> FirebaseDataManager:
    global _firebase_manager
    if _firebase_manager is None:
        _firebase_manager = FirebaseDataManager()
    return _firebase_manager

