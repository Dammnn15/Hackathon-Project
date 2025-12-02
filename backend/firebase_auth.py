import firebase_admin
from firebase_admin import credentials, auth
from functools import wraps
from flask import request, redirect, url_for
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Firebase
def initialize_firebase():
    """Initialize Firebase using environment variables or JSON file"""
    
    # Try environment variables first
    if os.getenv('FIREBASE_PROJECT_ID'):
        print("🔐 Loading Firebase credentials from environment variables...")
        firebase_credentials = {
            "type": os.getenv('FIREBASE_TYPE', 'service_account'),
            "project_id": os.getenv('FIREBASE_PROJECT_ID'),
            "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
            "private_key": os.getenv('FIREBASE_PRIVATE_KEY', '').replace('\\n', '\n'),
            "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
            "client_id": os.getenv('FIREBASE_CLIENT_ID'),
            "auth_uri": os.getenv('FIREBASE_AUTH_URI', 'https://accounts.google.com/o/oauth2/auth'),
            "token_uri": os.getenv('FIREBASE_TOKEN_URI', 'https://oauth2.googleapis.com/token'),
            "auth_provider_x509_cert_url": os.getenv('FIREBASE_AUTH_PROVIDER_CERT_URL'),
            "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_CERT_URL'),
            "universe_domain": os.getenv('FIREBASE_UNIVERSE_DOMAIN', 'googleapis.com')
        }
        cred = credentials.Certificate(firebase_credentials)
        print("✅ Firebase credentials loaded from .env")
    
    # Fallback to serviceAccountKey.json
    elif os.path.exists("serviceAccountKey.json"):
        print("🔐 Loading Firebase credentials from serviceAccountKey.json...")
        cred = credentials.Certificate("serviceAccountKey.json")
        print("✅ Firebase credentials loaded from serviceAccountKey.json")
    else:
        raise Exception("❌ No Firebase credentials found!")
    
    firebase_admin.initialize_app(cred)
    print("🔥 Firebase initialized!\n")

initialize_firebase()

def verify_firebase_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        id_token = request.cookies.get("token")
        if not id_token:
            return redirect(url_for("login"))
        try:
            decoded = auth.verify_id_token(id_token)
            request.user = decoded
        except Exception:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = getattr(request, "user", None)
        if not user:
            return redirect(url_for("login"))
        try:
            auth.get_user(user["uid"])
        except:
            return redirect(url_for("unauthorized"))
        return func(*args, **kwargs)
    return wrapper

