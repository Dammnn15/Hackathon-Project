"""
Admin Setter - Set admin privileges for users
"""
from firebase_admin import auth

def set_admin():
    email = input("Enter user email to make admin: ")
    
    try:
        user = auth.get_user_by_email(email)
        auth.set_custom_user_claims(user.uid, {'admin': True})
        print(f"✅ Admin privileges granted to {email}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    set_admin()

