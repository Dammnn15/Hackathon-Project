# 🔐 User Authentication System

## ✅ Complete Authentication Flow Implemented!

---

## 🎯 Overview:

**Only registered users can log in. After successful authentication, users access a protected dashboard.**

---

## 🚀 Quick Start (3 Steps):

### **Step 1: Register**
```
http://127.0.0.1:5000/register
```
- Create username (min 3 characters)
- Provide email address
- Set password (min 6 characters)
- Click "Create Account"

### **Step 2: Login**
```
http://127.0.0.1:5000/login
```
- Enter your username
- Enter your password
- Click "Login"

### **Step 3: Access Dashboard**
```
http://127.0.0.1:5000/dashboard
```
- Automatically redirected after login
- Protected page - only for authenticated users
- Shows your account info & available features

---

## 🔄 Complete Authentication Flow:

```
┌──────────────────────────────────────────────┐
│  1. User visits http://127.0.0.1:5000/      │
└─────────────────┬────────────────────────────┘
                  │
                  ▼
     ┌────────────────────────┐
     │ Not logged in?         │
     └────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────┐
│  2. Redirect to /login                       │
└─────────────────┬────────────────────────────┘
                  │
                  ▼
     ┌────────────────────────┐
     │ No account yet?        │
     └────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────┐
│  3. Click "Register" → /register             │
│     - Enter username, email, password        │
│     - System checks for SQL/XSS attacks      │
│     - User created in database               │
│     - Password hashed with SHA-256 + salt    │
└─────────────────┬────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────┐
│  4. Registration Success                     │
│     → Redirect to /login                     │
└─────────────────┬────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────┐
│  5. Enter credentials on /login              │
│     - Username & password checked            │
│     - System checks for attacks              │
│     - Password verified (hash comparison)    │
│     - Session token generated (64 bytes)     │
│     - Session expires in 24 hours            │
└─────────────────┬────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────┐
│  6. Login Success                            │
│     → Redirect to /dashboard                 │
└─────────────────┬────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────┐
│  7. Dashboard (Protected Page)               │
│     - Welcome message with username          │
│     - Account information displayed          │
│     - Links to Security Lab, Live Monitor    │
│     - Logout button available                │
└──────────────────────────────────────────────┘
```

---

## 🛡️ Security Features:

### **1. Password Security**
```python
✓ SHA-256 hashing with salt
✓ 32-byte random salt per user
✓ Passwords never stored in plaintext
✓ Minimum 6 characters required
```

### **2. Attack Protection**
```python
✓ SQL injection detection on registration
✓ XSS detection on login
✓ Input validation for username/email
✓ Dangerous character filtering
```

### **3. Account Locking**
```python
✓ Locks after 5 failed attempts
✓ 15-minute lockout period
✓ Attempts reset on successful login
✓ All attempts logged
```

### **4. Session Management**
```python
✓ Secure 64-byte session tokens
✓ 24-hour session expiry
✓ Sessions stored in database
✓ Token verification on protected pages
```

---

## 📊 Database Schema:

### **Users Table:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
)
```

### **Sessions Table:**
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT
)
```

### **Login History Table:**
```sql
CREATE TABLE login_history (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    success BOOLEAN NOT NULL,
    ip_address TEXT,
    timestamp TIMESTAMP,
    reason TEXT
)
```

---

## 🔒 Protected Pages:

### **Dashboard** (`/dashboard`)
- ✅ Requires authentication
- ✅ Redirects to login if not authenticated
- ✅ Shows user information
- ✅ Provides access to all features

### **Future Protected Pages:**
You can easily protect any page:

```python
@app.route("/protected-page")
def protected_page():
    session_token = session.get('session_token')
    
    if not session_token:
        return redirect(url_for("login_page"))
    
    user_data = auth_system.verify_session(session_token)
    
    if not user_data:
        session.clear()
        return redirect(url_for("login_page"))
    
    # User is authenticated
    return render_template("protected.html", user=user_data)
```

---

## 🧪 Testing the System:

### **Test 1: Registration**

1. Go to: `http://127.0.0.1:5000/register`
2. Fill in:
   - Username: `testuser`
   - Email: `test@example.com`
   - Password: `password123`
   - Confirm: `password123`
3. Click "Create Account"
4. See success message
5. Redirected to login

### **Test 2: Login**

1. Go to: `http://127.0.0.1:5000/login`
2. Enter:
   - Username: `testuser`
   - Password: `password123`
3. Click "Login"
4. See success message
5. Redirected to dashboard

### **Test 3: Protected Access**

1. Try accessing: `http://127.0.0.1:5000/dashboard`
2. Without login → Redirected to login page
3. After login → Dashboard displayed

### **Test 4: Logout**

1. On dashboard, click "Logout"
2. Session cleared
3. Redirected to login
4. Try accessing dashboard → Redirected to login

### **Test 5: Attack Detection**

1. Try registering with:
   - Username: `admin' OR 1=1 --`
2. System blocks with error message
3. Attack detected and prevented!

---

## 📈 Login Flow Examples:

### **Successful Login:**
```
Terminal Output:
✅ User logged in: testuser from 127.0.0.1

Browser:
✅ Login successful! Redirecting...
→ Redirect to /dashboard
→ Welcome, testuser!
```

### **Failed Login (Wrong Password):**
```
Terminal Output:
❌ Failed login attempt: testuser from 127.0.0.1 - Invalid password

Browser:
❌ Invalid username or password
```

### **Failed Login (Account Locked):**
```
Terminal Output:
❌ Account locked after 5 failed attempts

Browser:
❌ Too many failed attempts. Account locked for 15 minutes.
```

### **Attack Detected:**
```
Terminal Output:
🚨 BLOCKED malicious login attempt from 127.0.0.1

Browser:
🚨 Security Alert: Invalid login attempt detected.
```

---

## 🎯 API Endpoints:

### **POST `/api/register`**

Register a new user

**Request:**
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "password123"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "Registration successful"
}
```

**Response (Error):**
```json
{
  "success": false,
  "message": "Username already exists"
}
```

### **POST `/api/auth/login`**

Authenticate user

**Request:**
```json
{
  "username": "testuser",
  "password": "password123"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "Login successful",
  "redirect": "/dashboard"
}
```

**Response (Error):**
```json
{
  "success": false,
  "message": "Invalid username or password"
}
```

**Response (Attack):**
```json
{
  "success": false,
  "message": "Invalid login attempt detected.",
  "attack_detected": true
}
```

---

## 📊 Session Management:

### **Session Creation:**
```
1. User logs in successfully
2. Generate 64-byte secure token
3. Store in database with:
   - User ID
   - Expiration time (24 hours)
   - IP address
   - User agent
4. Store token in Flask session
5. Token required for protected pages
```

### **Session Verification:**
```
1. User visits protected page
2. Get session token from Flask session
3. Verify token in database
4. Check expiration time
5. If valid → Allow access
6. If invalid → Redirect to login
```

### **Session Expiry:**
```
✓ Automatic expiry after 24 hours
✓ Manual expiry on logout
✓ Cleared on authentication failure
```

---

## 🔧 Configuration:

### **Password Requirements:**
```python
MIN_USERNAME_LENGTH = 3
MIN_PASSWORD_LENGTH = 6
SESSION_EXPIRY_HOURS = 24
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
```

### **Security Settings:**
```python
PASSWORD_HASH_ALGORITHM = "SHA-256"
SALT_LENGTH = 32  # bytes
SESSION_TOKEN_LENGTH = 64  # bytes
```

---

## 📁 Files Created:

```
✅ backend/auth_system.py (500 lines)
   - AuthSystem class
   - User registration
   - Login authentication
   - Session management
   - Password hashing
   - Account locking

✅ backend/templates/register.html
   - User registration page
   - Form validation
   - Attack detection

✅ backend/templates/login.html (renamed from login_auth.html)
   - Authentication login page
   - Session creation
   - Security alerts

✅ backend/templates/dashboard.html
   - Protected success page
   - User information display
   - Feature access links

✅ backend/templates/login_testing.html (old login.html)
   - Attack testing page
   - No authentication required
```

---

## 📊 Database Files:

```
✅ users.db
   - Created automatically on first run
   - Contains users, sessions, login_history tables
   - SQLite3 format
```

---

## ✅ Security Checklist:

| Feature | Status |
|---------|--------|
| **Password Hashing** | ✅ SHA-256 + Salt |
| **SQL Injection Protection** | ✅ Parameterized queries |
| **XSS Protection** | ✅ Input validation |
| **Session Security** | ✅ Secure tokens |
| **Account Locking** | ✅ 5 attempts / 15 min |
| **Session Expiry** | ✅ 24 hours |
| **Attack Detection** | ✅ AI-powered |
| **Login History** | ✅ All attempts logged |
| **Protected Routes** | ✅ Token verification |

---

## 🎉 Summary:

✅ **Complete authentication system**
✅ **Only registered users can log in**
✅ **Protected dashboard after login**
✅ **Secure password storage (hashed)**
✅ **Session management (24 hours)**
✅ **Account locking (5 attempts)**
✅ **Attack detection on registration/login**
✅ **Login history tracking**
✅ **No unauthorized access**

---

## 🚀 URLs:

```
Register:  http://127.0.0.1:5000/register
Login:     http://127.0.0.1:5000/login
Dashboard: http://127.0.0.1:5000/dashboard (protected)
Logout:    http://127.0.0.1:5000/logout
```

**Your system now has complete user authentication!** 🔐

