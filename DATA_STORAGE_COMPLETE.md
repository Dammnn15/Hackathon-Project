# 📊 Complete Data Storage Guide

## ☁️ ALL Data Stored in Firebase Cloud!

---

## 🗺️ Storage Architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    YOUR FLASK APPLICATION                       │
│                 (Running on 127.0.0.1:5000)                     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ Firebase Admin SDK
                         │ (serviceAccountKey.json)
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  ☁️  GOOGLE FIREBASE CLOUD ☁️                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📦 FIRESTORE DATABASE                                          │
│  └─ Project: Your Firebase Project                             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Collection: users 👤                                    │  │
│  │  ├─ Document: kJ8sK2jD9sKd (john_doe)                   │  │
│  │  ├─ Document: mL9dN3pF8qRs (jane_smith)                 │  │
│  │  └─ Document: nK7eP4rG9sTv (bob_wilson)                 │  │
│  │                                                          │  │
│  │  Stores: username, email, password_hash, salt, etc.     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Collection: sessions 🔐                                 │  │
│  │  ├─ Document: sK9dL3mF7pQr (john_doe's session)         │  │
│  │  └─ Document: tL8eM4nG8qRs (jane_smith's session)       │  │
│  │                                                          │  │
│  │  Stores: session_token, user_id, expires_at, IP, etc.   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Collection: login_history 📊                            │  │
│  │  ├─ Document: hK7jL9mN2pQs (login attempt #1)           │  │
│  │  ├─ Document: iL8kM0nO3qRt (login attempt #2)           │  │
│  │  └─ Document: jM9lN1oP4rSu (login attempt #3)           │  │
│  │                                                          │  │
│  │  Stores: username, success, IP, timestamp, reason       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Collection: security_verdicts 🛡️                        │  │
│  │  ├─ Document: vK8dL2mF9pQr (SQL injection #1)           │  │
│  │  ├─ Document: wL9eM3nG0qRs (XSS attack #2)              │  │
│  │  └─ Document: xM0fN4oH1rSt (Command injection #3)       │  │
│  │                                                          │  │
│  │  Stores: verdict, attack_type, confidence, payload      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Detailed Data Structure:

### **1. users Collection** 👤

**What:** All registered user accounts

**Document Structure:**
```javascript
Document ID: kJ8sK2jD9sKd  // Auto-generated by Firebase
{
  username: "john_doe",
  email: "john@example.com",
  password_hash: "a1b2c3d4e5f6...",  // SHA-256 hash
  salt: "g7h8i9j0k1l2...",            // 32-byte random salt
  created_at: Timestamp(2025-12-02 12:00:00),
  last_login: Timestamp(2025-12-02 15:30:00),
  is_active: true,
  login_attempts: 0,
  locked_until: null
}
```

**Queries:**
- Get user by username
- Get all users
- Check for duplicates
- Update login attempts

---

### **2. sessions Collection** 🔐

**What:** Active login sessions (24-hour validity)

**Document Structure:**
```javascript
Document ID: sK9dL3mF7pQr  // Auto-generated
{
  user_id: "kJ8sK2jD9sKd",         // Links to users collection
  session_token: "xyz789abc456...", // 64-byte secure token
  created_at: Timestamp(2025-12-02 15:30:00),
  expires_at: Timestamp(2025-12-03 15:30:00),  // +24 hours
  ip_address: "192.168.1.100",
  user_agent: "Mozilla/5.0 (Macintosh; ..."
}
```

**Queries:**
- Verify session token
- Delete expired sessions
- Get user's active sessions

---

### **3. login_history Collection** 📊

**What:** Complete log of all login attempts

**Document Structure:**
```javascript
Document ID: hK7jL9mN2pQs  // Auto-generated
{
  username: "john_doe",
  user_id: "kJ8sK2jD9sKd",      // null if user doesn't exist
  success: true,                  // true = successful, false = failed
  ip_address: "192.168.1.100",
  timestamp: Timestamp(2025-12-02 15:30:00),
  reason: "Successful login"     // or "Invalid password", "Account locked", etc.
}
```

**Queries:**
- Get all login attempts for a user
- Get recent failures
- Track IP addresses
- Analyze attack patterns

---

### **4. security_verdicts Collection** 🛡️

**What:** All detected attacks and payloads

**Document Structure:**
```javascript
Document ID: vK8dL2mF9pQr  // Auto-generated
{
  verdict: "DROP",               // DROP, UNKNOWN, or PASS
  attack_type: "SQL Injection",
  confidence: 85.0,
  payload: "admin' OR 1=1 --",
  source_ip: "203.0.113.45",
  timestamp: Timestamp(2025-12-02 15:31:00),
  matched_rules: [
    { name: "SQL Injection - OR 1=1" },
    { name: "SQL Injection - Comment" }
  ],
  is_anomaly: false,
  reason: "High confidence attack detected"
}
```

**Queries:**
- Get recent attacks
- Filter by verdict type (DROP/UNKNOWN/PASS)
- Search by IP address
- Get statistics (count by type)

---

## 🔄 Complete Data Flow Example:

### **User Registration:**

```
1. User fills form at /register
   ├─ Username: john_doe
   ├─ Email: john@example.com
   └─ Password: mypass123
   
2. POST to /api/register
   
3. firebase_auth_system.register_user()
   ├─ Validate input (length, format)
   ├─ Check for attacks (SQL/XSS)
   └─ Call firebase_data_manager.create_user()
   
4. firebase_data_manager.create_user()
   ├─ Query Firebase for duplicates
   ├─ Generate salt: "d4e5f6..."
   ├─ Hash password: SHA-256(password + salt)
   └─ Create document in Firebase users collection
   
5. Firebase Firestore ☁️
   └─ User document created with ID: "kJ8sK2jD9sKd"
   
6. Response to user
   └─ "Registration successful" → Redirect to login
```

### **User Login:**

```
1. User enters credentials at /login
   ├─ Username: john_doe
   └─ Password: mypass123
   
2. POST to /api/auth/login
   
3. firebase_auth_system.login()
   ├─ Check for attacks
   └─ Call firebase_data_manager.verify_user()
   
4. firebase_data_manager.verify_user()
   ├─ Query Firebase users collection by username
   ├─ Get user document: "kJ8sK2jD9sKd"
   ├─ Retrieve salt and password_hash
   ├─ Hash provided password: SHA-256(password + salt)
   ├─ Compare hashes
   └─ If match → Generate session token
   
5. Create Session in Firebase
   ├─ Generate token: "xyz789abc456..."
   ├─ Set expiry: now + 24 hours
   └─ Save to sessions collection
   
6. Log Login Attempt
   └─ Add document to login_history collection
   
7. Response to user
   ├─ Set session cookie
   └─ Redirect to /dashboard
```

### **Access Protected Page:**

```
1. User visits /dashboard
   
2. Flask checks session
   ├─ Get session_token from cookie
   └─ Call firebase_auth_system.verify_session()
   
3. Verify in Firebase
   ├─ Query sessions collection by session_token
   ├─ Check if document exists
   ├─ Check if not expired (< 24 hours)
   └─ Get user_id from session
   
4. Get User Data
   ├─ Query users collection by user_id
   └─ Return user information
   
5. Render Dashboard
   └─ Show user's info (username, email, created_at, etc.)
```

### **Attack Detection:**

```
1. Malicious payload submitted
   └─ Example: "admin' OR 1=1 --"
   
2. AI Anomaly Detection
   ├─ ML model analysis
   ├─ Snort rule matching
   ├─ Ensemble scoring
   └─ Verdict: DROP (85% confidence)
   
3. Save to Firebase
   └─ firebase_data_manager.save_verdict()
   
4. Firebase Firestore ☁️
   └─ Document created in security_verdicts collection
   
5. Display
   ├─ Terminal logging
   ├─ Live monitor (/simple-monitor)
   └─ Rule review (/rule-review)
```

---

## 🔑 Firebase Credentials:

**Your Firebase credentials are in:**
```
backend/serviceAccountKey.json
```

**This file contains:**
- `project_id` - Your Firebase project ID
- `private_key` - Authentication key
- `client_email` - Service account email
- And more...

**Used by:**
- `firebase_data_manager.py` - Initializes connection
- `firebase_auth_system.py` - Uses for authentication
- All data operations go through Firebase Admin SDK

---

## 🎯 Local Files:

```
backend/
├── serviceAccountKey.json       (Firebase credentials - SECRET!)
├── .env                         (Backup credentials)
├── users.db                     (OLD - not used anymore)
└── security_system.db           (OLD - still used for some data)
```

**Note:** Local .db files are being phased out. All new data goes to Firebase!

---

## ☁️ Firebase Console Access:

### **Step 1: Open Firebase Console**
```
https://console.firebase.google.com/
```

### **Step 2: Select Your Project**
Look for the project_id from your `serviceAccountKey.json`

### **Step 3: Navigate to Firestore**
Click "Firestore Database" in the left sidebar

### **Step 4: View Collections**
You'll see:
- `users` - Click to see all registered users
- `sessions` - Click to see active sessions
- `login_history` - Click to see login attempts
- `security_verdicts` - Click to see attack detections

### **Step 5: Real-time Updates**
- Register a user → Appears instantly
- User logs in → Session document created
- Attack detected → Verdict document added

---

## 📈 Data Growth Example:

```
Day 1:
├─ users: 5 documents
├─ sessions: 3 documents
├─ login_history: 8 documents
└─ security_verdicts: 12 documents

Day 7:
├─ users: 25 documents
├─ sessions: 15 documents
├─ login_history: 150 documents
└─ security_verdicts: 300 documents

Firebase handles unlimited growth!
```

---

## ✅ Summary:

| Data Type | Storage Location | Collection Name |
|-----------|-----------------|-----------------|
| **User Accounts** | ☁️ Firebase | `users` |
| **Login Sessions** | ☁️ Firebase | `sessions` |
| **Login Attempts** | ☁️ Firebase | `login_history` |
| **Attack Detections** | ☁️ Firebase | `security_verdicts` |
| **Credentials** | 📁 Local | `serviceAccountKey.json` |

---

## 🎉 Benefits:

✅ **Cloud storage** - Access from anywhere  
✅ **Auto-backup** - Google handles backups  
✅ **Real-time sync** - Instant updates  
✅ **Scalable** - Unlimited users & data  
✅ **Secure** - Enterprise-level security  
✅ **No local .db files** - Clean project structure  
✅ **Firebase Console** - View data in browser  
✅ **Production-ready** - Used by millions of apps  

---

## 🔗 Quick Links:

**View Your Data:**
```
https://console.firebase.google.com/
```

**Documentation:**
- `FIREBASE_DATA_STORAGE.md` - Detailed guide
- `AUTHENTICATION_SYSTEM.md` - Auth flow

---

**All your data is now safely stored in Google's Firebase Cloud!** ☁️🔐

