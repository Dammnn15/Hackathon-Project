# 🔐 How to Login - Step by Step Guide

## 🚀 Quick Start (3 Simple Steps):

---

## Step 1: Start the Server

```bash
cd /Users/dachacha/Desktop/Hackathon\ Project/backend
python app.py
```

Wait for:
```
✅ Firebase Authentication System initialized
✅ Firestore client connected
🚀 Server running on http://127.0.0.1:5000
```

---

## Step 2: Register a New User

### **Option A: Using Web Browser** (Recommended)

1. Open your browser
2. Go to: **`http://127.0.0.1:5000/register`**
3. Fill in the form:
   - **Username:** `john` (or any name you want)
   - **Email:** `john@example.com`
   - **Password:** `password123` (min 6 characters)
   - **Confirm Password:** `password123`
4. Click **"Create Account"**
5. You'll see: ✅ "Registration successful! Redirecting to login..."
6. Wait 2 seconds → Auto-redirected to login page

### **Option B: Using Terminal (Quick)**

```bash
curl -X POST "http://127.0.0.1:5000/api/register" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "password123"
  }'
```

Expected response:
```json
{
  "success": true,
  "message": "Registration successful"
}
```

---

## Step 3: Login

### **Using Web Browser** (Recommended)

1. Go to: **`http://127.0.0.1:5000/login`**
2. Enter your credentials:
   - **Username:** `john`
   - **Password:** `password123`
3. Click **"🔓 Login"**
4. You'll see: ✅ "Login successful! Redirecting..."
5. Automatically redirected to dashboard!

### **Using Terminal:**

```bash
curl -X POST "http://127.0.0.1:5000/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "john",
    "password": "password123"
  }'
```

Expected response:
```json
{
  "success": true,
  "message": "Login successful",
  "redirect": "/dashboard"
}
```

---

## ✅ After Login:

You'll be redirected to: **`http://127.0.0.1:5000/dashboard`**

You'll see:
```
🎉 Welcome, john!
You're successfully logged in

📋 Your Account Information
- Username: john
- Email: john@example.com
- Account Created: 2025-12-02
- Last Login: Just now

Access to:
🔬 Security Lab
📡 Live Monitor  
🔧 Rule Review
```

---

## 🎯 Complete Example:

### **Terminal Commands (Full Flow):**

```bash
# 1. Start server
cd /Users/dachacha/Desktop/Hackathon\ Project/backend
python app.py

# 2. In another terminal - Register user
curl -X POST "http://127.0.0.1:5000/api/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"john","email":"john@example.com","password":"password123"}'

# 3. Login
curl -X POST "http://127.0.0.1:5000/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"john","password":"password123"}' \
  -c cookies.txt

# 4. Access dashboard (with session)
curl -b cookies.txt "http://127.0.0.1:5000/dashboard"
```

---

## 🌐 URLs:

| Page | URL | Purpose |
|------|-----|---------|
| **Register** | `http://127.0.0.1:5000/register` | Create account |
| **Login** | `http://127.0.0.1:5000/login` | Authenticate |
| **Dashboard** | `http://127.0.0.1:5000/dashboard` | Success page (protected) |
| **Logout** | `http://127.0.0.1:5000/logout` | End session |

---

## 🧪 Test Scenarios:

### **Test 1: Register & Login**
```
1. Register at /register
   Username: testuser
   Email: test@example.com
   Password: test123456

2. Login at /login
   Username: testuser
   Password: test123456

3. Access dashboard
   → ✅ Success! Welcome page shown
```

### **Test 2: Wrong Password**
```
1. Login with:
   Username: testuser
   Password: wrongpassword

2. Result:
   ❌ Invalid username or password
```

### **Test 3: Try Dashboard Without Login**
```
1. Open: http://127.0.0.1:5000/dashboard
2. Result:
   → Redirected to /login
   → Must authenticate first!
```

### **Test 4: Attack Detection**
```
1. Try registering:
   Username: admin' OR 1=1 --
   
2. Result:
   🚨 Invalid input detected
   → Attack blocked!
```

---

## 🔍 What Happens Behind the Scenes:

### **Registration:**
```
1. You submit form
2. System checks for SQL/XSS attacks
3. If clean → Hash password with salt
4. Save to Firebase users collection
5. Success message shown
```

### **Login:**
```
1. You enter credentials
2. System checks for attacks
3. Query Firebase for username
4. Verify password hash
5. Generate session token (64 bytes)
6. Save session to Firebase
7. Store token in browser cookie
8. Redirect to dashboard
```

### **Dashboard Access:**
```
1. Browser sends session token
2. System verifies token in Firebase
3. If valid → Load user data
4. Render dashboard with user info
```

---

## 📊 Terminal Output Examples:

### **Successful Registration:**
```
✅ User created in Firebase: john (ID: kJ8sK2jD9sKd)
```

### **Successful Login:**
```
✅ Session created in Firebase for user kJ8sK2jD9sKd
✅ User logged in (Firebase): john from 127.0.0.1
```

### **Attack Blocked:**
```
🚨 BLOCKED malicious login attempt from 127.0.0.1
```

---

## ⚠️ Common Issues:

### **Issue 1: "Invalid username or password"**
- Check spelling (usernames are case-sensitive)
- Make sure you registered first
- Verify password is correct

### **Issue 2: "Account locked"**
- You failed login 5 times
- Wait 15 minutes or register new account

### **Issue 3: Redirected to login**
- Your session expired (24 hours)
- Just login again

### **Issue 4: "Username already exists"**
- Someone already used that username
- Try a different username

---

## 🎯 Quick Reference:

### **First Time User:**
```
1. /register → Create account
2. /login → Enter credentials  
3. /dashboard → Success page!
```

### **Returning User:**
```
1. /login → Enter credentials
2. /dashboard → Welcome back!
```

### **Test Attacks:**
```
1. /login-testing → Old test page
   (No authentication required)
```

---

## ✅ You Have 2 Registered Users Already!

From the database check, you already have:

| Username | Email | Status |
|----------|-------|--------|
| `damm` | `dam@gmail.com` | ✅ Active |
| `div` | `dam2@gmail.com` | ✅ Active |

**Try logging in with these!** (if you remember the passwords)

Or register a new user!

---

## 🚀 START NOW:

### **Browser Method (Easy):**
```
1. Open: http://127.0.0.1:5000/register
2. Create account
3. Login at: http://127.0.0.1:5000/login
4. Access dashboard!
```

### **Terminal Method:**
```bash
# Register
curl -X POST "http://127.0.0.1:5000/api/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"john","email":"john@example.com","password":"password123"}'

# Login
curl -X POST "http://127.0.0.1:5000/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"john","password":"password123"}'
```

---

## 🎉 Summary:

✅ **Register:** `/register` → Create username + password  
✅ **Login:** `/login` → Enter credentials  
✅ **Dashboard:** `/dashboard` → Success page (auto-redirected)  
✅ **Only registered users** can access  
✅ **Sessions last 24 hours**  
✅ **Data stored in Firebase**  

**Just open `http://127.0.0.1:5000/register` and create your account!** 🚀

