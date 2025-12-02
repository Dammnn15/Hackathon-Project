# 🧪 How to Test UNKNOWN Attacks

## 📊 What is UNKNOWN?

**UNKNOWN** = Medium confidence attacks (60-84%) that require admin review.

```
Confidence ≥ 85%  → 🚨 DROP (High confidence - blocked immediately)
Confidence 60-84% → ⚠️ UNKNOWN (Medium confidence - admin review)
Confidence < 60%  → ✅ PASS (Low confidence - allowed)
```

---

## 🎯 How to Generate UNKNOWN Verdicts

### **Method 1: Weak SQL Injection Attempts**

These are SQL patterns that are suspicious but not definitive attacks:

#### **Test 1: Simple Quote**
```
Username: admin'
Password: test
```
**Why UNKNOWN?** Single quote is suspicious but could be typo.

#### **Test 2: Weak OR Pattern**
```
Username: user OR 1
Password: pass
```
**Why UNKNOWN?** Has OR but not complete SQL injection syntax.

#### **Test 3: Comment Without Attack**
```
Username: test--
Password: anything
```
**Why UNKNOWN?** SQL comment but no actual exploit.

#### **Test 4: UNION Without SELECT**
```
Username: admin UNION
Password: test
```
**Why UNKNOWN?** UNION keyword without complete statement.

---

### **Method 2: Weak XSS Attempts**

#### **Test 5: Incomplete Script Tag**
```
Username: <script
Password: test
```
**Why UNKNOWN?** Script tag started but not complete.

#### **Test 6: HTML Without JavaScript**
```
Username: <div onclick>
Password: test
```
**Why UNKNOWN?** Event handler but no actual code.

#### **Test 7: URL Encoding**
```
Username: %3Cscript%3E
Password: test
```
**Why UNKNOWN?** Encoded suspicious pattern.

---

### **Method 3: Obfuscation Attempts**

#### **Test 8: Mixed Encoding**
```
Username: ad\x6Din
Password: test
```
**Why UNKNOWN?** Hex encoding suggests evasion attempt.

#### **Test 9: Unicode Tricks**
```
Username: admin\u0027
Password: test
```
**Why UNKNOWN?** Unicode escape for quote character.

#### **Test 10: Case Mixing**
```
Username: AdMiN' oR 1=1
Password: test
```
**Why UNKNOWN?** Case mixing to evade detection.

---

### **Method 4: Command Injection Hints**

#### **Test 11: Pipe Symbol**
```
Username: user | whoami
Password: test
```
**Why UNKNOWN?** Pipe could be command chaining.

#### **Test 12: Semicolon**
```
Username: admin; ls
Password: test
```
**Why UNKNOWN?** Semicolon suggests command separation.

---

## 🚀 **QUICK TEST NOW:**

### **Step 1: Open Login Page**
```
http://127.0.0.1:5000/login
```

### **Step 2: Open Monitor (New Tab)**
```
http://127.0.0.1:5000/simple-monitor
```

### **Step 3: Test Each Payload**

Try these in order and watch the monitor:

```
1. Username: admin'          → Should get ⚠️ UNKNOWN
2. Username: test--          → Should get ⚠️ UNKNOWN  
3. Username: <script         → Should get ⚠️ UNKNOWN
4. Username: user OR 1       → Should get ⚠️ UNKNOWN
5. Username: admin UNION     → Should get ⚠️ UNKNOWN
```

---

## 📋 **Expected Results:**

### **Monitor Display:**

```
⚠️ 1. VERDICT: UNKNOWN | CONFIDENCE: 65% | TYPE: SQL Injection
PAYLOAD: Login: U=admin' P=****
ID: #45 | IP: 127.0.0.1 | TIME: 1:05:30 AM

⚠️ 2. VERDICT: UNKNOWN | CONFIDENCE: 72% | TYPE: potential_obfuscation
PAYLOAD: Login: U=test-- P=****
ID: #46 | IP: 127.0.0.1 | TIME: 1:05:32 AM

⚠️ 3. VERDICT: UNKNOWN | CONFIDENCE: 68% | TYPE: XSS
PAYLOAD: Login: U=<script P=****
ID: #47 | IP: 127.0.0.1 | TIME: 1:05:34 AM
```

### **Terminal Display:**

```
==================================================================
🔐 INCOMING LOGIN FORM SUBMISSION
==================================================================
Username: admin'
Password: ****
Source IP: 127.0.0.1
==================================================================

==================================================================
🤖 AI DETECTION RESULTS
==================================================================
📊 VERDICTS:
   Username Field: UNKNOWN (65.0%)
   Password Field: PASS (0.0%)
   Combined Analysis: UNKNOWN (65.0%)

🎯 FINAL VERDICT: UNKNOWN
   Confidence: 65.0%
   Attack Type: SQL Injection
   AI Risk Score: 68/100
   Threat Level: medium

🛡️  DETECTED ATTACK PATTERNS:
   ✓ SQL_QUOTE_ANOMALY

📝 REASON: Moderate confidence attack (65.0%). Requires admin review.
💾 Verdict ID: 45
==================================================================
```

---

## 🎯 **Filter to See Only UNKNOWN:**

On the monitor page, click the **"⚠️ UNKNOWN"** filter button to see only medium-confidence attacks!

---

## 📊 **Confidence Score Breakdown:**

| Payload | Expected Confidence | Verdict |
|---------|-------------------|---------|
| `admin' OR 1=1 --` | 90-100% | 🚨 DROP |
| `admin'` | 60-75% | ⚠️ UNKNOWN |
| `test--` | 65-80% | ⚠️ UNKNOWN |
| `<script>alert(1)</script>` | 85-95% | 🚨 DROP |
| `<script` | 60-70% | ⚠️ UNKNOWN |
| `normal_user` | 0-30% | ✅ PASS |

---

## 🧪 **Advanced UNKNOWN Test Cases:**

### **Multiple Weak Indicators:**

```
Username: admin' -- test
Password: pass123

Result: UNKNOWN (multiple weak SQL patterns)
Confidence: ~75%
```

### **Partial XSS:**

```
Username: <img src=x
Password: test

Result: UNKNOWN (incomplete XSS)
Confidence: ~70%
```

### **Path Traversal Hint:**

```
Username: ../
Password: test

Result: UNKNOWN (directory traversal pattern)
Confidence: ~65%
```

### **SQL Function Name:**

```
Username: SELECT
Password: test

Result: UNKNOWN (SQL keyword but no exploit)
Confidence: ~60%
```

---

## 🔍 **How to Verify UNKNOWN is Working:**

### **What You Should See:**

✅ **In Terminal:**
```
🎯 FINAL VERDICT: UNKNOWN
   Confidence: 60.0% - 84.9%
   Threat Level: medium
```

✅ **In Monitor:**
```
⚠️ VERDICT: UNKNOWN | CONFIDENCE: 60-84%
(Orange colored border)
```

✅ **In Filter:**
```
Click "⚠️ UNKNOWN" button to see only these
```

---

## 🎨 **Visual Indicators:**

| Type | Color | Symbol |
|------|-------|--------|
| DROP | 🔴 Red | 🚨 |
| **UNKNOWN** | **🟠 Orange** | **⚠️** |
| PASS | 🟢 Green | ✅ |
| TRAFFIC | 🔵 Blue | 📡 |

---

## 🚀 **START TESTING NOW:**

```bash
# Step 1: Open monitor
http://127.0.0.1:5000/simple-monitor

# Step 2: Open login
http://127.0.0.1:5000/login

# Step 3: Try these payloads:
Username: admin'     → ⚠️ UNKNOWN
Username: test--     → ⚠️ UNKNOWN
Username: <script    → ⚠️ UNKNOWN
Username: user OR 1  → ⚠️ UNKNOWN
```

---

## 📈 **Pro Tips:**

### **To Get More UNKNOWN Verdicts:**

1. **Use incomplete attack patterns**
   - Half-finished SQL: `admin'`, `test--`
   - Partial XSS: `<script`, `<img`

2. **Mix legitimate with suspicious**
   - `john' OR`
   - `user<test>`

3. **Use single suspicious keyword**
   - `SELECT`
   - `UNION`
   - `<iframe`

4. **Add minor obfuscation**
   - `ad\x6Din`
   - `%27test%27`

### **To Get DROP Instead:**

- Complete the attack:
  - `admin' OR 1=1 --` (full SQL injection)
  - `<script>alert(1)</script>` (full XSS)

### **To Get PASS:**

- Use normal text:
  - `john`
  - `user123`
  - `test@email.com`

---

## ✅ **Verification Checklist:**

Test each and mark when you see UNKNOWN:

- [ ] `admin'` → Should be UNKNOWN (~65%)
- [ ] `test--` → Should be UNKNOWN (~70%)
- [ ] `<script` → Should be UNKNOWN (~68%)
- [ ] `user OR 1` → Should be UNKNOWN (~72%)
- [ ] `admin UNION` → Should be UNKNOWN (~75%)
- [ ] `<img src=x` → Should be UNKNOWN (~70%)
- [ ] `../` → Should be UNKNOWN (~65%)
- [ ] `SELECT` → Should be UNKNOWN (~60%)

---

## 🎉 **That's It!**

**UNKNOWN verdicts** are the "suspicious but not certain" category that requires human review.

**Just test with incomplete/weak attack patterns and watch them appear in orange on your monitor!** ⚠️🟠
