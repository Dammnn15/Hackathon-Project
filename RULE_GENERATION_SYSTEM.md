# 🔧 Auto Rule Generation & Learning System

## 🎉 NEW FEATURE: System Learns from Attacks!

Your anomaly detection system now **automatically learns** from detected attacks and improves its accuracy over time!

---

## 🎯 How It Works:

```
┌─────────────────────────────────────────────────────────────┐
│  1. User submits attack (SQL injection, XSS, etc.)         │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  2. AI detects attack → Verdict: DROP or UNKNOWN           │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  3. System AUTO-GENERATES rule from attack patterns        │
│     • Extracts SQL keywords, XSS tags, obfuscation         │
│     • Creates rule signature                                │
│     • Assigns severity level                                │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Rule sent to Review Dashboard (PENDING status)         │
│     http://127.0.0.1:5000/rule-review                      │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  5. Admin reviews and APPROVES rule                         │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  6. Rule becomes ACTIVE                                      │
│     • Boosts confidence for similar attacks                 │
│     • Improves detection accuracy                           │
│     • System gets smarter!                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Getting Started:

### **Step 1: Generate an Attack**

Go to login page and test an attack:
```
http://127.0.0.1:5000/login

Username: admin' OR 1=1 --
Password: anything
```

### **Step 2: Check Terminal**

You'll see:
```
==================================================================
🤖 AI DETECTION RESULTS
==================================================================
🎯 FINAL VERDICT: DROP
   Confidence: 90.0%
   Attack Type: SQL Injection

🔧 AUTO-GENERATED RULE #1000 from DROP verdict
   Patterns: SQL_KEYWORD_OR, SQL_COMMENT, SQL_ALWAYS_TRUE...
   Status: Pending review at /rule-review
==================================================================
```

### **Step 3: Review the Rule**

Open the Rule Review Dashboard:
```
http://127.0.0.1:5000/rule-review
```

You'll see the auto-generated rule with:
- Rule ID
- Attack type
- Severity level
- Detected patterns
- Original payload
- Approve/Reject buttons

### **Step 4: Approve the Rule**

Click **"✅ Approve & Activate"**

The rule is now ACTIVE!

### **Step 5: Test Again**

Submit a similar attack - it will be detected **faster and with higher confidence**!

---

## 📊 Rule Review Dashboard:

### **Features:**

| Feature | Description |
|---------|-------------|
| **Pending Review** | All auto-generated rules awaiting approval |
| **Approved Rules** | Active rules boosting detection |
| **Statistics** | Total/Pending/Approved/Rejected counts |
| **Auto-Refresh** | Updates every 5 seconds |
| **Export** | Download rules in Snort format |

### **Dashboard URL:**
```
http://127.0.0.1:5000/rule-review
```

---

## 🎯 What Gets Extracted:

### **SQL Injection Patterns:**
```
✓ SQL Keywords: UNION, SELECT, INSERT, UPDATE, DELETE
✓ SQL Comments: --, /* */
✓ SQL Operators: OR, AND
✓ Always-True Conditions: 1=1, '1'='1'
✓ String Concatenation: ||, &&
```

### **XSS Patterns:**
```
✓ Script Tags: <script>
✓ Event Handlers: onerror, onload, onclick
✓ JavaScript Protocol: javascript:
✓ Dangerous Tags: <iframe>, <embed>, <img>
✓ JavaScript Functions: alert, eval, prompt
```

### **Obfuscation Patterns:**
```
✓ Hex Encoding: \x41
✓ Unicode Encoding: \u0041
✓ URL Encoding: %41
✓ Base64: YWRtaW4=
✓ Mixed Case: AdMiN
```

### **Generic Patterns:**
```
✓ Path Traversal: ../, ..\\
✓ Command Injection: |, ;, &&
✓ Null Bytes: \x00, %00
```

---

## 🔍 Example Rule Generation:

### **Attack Submitted:**
```
Username: admin' UNION SELECT * FROM users --
Password: test
```

### **Auto-Generated Rule:**
```json
{
  "rule_id": 1000,
  "name": "SQL Injection - Pattern 1000",
  "attack_type": "SQL Injection",
  "severity": "CRITICAL",
  "confidence": 90.0,
  "patterns": [
    "SQL_KEYWORD_UNION",
    "SQL_KEYWORD_SELECT",
    "SQL_COMMENT",
    "SQL_OR_OPERATOR"
  ],
  "status": "pending",
  "snort_format": "alert tcp any any -> any any (msg:\"SQL Injection - CRITICAL\"; content:\"SQL_KEYWORD_UNION; SQL_KEYWORD_SELECT; ...\"; sid:1000; rev:1;)"
}
```

---

## 📈 Accuracy Improvement:

### **Before Approval:**
```
Attack: admin' UNION SELECT
Confidence: 70%
Verdict: UNKNOWN
```

### **After Approval:**
```
Attack: admin' UNION SELECT
Confidence: 70% + 15% boost = 85%
Verdict: DROP (upgraded!)
Reason: Attack confirmed by generated rules
```

---

## 🎯 Confidence Boost System:

| Rule Severity | Confidence Boost |
|---------------|------------------|
| CRITICAL | +15% |
| HIGH | +10% |
| MEDIUM | +5% |
| LOW | +0% |

**Maximum boost: +25%** (multiple rules can stack)

---

## 🔧 API Endpoints:

### **Generate Rule from Attack:**
```bash
POST /api/rules/generate
{
  "payload": "admin' OR 1=1 --",
  "attack_type": "SQL Injection",
  "confidence": 85.0,
  "verdict_id": 123
}
```

### **Get Pending Rules:**
```bash
GET /api/rules/pending
```

### **Approve Rule:**
```bash
POST /api/rules/approve/1000
```

### **Reject Rule:**
```bash
POST /api/rules/reject/1000
{
  "reason": "False positive"
}
```

### **Get Statistics:**
```bash
GET /api/rules/stats
```

### **Export Rules (Snort Format):**
```bash
GET /api/rules/export
```

---

## 🧪 Testing the System:

### **Test 1: Generate Multiple Rules**

```bash
# SQL Injection attacks
1. admin' OR 1=1 --
2. ' UNION SELECT * FROM users --
3. admin'; DROP TABLE users --

# XSS attacks
4. <script>alert('XSS')</script>
5. <img src=x onerror=alert(1)>
6. <iframe src=javascript:alert(1)>
```

Each attack generates a new rule!

### **Test 2: Review & Approve**

1. Open `/rule-review`
2. You'll see 6 pending rules
3. Approve them all
4. Check statistics

### **Test 3: Verify Improvement**

Submit the same attacks again:
- Confidence will be higher
- Detection will be faster
- System learned from previous attacks!

---

## 📊 Statistics Dashboard:

```
╔══════════════════════════════════════╗
║      RULE GENERATION STATISTICS      ║
╠══════════════════════════════════════╣
║  Total Generated:        25          ║
║  Pending Review:         5           ║
║  Approved:              18           ║
║  Rejected:               2           ║
║  Approval Rate:         72%          ║
╚══════════════════════════════════════╝
```

---

## 🎯 Workflow Example:

### **Day 1:**
```
1. User tests 10 SQL injection attacks
2. System generates 10 rules (pending)
3. Admin approves 8, rejects 2
4. 8 rules now active
```

### **Day 2:**
```
1. Similar attacks submitted
2. Confidence boosted by +10-15%
3. More DROP verdicts (fewer UNKNOWN)
4. Accuracy improved!
```

### **Day 7:**
```
1. 50+ approved rules
2. System catches subtle variations
3. High accuracy on known attack patterns
4. System is now "trained" on your traffic!
```

---

## ✅ Benefits:

| Feature | Benefit |
|---------|---------|
| **Automatic Learning** | No manual rule writing |
| **Adaptive** | Improves with each attack |
| **Pattern Recognition** | Learns attack signatures |
| **Confidence Boost** | Better accuracy over time |
| **Reduces False Negatives** | Catches similar attacks |
| **Admin Control** | Review before activation |
| **Export** | Use in other systems (Snort) |

---

## 🚀 URLs:

```
Login Page (Test Attacks):
→ http://127.0.0.1:5000/login

Live Monitor (Watch Results):
→ http://127.0.0.1:5000/simple-monitor

Rule Review Dashboard:
→ http://127.0.0.1:5000/rule-review

Security Lab:
→ http://127.0.0.1:5000/security-lab
```

---

## 🎯 How to Test UNKNOWN → Rule → Improved Detection:

### **Step 1: Submit Medium Attack**
```
Username: admin'
Password: test

Result: UNKNOWN (65% confidence)
```

### **Step 2: Check /rule-review**
```
Rule #1000 generated
Status: Pending
```

### **Step 3: Approve Rule**
```
Click "Approve & Activate"
Rule Status: Approved
```

### **Step 4: Submit Same Attack**
```
Username: admin'
Password: test

Result: DROP (65% + 15% = 80% confidence)
Upgraded from UNKNOWN to DROP!
```

---

## 🎉 Summary:

✅ **DROP/UNKNOWN attacks** → Auto-generate rules  
✅ **Review at** `/rule-review`  
✅ **Approve rules** → Boost accuracy  
✅ **System learns** from each attack  
✅ **Export rules** in Snort format  
✅ **Improves over time** automatically  

**Your system now has adaptive learning! 🚀**

Start testing attacks and watch your system get smarter! 🎯

