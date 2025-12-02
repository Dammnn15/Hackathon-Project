# 🚀 Quick Test Guide

## Open These URLs:

### 1. Login Page (Test Attacks)
```
http://127.0.0.1:5000/login
```

### 2. Live Monitor (Watch Results) ⭐
```
http://127.0.0.1:5000/live-monitor
```

---

## Test Workflow:

1. **Open Live Monitor first** (Tab 1)
   - Dark theme dashboard
   - Real-time stats: 0/0/0

2. **Open Login Page** (Tab 2)
   - Click "💉 SQL: OR 1=1"
   - Click "🔍 Scan & Login"
   - See: 🚨 ATTACK BLOCKED!

3. **Switch to Live Monitor** (Tab 1)
   - See DROP count increase
   - See percentage bars update
   - See red alert in payload stream
   - Auto-refreshes every 3 seconds

---

## What You Should See:

### Login Page:
- 🌑 Dark navy background
- 🎴 White centered card
- 🟡 Gray test section
- 🔵 Blue gradient button
- ✨ Clean, modern design

### Live Monitor:
- ⚫ Professional dark theme
- 📊 4 stat cards (Total, DROP, UNKNOWN, PASS)
- 📈 Animated progress bars
- 🔴 Color-coded verdicts:
  - RED = DROP (blocked)
  - YELLOW = UNKNOWN (review)
  - GREEN = PASS (clean)
- ⚡ Auto-refresh every 3 seconds

---

## Expected Results:

| Payload | Verdict | Confidence | Type |
|---------|---------|------------|------|
| SQL: OR 1=1 | DROP | 75% | SQL Injection |
| SQL: UNION | DROP | 100% | SQL Injection |
| XSS: Script | DROP | 85% | XSS |
| XSS: Image | DROP | 60% | XSS |

---

## ✅ Everything Working:
- Login form accepts input ✓
- Test buttons load payloads ✓
- AI detects attacks ✓
- Live monitor updates ✓
- Statistics accurate ✓
- Filtering works ✓
- Auto-refresh active ✓

**Your system is ready!** 🎉
