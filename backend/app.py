from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
from firebase_auth import verify_firebase_token, admin_required
import json
import time
from anomaly_detector import get_anomaly_system
from database import get_database
from ai_agent import get_ai_agent, get_payload_stream
from traffic_monitor import monitor_traffic_middleware, get_traffic_monitor, create_traffic_dashboard_data
from rule_generator import get_rule_generator, get_rule_matching_engine

app = Flask(__name__)

# Initialize systems
anomaly_system = get_anomaly_system()
security_db = get_database()
ai_agent = get_ai_agent()
payload_stream = get_payload_stream()
traffic_monitor = get_traffic_monitor()
rule_generator = get_rule_generator()
rule_matcher = get_rule_matching_engine()

# Traffic monitoring
middleware = monitor_traffic_middleware(anomaly_system, ai_agent, payload_stream, security_db)
middleware(app)

print("\n🌐 AUTOMATIC TRAFFIC MONITORING ENABLED")

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login")
def login():
    from flask import make_response
    response = make_response(render_template("login.html"))
    # Force browser to never cache - always get fresh version
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/security-lab")
def security_lab():
    """Main security testing interface"""
    return render_template("security_lab.html")

@app.route("/admin/monitoring")
def admin_monitoring():
    """Real-time monitoring dashboard"""
    return render_template("admin_monitoring.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    """Admin dashboard for reviewing verdicts"""
    return render_template("admin_dashboard.html")

@app.route("/live-monitor")
def live_monitor():
    """Live monitoring dashboard with real-time PASS/UNKNOWN/DROP display"""
    return render_template("live_monitor.html")

@app.route("/test-monitor")
def test_monitor():
    """Simple test page to verify payloads are loading"""
    return render_template("test_monitor.html")

@app.route("/simple-monitor")
def simple_monitor():
    """Ultra-simple monitor page - guaranteed to work"""
    return render_template("simple_monitor.html")

@app.route("/api/login-check", methods=["POST"])
def login_check():
    """
    AI-powered login form attack detection
    Analyzes username and password for SQL injection and XSS attacks
    
    This endpoint is CRITICAL for detecting attacks in the login form:
    - SQL Injection: ' OR 1=1 --, UNION SELECT, etc.
    - XSS Attacks: <script>, <img onerror=>, etc.
    - Command Injection: Shell commands
    - Path Traversal: ../, /etc/passwd
    """
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    source_ip = request.remote_addr
    
    print(f"\n{'='*70}")
    print("🔐 INCOMING LOGIN FORM SUBMISSION")
    print(f"{'='*70}")
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password) if password else '(empty)'}")
    print(f"Source IP: {source_ip}")
    print(f"{'='*70}")
    
    # Analyze BOTH username and password separately
    username_verdict = anomaly_system.analyze_payload(username, source_ip, "Username Field")
    password_verdict = anomaly_system.analyze_payload(password, source_ip, "Password Field")
    
    # Also analyze combined (for complex attacks)
    combined_payload = f"{username} {password}"
    combined_verdict = anomaly_system.analyze_payload(combined_payload, source_ip, "Login Form")
    
    # Choose the WORST verdict (most dangerous)
    verdicts = [username_verdict, password_verdict, combined_verdict]
    verdict = max(verdicts, key=lambda v: v['confidence'])
    
    # If any field is DROP, entire login is DROP
    for v in verdicts:
        if v['verdict'] == 'DROP':
            verdict = v
            break
    
    # Collect ALL detected patterns from all fields
    all_patterns = []
    for v in verdicts:
        all_patterns.extend([rule['name'] for rule in v['matched_rules']])
    verdict['matched_rules'] = [{'name': p} for p in set(all_patterns)]
    
    # Save to database
    verdict_id = security_db.save_verdict(verdict)
    
    # AI analysis with full context
    ai_analysis = ai_agent.analyze_payload(verdict, combined_payload)
    
    # Add to real-time stream
    payload_stream.add_payload({
        'verdict_id': verdict_id,
        'payload': f"Login: U={username[:30]} P={'*' * min(len(password), 10)}",
        'source_ip': source_ip,
        'verdict': verdict['verdict'],
        'confidence': verdict['confidence'],
        'attack_type': verdict['attack_type'],
        'ai_risk_score': ai_analysis['risk_score']
    })
    
    # AUTO-GENERATE RULES for DROP/UNKNOWN verdicts
    if verdict['verdict'] in ['DROP', 'UNKNOWN']:
        rule = rule_generator.analyze_payload_for_rule(
            combined_payload,
            verdict['attack_type'],
            verdict['confidence']
        )
        rule_generator.add_generated_rule(rule)
        print(f"\n🔧 AUTO-GENERATED RULE #{rule['rule_id']} from {verdict['verdict']} verdict")
        print(f"   Patterns: {', '.join(rule['patterns'][:3])}...")
        print(f"   Status: Pending review at /rule-review")
    
    # Detailed logging
    print(f"\n{'='*70}")
    print("🤖 AI DETECTION RESULTS")
    print(f"{'='*70}")
    print(f"📊 VERDICTS:")
    print(f"   Username Field: {username_verdict['verdict']} ({username_verdict['confidence']:.1f}%)")
    print(f"   Password Field: {password_verdict['verdict']} ({password_verdict['confidence']:.1f}%)")
    print(f"   Combined Analysis: {combined_verdict['verdict']} ({combined_verdict['confidence']:.1f}%)")
    print(f"\n🎯 FINAL VERDICT: {verdict['verdict']}")
    print(f"   Confidence: {verdict['confidence']:.1f}%")
    print(f"   Attack Type: {verdict['attack_type']}")
    print(f"   AI Risk Score: {ai_analysis['risk_score']}/100")
    print(f"   Threat Level: {ai_analysis['ai_assessment']['threat_level']}")
    
    if verdict['matched_rules']:
        print(f"\n🛡️  DETECTED ATTACK PATTERNS:")
        for pattern in set([r['name'] for r in verdict['matched_rules']]):
            print(f"   ✓ {pattern}")
    
    print(f"\n📝 REASON: {verdict['reason']}")
    print(f"💾 Verdict ID: {verdict_id}")
    print(f"{'='*70}\n")
    
    # Return comprehensive response
    return jsonify({
        "verdict": verdict['verdict'],
        "confidence": float(verdict['confidence']),
        "attack_type": verdict['attack_type'],
        "is_malicious": verdict['verdict'] != 'PASS',
        "is_anomaly": bool(verdict['is_anomaly']),  # Convert numpy bool to Python bool
        "detected_patterns": list(set([r['name'] for r in verdict['matched_rules']])),
        "reason": verdict['reason'],
        "verdict_id": int(verdict_id),
        "ai_risk_score": int(ai_analysis['risk_score']),
        "threat_level": ai_analysis['ai_assessment']['threat_level'],
        "field_analysis": {
            "username": {
                "verdict": username_verdict['verdict'],
                "confidence": username_verdict['confidence']
            },
            "password": {
                "verdict": password_verdict['verdict'],
                "confidence": password_verdict['confidence']
            }
        }
    })

@app.route("/authenticate", methods=["POST"])
def authenticate():
    id_token = request.form.get("idToken")
    source_ip = request.remote_addr
    
    if not id_token:
        return redirect(url_for("login"))
    
    # Skip anomaly detection for JWT tokens (Firebase auth)
    is_jwt = id_token.count('.') == 2 and len(id_token) > 100
    
    if not is_jwt:
        verdict = anomaly_system.analyze_payload(id_token, source_ip)
        if verdict['verdict'] in ['DROP', 'UNKNOWN']:
            return jsonify({
                "error": "Security threat detected",
                "verdict": verdict['verdict']
            }), 403
    
    response = redirect(url_for("security_lab"))
    response.set_cookie("token", id_token, httponly=False, path="/")
    return response

@app.route("/api/test-sqli", methods=["POST"])
def test_sql_injection():
    """Test SQL injection detection"""
    data = request.get_json() or {}
    payload = data.get("payload") or request.form.get("payload")
    
    if not payload:
        return jsonify({"error": "No payload provided"}), 400
    
    source_ip = request.remote_addr
    verdict = anomaly_system.analyze_payload(payload, source_ip, "SQL Injection")
    
    verdict_id = security_db.save_verdict(verdict)
    
    print(f"\n{'='*60}")
    print(f"SQL INJECTION TEST")
    print(f"{'='*60}")
    print(f"Payload: {payload[:100]}")
    print(f"Verdict: {verdict['verdict']}")
    print(f"Confidence: {verdict['confidence']:.1f}%")
    print(f"Attack Type: {verdict['attack_type']}")
    print(f"{'='*60}\n")
    
    return jsonify({
        "payload": payload,
        "verdict": verdict['verdict'],
        "confidence": verdict['confidence'],
        "attack_type": verdict['attack_type'],
        "is_malicious": verdict['verdict'] != 'PASS',
        "is_anomaly": verdict['is_anomaly'],
        "detected_patterns": [rule['name'] for rule in verdict['matched_rules']],
        "reason": verdict['reason'],
        "verdict_id": verdict_id
    })

@app.route("/api/test-xss", methods=["POST"])
def test_xss():
    """Test XSS detection"""
    data = request.get_json() or {}
    payload = data.get("payload") or request.form.get("payload")
    
    if not payload:
        return jsonify({"error": "No payload provided"}), 400
    
    source_ip = request.remote_addr
    verdict = anomaly_system.analyze_payload(payload, source_ip, "XSS")
    
    verdict_id = security_db.save_verdict(verdict)
    
    print(f"\n{'='*60}")
    print(f"XSS TEST")
    print(f"{'='*60}")
    print(f"Payload: {payload[:100]}")
    print(f"Verdict: {verdict['verdict']}")
    print(f"Confidence: {verdict['confidence']:.1f}%")
    print(f"Attack Type: {verdict['attack_type']}")
    print(f"{'='*60}\n")
    
    return jsonify({
        "payload": payload,
        "verdict": verdict['verdict'],
        "confidence": verdict['confidence'],
        "attack_type": verdict['attack_type'],
        "is_malicious": verdict['verdict'] != 'PASS',
        "is_anomaly": verdict['is_anomaly'],
        "detected_patterns": [rule['name'] for rule in verdict['matched_rules']],
        "reason": verdict['reason'],
        "verdict_id": verdict_id
    })

@app.route("/api/anomaly-predict", methods=["POST"])
def anomaly_predict():
    """AI-powered anomaly prediction"""
    data = request.get_json()
    
    if not data or 'payload' not in data:
        return jsonify({"error": "Payload required"}), 400
    
    payload = data['payload']
    source_ip = data.get('source_ip', request.remote_addr)
    attack_type_hint = data.get('attack_type')
    
    # Analyze with anomaly detection
    verdict = anomaly_system.analyze_payload(payload, source_ip, attack_type_hint)
    
    # AI analysis
    ai_analysis = ai_agent.analyze_payload(verdict, payload)
    
    # Save to database
    verdict_id = security_db.save_verdict(verdict)
    verdict['verdict_id'] = verdict_id
    verdict['ai_analysis'] = ai_analysis
    
    # Add to real-time stream
    payload_stream.add_payload({
        'verdict_id': verdict_id,
        'payload': payload[:200],
        'source_ip': source_ip,
        'verdict': verdict['verdict'],
        'confidence': verdict['confidence'],
        'attack_type': verdict['attack_type'],
        'ai_risk_score': ai_analysis['risk_score']
    })
    
    print(f"\n{'='*60}")
    print("AI ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"ML Verdict: {verdict['verdict']} ({verdict['confidence']:.1f}%)")
    print(f"AI Risk Score: {ai_analysis['risk_score']}/100")
    print(f"Threat Level: {ai_analysis['ai_assessment']['threat_level']}")
    print(f"{'='*60}\n")
    
    return jsonify(verdict)

@app.route("/api/admin/stats")
def admin_stats():
    """Get system statistics"""
    stats = security_db.get_statistics(days=7)
    return jsonify(stats)

@app.route("/api/admin/verdicts")
def admin_verdicts():
    """Get recent verdicts"""
    limit = request.args.get('limit', 100, type=int)
    verdicts = security_db.get_recent_verdicts(limit=limit)
    return jsonify({"verdicts": verdicts, "count": len(verdicts)})

@app.route("/api/admin/warnings")
def admin_warnings():
    """Get pending warnings"""
    warnings = security_db.get_pending_warnings(limit=50)
    return jsonify({"warnings": warnings, "count": len(warnings)})

@app.route("/api/realtime/payloads")
def realtime_payloads():
    """Get recent payloads"""
    limit = request.args.get('limit', 50, type=int)
    payloads = payload_stream.get_recent(limit=limit)
    return jsonify({'payloads': payloads, 'count': len(payloads)})

@app.route("/api/traffic/stats")
def traffic_stats():
    """Get traffic statistics"""
    data = create_traffic_dashboard_data()
    return jsonify(data)

@app.route("/api/traffic/recent")
def recent_traffic():
    """Get recent traffic logs"""
    limit = request.args.get('limit', 50, type=int)
    recent = traffic_monitor.get_recent_traffic(limit=limit)
    return jsonify({'traffic': recent, 'count': len(recent)})

@app.route("/rule-review")
def rule_review_page():
    """Rule review and approval dashboard"""
    return render_template("rule_review.html")

@app.route("/api/rules/generate", methods=["POST"])
def generate_rule_from_verdict():
    """
    Generate a new rule from a DROP/UNKNOWN verdict
    Automatically called for verdicts requiring review
    """
    data = request.get_json() or {}
    verdict_id = data.get('verdict_id')
    payload = data.get('payload')
    attack_type = data.get('attack_type')
    confidence = data.get('confidence')
    
    if not all([payload, attack_type, confidence]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Generate rule from this attack
    rule = rule_generator.analyze_payload_for_rule(payload, attack_type, confidence)
    rule_generator.add_generated_rule(rule)
    
    print(f"\n{'='*70}")
    print(f"📝 NEW RULE GENERATED FROM ATTACK")
    print(f"{'='*70}")
    print(f"Rule ID: {rule['rule_id']}")
    print(f"Attack Type: {attack_type}")
    print(f"Patterns Found: {len(rule['patterns'])}")
    print(f"Severity: {rule['severity']}")
    print(f"Patterns: {', '.join(rule['patterns'])}")
    print(f"Status: Pending Admin Review")
    print(f"{'='*70}\n")
    
    return jsonify({
        "success": True,
        "rule_id": rule['rule_id'],
        "rule": rule,
        "message": "Rule generated and pending review"
    })

@app.route("/api/rules/pending")
def get_pending_rules():
    """Get all pending rules for review"""
    pending = rule_generator.get_pending_rules()
    return jsonify({
        "rules": pending,
        "count": len(pending)
    })

@app.route("/api/rules/approve/<int:rule_id>", methods=["POST"])
def approve_rule(rule_id):
    """Approve a rule - makes it active"""
    success = rule_generator.approve_rule(rule_id)
    
    if success:
        print(f"\n✅ RULE {rule_id} APPROVED - Now Active!")
        return jsonify({
            "success": True,
            "message": f"Rule {rule_id} approved and activated"
        })
    else:
        return jsonify({
            "success": False,
            "error": "Rule not found"
        }), 404

@app.route("/api/rules/reject/<int:rule_id>", methods=["POST"])
def reject_rule(rule_id):
    """Reject a rule"""
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')
    
    success = rule_generator.reject_rule(rule_id, reason)
    
    if success:
        print(f"\n❌ RULE {rule_id} REJECTED: {reason}")
        return jsonify({
            "success": True,
            "message": f"Rule {rule_id} rejected"
        })
    else:
        return jsonify({
            "success": False,
            "error": "Rule not found"
        }), 404

@app.route("/api/rules/approved")
def get_approved_rules():
    """Get all approved (active) rules"""
    approved = rule_generator.get_approved_rules()
    return jsonify({
        "rules": approved,
        "count": len(approved)
    })

@app.route("/api/rules/stats")
def get_rule_stats():
    """Get rule generation statistics"""
    stats = rule_generator.get_statistics()
    return jsonify(stats)

@app.route("/api/rules/export")
def export_rules():
    """Export approved rules in Snort format"""
    snort_rules = rule_generator.export_rules_to_snort_format()
    return Response(
        snort_rules,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment;filename=generated_rules.rules'}
    )

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🤖 STARTING AI ANOMALY DETECTION SYSTEM")
    print("="*70)
    print("\n✅ System Components:")
    print("   📊 ML Anomaly Detection - READY (87% accuracy)")
    print("   💾 Security Database - READY")
    print("   🛡️  Snort Rules (9 patterns) - LOADED")
    print("   🤖 AI Agent - ACTIVE")
    print("   📡 Real-time Payload Stream - ENABLED")
    print("   🔐 Login Attack Detection - ACTIVE")
    print("   🔧 Auto Rule Generation - ENABLED ⭐ NEW!")
    print("   🎯 Adaptive Learning System - ACTIVE")
    print("\n" + "="*70)
    print("🌐 WEB INTERFACES:")
    print("="*70)
    print("   🔐 Login Page (Test Here):")
    print("      → http://127.0.0.1:5000/login")
    print("      (Test SQL injection & XSS attacks!)")
    print("")
    print("   📡 Live Monitor (Watch Results):")
    print("      → http://127.0.0.1:5000/simple-monitor")
    print("      (Real-time traffic & attack monitoring!)")
    print("")
    print("   🔧 Rule Review Dashboard: ⭐ NEW!")
    print("      → http://127.0.0.1:5000/rule-review")
    print("      (Review & approve auto-generated rules!)")
    print("")
    print("   🔬 Security Lab:")
    print("      → http://127.0.0.1:5000/security-lab")
    print("      (Advanced payload testing)")
    print("\n" + "="*70)
    print("🔌 API ENDPOINTS:")
    print("="*70)
    print("   POST /api/login-check - Login form attack detection")
    print("   POST /api/test-sqli - SQL injection testing")
    print("   POST /api/test-xss - XSS testing")
    print("   POST /api/anomaly-predict - AI threat analysis")
    print("   GET  /api/realtime/payloads - Real-time payload stream")
    print("   POST /api/rules/generate - Generate rule from attack ⭐")
    print("   GET  /api/rules/pending - Get pending rules")
    print("   POST /api/rules/approve/<id> - Approve rule")
    print("   POST /api/rules/reject/<id> - Reject rule")
    print("\n" + "="*70)
    print("💡 QUICK START:")
    print("="*70)
    print("   1. Open: http://127.0.0.1:5000/login (test attacks)")
    print("   2. Open: http://127.0.0.1:5000/simple-monitor (watch results)")
    print("   3. DROP/UNKNOWN attacks → Auto-generate rules")
    print("   4. Open: http://127.0.0.1:5000/rule-review (approve rules)")
    print("   5. System learns and improves accuracy! 🚀")
    print("\n" + "="*70)
    print("🎯 ADAPTIVE LEARNING:")
    print("="*70)
    print("   • DROP/UNKNOWN verdicts → Auto-generate rules")
    print("   • Review rules at /rule-review")
    print("   • Approve rules → Boost detection accuracy")
    print("   • System improves with each attack!")
    print("\n" + "="*70)
    print("🚀 Server running on http://127.0.0.1:5000")
    print("="*70 + "\n")
    app.run(debug=True, port=5000)

