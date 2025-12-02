"""
Traffic Monitor - Monitors all incoming HTTP traffic
"""
from datetime import datetime
from typing import Dict, List
from collections import deque
import threading

class TrafficMonitor:
    def __init__(self, max_size: int = 1000):
        self.traffic_logs = deque(maxlen=max_size)
        self.enabled = True
        self.lock = threading.Lock()
    
    def log_request(self, request_data: Dict):
        if not self.enabled:
            return
        
        with self.lock:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'method': request_data.get('method'),
                'path': request_data.get('path'),
                'source_ip': request_data.get('source_ip'),
                'user_agent': request_data.get('user_agent'),
                'verdict': request_data.get('verdict'),
                'confidence': request_data.get('confidence'),
                'attack_type': request_data.get('attack_type')
            }
            self.traffic_logs.append(log_entry)
    
    def get_recent_traffic(self, limit: int = 50) -> List[Dict]:
        with self.lock:
            return list(self.traffic_logs)[-limit:]

def monitor_traffic_middleware(anomaly_system, ai_agent, payload_stream, security_db):
    def middleware(app):
        @app.before_request
        def log_traffic():
            from flask import request
            import json
            
            # Skip static files and monitor pages
            if request.path.startswith('/static') or 'monitor' in request.path:
                return
            
            # Capture ALL data
            payload_parts = []
            
            # GET parameters
            if request.args:
                params = dict(request.args)
                payload_parts.append(f"GET: {params}")
            
            # POST/PUT body
            if request.method in ['POST', 'PUT', 'PATCH']:
                try:
                    if request.is_json:
                        body = request.get_json(silent=True) or {}
                        # Mask passwords
                        if 'password' in body:
                            body['password'] = '*' * len(str(body.get('password', '')))
                        payload_parts.append(f"{request.method}: {body}")
                    elif request.form:
                        form_data = dict(request.form)
                        if 'password' in form_data:
                            form_data['password'] = '***'
                        payload_parts.append(f"{request.method} Form: {form_data}")
                except:
                    pass
            
            # Create payload summary
            payload_text = ' | '.join(payload_parts) if payload_parts else f"{request.method} {request.path}"
            
            # Log to traffic monitor
            monitor = get_traffic_monitor()
            monitor.log_request({
                'method': request.method,
                'path': request.path,
                'source_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', '')[:100],
                'payload': payload_text[:200]
            })
            
            # Also add to payload stream for live monitoring
            payload_stream.add_payload({
                'verdict_id': 0,
                'payload': payload_text[:150],
                'source_ip': request.remote_addr,
                'verdict': 'TRAFFIC',  # New type for general traffic
                'confidence': 0,
                'attack_type': f'{request.method} {request.path}',
                'ai_risk_score': 0
            })
        
        return app
    return middleware

def create_traffic_dashboard_data() -> Dict:
    monitor = get_traffic_monitor()
    recent = monitor.get_recent_traffic(100)
    
    threats = [t for t in recent if t.get('verdict') in ['DROP', 'UNKNOWN']]
    
    return {
        'total_requests': len(recent),
        'total_threats': len(threats),
        'recent_traffic': recent[-20:]
    }

_traffic_monitor = None

def get_traffic_monitor() -> TrafficMonitor:
    global _traffic_monitor
    if _traffic_monitor is None:
        _traffic_monitor = TrafficMonitor()
    return _traffic_monitor
