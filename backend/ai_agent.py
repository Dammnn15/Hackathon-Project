"""
AI Agent for intelligent payload analysis
Provides context-aware threat assessment beyond rule-based detection
"""
import json
import time
from datetime import datetime
from typing import Dict, List
from collections import deque
import threading

class PayloadStream:
    """Captures and stores real-time payloads"""
    
    def __init__(self, max_size: int = 1000):
        self.payloads = deque(maxlen=max_size)
        self.lock = threading.Lock()
    
    def add_payload(self, payload: Dict):
        """Add a new payload to the stream"""
        with self.lock:
            payload['captured_at'] = datetime.now().isoformat()
            payload['stream_id'] = len(self.payloads) + 1
            self.payloads.append(payload)
    
    def get_recent(self, limit: int = 100) -> List[Dict]:
        """Get recent payloads"""
        with self.lock:
            return list(self.payloads)[-limit:]


class AIAgent:
    """AI Agent for intelligent payload analysis"""
    
    def __init__(self):
        self.analysis_history = []
        self.threat_patterns = self._load_threat_intelligence()
    
    def _load_threat_intelligence(self) -> Dict:
        """Load known threat patterns"""
        return {
            'sql_injection': {
                'keywords': ['union', 'select', 'drop', 'insert', 'update', 'delete'],
                'threat_level': 'CRITICAL'
            },
            'xss': {
                'keywords': ['script', 'alert', 'onerror', 'onload', 'eval'],
                'threat_level': 'HIGH'
            },
            'command_injection': {
                'keywords': ['cat', 'ls', 'whoami', 'wget', 'curl', 'bash'],
                'threat_level': 'CRITICAL'
            }
        }
    
    def analyze_payload(self, verdict: Dict, payload: str) -> Dict:
        """Perform AI-powered analysis on payload"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'verdict': verdict['verdict'],
            'ml_confidence': verdict['confidence'],
            'attack_type': verdict['attack_type'],
            'ai_assessment': self._assess_threat_level(verdict, payload),
            'risk_score': 0,
            'ai_confidence': 0,
            'recommendations': self._generate_recommendations(verdict)
        }
        
        # Calculate risk score
        analysis['risk_score'] = self._calculate_risk_score(analysis)
        analysis['ai_confidence'] = min(analysis['ml_confidence'] * 0.9, 100)
        
        self.analysis_history.append(analysis)
        return analysis
    
    def _assess_threat_level(self, verdict: Dict, payload: str) -> Dict:
        """AI-based threat level assessment"""
        threat_level = "UNKNOWN"
        severity = 0
        reasoning = []
        
        for attack_type, intel in self.threat_patterns.items():
            payload_lower = payload.lower()
            keyword_matches = [kw for kw in intel['keywords'] if kw in payload_lower]
            
            if keyword_matches:
                threat_level = intel['threat_level']
                severity += len(keyword_matches) * 10
                reasoning.append(f"Detected {attack_type} indicators: {keyword_matches}")
        
        if verdict['verdict'] == 'DROP':
            severity = int(severity * 1.5)
        
        return {
            'threat_level': threat_level if severity > 0 else 'LOW',
            'severity_score': min(severity, 100),
            'reasoning': reasoning,
            'is_critical': severity >= 80
        }
    
    def _generate_recommendations(self, verdict: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if verdict['verdict'] == 'DROP':
            recommendations.append("🚫 Block this IP at firewall level")
            recommendations.append("📝 Log incident for compliance")
        elif verdict['verdict'] == 'UNKNOWN':
            recommendations.append("⚠️ Manual inspection recommended")
            recommendations.append("📊 Monitor source for additional activity")
        
        if verdict['confidence'] > 90:
            recommendations.append("🛡️ Update WAF rules to block similar patterns")
        
        return recommendations
    
    def _calculate_risk_score(self, analysis: Dict) -> int:
        """Calculate overall risk score"""
        risk = analysis['ml_confidence'] * 0.7
        risk += analysis['ai_assessment']['severity_score'] * 0.3
        return min(int(risk), 100)
    
    def get_real_time_stats(self) -> Dict:
        """Get real-time statistics"""
        if not self.analysis_history:
            return {'total_analyzed': 0, 'avg_risk_score': 0, 'critical_threats': 0}
        
        recent = self.analysis_history[-100:]
        return {
            'total_analyzed': len(self.analysis_history),
            'avg_risk_score': sum(a['risk_score'] for a in recent) / len(recent),
            'critical_threats': sum(1 for a in recent if a['ai_assessment']['is_critical'])
        }


# Global instances
_payload_stream = None
_ai_agent = None

def get_payload_stream() -> PayloadStream:
    global _payload_stream
    if _payload_stream is None:
        _payload_stream = PayloadStream()
    return _payload_stream

def get_ai_agent() -> AIAgent:
    global _ai_agent
    if _ai_agent is None:
        _ai_agent = AIAgent()
    return _ai_agent

