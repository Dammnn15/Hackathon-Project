"""
Suspicious Log Detector - Detects reconnaissance and suspicious patterns
"""
import re
from typing import Dict, List, Tuple

class SuspiciousLogDetector:
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict:
        return {
            'port_scanning': {
                'patterns': [r'nmap', r'masscan', r':\d{1,5}\s.*:\d{1,5}'],
                'score': 30
            },
            'directory_traversal': {
                'patterns': [r'\.\./|\.\.\\', r'/etc/passwd', r'c:\\windows'],
                'score': 25
            },
            'suspicious_user_agents': {
                'patterns': [r'bot', r'crawler', r'scanner', r'nikto', r'sqlmap'],
                'score': 20
            }
        }
    
    def detect_suspicious(self, payload: str, source_ip: str = '') -> Tuple[bool, List[str]]:
        detected = []
        for name, info in self.patterns.items():
            for pattern in info['patterns']:
                if re.search(pattern, payload, re.IGNORECASE):
                    detected.append(name)
                    break
        return len(detected) > 0, detected
    
    def calculate_suspicion_score(self, detected_patterns: List[str]) -> int:
        score = 0
        for pattern_name in detected_patterns:
            if pattern_name in self.patterns:
                score += self.patterns[pattern_name]['score']
        return min(score, 100)

class XSSDetector:
    def detect_xss(self, payload: str) -> Tuple[bool, List[str], float]:
        patterns = []
        confidence = 0
        
        if re.search(r'<script', payload, re.IGNORECASE):
            patterns.append('script_tag')
            confidence += 35
        if re.search(r'on\w+\s*=', payload, re.IGNORECASE):
            patterns.append('event_handler')
            confidence += 30
        if re.search(r'javascript:', payload, re.IGNORECASE):
            patterns.append('javascript_protocol')
            confidence += 30
        
        return len(patterns) > 0, patterns, min(confidence, 100)

_suspicious_detector = None
_xss_detector = None

def get_suspicious_detector():
    global _suspicious_detector
    if _suspicious_detector is None:
        _suspicious_detector = SuspiciousLogDetector()
    return _suspicious_detector

def get_xss_detector():
    global _xss_detector
    if _xss_detector is None:
        _xss_detector = XSSDetector()
    return _xss_detector
