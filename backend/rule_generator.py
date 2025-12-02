"""
Rule Generator - Converts DROP/UNKNOWN verdicts into Snort-like rules
Improves accuracy by learning from detected attacks
"""
import re
from typing import Dict, List, Tuple
from datetime import datetime
import json

class RuleGenerator:
    """Generates Snort-like rules from confirmed attacks"""
    
    def __init__(self):
        self.generated_rules = []
        self.rule_id_counter = 1000  # Start custom rules at 1000
        
    def analyze_payload_for_rule(self, payload: str, attack_type: str, confidence: float) -> Dict:
        """
        Analyze a payload and generate a rule signature
        
        Args:
            payload: The attack payload
            attack_type: Type of attack (SQL Injection, XSS, etc.)
            confidence: Detection confidence
            
        Returns:
            Dictionary with rule information
        """
        rule_patterns = []
        severity = self._determine_severity(confidence)
        
        # Extract patterns based on attack type
        if attack_type == "SQL Injection":
            rule_patterns = self._extract_sql_patterns(payload)
        elif attack_type == "XSS":
            rule_patterns = self._extract_xss_patterns(payload)
        elif attack_type == "potential_obfuscation":
            rule_patterns = self._extract_obfuscation_patterns(payload)
        else:
            rule_patterns = self._extract_generic_patterns(payload)
        
        # Generate rule structure
        rule = {
            'rule_id': self.rule_id_counter,
            'name': f"{attack_type} - Pattern {self.rule_id_counter}",
            'patterns': rule_patterns,
            'attack_type': attack_type,
            'severity': severity,
            'confidence': confidence,
            'created_at': datetime.now().isoformat(),
            'status': 'pending',  # pending, approved, rejected
            'original_payload': payload[:200],  # Store sample
            'snort_format': self._generate_snort_rule(rule_patterns, attack_type, severity)
        }
        
        self.rule_id_counter += 1
        return rule
    
    def _extract_sql_patterns(self, payload: str) -> List[str]:
        """Extract SQL injection patterns"""
        patterns = []
        
        # Common SQL injection patterns
        sql_keywords = ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE']
        for keyword in sql_keywords:
            if re.search(rf'\b{keyword}\b', payload, re.IGNORECASE):
                patterns.append(f"SQL_KEYWORD_{keyword}")
        
        # SQL comments
        if '--' in payload or '/*' in payload or '*/' in payload:
            patterns.append("SQL_COMMENT")
        
        # SQL operators
        if re.search(r"'\s*OR\s+", payload, re.IGNORECASE):
            patterns.append("SQL_OR_OPERATOR")
        if re.search(r"'\s*AND\s+", payload, re.IGNORECASE):
            patterns.append("SQL_AND_OPERATOR")
        
        # SQL comparison tricks
        if re.search(r"['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", payload):
            patterns.append("SQL_ALWAYS_TRUE")
        
        # SQL string concatenation
        if '||' in payload or '&&' in payload:
            patterns.append("SQL_CONCATENATION")
        
        return patterns
    
    def _extract_xss_patterns(self, payload: str) -> List[str]:
        """Extract XSS patterns"""
        patterns = []
        
        # Script tags
        if re.search(r'<script[\s>]', payload, re.IGNORECASE):
            patterns.append("XSS_SCRIPT_TAG")
        
        # Event handlers
        event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus']
        for handler in event_handlers:
            if handler in payload.lower():
                patterns.append(f"XSS_EVENT_{handler.upper()}")
        
        # JavaScript protocol
        if 'javascript:' in payload.lower():
            patterns.append("XSS_JAVASCRIPT_PROTOCOL")
        
        # Dangerous tags
        dangerous_tags = ['<iframe', '<embed', '<object', '<img', '<svg']
        for tag in dangerous_tags:
            if tag in payload.lower():
                patterns.append(f"XSS_TAG_{tag[1:].upper()}")
        
        # JavaScript functions
        js_functions = ['alert', 'prompt', 'confirm', 'eval']
        for func in js_functions:
            if func in payload.lower():
                patterns.append(f"XSS_FUNCTION_{func.upper()}")
        
        return patterns
    
    def _extract_obfuscation_patterns(self, payload: str) -> List[str]:
        """Extract obfuscation patterns"""
        patterns = []
        
        # Hex encoding
        if re.search(r'\\x[0-9a-fA-F]{2}', payload):
            patterns.append("OBFUSCATION_HEX")
        
        # Unicode encoding
        if re.search(r'\\u[0-9a-fA-F]{4}', payload):
            patterns.append("OBFUSCATION_UNICODE")
        
        # URL encoding
        if re.search(r'%[0-9a-fA-F]{2}', payload):
            patterns.append("OBFUSCATION_URL_ENCODED")
        
        # Base64-like
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', payload):
            patterns.append("OBFUSCATION_BASE64")
        
        # Mixed case evasion
        if re.search(r'[a-z][A-Z]|[A-Z][a-z]', payload):
            patterns.append("OBFUSCATION_MIXED_CASE")
        
        return patterns
    
    def _extract_generic_patterns(self, payload: str) -> List[str]:
        """Extract generic malicious patterns"""
        patterns = []
        
        # Path traversal
        if '../' in payload or '..\\' in payload:
            patterns.append("PATH_TRAVERSAL")
        
        # Command injection
        cmd_chars = ['|', ';', '&&', '||', '`', '$']
        for char in cmd_chars:
            if char in payload:
                patterns.append(f"COMMAND_INJECTION_{char.replace('|', 'PIPE').replace(';', 'SEMICOLON')}")
        
        # Null bytes
        if '\x00' in payload or '%00' in payload:
            patterns.append("NULL_BYTE")
        
        return patterns
    
    def _determine_severity(self, confidence: float) -> str:
        """Determine rule severity based on confidence"""
        if confidence >= 85:
            return "CRITICAL"
        elif confidence >= 70:
            return "HIGH"
        elif confidence >= 60:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_snort_rule(self, patterns: List[str], attack_type: str, severity: str) -> str:
        """Generate Snort-compatible rule format"""
        pattern_str = "; ".join(patterns)
        return f"alert tcp any any -> any any (msg:\"{attack_type} - {severity}\"; content:\"{pattern_str}\"; sid:{self.rule_id_counter}; rev:1;)"
    
    def add_generated_rule(self, rule: Dict):
        """Add a generated rule to the collection"""
        self.generated_rules.append(rule)
    
    def get_pending_rules(self) -> List[Dict]:
        """Get all pending rules for review"""
        return [r for r in self.generated_rules if r['status'] == 'pending']
    
    def approve_rule(self, rule_id: int) -> bool:
        """Approve a rule and activate it"""
        for rule in self.generated_rules:
            if rule['rule_id'] == rule_id:
                rule['status'] = 'approved'
                rule['approved_at'] = datetime.now().isoformat()
                return True
        return False
    
    def reject_rule(self, rule_id: int, reason: str = "") -> bool:
        """Reject a rule"""
        for rule in self.generated_rules:
            if rule['rule_id'] == rule_id:
                rule['status'] = 'rejected'
                rule['rejection_reason'] = reason
                rule['rejected_at'] = datetime.now().isoformat()
                return True
        return False
    
    def get_approved_rules(self) -> List[Dict]:
        """Get all approved rules"""
        return [r for r in self.generated_rules if r['status'] == 'approved']
    
    def export_rules_to_snort_format(self) -> str:
        """Export approved rules in Snort format"""
        approved = self.get_approved_rules()
        snort_rules = []
        
        for rule in approved:
            snort_rules.append(f"# {rule['name']}")
            snort_rules.append(f"# Created: {rule['created_at']}")
            snort_rules.append(rule['snort_format'])
            snort_rules.append("")
        
        return "\n".join(snort_rules)
    
    def get_statistics(self) -> Dict:
        """Get rule generation statistics"""
        total = len(self.generated_rules)
        pending = len([r for r in self.generated_rules if r['status'] == 'pending'])
        approved = len([r for r in self.generated_rules if r['status'] == 'approved'])
        rejected = len([r for r in self.generated_rules if r['status'] == 'rejected'])
        
        return {
            'total_generated': total,
            'pending_review': pending,
            'approved': approved,
            'rejected': rejected,
            'approval_rate': (approved / total * 100) if total > 0 else 0
        }


class RuleMatchingEngine:
    """
    Advanced rule matching engine that uses generated rules
    to improve detection accuracy
    """
    
    def __init__(self, rule_generator: RuleGenerator):
        self.rule_generator = rule_generator
    
    def match_against_generated_rules(self, payload: str) -> Tuple[bool, List[Dict], float]:
        """
        Match payload against generated (approved) rules
        
        Returns:
            (has_match, matched_rules, confidence_boost)
        """
        approved_rules = self.rule_generator.get_approved_rules()
        matched_rules = []
        confidence_boost = 0
        
        for rule in approved_rules:
            patterns_matched = 0
            for pattern in rule['patterns']:
                if self._pattern_matches(payload, pattern):
                    patterns_matched += 1
            
            # If majority of patterns match, consider it a match
            match_ratio = patterns_matched / len(rule['patterns']) if rule['patterns'] else 0
            if match_ratio >= 0.5:  # 50% of patterns must match
                matched_rules.append({
                    'rule_id': rule['rule_id'],
                    'name': rule['name'],
                    'match_ratio': match_ratio,
                    'severity': rule['severity']
                })
                
                # Boost confidence based on severity
                if rule['severity'] == 'CRITICAL':
                    confidence_boost += 15
                elif rule['severity'] == 'HIGH':
                    confidence_boost += 10
                elif rule['severity'] == 'MEDIUM':
                    confidence_boost += 5
        
        has_match = len(matched_rules) > 0
        confidence_boost = min(confidence_boost, 25)  # Cap at 25%
        
        return has_match, matched_rules, confidence_boost
    
    def _pattern_matches(self, payload: str, pattern: str) -> bool:
        """Check if a pattern matches the payload"""
        # SQL patterns
        if pattern.startswith("SQL_KEYWORD_"):
            keyword = pattern.split("_")[-1]
            return bool(re.search(rf'\b{keyword}\b', payload, re.IGNORECASE))
        
        if pattern == "SQL_COMMENT":
            return '--' in payload or '/*' in payload
        
        if pattern == "SQL_OR_OPERATOR":
            return bool(re.search(r"'\s*OR\s+", payload, re.IGNORECASE))
        
        if pattern == "SQL_AND_OPERATOR":
            return bool(re.search(r"'\s*AND\s+", payload, re.IGNORECASE))
        
        # XSS patterns
        if pattern == "XSS_SCRIPT_TAG":
            return bool(re.search(r'<script[\s>]', payload, re.IGNORECASE))
        
        if pattern.startswith("XSS_EVENT_"):
            event = pattern.split("_")[-1].lower()
            return event in payload.lower()
        
        if pattern == "XSS_JAVASCRIPT_PROTOCOL":
            return 'javascript:' in payload.lower()
        
        # Obfuscation patterns
        if pattern == "OBFUSCATION_HEX":
            return bool(re.search(r'\\x[0-9a-fA-F]{2}', payload))
        
        if pattern == "OBFUSCATION_UNICODE":
            return bool(re.search(r'\\u[0-9a-fA-F]{4}', payload))
        
        if pattern == "OBFUSCATION_URL_ENCODED":
            return bool(re.search(r'%[0-9a-fA-F]{2}', payload))
        
        # Generic patterns
        if pattern == "PATH_TRAVERSAL":
            return '../' in payload or '..\\' in payload
        
        return False


# Singleton instances
_rule_generator = None
_rule_matching_engine = None

def get_rule_generator() -> RuleGenerator:
    global _rule_generator
    if _rule_generator is None:
        _rule_generator = RuleGenerator()
    return _rule_generator

def get_rule_matching_engine() -> RuleMatchingEngine:
    global _rule_matching_engine
    if _rule_matching_engine is None:
        rule_gen = get_rule_generator()
        _rule_matching_engine = RuleMatchingEngine(rule_gen)
    return _rule_matching_engine

