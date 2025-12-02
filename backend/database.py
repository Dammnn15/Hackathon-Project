"""
Security Database for storing verdicts, warnings, and analytics
"""
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class SecurityDatabase:
    def __init__(self, db_path: str = "security_system.db"):
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        """Create tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Verdicts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                verdict TEXT NOT NULL,
                confidence REAL,
                attack_type TEXT,
                payload_preview TEXT,
                matched_rules TEXT,
                is_anomaly INTEGER,
                reason TEXT,
                admin_reviewed INTEGER DEFAULT 0,
                admin_decision TEXT,
                admin_notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Warnings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                verdict_id INTEGER,
                warning_type TEXT,
                message TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (verdict_id) REFERENCES security_verdicts(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_verdict(self, verdict: Dict) -> int:
        """Save a security verdict to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_verdicts (
                timestamp, source_ip, verdict, confidence, attack_type,
                payload_preview, matched_rules, is_anomaly, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            verdict.get('timestamp'),
            verdict.get('features', {}).get('source_ip', 'unknown'),
            verdict.get('verdict'),
            verdict.get('confidence'),
            verdict.get('attack_type'),
            verdict.get('payload_preview'),
            json.dumps([r['name'] for r in verdict.get('matched_rules', [])]),
            1 if verdict.get('is_anomaly') else 0,
            verdict.get('reason')
        ))
        
        verdict_id = cursor.lastrowid
        
        # Create warning for UNKNOWN verdicts
        if verdict.get('verdict') == 'UNKNOWN':
            cursor.execute('''
                INSERT INTO admin_warnings (verdict_id, warning_type, message)
                VALUES (?, ?, ?)
            ''', (
                verdict_id,
                'UNKNOWN_VERDICT',
                f"Suspicious activity detected: {verdict.get('attack_type')}"
            ))
        
        conn.commit()
        conn.close()
        
        return verdict_id
    
    def get_verdict_by_id(self, verdict_id: int) -> Optional[Dict]:
        """Get verdict by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM security_verdicts WHERE id = ?', (verdict_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def get_recent_verdicts(self, limit: int = 100) -> List[Dict]:
        """Get recent verdicts"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM security_verdicts 
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_pending_warnings(self, limit: int = 50) -> List[Dict]:
        """Get pending admin warnings"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT w.*, v.payload_preview, v.attack_type, v.confidence
            FROM admin_warnings w
            JOIN security_verdicts v ON w.verdict_id = v.id
            WHERE w.status = 'pending'
            ORDER BY w.created_at DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def update_admin_review(self, verdict_id: int, decision: str, notes: str = '') -> bool:
        """Update admin review for a verdict"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE security_verdicts
            SET admin_reviewed = 1, admin_decision = ?, admin_notes = ?
            WHERE id = ?
        ''', (decision, notes, verdict_id))
        
        # Update warning status
        cursor.execute('''
            UPDATE admin_warnings
            SET status = 'reviewed'
            WHERE verdict_id = ?
        ''', (verdict_id,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def get_statistics(self, days: int = 7) -> Dict:
        """Get system statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        # Total threats
        cursor.execute('''
            SELECT COUNT(*) FROM security_verdicts
            WHERE verdict IN ('DROP', 'UNKNOWN') AND created_at > ?
        ''', (since_date,))
        total_threats = cursor.fetchone()[0]
        
        # By verdict
        cursor.execute('''
            SELECT verdict, COUNT(*) as count
            FROM security_verdicts
            WHERE created_at > ?
            GROUP BY verdict
        ''', (since_date,))
        verdict_counts = dict(cursor.fetchall())
        
        # By attack type
        cursor.execute('''
            SELECT attack_type, COUNT(*) as count
            FROM security_verdicts
            WHERE created_at > ? AND verdict != 'PASS'
            GROUP BY attack_type
        ''', (since_date,))
        attack_types = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_threats': total_threats,
            'drop_count': verdict_counts.get('DROP', 0),
            'unknown_count': verdict_counts.get('UNKNOWN', 0),
            'pass_count': verdict_counts.get('PASS', 0),
            'attack_types': attack_types,
            'days': days
        }

# Singleton instance
_database = None

def get_database() -> SecurityDatabase:
    """Get or create singleton database instance"""
    global _database
    if _database is None:
        _database = SecurityDatabase()
    return _database

