import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional


class MemoryEngine:
    def __init__(self, db_path: str = "cyberllm_memory.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_tables()
    
    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                data TEXT NOT NULL,
                severity TEXT DEFAULT 'LOW',
                resolved INTEGER DEFAULT 0
            );
            
            CREATE TABLE IF NOT EXISTS learned_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                seen_count INTEGER DEFAULT 1,
                last_seen TEXT NOT NULL,
                threat_level TEXT DEFAULT 'UNKNOWN'
            );
            
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                intent TEXT
            );
            
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                results TEXT NOT NULL,
                summary TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(type);
            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_patterns_category ON learned_patterns(category);
        """)
        self.conn.commit()
    
    def remember_incident(self, inc_type: str, data: Dict, severity: str = "LOW") -> int:
        cursor = self.conn.execute(
            "INSERT INTO incidents (timestamp, type, data, severity) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), inc_type, json.dumps(data), severity)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def get_incidents(self, limit: int = 10, severity: Optional[str] = None) -> List[Dict]:
        query = "SELECT id, timestamp, type, data, severity, resolved FROM incidents"
        params = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        rows = self.conn.execute(query, params).fetchall()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "type": r[2],
                "data": json.loads(r[3]),
                "severity": r[4],
                "resolved": bool(r[5])
            }
            for r in rows
        ]
    
    def learn_pattern(self, pattern: str, category: str, threat_level: str = "UNKNOWN"):
        existing = self.conn.execute(
            "SELECT id, seen_count FROM learned_patterns WHERE pattern = ?",
            (pattern,)
        ).fetchone()
        
        if existing:
            self.conn.execute(
                "UPDATE learned_patterns SET seen_count = seen_count + 1, last_seen = ? WHERE pattern = ?",
                (datetime.now().isoformat(), pattern)
            )
        else:
            self.conn.execute(
                "INSERT INTO learned_patterns (pattern, category, last_seen, threat_level) VALUES (?,?,?,?)",
                (pattern, category, datetime.now().isoformat(), threat_level)
            )
        self.conn.commit()
    
    def get_patterns(self, category: Optional[str] = None, limit: int = 20) -> List[Dict]:
        query = "SELECT pattern, category, seen_count, threat_level FROM learned_patterns"
        if category:
            query += " WHERE category = ?"
            query += " ORDER BY seen_count DESC LIMIT ?"
            rows = self.conn.execute(query, (category, limit)).fetchall()
        else:
            query += " ORDER BY seen_count DESC LIMIT ?"
            rows = self.conn.execute(query, (limit,)).fetchall()
        
        return [
            {"pattern": r[0], "category": r[1], "seen": r[2], "threat": r[3]}
            for r in rows
        ]
    
    def add_chat(self, role: str, content: str, intent: Optional[str] = None):
        self.conn.execute(
            "INSERT INTO chat_history (timestamp, role, content, intent) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), role, content, intent)
        )
        self.conn.commit()
    
    def get_chat_history(self, limit: int = 20) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT role, content, intent, timestamp FROM chat_history ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [
            {"role": r[0], "content": r[1], "intent": r[2], "timestamp": r[3]}
            for r in rows
        ]
    
    def save_scan_result(self, scan_type: str, results: Dict, summary: Optional[str] = None):
        self.conn.execute(
            "INSERT INTO scan_results (timestamp, scan_type, results, summary) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), scan_type, json.dumps(results), summary)
        )
        self.conn.commit()
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT scan_type, results, summary, timestamp FROM scan_results ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [
            {"type": r[0], "results": json.loads(r[1]), "summary": r[2], "timestamp": r[3]}
            for r in rows
        ]
    
    def get_context(self, limit: int = 10) -> str:
        incidents = self.get_incidents(limit)
        patterns = self.get_patterns(limit=5)
        
        context = "CONTEXT FROM PREVIOUS SESSIONS:\n"
        context += f"- Past incidents: {len(incidents)}\n"
        
        if incidents:
            context += "Recent incidents:\n"
            for inc in incidents[:3]:
                context += f"  * {inc['type']} ({inc['severity']})\n"
        
        if patterns:
            context += "Known patterns:\n"
            for pat in patterns[:3]:
                context += f"  * {pat['pattern']} ({pat['category']}, seen {pat['seen']} times)\n"
        
        return context
    
    def close(self):
        self.conn.close()
