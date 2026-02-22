import sqlite3
import json
import datetime
import os
import logging
import utils.constants

# Use a dedicated database file in the working directory
DB_PATH = os.path.join(utils.constants.LLM_WORKING_FOLDER, "memory.db")

logger = logging.getLogger(__name__)

class MemoryStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS execution_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    scenario_name TEXT,
                    step_name TEXT,
                    agent_name TEXT,
                    input_text TEXT,
                    output_text TEXT
                )
            ''')
            
            # New table for structured threat events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    indicators TEXT,
                    risk_score REAL,
                    verdict TEXT
                )
            ''')
            
            # Knowledge Base for Learned Patterns (JARVIS Memory)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS knowledge_base (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    entry_type TEXT,
                    content TEXT,
                    tags TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"MemoryStore initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize MemoryStore: {e}")

    def log_step(self, scenario_name: str, step_name: str, agent_name: str, input_text: str, output_text: str):
        """Log a step execution."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            timestamp = datetime.datetime.now().isoformat()
            
            # Ensure output is a string (encode JSON if dict)
            if isinstance(output_text, (dict, list)):
                output_text = json.dumps(output_text)
            
            cursor.execute('''
                INSERT INTO execution_logs (timestamp, scenario_name, step_name, agent_name, input_text, output_text)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, scenario_name, step_name, agent_name, input_text, str(output_text)))
            
            conn.commit()
            conn.close()
            logger.info(f"Logged step '{step_name}' to memory.")
        except Exception as e:
            logger.error(f"Failed to log step: {e}")

    def log_threat_event(self, indicators: list, risk_score: float, verdict: str):
        """Log a high-level threat event."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            timestamp = datetime.datetime.now().isoformat()
            
            cursor.execute('''
                INSERT INTO threat_events (timestamp, indicators, risk_score, verdict)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, json.dumps(indicators), risk_score, verdict))
            
            conn.commit()
            conn.close()
            logger.info(f"Logged threat event: {verdict}")
        except Exception as e:
            logger.error(f"Failed to log threat event: {e}")

    def find_related_threats(self, indicators: list) -> list:
        """Find past events that share indicators (Cross-Session Correlation)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            results = []
            # This is a basic correlation check. In production, use FTS or normalized tags.
            # Here we check if any previous record contains the exact same indicator string? 
            # Or simpler: get all recent events and python-filter.
            
            cursor.execute('SELECT timestamp, indicators, verdict, risk_score FROM threat_events ORDER BY id DESC LIMIT 50')
            rows = cursor.fetchall()
            conn.close()
            
            # Basic correlation logic
            for row in rows:
                ts, past_indicators_str, verdict, risk = row
                try:
                    past_indicators = json.loads(past_indicators_str)
                    # Check intersection
                    if set(indicators) & set(past_indicators):
                        results.append({
                            "timestamp": ts,
                            "verdict": verdict,
                            "risk_score": risk,
                            "common_indicators": list(set(indicators) & set(past_indicators))
                        })
                except:
                    pass
                    
            return results
        except Exception as e:
            logger.error(f"Failed to find related threats: {e}")
            return []

    def query_logs(self, query: str, limit: int = 5) -> list:
        """Search logs for a specific query (simple text match)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Simple LIKE query on inputs and outputs
            search_term = f"%{query}%"
            cursor.execute('''
                SELECT timestamp, scenario_name, step_name, agent_name, output_text 
                FROM execution_logs 
                WHERE input_text LIKE ? OR output_text LIKE ?
                ORDER BY id DESC
                LIMIT ?
            ''', (search_term, search_term, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                results.append({
                    "timestamp": row[0],
                    "scenario": row[1],
                    "step": row[2],
                    "agent": row[3],
                    "output": row[4]
                })
            return results
        except Exception as e:
            logger.error(f"Failed to query logs: {e}")
            return []

    def learn_from_incident(self, report: dict):
        """Stores a finalized incident report into the Knowledge Base."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            timestamp = datetime.datetime.now().isoformat()
            
            # Auto-tagging
            tags = []
            if report.get('risk_level') == 'HIGH': tags.append('HIGH_RISK')
            if 'threat_type' in report: tags.append(report['threat_type'].upper().replace(" ", "_"))
            
            cursor.execute('''
                INSERT INTO knowledge_base (timestamp, entry_type, content, tags)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, "INCIDENT_REPORT", json.dumps(report), ",".join(tags)))
            
            conn.commit()
            conn.close()
            logger.info("JARVIS: Learned new pattern from incident.")
        except Exception as e:
            logger.error(f"Failed to learn from incident: {e}")
