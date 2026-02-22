from typing import Dict, List, Any
from engine.memory_store import MemoryStore
import json
import uuid
import datetime

class DecisionEngine:
    def __init__(self):
        self.memory = MemoryStore()

    def analyze_and_decide(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Final decision logic before reporting.
        """
        # 1. Gather Context
        risk_result = context.get('risk_result', {})
        if isinstance(risk_result, str):
             # Try parsing if string
             try: risk_result = json.loads(risk_result)
             except: risk_result = {}
             
        risk_score = float(risk_result.get('risk_score', 0.0))
        matched_factors = risk_result.get('matched_factors', [])
        
        # Get IOCs flat list for correlation
        ioc_data = context.get('ioc_result', {})
        if isinstance(ioc_data, str):
            try: ioc_data = json.loads(ioc_data)
            except: ioc_data = {}
            
        all_process = ioc_data.get('process_iocs', [])
        all_files = ioc_data.get('file_iocs', [])
        all_indicators = all_process + all_files
        
        # 2. Correlate (Step 6)
        related_events = self.memory.find_related_threats(all_indicators)
        history_note = ""
        if related_events:
            history_note = f"Identified {len(related_events)} prior occurrences. Potential persistence/reinfection."
        
        # 3. Decision Logic (Step 7)
        verdict = "BENIGN"
        action_level = "LOG ONLY"
        recommended_actions = []
        
        if risk_score > 50:
            verdict = "MALICIOUS"
            action_level = "QUARANTINE + ALERT"
            recommended_actions = ["Isolate Host", "Kill Processes", "Forensic Backup"]
        elif risk_score > 20:
            verdict = "SUSPICIOUS"
            action_level = "ALERT"
            recommended_actions = ["Increase Monitoring", "Scan with AV"]
        else:
            verdict = "BENIGN"
            action_level = "LOG ONLY"
            recommended_actions = ["Log Event", "Routine Check"]
            
        # 4. Explainable AI (Step 8)
        reasons = []
        if matched_factors:
            reasons.append(f"Detected risk indicators: {', '.join(matched_factors)}")
        if history_note:
            reasons.append(history_note)
        if not reasons:
            reasons.append("No significant risk factors found.")
            
        # 5. Production Output (Step 9)
        incident_id = f"TH-{datetime.datetime.now().strftime('%Y-%m-%d')}-{str(uuid.uuid4())[:4]}"
        
        final_output = {
            "incident_id": incident_id,
            "summary": f"{verdict} activity detected. {history_note}",
            "threat_type": context.get('classification_result', {}).get('threat_type', 'Unknown'),
            "risk_level": verdict, # Using verdict as level
            "risk_score": risk_score,
            "confidence": 0.85, # Static for now or derive
            "iocs": {
                "processes": all_process,
                "files": all_files
            },
            "explanation": reasons,
            "recommended_actions": recommended_actions
        }
        
        # Log this final event
        self.memory.log_threat_event(
            indicators=all_indicators,
            risk_score=risk_score,
            verdict=verdict
        )
        
        return final_output
