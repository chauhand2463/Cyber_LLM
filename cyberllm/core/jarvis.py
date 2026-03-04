import os
import re
import json
from typing import Dict, Any, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are ARTEMIS - an advanced intelligent AI assistant specialized in cybersecurity.

GUIDELINES:
1. Be helpful, concise, and direct
2. For simple questions, give straightforward answers
3. For security-related tasks, provide analysis with context

RESPONSE STYLE:
- General questions: Short, direct answers
- Security scans: Findings + risk rating + recommendations
"""


class ARTEMIS:
    def __init__(self, use_local: bool = True):
        self.use_local = use_local
        self.client = None
        self._init_client()
        
    def _init_client(self):
        try:
            from openai import OpenAI
            
            if self.use_local:
                local_url = os.getenv('LOCAL_LLM_URL', 'http://localhost:11434/v1')
                local_model = os.getenv('LOCAL_LLM_MODEL', 'gpt-oss-20b')
                
                if ':' not in local_model and '-' in local_model:
                    parts = local_model.rsplit('-', 1)
                    if len(parts) == 2 and parts[1].endswith(('b', 'B')):
                        local_model = f"{parts[0]}:{parts[1]}"
                
                self.client = OpenAI(
                    base_url=local_url,
                    api_key=os.getenv('LOCAL_LLM_API_KEY', 'ollama')
                )
                self.model = local_model
                print(f"[ARTEMIS] Using LOCAL model: {local_model}")
            else:
                self.client = OpenAI(
                    api_key=os.getenv('GROQ_API_KEY') or os.getenv('OPENAI_API_KEY'),
                    base_url=os.getenv('OPENAI_API_BASE', 'https://api.groq.com/openai/v1')
                )
                self.model = "llama-3.3-70b-versatile"
                print(f"[ARTEMIS] Using API model: {self.model}")
                
        except Exception as e:
            print(f"[ARTEMIS] Client init error: {e}")
            self.client = None
    
    def set_mode(self, use_local: bool):
        self.use_local = use_local
        self._init_client()
    
    def chat(self, user_input: str, context: str = "") -> str:
        if not self.client:
            return "Error: LLM client not initialized. Check your configuration."
        
        try:
            system_with_context = SYSTEM_PROMPT
            if context:
                system_with_context += f"\n\n{context}"
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_with_context},
                    {"role": "user", "content": user_input}
                ],
                temperature=0.1,
                max_tokens=2048
            )
            return response.choices[0].message.content or "I'm here to help!"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def analyze_scan(self, scan_data: Dict[str, Any]) -> str:
        prompt = f"""Analyze this scan output and provide:
1. CRITICAL findings (list first)
2. WHY each is dangerous
3. Remediation steps
4. Overall risk rating: LOW/MEDIUM/HIGH/CRITICAL

Scan Data:
{json.dumps(scan_data, indent=2)}
"""
        return self.chat(prompt)
    
    def explain_threat(self, finding: str) -> str:
        prompt = f"""Explain this security finding to a non-technical user:
- What it means
- Why it's dangerous  
- What to do about it

Finding: {finding}
"""
        return self.chat(prompt)
    
    def correlate_intel(self, iocs: list) -> str:
        prompt = f"""Correlate these Indicators of Compromise (IOCs) and identify:
1. Potential attack vectors
2. Related threats
3. Priority for investigation

IOCs: {', '.join(iocs)}
"""
        return self.chat(prompt)


class ArtemisController:
    def __init__(self, use_local: bool = True):
        from cyberllm.core.scanner import Scanner
        from cyberllm.core.intent import IntentClassifier
        from cyberllm.core.memory import MemoryEngine
        from cyberllm.core.osint import OSINT
        
        self.scanner = Scanner()
        self.classifier = IntentClassifier()
        self.memory = MemoryEngine()
        self.osint = OSINT()
        self.jarvis = ARTEMIS(use_local)
        
    def set_llm_mode(self, use_local: bool):
        self.jarvis.set_mode(use_local)
    
    def process(self, user_input: str) -> Dict[str, Any]:
        intent, match = self.classifier.classify(user_input)
        
        self.memory.add_chat("user", user_input, intent)
        
        if intent == "CVE_LOOKUP" and match:
            result = self.osint.lookup_cve(match)
            if result.get('status') == 'success':
                analysis = self.jarvis.chat(
                    f"Explain this vulnerability to a security professional:\n{json.dumps(result)}"
                )
                return {"intent": intent, "data": result, "analysis": analysis}
            return {"intent": intent, "error": result.get('message')}
        
        elif intent == "IP_LOOKUP" and match:
            result = self.osint.ip_info(match)
            if result.get('status') == 'success':
                threat = self.osint.check_threat_intel(match)
                result['threat_intel'] = threat.get('findings', {})
            return {"intent": intent, "data": result}
        
        elif intent == "URL_SCRAPE":
            result = self.osint.scrape_url(user_input)
            return {"intent": intent, "data": result}
        
        elif intent == "NETWORK_SCAN":
            scan_result = self.scanner.run_safe("network_extended")
            analysis = self.jarvis.analyze_scan(scan_result)
            self.memory.save_scan_result("network", scan_result, analysis[:200])
            return {"intent": intent, "scan": scan_result, "analysis": analysis}
        
        elif intent == "USER_AUDIT":
            users = self.scanner.run_safe("users")
            admins = self.scanner.run_safe("admins")
            whoami = self.scanner.run_safe("whoami")
            scan_data = {"users": users, "admins": admins, "whoami": whoami}
            analysis = self.jarvis.analyze_scan(scan_data)
            return {"intent": intent, "scan": scan_data, "analysis": analysis}
        
        elif intent == "PROCESS_SCAN":
            processes = self.scanner.get_processes()[:50]
            analysis = self.jarvis.chat(
                f"Analyze these running processes for suspicious activity:\n{json.dumps(processes[:20])}"
            )
            return {"intent": intent, "processes": processes, "analysis": analysis}
        
        elif intent == "SERVICE_SCAN":
            services = self.scanner.run_safe("services")
            return {"intent": intent, "scan": services}
        
        elif intent == "SYSTEM_INFO":
            scan_result = self.scanner.run_safe("systeminfo")
            return {"intent": intent, "scan": scan_result}
        
        elif intent == "PERSISTENCE":
            startup = self.scanner.run_safe("startup")
            tasks = self.scanner.run_safe("tasks")
            analysis = self.jarvis.analyze_scan({"startup": startup, "tasks": tasks})
            return {"intent": intent, "scan": {"startup": startup, "tasks": tasks}, "analysis": analysis}
        
        elif intent == "FIREWALL":
            firewall = self.scanner.run_safe("firewall")
            return {"intent": intent, "scan": firewall}
        
        elif intent == "FULL_SCAN":
            scan_result = self.scanner.full_scan()
            analysis = self.jarvis.analyze_scan(scan_result)
            self.memory.save_scan_result("full", scan_result, analysis[:200])
            return {"intent": intent, "scan": scan_result, "analysis": analysis}
        
        elif intent == "THREAT_HUNT":
            scan_result = self.scanner.quick_scan()
            analysis = self.jarvis.analyze_scan(scan_result)
            return {"intent": intent, "scan": scan_result, "analysis": analysis}
        
        else:
            context = self.memory.get_context()
            response = self.jarvis.chat(user_input, context) or "I'm here to help! Type 'help' for available commands."
            self.memory.add_chat("assistant", response)
            return {"intent": intent, "response": response}
    
    def get_help(self) -> str:
        return self.jarvis.chat("List all available commands and what they do")
