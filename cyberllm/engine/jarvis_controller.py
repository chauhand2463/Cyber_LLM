import logging
import platform
import json
from typing import Dict, Any, Optional
from engine.intent_classifier import IntentClassifier
from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
from engine.memory_store import MemoryStore
from scenarios.definitions import (
    ThreatHuntScenario, SystemInfoScenario, NetworkCheckScenario
)
from scenarios.advanced_scenarios import (
    AdvancedThreatHuntScenario, AdvancedSystemInfoScenario, 
    AdvancedNetworkScan, AdvancedUserAudit, AdvancedPersistenceCheck
)
from agents.coordinator_agents import task_coordinator_agent, jarvis_analyst_agent
from agents.text_agents import text_analyst_agent
from agents.code_agents import cmd_exec_agent
from agents.intelligence_agents import ioc_extractor_agent, threat_classifier_agent

logger = logging.getLogger(__name__)

JARVIS_CYBER_PROMPT = """SYSTEM ROLE: RED-TEAM LEAD
MISSION: Penetration Test & Vulnerability Assessment

Identify:
- Crown Jewels: Admin accounts, sensitive files
- Entry Point: Open ports, weak services
- Exploit Path: How to escalate from User to Admin

OUTPUT FORMAT:
TARGET: [Service/Account]
VULNERABILITY: [CVE or config weakness]
EXPLOIT: [step 1, step 2]
MITIGATION: [CLI fix]

STRICT: Code-ready commands. Zero fluff. Max 30 words."""

JARVIS_REGULAR_PROMPT = """You are Jarvis, a helpful AI assistant. Be witty, charming, and efficient.
Keep response under 2 sentences. Answer directly."""

# Intent types that trigger CYBER mode
CYBER_INTENTS = {"THREAT_HUNT", "NETWORK_SCAN", "USER_AUDIT", "PERSISTENCE_CHECK", "SYS_INFO", "FILE_SCAN", "WEB_SCRAPE"}

# Safe to test - local only
SAFE_TARGETS = ("127.0.0.1", "localhost", "0.0.0.0")

def get_prompt_for_intent(intent: str) -> str:
    """Get the appropriate prompt based on intent type."""
    if intent in CYBER_INTENTS:
        return JARVIS_CYBER_PROMPT
    return JARVIS_REGULAR_PROMPT

def validate_target(target: str) -> bool:
    """Safety: Only allow local targets."""
    if not target:
        return True  # No target = safe
    target = target.strip().lower()
    return any(safe in target for safe in SAFE_TARGETS)

class JarvisController:
    """
    The central brain of the system.
    Orchestrates Intent Detection -> Scenario Selection -> Execution -> Recovery.
    """
    
    SCENARIO_MAP = {
        "FILE_SCAN": None,  # Handled specially
        "WEB_SCRAPE": None,  # Handled specially
        "THREAT_HUNT": AdvancedThreatHuntScenario,
        "NETWORK_SCAN": AdvancedNetworkScan,
        "USER_AUDIT": AdvancedUserAudit,
        "PERSISTENCE_CHECK": AdvancedPersistenceCheck,
        "SYS_INFO": AdvancedSystemInfoScenario
    }

    def __init__(self):
        self.classifier = IntentClassifier()
        self.memory = MemoryStore()
        self.os_type = platform.system()
        
        # Initialize Agents
        self.agent_map = {
            "task_coordinator_agent": task_coordinator_agent,
            "jarvis_analyst_agent": jarvis_analyst_agent,
            "text_analyst_agent": text_analyst_agent,
            "cmd_exec_agent": cmd_exec_agent,
            "ioc_extractor_agent": ioc_extractor_agent,
            "threat_classifier_agent": threat_classifier_agent
        }
        self.runner = ScenarioRunner(self.agent_map)

    def process_input(self, user_input: str) -> Dict[str, Any]:
        """
        Main entry point for user interaction.
        """
        import re
        
        # Check for CVE lookup
        if re.search(r'CVE-\d{4}-\d{4,}', user_input, re.IGNORECASE):
            return self._execute_cve_lookup(user_input)
        
        # Check for IP lookup
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input):
            return self._execute_ip_lookup(user_input)
        
        # 1. Intent Detection
        intent = self.classifier.detect_intent(user_input)
        
        # 2. Handle URL scraping
        if intent == "WEB_SCRAPE":
            return self._execute_web_scrape(user_input)
        
        # 3. Handle general questions with AI
        if intent == "UNKNOWN":
            return self._answer_general_question(user_input)
        
        # 4. Handle FILE_SCAN specially
        if intent == "FILE_SCAN":
            return self._execute_file_scan(user_input)
        
        # 5. Scenario Selection
        scenario_class = self.SCENARIO_MAP.get(intent)
        if not scenario_class:
             return self._answer_general_question(user_input)

        # 6. Execute using Jarvis-specific scenario with elite analysis
        return self._execute_jarvis_scenario(intent, user_input)

    def _answer_general_question(self, user_input: str) -> Dict[str, Any]:
        """Answer general questions using AI."""
        try:
            from openai import OpenAI
            import os
            from dotenv import load_dotenv
            
            load_dotenv()
            
            client = OpenAI(
                api_key=os.getenv('GROQ_API_KEY') or os.getenv('OPENAI_API_KEY'),
                base_url=os.getenv('OPENAI_API_BASE', 'https://api.groq.com/openai/v1')
            )
            
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are JARVIS, an elite AI assistant. Be helpful, concise, and smart. Answer questions directly."},
                    {"role": "user", "content": user_input}
                ],
                max_tokens=300
            )
            
            answer = response.choices[0].message.content
            
            return {
                "status": "success",
                "intent": "GENERAL_QUESTION",
                "data": answer,
                "context": {}
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"I couldn't answer that. Error: {str(e)}"
            }

    def _execute_file_scan(self, user_input: str) -> Dict[str, Any]:
        """Execute file listing scan."""
        
        # Determine which directories to scan
        scan_paths = []
        user_lower = user_input.lower()
        
        if "download" in user_lower:
            scan_paths.append(("%USERPROFILE%\\Downloads", "Downloads"))
        if "desktop" in user_lower:
            scan_paths.append(("%USERPROFILE%\\Desktop", "Desktop"))
        if "document" in user_lower:
            scan_paths.append(("%USERPROFILE%\\Documents", "Documents"))
        if "recent" in user_lower:
            scan_paths.append(("%USERPROFILE%\\AppData\\Local\\Recent", "Recent"))
        
        # Default: scan user home
        if not scan_paths:
            scan_paths = [
                ("%USERPROFILE%", "UserHome"),
                ("%USERPROFILE%\\Downloads", "Downloads"),
                ("%USERPROFILE%\\Desktop", "Desktop"),
            ]
        
        class FileScanScenario(Scenario):
            name = "JARVIS File Scan"
            steps = []
            
            for path, key in scan_paths[:3]:  # Max 3 directories
                steps.append(ScenarioStep(
                    step_name=f"Scan_{key}",
                    agent_name="cmd_exec_agent",
                    instruction_template=f"dir {path} /b 2>nul | findstr .",
                    save_output_to_context_key=f"files_{key}"
                ))
        
        try:
            print(f"JARVIS: Scanning files...")
            context = self.runner.run(FileScanScenario())
            
            # Format results
            result = "**FILE LISTING**\n\n"
            for path, key in scan_paths[:3]:
                files = context.get(f"files_{key}", "")
                if files:
                    file_list = [f.strip() for f in files.split('\n') if f.strip()][:20]
                    result += f"**{key}** ({len(file_list)} files):\n"
                    for f in file_list:
                        result += f"  - {f}\n"
                    result += "\n"
            
            return {
                "status": "success",
                "intent": "FILE_SCAN",
                "data": result,
                "context": context
            }
        except Exception as e:
            logger.error(f"File scan failed: {e}")
            return {
                "status": "failure",
                "message": f"File scan failed: {str(e)}"
            }

    def _execute_web_scrape(self, user_input: str) -> Dict[str, Any]:
        """Execute web scraping when URL is detected."""
        from tools.scraper_tool import scrape_basic, scrape_security_info
        
        url = user_input.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            print(f"JARVIS: Scraping {url}...")
            
            basic_result = scrape_basic(url)
            
            if basic_result.get("status") != "success":
                return {
                    "status": "error",
                    "intent": "WEB_SCRAPE",
                    "message": f"Failed to scrape: {basic_result.get('message', 'Unknown error')}"
                }
            
            security_result = scrape_security_info(url)
            
            findings = {}
            if security_result.get("status") == "success":
                findings = security_result.get("findings", {})
            
            output = {
                "URL": url,
                "Title": basic_result.get("title", "N/A"),
                "Server": basic_result.get("server", "N/A"),
                "Status": basic_result.get("status_code", "N/A"),
            }
            
            if findings.get("emails"):
                output["Emails"] = findings["emails"][:5]
            if findings.get("tech_stack"):
                output["Tech Stack"] = findings["tech_stack"]
            if findings.get("versions"):
                output["Versions"] = findings["versions"][:5]
            if findings.get("endpoints"):
                output["Endpoints"] = findings["endpoints"][:10]
            if findings.get("ipv4"):
                output["IPs Found"] = findings["ipv4"][:5]
            if findings.get("cve_mentions"):
                output["CVEs"] = findings["cve_mentions"][:5]
            
            output["Content"] = basic_result.get("text", "")[:1000] + "..."
            
            return {
                "status": "success",
                "intent": "WEB_SCRAPE",
                "data": output,
                "context": {"url": url, "basic": basic_result, "security": security_result}
            }
        except Exception as e:
            logger.error(f"Web scrape failed: {e}")
            return {
                "status": "failure",
                "message": f"Web scrape failed: {str(e)}"
            }
    
    def _execute_cve_lookup(self, user_input: str) -> Dict[str, Any]:
        """Execute CVE lookup."""
        from tools.scraper_tool import lookup_cve
        import re
        
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', user_input, re.IGNORECASE)
        if not cve_match:
            return {"status": "error", "message": "No CVE ID found in input"}
        
        cve_id = cve_match.group()
        print(f"JARVIS: Looking up {cve_id}...")
        
        result = lookup_cve(cve_id)
        
        if result.get("status") == "success":
            output = {
                "CVE": result.get("id"),
                "Description": result.get("description", "N/A")[:300],
                "Severity": result.get("severity", "N/A"),
                "CVSS Score": result.get("cvss_score", "N/A"),
                "Published": result.get("published", "N/A"),
            }
            return {"status": "success", "intent": "CVE_LOOKUP", "data": output}
        else:
            return {"status": "error", "message": result.get("message", "Lookup failed")}
    
    def _execute_ip_lookup(self, user_input: str) -> Dict[str, Any]:
        """Execute IP lookup."""
        from tools.scraper_tool import ip_info
        import re
        
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input)
        if not ip_match:
            return {"status": "error", "message": "No IP address found in input"}
        
        ip = ip_match.group()
        print(f"JARVIS: Looking up IP {ip}...")
        
        result = ip_info(ip)
        
        if result.get("status") == "success":
            output = {
                "IP": result.get("ip"),
                "Country": result.get("country"),
                "Region": result.get("region"),
                "City": result.get("city"),
                "ISP": result.get("isp"),
                "Organization": result.get("org"),
                "AS": result.get("as"),
            }
            return {"status": "success", "intent": "IP_LOOKUP", "data": output}
        else:
            return {"status": "error", "message": result.get("message", "Lookup failed")}

    def _execute_jarvis_scenario(self, intent: str, user_input: str) -> Dict[str, Any]:
        """Execute a scenario using Jarvis-style analysis."""
        
        # Create a custom scenario based on intent
        class JarvisScenario(Scenario):
            name = f"JARVIS {intent} Analysis"
            
            if intent == "NETWORK_SCAN":
                steps = [
                    ScenarioStep(step_name="Run Netstat", agent_name="cmd_exec_agent",
                               instruction_template="netstat -ano", save_output_to_context_key="raw_netstat"),
                    ScenarioStep(step_name="Run IPConfig", agent_name="cmd_exec_agent",
                               instruction_template="ipconfig /all", save_output_to_context_key="raw_ipconfig"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw Network Data:
=== NETSTAT ===
{{raw_netstat}}

=== IPCONFIG ===
{{raw_ipconfig}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
            elif intent == "USER_AUDIT":
                steps = [
                    ScenarioStep(step_name="List Admins", agent_name="cmd_exec_agent",
                               instruction_template="net localgroup administrators", save_output_to_context_key="raw_admins"),
                    ScenarioStep(step_name="List Users", agent_name="cmd_exec_agent",
                               instruction_template="net user", save_output_to_context_key="raw_users"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw User Data:
=== ADMIN GROUP ===
{{raw_admins}}

=== ALL USERS ===
{{raw_users}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
            elif intent == "PERSISTENCE_CHECK":
                steps = [
                    ScenarioStep(step_name="Check Registry", agent_name="cmd_exec_agent",
                               instruction_template="reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                               save_output_to_context_key="raw_registry"),
                    ScenarioStep(step_name="Check Services", agent_name="cmd_exec_agent",
                               instruction_template="sc query", save_output_to_context_key="raw_services"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw Persistence Data:
=== REGISTRY RUN KEYS ===
{{raw_registry}}

=== SERVICES ===
{{raw_services}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
            else:
                # Default: system info
                steps = [
                    ScenarioStep(step_name="Get SystemInfo", agent_name="cmd_exec_agent",
                               instruction_template="systeminfo", save_output_to_context_key="raw_sysinfo"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw System Data:
{{raw_sysinfo}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
        
        scenario = JarvisScenario()
        try:
            print(f"JARVIS: Initiating {scenario.name}...")
            context = self.runner.run(scenario)
            
            report = context.get('jarvis_report', context.get('final_report', {}))
            
            self._log_history(scenario.name, "success")
            
            return {
                "status": "success",
                "intent": scenario.name,
                "data": report,
                "context": context
            }
            
        except Exception as e:
            logger.error(f"JARVIS: Scenario failed: {e}")
            self._log_history(scenario.name, "failure", str(e))
            
            return {
                "status": "failure",
                "message": f"I couldn't complete the {scenario.name}. Error: {str(e)}",
                "suggestion": "Check your system configuration or try a different scan."
            }

    def _safe_execute_scenario(self, scenario_class) -> Dict[str, Any]:
        """
        Executes a scenario with error handling and recovery logic.
        """
        scenario = scenario_class()
        try:
            print(f"JARVIS: Initiating {scenario.name}...")
            context = self.runner.run(scenario)
            
            # Extract Report for simple return
            report = context.get('final_report', {})
            
            # Log success
            self._log_history(scenario.name, "success")
            
            return {
                "status": "success",
                "intent": scenario.name,
                "data": report,
                "context": context # Full context for advanced inspection
            }
            
        except Exception as e:
            logger.error(f"JARVIS: Scenario failed: {e}")
            self._log_history(scenario.name, "failure", str(e))
            
            return {
                "status": "failure",
                "message": f"I couldn't complete the {scenario.name}. Error: {str(e)}",
                "suggestion": "Check your system configuration or try a different scan."
            }

    def _log_history(self, action: str, status: str, error: str = ""):
        """
        Logs execution capability to memory (placeholder for now).
        """
        # In a full implementation, this would write to a 'history' table in DB.
        pass
