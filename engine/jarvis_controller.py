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

JARVIS_ANALYSIS_PROMPT = """You are JARVIS, an elite Cyber Security Analyst. Analyze the data and provide tactical intelligence.

Format:
**CRITICAL**: [Key threats in 1 line]
**RED FLAGS**: [Max 3 bullet points]
**ACTION**: [One command to fix]

Max 50 words. Be blunt."""

class JarvisController:
    """
    The central brain of the system.
    Orchestrates Intent Detection -> Scenario Selection -> Execution -> Recovery.
    """
    
    SCENARIO_MAP = {
        "FILE_SCAN": None,  # Handled specially
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
        # 1. Intent Detection
        intent = self.classifier.detect_intent(user_input)
        
        if intent == "UNKNOWN":
            return {
                "status": "error",
                "message": "I'm not sure what you want me to do. Try asking to 'scan network', 'check threats', 'list files', or 'audit users'."
            }

        # 2. Handle FILE_SCAN specially
        if intent == "FILE_SCAN":
            return self._execute_file_scan(user_input)
        
        # 3. Scenario Selection
        scenario_class = self.SCENARIO_MAP.get(intent)
        if not scenario_class:
             return {
                "status": "error",
                "message": f"Intent '{intent}' is recognized but no scenario is mapped to it."
            }

        # 4. Execute using Jarvis-specific scenario with elite analysis
        return self._execute_jarvis_scenario(intent, user_input)

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
                               instruction_template=f"""{JARVIS_ANALYSIS_PROMPT}

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
                               instruction_template=f"""{JARVIS_ANALYSIS_PROMPT}

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
                               instruction_template=f"""{JARVIS_ANALYSIS_PROMPT}

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
                               instruction_template=f"""{JARVIS_ANALYSIS_PROMPT}

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
