import sys
import argparse
import logging
from typing import Optional
from scenarios.definitions import (
    ThreatHuntScenario, SystemInfoScenario, NetworkCheckScenario, 
    FileContentScenario, ProcessAnalysisScenario
)
from scenarios.advanced_scenarios import (
    AdvancedThreatHuntScenario, AdvancedSystemInfoScenario, 
    AdvancedNetworkScan, AdvancedUserAudit, AdvancedPersistenceCheck
)
from engine.scenario_engine import ScenarioRunner
from agents.coordinator_agents import task_coordinator_agent
from agents.text_agents import text_analyst_agent
from agents.code_agents import cmd_exec_agent
from agents.intelligence_agents import ioc_extractor_agent, threat_classifier_agent

# Configure quieter logging for interactive mode
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

SCENARIOS = {
    # Advanced / Extreme Scenarios (Preferred)
    "adv_threat_hunt": AdvancedThreatHuntScenario,
    "adv_sys_info": AdvancedSystemInfoScenario,
    "adv_network": AdvancedNetworkScan,
    "adv_user": AdvancedUserAudit,
    "adv_persistence": AdvancedPersistenceCheck,
    
    # Basic Scenarios (Legacy)
    "threat_hunt": ThreatHuntScenario,
    "sys_info": SystemInfoScenario
}

from engine.jarvis_controller import JarvisController

def run_interactive():
    print("="*60)
    print("      CYBERLLM SECURITY AGENT - JARVIS MODE")
    print("="*60)
    print("Type 'exit' to quit.")
    print("Examples: 'Check open ports', 'Scan for malware', 'Audit admins'")
    
    # Initialize JARVIS
    jarvis = JarvisController()
    
    while True:
        try:
            user_input = input("\nJARVIS > ").strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
            
        if not user_input:
            continue
            
        if user_input.lower() in ["exit", "quit", "q"]:
            print("Goodbye, Agent.")
            break
            
        # Process via JARVIS
        try:
            result = jarvis.process_input(user_input)
            
            if result['status'] == 'error':
                 print(f"[!] {result['message']}")
                 continue
                 
            # Success
            print("\n" + "-"*40)
            print("MISSION REPORT")
            print("-" * 40)
            report = result.get('data', {})
            
            if isinstance(report, dict):
                print(f"Intent:     {result.get('intent')}")
                print(f"Risk Level: {report.get('risk_level', 'UNKNOWN')}")
                print(f"Summary:    {report.get('summary', 'No summary provided')}")
                
                 # Dynamic Field Printing based on context
                for key, val in report.items():
                    if key not in ['risk_level', 'summary', 'incident_id'] and val:
                        # Print list-like or interesting fields
                        if isinstance(val, list):
                            print(f"{key.replace('_', ' ').title()}: {val}")
            else:
                print(str(report))
                
            print("-" * 40)
            
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled by user.")
            continue
        except Exception as e:
            print(f"[CRITICAL_FAILURE] System Error: {e}")

if __name__ == "__main__":
    run_interactive()
