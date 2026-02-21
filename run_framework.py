import autogen_compat as autogen
from agents.coordinator_agents import task_coordinator_agent
from agents.text_agents import text_analyst_agent, register_tools as register_text_tools
from agents.code_agents import cmd_exec_agent, register_tools as register_code_tools
from agents.intelligence_agents import ioc_extractor_agent, threat_classifier_agent
import sys
import json

# Register tools
register_text_tools()
register_code_tools()

import argparse
from engine.scenario_engine import ScenarioRunner
from scenarios.threat_hunt import ThreatHuntScenario

# ... (Previous imports and setup)

import argparse
from engine.scenario_engine import ScenarioRunner
from scenarios.definitions import (
    ThreatHuntScenario, SystemInfoScenario, NetworkCheckScenario, 
    FileContentScenario, ProcessAnalysisScenario
)
from scenarios.advanced_scenarios import AdvancedThreatHuntScenario, AdvancedSystemInfoScenario, AdvancedNetworkScan, AdvancedUserAudit, AdvancedPersistenceCheck

SCENARIOS = {
    "threat_hunt": ThreatHuntScenario,
    "sys_info": SystemInfoScenario,
    "net_check": NetworkCheckScenario,
    "file_content": FileContentScenario,
    "process_check": ProcessAnalysisScenario,
    "adv_threat_hunt": AdvancedThreatHuntScenario,
    "adv_sys_info": AdvancedSystemInfoScenario,
    "adv_network": AdvancedNetworkScan,
    "adv_user": AdvancedUserAudit,
    "adv_persistence": AdvancedPersistenceCheck
}

def run_framework(task_description=None, scenario_name=None):
    if scenario_name:
        if scenario_name not in SCENARIOS:
            print(f"Unknown scenario: {scenario_name}")
            print("Available scenarios:", list(SCENARIOS.keys()))
            return

        print(f"Starting Scenario: {scenario_name}")
        
        # Initialize the runner with our agents
        agent_map = {
            "task_coordinator_agent": task_coordinator_agent,
            "text_analyst_agent": text_analyst_agent,
            "cmd_exec_agent": cmd_exec_agent,
            "ioc_extractor_agent": ioc_extractor_agent,
            "threat_classifier_agent": threat_classifier_agent
        }
        runner = ScenarioRunner(agent_map)
        
        scenario_class = SCENARIOS[scenario_name]
        scenario = scenario_class()
        context = runner.run(scenario)
        print("\nFinal Context:", json.dumps(context, indent=2, default=str))
            
    elif task_description:
        # GroupChat Mode for ad-hoc tasks
        print(f"Starting Multi-Agent Framework with task: {task_description}")
        
        # Ensure user_proxy can execute tools in GroupChat mode too
        user_proxy = autogen.UserProxyAgent(
            name="user_proxy",
            human_input_mode="NEVER",
            code_execution_config={"work_dir": "llm_working_folder/code", "use_docker": False},
            is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE"),
        )
        
        # Register tools to user_proxy for GroupChat execution
        from tools.code_tools import exec_shell_command
        user_proxy.register_for_execution(name="exec_shell_command")(exec_shell_command)
        
        groupchat = autogen.GroupChat(
            agents=[user_proxy, task_coordinator_agent, text_analyst_agent, cmd_exec_agent],
            messages=[],
            max_round=20,
            speaker_selection_method="auto" 
        )
        # Prepare a clean config for the manager (no tools allowed in manager config in recent AutoGen)
        manager_llm_config = task_coordinator_agent.llm_config.copy()
        if "functions" in manager_llm_config:
            del manager_llm_config["functions"]
        if "tools" in manager_llm_config:
            del manager_llm_config["tools"]

        manager = autogen.GroupChatManager(groupchat=groupchat, llm_config=manager_llm_config)

        user_proxy.initiate_chat(
            manager,
            message=f"Current Task: {task_description}. Please coordinate the execution."
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("task", nargs="*", help="The task description")
    parser.add_argument("--scenario", help=f"Name of the scenario to run. Available: {', '.join(SCENARIOS.keys())}")
    args = parser.parse_args()
    
    task_desc = " ".join(args.task) if args.task else None
    
    # Default task if nothing provided
    if not task_desc and not args.scenario:
        print("No task or scenario provided. Running default task.")
        task_desc = "List the files in the current directory and analyze if there are any suspicious files."

    run_framework(task_desc, args.scenario)
