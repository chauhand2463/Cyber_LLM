import warnings
import sys
import actions.agent_actions

from autogen_compat import (
    ConversableAgent,
    UserProxyAgent,
    runtime_logging,
    AUTOGEN_AVAILABLE
)

from agents import text_agents, caldera_agents, code_agents
from utils.logs import print_usage_statistics
from agents.text_agents import task_coordinator_agent
from utils.shared_config import clean_working_directory


def init_agents():
    """Initialize all agents and register tools."""
    warnings.filterwarnings("ignore", category=UserWarning)

    # Windows console encoding fix
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass

    # Clean working directories
    clean_working_directory("/caldera")
    clean_working_directory("/pdf")
    clean_working_directory("/code")

    # Register tools
    text_agents.register_tools()
    code_agents.register_tools()


def retrieve_agent(agent_name):
    """Retrieve agent by name."""
    agent_map = {
        "caldera_agent": caldera_agents.caldera_agent,
        "internet_agent": text_agents.internet_agent,
        "text_analyst_agent": text_agents.text_analyst_agent,
        "cmd_exec_agent": code_agents.cmd_exec_agent,
    }
    return agent_map.get(agent_name)


def run_scenario(scenario_name):
    """Run a specific scenario."""
    init_agents()

    scenario_tasks = []

    if scenario_name in actions.agent_actions.scenarios.keys():
        scenario_action_names = actions.agent_actions.scenarios[scenario_name]

        for scenario_action_name in scenario_action_names:
            for scenario_action in actions.agent_actions.actions[scenario_action_name]:
                scenario_task = {
                    "recipient": retrieve_agent(scenario_action["agent"]),
                    "message": scenario_action["message"],
                    "silent": False,
                }

                scenario_task["clear_history"] = scenario_action.get("clear_history", True)
                
                if "summary_prompt" in scenario_action:
                    scenario_task["summary_prompt"] = scenario_action["summary_prompt"]
                if "summary_method" in scenario_action:
                    scenario_task["summary_method"] = scenario_action["summary_method"]
                if "carryover" in scenario_action:
                    scenario_task["carryover"] = scenario_action["carryover"]

                scenario_tasks.append(scenario_task)

    if scenario_tasks:
        if AUTOGEN_AVAILABLE and runtime_logging:
            logging_session_id = runtime_logging.start(config={"dbname": "logs.db"})
        
        task_coordinator_agent.initiate_chats(scenario_tasks)
        
        if AUTOGEN_AVAILABLE and runtime_logging:
            runtime_logging.stop()
            print_usage_statistics(logging_session_id)
    else:
        print("Scenario not found, exiting")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_agents.py <scenario_name>")
        print("Example: python run_agents.py DETECT_EDR")
        sys.exit(1)

    scenario_to_run = sys.argv[1]
    run_scenario(scenario_to_run)
