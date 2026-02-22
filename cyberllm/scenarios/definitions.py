from engine.scenario_engine import Scenario, ScenarioStep

class ThreatHuntScenario(Scenario):
    name = "Threat Hunting Workflow"
    steps = [
        ScenarioStep(
            step_name="List Process Files",
            agent_name="cmd_exec_agent",
            instruction_template="Please list the files in the current directory using 'dir'.",
            save_output_to_context_key="file_list_result"
        ),
        ScenarioStep(
            step_name="Analyze Files",
            agent_name="text_analyst_agent",
            instruction_template="Here is the output from the file listing:\n{file_list_result}\n\nPlease analyze this list for any suspicious files or anomalies. Return your analysis in JSON.",
            save_output_to_context_key="analysis_result"
        ),
        ScenarioStep(
            step_name="Synthesize Findings",
            agent_name="task_coordinator_agent",
            instruction_template="We have completed a threat hunt. \nAnalysis Result: {analysis_result}\n\nPlease provide a final summary.",
            save_output_to_context_key="final_summary"
        )
    ]

class SystemInfoScenario(Scenario):
    name = "System Information"
    steps = [
        ScenarioStep(
            step_name="Get System Info",
            agent_name="cmd_exec_agent",
            instruction_template="Get system information (hostname, OS version). On Windows use 'systeminfo'.",
            save_output_to_context_key="sys_info"
        ),
        ScenarioStep(
            step_name="Summarize Info",
            agent_name="text_analyst_agent",
            instruction_template="Analyze the following system info:\n{sys_info}\n\nProvide a brief summary of the environment.",
            save_output_to_context_key="summary"
        )
    ]

class NetworkCheckScenario(Scenario):
    name = "Network Check"
    steps = [
        ScenarioStep(
            step_name="Check Connections",
            agent_name="cmd_exec_agent",
            instruction_template="Check active network connections using 'netstat -an'.",
            save_output_to_context_key="net_connections"
        ),
        ScenarioStep(
            step_name="Analyze Connections",
            agent_name="text_analyst_agent",
            instruction_template="Analyze these network connections:\n{net_connections}\n\nFlag any suspicious ports (e.g., non-standard high ports) or listening services.",
            save_output_to_context_key="net_analysis"
        )
    ]

class FileContentScenario(Scenario):
    name = "File Content Analysis"
    steps = [
        ScenarioStep(
            step_name="Create Dummy File",
            agent_name="cmd_exec_agent",
            instruction_template="Create a file named 'suspicious_log.txt' with the content 'User=root Password=password123' using echo.",
            save_output_to_context_key="create_result"
        ),
        ScenarioStep(
            step_name="Read File",
            agent_name="cmd_exec_agent",
            instruction_template="Read the content of 'suspicious_log.txt' using 'type' or 'cat'.",
            save_output_to_context_key="file_content"
        ),
        ScenarioStep(
            step_name="Analyze Content",
            agent_name="text_analyst_agent",
            instruction_template="Analyze this file content:\n{file_content}\n\nLook for sensitive data/credentials.",
            save_output_to_context_key="content_analysis"
        )
    ]

class ProcessAnalysisScenario(Scenario):
    name = "Process Analysis"
    steps = [
        ScenarioStep(
            step_name="List Processes",
            agent_name="cmd_exec_agent",
            instruction_template="List running processes using 'tasklist'.",
            save_output_to_context_key="process_list"
        ),
        ScenarioStep(
            step_name="Analyze Processes",
            agent_name="text_analyst_agent",
            instruction_template="Analyze this process list:\n{process_list}\n\nIdentify any known malicious or suspicious process names.",
            save_output_to_context_key="process_analysis"
        )
    ]
