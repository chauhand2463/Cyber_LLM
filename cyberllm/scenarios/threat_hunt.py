from engine.scenario_engine import Scenario, ScenarioStep

class ThreatHuntScenario(Scenario):
    name = "Threat Hunting Workflow"
    steps = [
        ScenarioStep(
            step_name="List Process Files",
            agent_name="cmd_exec_agent",
            instruction_template="Please list the files in the current directory.",
            save_output_to_context_key="file_list_result"
        ),
        ScenarioStep(
            step_name="Analyze Files",
            agent_name="text_analyst_agent",
            instruction_template="Here is a list of files obtained from the system:\n{file_list_result}\n\nPlease analyze this list for any suspicious files or anomalies. Return your analysis in JSON.",
            save_output_to_context_key="analysis_result"
        ),
        ScenarioStep(
            step_name="Synthesize Findings",
            agent_name="task_coordinator_agent",
            instruction_template="We have completed a threat hunt. \nAnalysis Result: {analysis_result}\n\nPlease provide a final summary and recommendation for the user.",
            save_output_to_context_key="final_summary"
        )
    ]
