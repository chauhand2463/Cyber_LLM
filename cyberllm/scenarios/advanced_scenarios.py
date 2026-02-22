from engine.scenario_engine import Scenario, ScenarioStep
from engine.risk_engine import RiskScoringEngine
from engine.decision_engine import DecisionEngine
from engine.normalization import normalize_data, parse_systeminfo, parse_netstat, parse_localgroup_admins, parse_reg_query, preprocess_threat_hunt_data
import json
import logging
from tools.code_tools import exec_shell_command

logger = logging.getLogger(__name__)

# --- ADAPTER FUNCTIONS (Deterministic) ---

def execute_tasklist_adapter(context):
    """Executes 'tasklist' without using LLM."""
    result = exec_shell_command("tasklist")
    if result.get("returncode") == 0:
        return result.get("stdout")
    return ""

def execute_dir_adapter(context):
    """Executes 'dir' without using LLM."""
    result = exec_shell_command("dir")
    if result.get("returncode") == 0:
        return result.get("stdout")
    return ""

def validation_check_adapter(context):
    """
    Checks if we have enough data to proceed.
    Returns 'VALID' or 'INVALID'.
    """
    summary = context.get("normalized_data", {})
    if not isinstance(summary, dict):
        return "INVALID: Summary is not a dict"
    
    proc_count = summary.get("process_count", 0)
    file_count = summary.get("file_count", 0)
    
    if proc_count == 0 and file_count == 0:
        return "INVALID: No data collected"
    
    # Check for suspicious items to decide if we need deep analysis
    suspicious = summary.get("suspicious_processes", [])
    if not suspicious and proc_count > 0:
        # If we have processes but none match our quick filter, we might still want the LLM to look 
        # at the summary, but maybe we can warn.
        pass
        
    return "VALID"

def risk_scoring_adapter(context):
    ioc_data = context.get('ioc_result', {})
    if isinstance(ioc_data, str):
        try: ioc_data = json.loads(ioc_data)
        except: ioc_data = {}
    indicators = []
    for key in ['process_iocs', 'file_iocs', 'behavior_iocs']:
        if key in ioc_data:
            indicators.extend(ioc_data[key])
    return RiskScoringEngine.calculate_score(indicators)

def decision_engine_adapter(context):
    """
    Adapter for the Decision Engine with robust error handling.
    """
    # 1. Parse Inputs (Handle potential strings/errors from previous steps)
    threat_data = context.get('classification_result', {})
    if isinstance(threat_data, str):
        try: 
            threat_data = json.loads(threat_data)
        except: 
            # If parsing fails, it's likely an error message (Result: Error...)
            logger.warning(f"DecisionAdapter: Invalid threat data: {threat_data}")
            threat_data = {}

    risk_result = context.get('risk_result', {})
    if isinstance(risk_result, str):
        try:
             risk_result = json.loads(risk_result)
        except:
             risk_result = {}

    # 2. Guard Clause: If critical data is missing (due to API failure), return fallback
    if not threat_data and not risk_result:
        logger.error("DecisionAdapter: Missing critical inputs (Likely Rate Limit failure). Returning fallback.")
        return {
            "incident_id": "ERROR-429-RATE-LIMIT",
            "risk_level": "UNKNOWN",
            "summary": "Analysis incomplete due to API constraints.",
            "recommended_actions": ["Retry Analysis later", "Check Raw Logs"]
        }

    # 3. Modify Context for Engine (it expects dicts)
    # We create a temporary context just for the engine call to ensure types are correct
    safe_context = context.copy()
    safe_context['classification_result'] = threat_data
    safe_context['risk_result'] = risk_result
    
    engine = DecisionEngine()
    return engine.analyze_and_decide(safe_context)

def validation_step(context):
    report = context.get('final_report', {})
    if isinstance(report, str):
        try: report = json.loads(report)
        except: pass
    if not isinstance(report, dict):
         logger.error("Final report is not a dictionary/JSON.")
         return "Validation Failed: Not JSON"
    required = ["incident_id", "risk_level"]
    for req in required:
        if req not in report:
            logger.warning(f"Validation Warning: Missing field {req}")
    return "Validation Passed"

def sys_risk_adapter(context):
    return RiskScoringEngine.calculate_system_risk(context.get('sys_data', {}))

def sys_norm_adapter(context):
    return parse_systeminfo(context.get('raw_sys_data', ""))

def net_norm_adapter(context):
    return parse_netstat(context.get('raw_net_data', ""))

def user_norm_adapter(context):
    return parse_localgroup_admins(context.get('raw_user_data', ""))

def reg_norm_adapter(context):
    return parse_reg_query(context.get('raw_reg_data', ""))

def net_risk_adapter(context):
    return RiskScoringEngine.calculate_network_risk(context.get('net_data', []))

def user_risk_adapter(context):
    return RiskScoringEngine.calculate_user_risk(context.get('user_data', []))

def persist_risk_adapter(context):
    return RiskScoringEngine.calculate_persistence_risk(context.get('reg_data', []))

def learning_adapter(context):
    """
    Adapter to learn from the final report.
    """
    from engine.memory_store import MemoryStore
    report = context.get('final_report', {})
    if isinstance(report, str):
        try: report = json.loads(report)
        except: return "Failed to parse report for learning."
        
    store = MemoryStore()
    store.learn_from_incident(report)
    return "Incident stored in Knowledge Base."

def should_generate_detection(context):
    """
    Guard condition: Only generate heavy artifacts (Sigma, Learning) if there is a real threat.
    """
    risk_result = context.get('risk_result', {})
    if isinstance(risk_result, str): return False # Error state
    
    score = risk_result.get('risk_score', 0)
    level = risk_result.get('risk_level', 'BENIGN')
    
    # Run only if score > 0 OR level is not BENIGN/LOW
    if score > 0 or level not in ['BENIGN', 'LOW']:
        return True
    return False

# --- SCENARIOS ---

class AdvancedThreatHuntScenario(Scenario):
    name = "Advanced Threat Hunt"
    steps = [
        # Optimized Steps (Python Execution, No LLM)
        ScenarioStep(step_name="List Processes", function_call=execute_tasklist_adapter, save_output_to_context_key="raw_process_data"),
        ScenarioStep(step_name="List Files", function_call=execute_dir_adapter, save_output_to_context_key="raw_file_data"),
        
        # Local Summarization
        ScenarioStep(step_name="Normalize & Summarize", function_call=preprocess_threat_hunt_data, save_output_to_context_key="normalized_data"),
        
        # Validation Check
        ScenarioStep(step_name="Validate Data Sufficiency", function_call=validation_check_adapter, save_output_to_context_key="data_validity"),

        # LLM Analysis
        ScenarioStep(step_name="Extract IOCs", agent_name="ioc_extractor_agent", instruction_template="""Analyze this system summary for IOCs.
If 'data_validity' is INVALID, return empty JSON.
Summary:
{normalized_data}""", save_output_to_context_key="ioc_result"),
        
        ScenarioStep(step_name="Classify Threats", agent_name="threat_classifier_agent", instruction_template="Classify:\n{ioc_result}", save_output_to_context_key="classification_result"),
        ScenarioStep(step_name="Risk Scoring", function_call=risk_scoring_adapter, save_output_to_context_key="risk_result"),
        ScenarioStep(step_name="Decision Logic", function_call=decision_engine_adapter, save_output_to_context_key="final_production_output"),
        ScenarioStep(step_name="Final Report", agent_name="task_coordinator_agent", instruction_template="Report: {final_production_output}", save_output_to_context_key="final_report"),
        
        # GUARDED STEPS (Only run if malicious)
        ScenarioStep(
            step_name="Generate Sigma Rule", 
            agent_name="text_analyst_agent", 
            instruction_template="""Based on the IOCs and Analysis below, generate a SIGMA RULE (YAML format) to detect this threat in the future.
IOCs: {ioc_result}
Analysis: {classification_result}
Output format: valid YAML code block.""", 
            save_output_to_context_key="sigma_rule",
            condition=should_generate_detection
        ),
            
        ScenarioStep(
            step_name="Learn Incident", 
            function_call=learning_adapter,
            condition=should_generate_detection
        )
    ]

class AdvancedSystemInfoScenario(Scenario):
    name = "Advanced System Info"
    steps = [
        ScenarioStep(step_name="Get System Info", agent_name="cmd_exec_agent", instruction_template="Run 'systeminfo'.", save_output_to_context_key="raw_sys_data"),
        ScenarioStep(step_name="Normalize Data", function_call=sys_norm_adapter, save_output_to_context_key="sys_data"),
        ScenarioStep(step_name="System Risk Scoring", function_call=sys_risk_adapter, save_output_to_context_key="sys_risk"),
        ScenarioStep(step_name="Generate Report", agent_name="text_analyst_agent", 
            instruction_template="""Generate System Security Report (STRICT JSON):
Data: {sys_data}
Risk: {sys_risk}
Format:
{{
  "incident_id": "SYS-2026-...",
  "risk_level": "{sys_risk[risk_level]}",
  "summary": "...",
  "recommendations": []
}}""", save_output_to_context_key="final_report"),
        ScenarioStep(step_name="Validate Output", function_call=validation_step)
    ]

# Optimized Extreme Scenarios (Already Fixed)
class AdvancedNetworkScan(Scenario):
    name = "Advanced Network Scan"
    steps = [
        ScenarioStep(step_name="Scan Ports", agent_name="cmd_exec_agent", instruction_template="Run 'netstat -ano'.", save_output_to_context_key="raw_net_data"),
        ScenarioStep(step_name="Normalize", function_call=net_norm_adapter, save_output_to_context_key="net_data"),
        ScenarioStep(step_name="Risk Score", function_call=net_risk_adapter, save_output_to_context_key="net_risk"),
        ScenarioStep(step_name="Report", agent_name="text_analyst_agent", 
            instruction_template="Generate JSON Report (incident_id, risk_level, open_risky_ports). Risk Assessment: {net_risk}", 
            save_output_to_context_key="final_report"),
        ScenarioStep(step_name="Validate", function_call=validation_step)
    ]

class AdvancedUserAudit(Scenario):
    name = "Advanced User Audit"
    steps = [
        ScenarioStep(step_name="Audit Admins", agent_name="cmd_exec_agent", instruction_template="Run 'net localgroup administrators'.", save_output_to_context_key="raw_user_data"),
        ScenarioStep(step_name="Normalize", function_call=user_norm_adapter, save_output_to_context_key="user_data"),
        ScenarioStep(step_name="Risk Score", function_call=user_risk_adapter, save_output_to_context_key="user_risk"),
        ScenarioStep(step_name="Report", agent_name="text_analyst_agent", 
            instruction_template="Generate JSON Report (incident_id, risk_level, suspicious_admins). Risk Assessment: {user_risk}", 
            save_output_to_context_key="final_report"),
        ScenarioStep(step_name="Validate", function_call=validation_step)
    ]

class AdvancedPersistenceCheck(Scenario):
    name = "Advanced Persistence Check"
    steps = [
        ScenarioStep(step_name="Check Registry", agent_name="cmd_exec_agent", instruction_template="Run 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'.", save_output_to_context_key="raw_reg_data"),
        ScenarioStep(step_name="Normalize", function_call=reg_norm_adapter, save_output_to_context_key="reg_data"),
        ScenarioStep(step_name="Risk Score", function_call=persist_risk_adapter, save_output_to_context_key="reg_risk"),
        ScenarioStep(step_name="Report", agent_name="text_analyst_agent", 
            instruction_template="Generate JSON Report (incident_id, risk_level, summary, suspicious_keys). Risk Assessment: {reg_risk}", 
            save_output_to_context_key="final_report"),
        ScenarioStep(step_name="Validate", function_call=validation_step)
    ]
