from autogen_compat import ConversableAgent
from utils.shared_config import llm_config, fast_llm_config
import json

# 1. IOC Extraction Agent
ioc_extractor_agent = ConversableAgent(
    name="ioc_extractor_agent",
    llm_config=fast_llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=1,
    description="Extracts IOCs from raw text.",
    system_message="""You are an expert IOC (Indicator of Compromise) Extractor.

Your task:
1. Read the provided text (logs, lists, reports).
2. Extract specific entities: Processes, Files, Network Behavior/Patterns.
3. Return STRICTLY JSON.

Input Format: Unstructured text.
Output Schema:
{
  "process_iocs": ["list", "of", "process", "names"],
  "file_iocs": ["list", "of", "filenames"],
  "behavior_iocs": ["list", "of", "behaviors"]
}

Do not add markdown formatting like ```json ... ```. Just return the raw JSON string if possible, or strictly valid JSON.
Ignore benign common items if clearly safe (like 'System Idle Process'), but err on the side of capturing potential signals.
""",
)

# 2. Threat Classification Agent
threat_classifier_agent = ConversableAgent(
    name="threat_classifier_agent",
    llm_config=fast_llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=1,
    description="Classifies threats based on IOCs.",
    system_message="""You are a Threat Classifier.

Your task:
1. Analyze the provided list of IOCs.
2. Classify the threat into one of: "Malware", "Living-off-the-land", "Unauthorized application", "Benign", "Suspicious but unconfirmed".
3. Assign a severity level (LOW, MEDIUM, HIGH, CRITICAL).
4. Return STRICTLY JSON.

Output Schema:
{
  "threat_type": "Category",
  "severity": "Level",
  "reason": "Brief explanation"
}

Do not add commentary. Return strict JSON.
""",
)
