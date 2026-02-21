from autogen_compat import ConversableAgent
from utils.shared_config import llm_config, fast_llm_config
from tools.web_tools import download_web_page, detect_telemetry_gaps
from agents.coordinator_agents import task_coordinator_agent

text_analyst_agent = ConversableAgent(
    name="text_analyst_agent",
    llm_config=fast_llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=5,
    is_termination_msg=lambda msg: (
        "terminate" in (msg.get("content") or "").lower() if msg else False
    ),
    description="""An expert analyst that processes text and returns insights in JSON.""",
    system_message="""You are the Text Analyst. Your role is to analyze the text provided by the coordinator and extract key insights.

Your output must be STRICTLY in JSON format. Do not use markdown blocks.
Schema:
{
  "summary": "Brief summary of findings",
  "indicators": ["list", "of", "key", "points"],
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.0 to 1.0,
  "recommended_actions": ["action 1", "action 2"]
}

Do not add any explanation outside the JSON.
""",
)

internet_agent = ConversableAgent(
    name="internet_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=5,
    is_termination_msg=lambda msg: (
        "terminate" in (msg.get("content") or "").lower() if msg else False
    ),
    description="""A helpful assistant that can assist in interacting with content on the internet.""",
    system_message="""Append "TERMINATE" to your response when you successfully completed the objective.""",
)


def register_tools():
    # Download a web page

    internet_agent.register_for_llm(
        name="download_web_page",
        description="Download the content of a web page and return it as a string. Only for text content such as markdown pages.",
    )(download_web_page)

    task_coordinator_agent.register_for_execution(name="download_web_page")(
        download_web_page
    )

    # Detect telemetry NOT detected by an EDR

    internet_agent.register_for_llm(
        name="detect_telemetry_gaps",
        description="Detect telemetry NOT detected by an EDR.",
    )(detect_telemetry_gaps)

    task_coordinator_agent.register_for_execution(name="detect_telemetry_gaps")(
        detect_telemetry_gaps
    )