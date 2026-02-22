from autogen_compat import ConversableAgent, register_function
from utils.shared_config import llm_config
from tools.memory_tools import query_memory

JARVIS_SYSTEM_PROMPT = """You are JARVIS, an elite Cyber Security Analyst. Analyze the data and provide tactical intelligence.

Format:
**CRITICAL**: [Key threats in 1 line]
**RED FLAGS**: [Max 3 bullet points]
**ACTION**: [One command to fix]

Max 50 words. Be blunt."""

task_coordinator_agent = ConversableAgent(
    name="task_coordinator_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=5,
    is_termination_msg=lambda msg: (
        "terminate" in (msg.get("content") or "").lower() if msg else False
    ),
    description="""The lead coordinator agent that plans and delegates tasks.""",
    system_message="""You are the Task Coordinator. Your role is to:
1. Receive a high-level security task.
2. Break it down into discrete steps.
3. Delegate specific steps to 'text_analyst_agent' (for analysis) or 'cmd_exec_agent' (for execution).
4. Aggregate results.

You have access to a persistent memory of past tasks.
Use 'query_memory' tool to check if a similar task was done before or to retrieve past findings.

You communicate ONLY via JSON. Your output must ALWAYS be a valid JSON object:
{
    "thought": "Your reasoning here",
    "next_action": "query_memory | delegate_to_text_agent | delegate_to_cmd_agent | reply_to_user",
    "params": {
        "message": "The content to send to the sub-agent or user (or query string for memory)",
        "task_id": "optional_id"
    },
    "is_complete": boolean
}

If you are done, set "is_complete": true and provide the final answer in "params.message".
Append "TERMINATE" to your response ONLY if "is_complete": true.
""",
)

jarvis_analyst_agent = ConversableAgent(
    name="jarvis_analyst_agent",
    llm_config=llm_config,
    human_input_mode="NEVER",
    code_execution_config=False,
    max_consecutive_auto_reply=5,
    is_termination_msg=lambda msg: (
        "terminate" in (msg.get("content") or "").lower() if msg else False
    ),
    description="""Elite Cyber Security Analyst (Jarvis) that provides actionable intelligence.""",
    system_message=JARVIS_SYSTEM_PROMPT,
)

# Register the memory tool
register_function(
    query_memory,
    caller=task_coordinator_agent,
    executor=task_coordinator_agent,
    name="query_memory",
    description="Search past execution logs for keywords."
)

# Register the memory tool
register_function(
    query_memory,
    caller=task_coordinator_agent,
    executor=task_coordinator_agent,
    name="query_memory",
    description="Search past execution logs for keywords."
)
