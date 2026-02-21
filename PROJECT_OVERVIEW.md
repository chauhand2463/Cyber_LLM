# Project Overview: CyberLLM

## 1. Vision
**CyberLLM** transforms cybersecurity from a manual, reactive process into an **autonomous, agentic workflow**. By leveraging Large Language Models (LLMs) and a custom JARVIS Controller, this project allows security teams to delegate complex tasks to AI agents.

## 2. Architecture: The JARVIS System

The project is built around the **JARVIS Controller**, which acts as the central nervous system:

1.  **Intent Classification**: "Brain" that processes natural language.
2.  **Scenario Engine**: "Reflexes" that execute pre-defined, safe workflows (Threat Hunt, Network Scan).
3.  **Agent Swarm**: "Hands" that interact with the OS (cmd_exec_agent, text_analyst_agent).
4.  **Knowledge Base**: "Memory" that learns from past incidents.

## 3. Agents & Roles
-   **JARVIS**: The decision maker.
-   **Task Coordinator**: Orchestrates sub-tasks.
-   **Text Analyst**: Forensic analysis of logs and files.
-   **Command Executor**: Safely runs shell commands (PowerShell/Bash awareness).
-   **IOC Extractor**: specialized in finding Indicators of Compromise.

## 4. Scenarios
-   **Advanced Threat Hunt**: Full system sweep for malware.
-   **Network Pulse**: Port scanning and risk assessment.
-   **User Audit**: Privilege escalation detection.
-   **Persistence Check**: Registry and startup analysis.

## 5. Deployment
The system is designed to run locally or in a container, providing maximum privacy and control over the security data.

---
*Built by DK CHAUHAN*
