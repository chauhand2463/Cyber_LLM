# 📘 CyberLLM Master Manual

This guide covers everything you need to know to run, control, and understand the **CyberLLM** system.

---

## 1. 🌟 Interactive Mode (JARVIS)
**The Recommended Experience.**
This mode launches the JARVIS Controller, which allows you to speak to the system in plain English. JARVIS understands your intent, fixes syntax errors, and manages the agents for you.

### How to Run
```powershell
.venv\Scripts\python.exe interactive_session.py
```

### Example Commands
Once the `JARVIS >` prompt appears, try these:

| Your Command | JARVIS Action | Expected Result |
| :--- | :--- | :--- |
| **"Scan the network"** | Runs `AdvancedNetworkScan` | Lists open ports, identifies services, and alerts on risky ports (e.g. 3389). |
| **"Is anyone logged in?"** | Runs `AdvancedUserAudit` | Lists active users/admins and flags suspicious accounts. |
| **"Check for malware"** | Runs `AdvancedThreatHunt` | Scans processes/files, checks for IOCs, and generates a Risk Report. |
| **"Check persistence"** | Runs `AdvancedPersistenceCheck` | Scans Registry Run keys and Startup folders for backdoors. |

### What Happens Behind the Scenes
1.  **Intent Classification**: JARVIS decides which scenario matches your request.
2.  **Execution**: Agents (Hunter, Analyst, Executor) perform the task.
3.  **Optimization**: If the finding is **BENIGN**, expensive steps (Sigma Rule Generation, Learning) are **skipped** to save tokens.
4.  **Learning**: If a **REAL THREAT** is found, JARVIS learns the pattern for future detection.

---

## 2. ⚡ CLI Mode (Direct Scenario)
**For Automation & Testing.**
Use this mode if you want to run a specific scenario immediately without chatting. Good for cron jobs or automated testing.

### How to Run
Use the `run_framework.ps1` script with the `--scenario` argument.

```powershell
.\run_framework.ps1 --scenario [SCENARIO_NAME]
```

### Available Scenarios

| Scenario Name | Description |
| :--- | :--- |
| `adv_threat_hunt` | **Full System Sweep**. Process, File, and IOC analysis. |
| `adv_network` | **Network Pulse**. Port scanning and service discovery. |
| `adv_user` | **User Audit**. Privilege and account analysis. |
| `adv_persistence` | **Startup/Registry Scan**. Checks for hidden startup items. |
| `adv_sys_info` | **System Health**. General OS and resource info. |

**Example:**
```powershell
.\run_framework.ps1 --scenario adv_threat_hunt
```

---

## 3. 🧠 Configuration & Tuning

### Adjusting Intelligence (Tokens vs Cost)
Edit: `utils/shared_config.py`

*   **Fast Model (`llama-3.1-8b-instant`)**: Used for IOC Extraction, Classification, and simple Analysis. Very fast and cheap.
*   **Smart Model (`llama-3.3-70b-versatile`)**: Used for complex Decision Logic and Reasoning.
*   **Max Tokens**: Default is `256` to prevent verbose outputs. Increase this if reports are cut off.

### Adding New Intents
Edit: `engine/intent_classifier.py`
Add your new keywords to the `KEYWORD_MAP` dictionary.

---

## 4. 📂 Directory Structure

*   `agents/`: Definitions of the AI Agents (Coordinator, Analyst, Hunter).
*   `engine/`: Core logic (JARVIS, Memory Store, Scenario Engine).
*   `scenarios/`: The workflows defining what agents do step-by-step.
*   `llm_working_folder/`: **(Important)** This is where the agents "live".
    *   `memory.db`: The SQLite database storing all logs and learned patterns.
    *   `code/`: Where the `cmd_exec_agent` runs commands.

---

## 5. Troubleshooting

**Q: "Rate Limit Exceeded" / 429 Error?**
**A:** The system has auto-optimization. Wait 1-2 minutes. The system will now fail gracefully (returning a "Partial Report") instead of crashing.

**Q: The system is just outputting strings like `{"action": "run_command"}`?**
**A:** This is normal. We upgraded the agent protocol to use **JSON Actions** instead of native Tool Calls to prevent compatibility errors with some API providers (Groq). The engine automatically executes these.

---
*Powered by CyberLLM*
