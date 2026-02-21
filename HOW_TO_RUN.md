# How to Run CyberLLM Agents

This project provides **3 distinct modes** for running cybersecurity operations.

## Prerequisites
Ensure your virtual environment is active:
```powershell
# Activate venv
.venv\Scripts\Activate
```

---

## 1. Interactive Real-Time Mode (Recommended)
**Best for**: Daily usage, chat-based interaction, and exploring the system.
You speak naturally, and the system uses a **Hybrid Router** to choose the best agent for the job.

**Command:**
```powershell
python interactive_session.py
```

**Example Commands:**
- "Scan the network for open ports"
- "Is there any malware on this system?"
- "Audit the admin users"
- "Check the registry for persistence"

---

## 2. Targeted Scenario Mode (Automation)
**Best for**: CI/CD pipelines, scheduled tasks, or running a specific, repeatable playbook.
This bypasses the router and guarantees a specific scenario runs.

**Command:**
```powershell
.\run_framework.ps1 --scenario [scenario_name]
```

**Available Scenarios:**
- `adv_threat_hunt` : Full AI hunting loop (Process + File Analysis + Sigma Rule Gen).
- `adv_network`     : Advanced Network Analysis (Risk Scoring + Port Scan).
- `adv_user`        : User Privilege Audit (Admin checks).
- `adv_persistence` : Registry Persistence Audit.
- `adv_sys_info`    : System Configuration Security Check.

**Example:**
```powershell
.\run_framework.ps1 --scenario adv_network
```

---

## 3. Custom Task Mode (Ad-Hoc)
**Best for**: One-off experiments or unique tasks not covered by pre-built scenarios.
The `Task Coordinator Agent` will assemble a team to solve your specific problem.

**Command:**
```powershell
.\run_framework.ps1 "Your task description here"
```

**Example:**
```powershell
.\run_framework.ps1 "Analyze the file scenarios/definitions.py and count the lines of code"
```

---

## Troubleshooting
- **Rate Limit Errors (429)**: The system automatically handles this by pausing or summarizing data locally. If you see this, just wait 60 seconds.
- **AutoML Warning**: If you see a warning about `flaml`, it is harmless, but you can ignore it as we have optimized the CLI to work without it.
