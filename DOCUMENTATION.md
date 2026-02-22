# CyberLLM - Complete Documentation

## Table of Contents
1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Project Structure](#project-structure)
4. [Usage](#usage)
5. [Technical Details](#technical-details)

---

## Features

### 1. JARVIS AI Assistant
- **Natural Language Processing**: Ask questions in plain English
- **Security Scanning**: Detects security-related commands and runs appropriate scans
- **General Q&A**: Can answer any question using Groq's free AI
- **File Listing**: Scan directories like Downloads, Desktop, Documents

### 2. 7 Scan Modes

| Mode | Description |
|------|-------------|
| **INFO** | Quick system info (hostname, IP, OS, user) |
| **EXTREME** | Full threat hunt (system, network, processes, services, registry, tasks, users, drivers, firewall) |
| **JARVIS** | AI Assistant - chat naturally |
| **NETWORK** | Network scan (IP, netstat, ARP, routes) |
| **AUDIT** | User audit (users, admins, guest, policies) |
| **THREAT** | Threat scan (processes, services, network, registry, tasks, firewall) |
| **FULL** | Complete security scan |

### 3. Key Capabilities

- **Intent Classification**: Automatically detects what you want to do
- **Local Execution**: Runs Windows commands directly (no API for scans)
- **AI Analysis**: Uses Groq's free API for intelligent responses
- **Memory Storage**: Stores scan results in SQLite database
- **Error Recovery**: Automatically handles failed commands

---

## How It Works

### 1. Main Entry Point (main.py)

When you run `python main.py`:
1. Displays CyberLLM banner
2. Shows menu with 7 options
3. Waits for user Exec input
4.utes selected mode

### 2. Menu System

```
Select [0-7]: 1
```

Each mode maps to a function:
- `1` → `run_simple()` - Quick info
- `2` → `run_extreme()` - Full scan
- `3` → `run_jarvis()` - AI assistant
- `4` → `run_network()` - Network scan
- `5` → `run_user_audit()` - User audit
- `6` → `run_threat_scan()` - Threat scan
- `7` → `run_all_scan()` - Complete scan

### 3. Scenario Engine

The `ScenarioRunner` executes steps sequentially:

```python
class Scenario:
    name = "Scan Name"
    steps = [
        ScenarioStep(
            step_name="Step1",
            agent_name="cmd_exec_agent",
            instruction_template="command to run",
            save_output_to_context_key="result_key"
        ),
    ]
```

### 4. Command Execution (cmd_exec_agent)

```
User Input → Intent Detection → Command Extraction → Local Execution → Result
```

Steps:
1. Receives instruction (e.g., "Run 'netstat -ano'")
2. Extracts actual command using regex
3. Executes via `subprocess.run()`
4. Returns output

### 5. JARVIS Controller

For mode 3 (JARVIS):

```
User Question → Intent Classifier → 
    ├─ Known Intent → Run Security Scan → AI Analysis → Report
    └─ Unknown Intent → Ask AI → Direct Answer
```

#### Intent Detection
Detects these intents:
- `FILE_SCAN` - "list files", "scan downloads"
- `NETWORK_SCAN` - "check ports", "network scan"
- `USER_AUDIT` - "audit admins", "list users"
- `THREAT_HUNT` - "scan malware", "check threats"
- `PERSISTENCE_CHECK` - "check registry", "startup"
- `SYS_INFO` - "system info", "hostname"

### 6. AI Integration

Uses Groq's free API:
- Model: `llama-3.3-70b-versatile`
- Endpoint: `https://api.groq.com/openai/v1`
- No OpenAI cost

---

## Project Structure

```
cyber-security-llm-agents/
├── main.py                    # Entry point with menu
├── interactive_session.py     # JARVIS chat interface
├── autogen_compat.py         # AutoGen compatibility
├── .env                      # API keys
│
├── agents/
│   ├── code_agents.py        # CmdExecutor - runs local commands
│   ├── text_agents.py        # Text analysis agent
│   ├── coordinator_agents.py # Task coordination
│   └── intelligence_agents.py # IOC extraction
│
├── engine/
│   ├── scenario_engine.py    # Runs scenarios step by step
│   ├── jarvis_controller.py # AI controller with intent detection
│   ├── intent_classifier.py # Detects user intent
│   ├── memory_store.py      # SQLite storage
│   └── ...
│
├── scenarios/
│   ├── definitions.py        # Basic scenarios
│   ├── advanced_scenarios.py # Complex scenarios
│   └── threat_hunt.py       # Threat hunting
│
├── tools/
│   ├── code_tools.py        # Command execution
│   └── memory_tools.py      # Memory queries
│
└── utils/
    ├── constants.py          # Configuration
    └── shared_config.py     # LLM config
```

---

## Usage

### Basic Commands

```bash
# Interactive menu
python main.py

# Direct modes
python main.py 1       # INFO
python main.py 2       # EXTREME
python main.py 3       # JARVIS
python main.py 4       # NETWORK
python main.py 5       # AUDIT
python main.py 6       # THREAT
python main.py 7       # FULL
```

### JARVIS Examples

```bash
python main.py 3
```

Then type:

```
JARVIS > check open ports
JARVIS > audit admins
JARVIS > list files in downloads
JARVIS > what is malware
JARVIS > how to secure my wifi
JARVIS > who are you
```

---

## Technical Details

### Command Execution Flow

1. **Input**: "Run 'netstat -ano'"
2. **Extract**: `extract_command()` → "netstat -ano"
3. **Execute**: `exec_shell_command()` → `subprocess.run()`
4. **Return**: JSON with stdout, stderr, returncode

### Intent Classification

```python
INTENTS = {
    "NETWORK_SCAN": ["port", "netstat", "tcp", "connection", ...],
    "USER_AUDIT": ["user", "admin", "group", ...],
    "FILE_SCAN": ["file", "directory", "list", ...],
    ...
}
```

### AI Analysis Prompt

JARVIS uses a concise format:

```
**CRITICAL**: [Key threat in 1 line]
**RED FLAGS**: [Max 3 bullet points]
**ACTION**: [One fix command]

Max 50 words.
```

### API Configuration

In `.env`:
```
GROQ_API_KEY=your_groq_key_here
OPENAI_API_BASE=https://api.groq.com/openai/v1
OPENAI_MODEL_NAME=llama-3.3-70b-versatile
```

---

## Security Notes

- All scans run locally on your machine
- No data sent to external servers (except AI questions)
- Uses Windows built-in commands only
- Results stored locally in SQLite
- Payload generation is BLOCKED for external IPs

---

## Advanced Features

### CVE Database
Local knowledge base of common vulnerabilities:
- SMB: CVE-2020-0796 (SMBGhost), CVE-2017-0144 (EternalBlue)
- RDP: CVE-2019-0708 (BlueKeep)
- SSH: CVE-2023-48795 (RegreSSHion)

### Banner Grabbing
Service version detection for vulnerability assessment.

### Process-to-Network Correlation
Match PIDs to ports to identify which process is communicating.

### Safe Payload Generation
- Only generates for local/private networks (127.0.0.1, 10.x.x.x, 192.168.x.x)
- Blocks external targets for safety
- For authorized lab testing only

---

## Author

**DK CHAUHAN** - Lead Developer & Architect

---

## License

This is a security tool for educational and authorized testing purposes only.
