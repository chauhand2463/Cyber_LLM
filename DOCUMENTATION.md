# ARTEMIS - Advanced Cybersecurity AI Agent

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-green" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Menu Options](#menu-options)
6. [Penetration Testing](#penetration-testing)
7. [AI Assistant](#ai-assistant)
8. [Configuration](#configuration)
9. [Troubleshooting](#troubleshooting)

---

## Overview

**ARTEMIS** (Advanced Research and Modeling for Ethical Intelligence System) is an advanced AI-powered cybersecurity assistant designed for security professionals, penetration testers, and system administrators.

### Key Features

- **Dual LLM Support** - Local (Ollama) or Cloud (Groq API)
- **System Scanning** - Quick system info, processes, services
- **Network Analysis** - Connections, ports, firewall status
- **User Auditing** - User enumeration, privilege analysis
- **Penetration Testing** - Nmap, Nikto, Nuclei, Enum4linux
- **CTI Integration** - CVE lookup, threat intelligence
- **AI-Powered Analysis** - Natural language processing

---

## Features

### 1. System Scanning
- Quick system info (hostname, user, IP)
- Running processes with CPU/Memory
- Windows services
- Registry startup entries
- Firewall configuration

### 2. Network Scanning
- All network connections
- Open ports listing
- Routing table

### 3. User Auditing
- List all local users
- Administrator group members
- Privilege analysis

### 4. Penetration Testing
- **Nmap** - Port scanning
- **Nikto** - Web vulnerability scanner
- **Nuclei** - Template-based vulnerability scanner
- **Enum4linux** - SMB enumeration
- **Exploit Search** - SearchSploit integration

### 5. Threat Intelligence
- NIST CVE lookup
- CVE enrichment with threat intel
- Recent vulnerabilities tracking
- IP reputation checking

### 6. AI Assistant
- Natural language commands
- Automated task planning
- Security analysis
- Remediation recommendations

---

## Installation

### Prerequisites

```bash
# Python 3.9+
python --version

# Optional: Ollama for local LLM
# Download from https://ollama.ai
```

### Setup

```bash
# Clone repository
git clone <repo-url>
cd cyber-security-llm-agents

# Install dependencies
pip install -r requirements.txt

# Configure .env file
# See Configuration section
```

---

## Quick Start

### Option 1: Menu Interface

```bash
python main.py
```

### Option 2: AI Assistant

```bash
python artemis.py
```

---

## Menu Options

### Main Menu

```
================================================================================
                              MAIN MENU
================================================================================
  [1] SYSTEM SCANS      - Quick system information
  [2] NETWORK SCAN      - Network connections and ports
  [3] USER AUDIT        - User accounts and privileges
  [4] PROCESSES         - Running processes
  [5] SERVICES          - System services
  [6] FULL SCAN         - Complete security scan
--------------------------------------------------------------------------------
  [E] EXTREME MODE     - Full penetration testing suite
  [W] WEB SCAN         - Web application testing
  [P] PENTEST          - All penetration testing tools
--------------------------------------------------------------------------------
  [A] ARTEMIS          - Interactive AI Assistant
--------------------------------------------------------------------------------
  [L] LOCAL            - Switch to local Ollama
  [R] API              - Switch to Groq API
--------------------------------------------------------------------------------
  [D] DOCUMENTATION    - View complete documentation
  [F] FEATURES         - View all features
--------------------------------------------------------------------------------
  [0] EXIT             - Quit
================================================================================
```

### System Scans
| Option | Description |
|--------|-------------|
| 1 | Quick system info (hostname, user, IP) |
| 4 | List running processes |
| 5 | List system services |

### Network Scans
| Option | Description |
|--------|-------------|
| 2 | Network connections and ports |

### User Auditing
| Option | Description |
|--------|-------------|
| 3 | User accounts and admin groups |

### Full Scan
| Option | Description |
|--------|-------------|
| 6 | Complete security scan |

---

## Penetration Testing

### EXTREME MODE [E]

Comprehensive security assessment including:
- Phase 1: System Reconnaissance
- Phase 2: Network Analysis
- Phase 3: Process Analysis
- Phase 4: Service Enumeration
- Phase 5: User Auditing
- Phase 6: Persistence Check
- Phase 7: Firewall Status

### WEB SCAN [W]

Web application testing:
- **Nikto** - Web vulnerability scanner
- **Nuclei** - Template-based scanner
- **Full Web Assessment**

### PENTEST [P]

Full penetration testing tools:

```
Select tool:
  [1] Nmap - Port Scanner
  [2] Nikto - Web Vulnerability
  [3] Nuclei - Template Scanner
  [4] Enum4linux - SMB Enum
  [5] Exploit Search
  [6] Full Recon
```

### Usage Example

```
Select option: P

[PENETRATION TESTING SUITE]
Select tool:
  [1] Nmap - Port Scanner
  [2] Nikto - Web Vulnerability
  [3] Nuclei - Template Scanner
  [4] Enum4linux - SMB Enum
  [5] Exploit Search
  [6] Full Recon

Choice: 1
Enter target (IP/URL): 192.168.1.1

[+] Running on 192.168.1.1...

[RESULTS]
{
  "status": "success",
  "target": "192.168.1.1",
  "scan_type": "quick",
  "output": "..."
}
```

---

## AI Assistant

### Using ARTEMIS [A]

```
Select option: A

ARTEMIS > help
ARTEMIS > feature
ARTEMIS > network
ARTEMIS > CVE-2024-1234
ARTEMIS > plan scan for vulnerabilities
ARTEMIS > who is the president
```

### Commands in ARTEMIS

```
Scans:
  network, ports, processes, users, admins, services, startup, firewall, full scan

CTI:
  CVE-2024-xxxx, cve enrich, recent cves, threat IP

PenTest:
  scan TARGET, vuln TARGET, nikto URL, nuclei URL, exploit SEARCH

AI:
  plan TASK, history, audit

General:
  feature, help, local/api, clear, exit
```

---

## Configuration

### Environment Variables (.env)

```bash
# LOCAL LLM (Ollama)
USE_LOCAL_LLM=true
LOCAL_LLM_URL=http://localhost:11434/v1
LOCAL_LLM_MODEL=gpt-oss-20b
LOCAL_LLM_API_KEY=ollama

# API LLM (Groq)
USE_LOCAL_LLM=false
GROQ_API_KEY=your_groq_api_key
OPENAI_API_BASE=https://api.groq.com/openai/v1

# Other
WEB_SERVER_PORT=8800
```

### Switching Modes

```
[L] - Switch to Local (Ollama)
[R] - Switch to API (Groq)
```

---

## Troubleshooting

### Ollama Not Running

```bash
# Start Ollama
ollama serve

# Pull model
ollama pull gpt-oss-20b
```

### API Key Issues

Ensure `.env` file exists with correct API key:
```bash
GROQ_API_KEY=your_key_here
```

### Import Errors

```bash
pip install -r requirements.txt
```

---

## Model Information

### Local Model (Recommended)
- **Model**: gpt-oss-20b
- **Provider**: Ollama
- **Benefits**: Privacy, offline use, no API costs

### API Model (Cloud)
- **Model**: llama-3.3-70b-versatile
- **Provider**: Groq
- **Benefits**: Faster, more powerful

---

## Safety & Compliance

- All actions are logged
- Safety checks on commands
- Authorization verification
- Audit trail maintained

> **Note**: Only use for authorized security testing in controlled environments.

---

## License

MIT License

---

## Author

**DK CHAUHAN** - Lead Developer & Architect

---

<div align="center">
  <i>ARTEMIS v2.0 - Advanced AI-Powered Cybersecurity Assistant</i>
</div>
