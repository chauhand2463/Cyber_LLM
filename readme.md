# CyberLLM: Autonomous Security Agents
### Powered by JARVIS Controller Architecture

---

## Overview

**CyberLLM** is an advanced autonomous cybersecurity framework. It uses a JARVIS Controller to understand natural language intent, orchestrate specialized AI agents, and learn from every incident.

This system is capable of:

- **Autonomous Threat Hunting**: Scans processes, files, and logs for IOCs.
- **Intelligent Routing**: Understands commands like "check open ports" or "audit admins".
- **Self-Healing**: Automatically recovers from execution errors.
- **Continuous Learning**: Remembers past incidents to detect patterns.

## Key Capabilities

- **JARVIS Interface**: Chat naturally with your security system.
- **Multi-Agent Swarm**:
  - **Coordinator**: Manages the mission.
  - **Hunter**: Scans for threats.
  - **Analyst**: Analyzes data and provides intelligence.
- **Memory Engine**: Stores threat events and learns from them.
- **Auto-Recovery**: Detects and fixes OS-specific errors.

---

## Getting Started

### Interactive Mode (Recommended)

```bash
python main.py
```

Then select mode 3 for JARVIS:

```
Select [0-7]: 3
JARVIS > check open ports
```

### Quick Commands

```bash
python main.py 1       # Quick system info
python main.py 2       # EXTREME - Full threat hunt
python main.py 3       # JARVIS - AI Assistant
python main.py 4       # NETWORK - Network scan
python main.py 5       # AUDIT - User audit
python main.py 6       # THREAT - Threat scan
python main.py 7       # FULL - Complete scan
```

---

## Menu Options

| Mode | Command | Description |
|------|---------|-------------|
| INFO | 1 | Quick system info (hostname, IP, OS, user) |
| EXTREME | 2 | Full threat hunt (system, network, processes, services, registry, tasks, users, drivers, firewall) |
| JARVIS | 3 | AI Assistant - Ask questions naturally |
| NETWORK | 4 | Network scan (IP, netstat, ARP, routes) |
| AUDIT | 5 | User audit (users, admins, guest, policies) |
| THREAT | 6 | Threat scan (processes, services, network, registry, tasks, firewall) |
| FULL | 7 | Complete security scan |

---

## JARVIS Examples

```
JARVIS > check open ports
**CRITICAL**: Multiple unknown connections to foreign addresses.
**RED FLAGS**: Unusual TCP connections to ports 443 and 5222
**ACTION**: Run a full network scan.

JARVIS > audit admins
**CRITICAL**: Unrestricted admin access.
**RED FLAGS**: Unknown user "chauh", Guest account enabled
**ACTION**: Disable Guest account.

JARVIS > list files in downloads
**FILE LISTING**
**Downloads** (13 files):
  - file1.exe
  - document.pdf
```

---

## Technology Stack

- **Core**: Python 3.x
- **Brain**: Groq API (llama-3.3-70b-versatile) - FREE
- **Controller**: JARVIS Intent Classifier
- **Memory**: SQLite

---

## Author

**DK CHAUHAN** - Lead Developer & Architect

---

<div align="center">
<i>From Chatbot to Cyber Defense Grid</i>
</div>
