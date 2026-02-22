# CyberLLM: Autonomous Cybersecurity AI Agent

<p align="center">
  <img src="https://img.shields.io/badge/CyberLLM-v1.0.0-green" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/Groq-FreeAPI-orange" alt="Groq API">
</p>

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [How to Run](#how-to-run)
5. [Menu Options](#menu-options)
6. [JARVIS AI Assistant](#jarvis-ai-assistant)
7. [OSINT Tools](#osint-tools)
8. [Security Scans](#security-scans)
9. [Architecture](#architecture)
10. [Configuration](#configuration)
11. [Troubleshooting](#troubleshooting)
12. [License](#license)

---

## Overview

**CyberLLM** is an advanced autonomous cybersecurity framework powered by AI. It uses a built-in JARVIS AI assistant that understands natural language to perform security operations, threat hunting, and OSINT tasks.

### Key Highlights

- 🤖 **JARVIS AI** - Natural language interface for security operations
- 🔍 **Automated Scanning** - Multiple scan modes (INFO, EXTREME, NETWORK, AUDIT, THREAT, FULL)
- 🌐 **Web Scraping** - Scrape websites for security research
- 🔎 **CVE Lookup** - Look up vulnerabilities from NIST database
- 🌍 **IP Lookup** - Get IP geolocation and ISP information
- 🛡️ **Threat Hunting** - Scan for malware and suspicious processes
- 👥 **User Auditing** - List administrators and user accounts
- 📡 **Network Analysis** - Check open ports and connections

---

## Features

### Core Features

| Feature | Description |
|---------|-------------|
| **JARVIS AI** | Natural language assistant that understands commands like "check open ports" or "show me CVE-2024-1234" |
| **Intent Classification** | Automatically detects user intent (NETWORK_SCAN, USER_AUDIT, THREAT_HUNT, etc.) |
| **Multi-Agent System** | Coordinator, Hunter, Analyst agents working together |
| **Memory Engine** | SQLite-based learning from past incidents |
| **Auto-Recovery** | Detects and fixes OS-specific errors automatically |

### Scan Modes

- **INFO** - Quick system information
- **EXTREME** - Full threat hunt with all checks
- **JARVIS** - Interactive AI assistant
- **NETWORK** - Network connections and ports
- **AUDIT** - User and group auditing
- **THREAT** - Malware and threat detection
- **FULL** - Complete security scan

---

## Installation

### Prerequisites

- Python 3.9 or higher
- Groq API Key (free)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/cyberllm/cyber-security-llm-agents.git
cd cyber-security-llm-agents

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install the package
pip install -e .

# 4. Configure API key
# Create .env file with your Groq API key
echo "GROQ_API_KEY=your_api_key_here" > .env
```

### Get Free Groq API Key

1. Go to [groq.com](https://groq.com)
2. Sign up for free
3. Copy your API key
4. Add to `.env` file

---

## How to Run

### Method 1: Using cyberllm command (Recommended)

```bash
# After installation
cyberllm
```

### Method 2: Using Python module

```bash
python -m cyberllm
```

### Method 3: Using main.py directly

```bash
python main.py
```

### Method 4: Interactive Session

```bash
python interactive_session.py
```

### Quick Start with Mode Number

```bash
# Run directly with mode number
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

When you run `cyberllm`, you'll see this menu:

```
==================================================
  MODE  |  COMMAND                                  
==================================================
  [1]   |  INFO      - Quick system info            
  [2]   |  EXTREME   - Full threat hunt             
  [3]   |  JARVIS    - AI Assistant (Interactive)  
  [4]   |  NETWORK   - Network scan                 
  [5]   |  AUDIT     - User audit                   
  [6]   |  THREAT    - Threat scan                  
  [7]   |  FULL      - Complete scan                 
  [0]   |  EXIT      - Quit                         
==================================================
```

### Mode Details

| Mode | Number | Description | Commands Run |
|------|--------|-------------|--------------|
| **INFO** | 1 | Quick system info | hostname, ipconfig, ver, whoami |
| **EXTREME** | 2 | Full threat hunt | All system, network, process, service, registry checks |
| **JARVIS** | 3 | AI Assistant | Natural language interface |
| **NETWORK** | 4 | Network scan | ipconfig, netstat, arp, route |
| **AUDIT** | 5 | User audit | net user, net localgroup administrators |
| **THREAT** | 6 | Threat scan | Processes, services, network, registry |
| **FULL** | 7 | Complete scan | All above + drivers, firewall |
| **EXIT** | 0 | Quit | - |

---

## JARVIS AI Assistant

Mode 3 launches the JARVIS AI Assistant. You can interact with it using natural language.

### What You Can Ask JARVIS

#### 🔗 Web Scraping
```
JARVIS > https://example.com
JARVIS > https://github.com
```
JARVIS will scrape the website and extract:
- Title
- Tech stack
- Emails
- Endpoints
- Versions
- Content snippets

#### 🔎 CVE Lookup
```
JARVIS > CVE-2024-1234
JARVIS > CVE-2021-44228
```
JARVIS fetches:
- CVE ID
- Description
- Severity (LOW/MEDIUM/HIGH/CRITICAL)
- CVSS Score
- Publication date

#### 🌐 IP Lookup
```
JARVIS > 8.8.8.8
JARVIS > 1.1.1.1
```
JARVIS provides:
- Country
- Region/City
- ISP
- Organization
- AS number

#### 💻 Security Scans
```
JARVIS > check open ports
JARVIS > list administrators
JARVIS > system info
JARVIS > scan for threats
JARVIS > check startup programs
JARVIS > show network connections
```

#### ❓ General Questions
```
JARVIS > what is Python?
JARVIS > how does HTTPS work?
JARVIS > explain SQL injection
```

#### 📊 Format Requests
```
JARVIS > show me data in json format
JARVIS > give me a table of ports
JARVIS > export as csv
```

### JARVIS Commands

| Command | Description |
|---------|-------------|
| `help` or `?` | Show help menu |
| `menu` | Return to main menu |
| `clear` or `cls` | Clear screen |
| `exit` or `quit` | Exit JARVIS |
| `back` | Return to main menu |

---

## OSINT Tools

CyberLLM includes built-in OSINT tools:

### CVE Lookup
- Uses NIST National Vulnerability Database
- Returns severity, CVSS score, description

### IP Lookup
- Uses ip-api.com (free)
- Returns geolocation, ISP, organization

### Web Scraping
- Fast static HTML scraping
- Security-focused extraction:
  - Emails
  - API keys
  - AWS keys
  - Tech stack detection
  - API endpoints
  - Version numbers
  - CVE mentions

### Domain Info
- DNS resolution
- A record lookup

### Google Dorks (Limited)
- Provides manual search URLs
- Pre-built dork queries for:
  - Exposed configs (.env, .config)
  - Exposed databases
  - Credentials
  - Admin panels
  - Git exposures

---

## Security Scans

### Network Scanning
- `ipconfig` - IP configuration
- `netstat -ano` - All network connections
- `arp -a` - ARP table
- `route print` - Routing table

### User Auditing
- `net user` - All users
- `net localgroup administrators` - Admin group
- `net user username` - User details

### Process & Service Analysis
- `tasklist` - Running processes
- `sc query` - Windows services
- `tasklist /v` - Detailed process info

### Persistence Detection
- Registry Run keys
- Scheduled tasks
- Startup programs
- Windows services

### System Information
- `systeminfo` - Full system details
- `hostname` - Computer name
- `whoami` - Current user
- `ver` - Windows version
- `driverquery` - Installed drivers
- `netsh advfirewall show allprofiles` - Firewall rules

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              CyberLLM Main Menu                  │
└─────────────────┬───────────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌───────┐   ┌─────────┐   ┌─────────┐
│ INFO  │   │ JARVIS  │   │ NETWORK │
│ MODE  │   │  MODE   │   │  MODE   │
└───┬───┘   └────┬────┘   └───┬─────┘
    │            │             │
    └────────────┼─────────────┘
                 │
         ┌───────▼────────┐
         │   JARVIS       │
         │ Controller     │
         └───────┬────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
    ▼            ▼            ▼
┌────────┐ ┌──────────┐ ┌─────────┐
│Intent  │ │ Scenario │ │  Agent  │
│Classif.│ │ Engine   │ │ Coord.  │
└───┬────┘ └────┬────┘ └────┬────┘
    │            │            │
    ▼            ▼            ▼
┌────────┐ ┌──────────┐ ┌─────────┐
│Network │ │ Security │ │  Cmd    │
│Scan    │ │ Tools    │ │ Executor│
└────────┘ └──────────┘ └─────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **Intent Classifier** | Detects user intent from natural language |
| **Scenario Engine** | Orchestrates multi-step security scans |
| **JARVIS Controller** | Main brain coordinating all operations |
| **Memory Store** | SQLite database for learning |
| **CmdExecutor** | Executes local OS commands |
| **Agent System** | Coordinator, Analyst, Hunter agents |

---

## Configuration

### Environment Variables

Create a `.env` file:

```bash
# Required
GROQ_API_KEY=your_groq_api_key_here

# Optional
OPENAI_API_KEY=your_openai_key
OPENAI_API_BASE=https://api.groq.com/openai/v1
```

### Package Configuration (pyproject.toml)

```toml
[project]
name = "cyberllm"
version = "1.0.0"
description = "CyberLLM - Autonomous Cybersecurity AI Agent"
requires-python = ">=3.9"

[project.scripts]
cyberllm = "cyberllm.main:main"
```

---

## Troubleshooting

### Common Issues

#### 1. "No module named 'xxx'"
```bash
# Install missing dependencies
pip install -r requirements.txt
```

#### 2. "GROQ_API_KEY not found"
```bash
# Create .env file
echo "GROQ_API_KEY=your_key" > .env
```

#### 3. "Command not found" (cyberllm)
```bash
# Reinstall the package
pip install -e .
```

#### 4. Network scan fails
- Ensure you're running on Windows
- Some commands require admin privileges

### Getting Help

1. Check the menu help: Type `help` in JARVIS mode
2. Review the logs in `llm_working_folder/memory.db`
3. Run in verbose mode for more output

---

## Publishing to PyPI

To share your package with the world:

```bash
# Install build tools
pip install build twine

# Build the package
python -m build

# Upload to PyPI
twine upload dist/*
```

Then users can install with:
```bash
pip install cyberllm
```

---

## License

MIT License - See LICENSE file for details.

---

## Author

**DK CHAUHAN** - Lead Developer & Architect

---

<div align="center">
  <i>CyberLLM - From Chatbot to Cyber Defense Grid</i>
</div>
