# CyberLLM: Autonomous Cybersecurity AI Agent

<p align="center">
  <img src="https://img.shields.io/badge/CyberLLM-v2.0-green" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge-LLM-Local%20%2B%20API-orange" alt="LLM">
</p>

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [How to Run](#how-to-run)
5. [LLM Configuration](#llm-configuration)
6. [Menu Options](#menu-options)
7. [ARTEMIS AI Assistant](#artemis-ai-assistant)
8. [OSINT Tools](#osint-tools)
9. [Architecture](#architecture)
10. [Configuration](#configuration)
11. [Troubleshooting](#troubleshooting)
12. [License](#license)

---

## Overview

**CyberLLM** is an advanced autonomous cybersecurity framework powered by AI. It uses a built-in ARTEMIS AI assistant that understands natural language to perform security operations, threat hunting, and OSINT tasks.

### Key Highlights

- **Dual LLM Support** - Use local Ollama models or Groq API
- **ARTEMIS AI** - Natural language interface for security operations
- **Cross-Platform** - Works on Windows, Linux, and Mac
- **Persistent Memory** - SQLite-based learning from past incidents
- **Auto-Detection** - Automatically detects Ollama when available

---

## Features

### Core Features

| Feature | Description |
|---------|-------------|
| **Dual LLM Mode** | Use local Ollama (gpt-oss-20b) or Groq API |
| **ARTEMIS AI** | Natural language assistant for security operations |
| **Intent Classification** | Automatically detects user intent |
| **Memory Engine** | SQLite-based persistent learning |
| **Cross-Platform** | Windows, Linux, Mac support |
| **OSINT Tools** | CVE lookup, IP lookup, web scraping |

### Scan Modes

- **QUICK** - Quick system information
- **NETWORK** - Network connections and ports
- **USERS** - User and group auditing
- **PROCESSES** - Running processes
- **SERVICES** - System services
- **FULL** - Complete security scan
- **ARTEMIS** - Interactive AI assistant

---

## Installation

### Prerequisites

- Python 3.9 or higher
- **Option A**: Ollama (for local LLM)
- **Option B**: Groq API Key (free)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/cyberllm/cyber-security-llm-agents.git
cd cyber-security-llm-agents

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure LLM (see below)
```

---

## How to Run

### Option 1: Menu Interface (Recommended)

```bash
python main.py
```

### Option 2: ARTEMIS AI Assistant

```bash
python artemis.py
```

### Quick Commands

```
# From main.py menu:
  [A] ARTEMIS    - Interactive AI Assistant
[L] LOCAL     - Switch to local Ollama
[A] API       - Switch to Groq API
[1-6]         - Run scans
[0] EXIT      - Quit
```

---

## LLM Configuration

### Option A: Local Ollama (Recommended)

```bash
# Install Ollama
curl https://ollama.ai/install.sh

# Pull your model
ollama pull gpt-oss-20b
# or
ollama pull llama3

# Start Ollama
ollama serve
```

### Option B: Groq API

```bash
# Get free API key at https://groq.com
# Add to .env file:
GROQ_API_KEY=your_groq_api_key
```

### .env Configuration

```bash
# Local LLM (Ollama)
USE_LOCAL_LLM=true
LOCAL_LLM_URL=http://localhost:11434/v1
LOCAL_LLM_MODEL=gpt-oss-20b
LOCAL_LLM_API_KEY=ollama

# Or API (Groq)
USE_LOCAL_LLM=false
GROQ_API_KEY=your_api_key_here
OPENAI_API_BASE=https://api.groq.com/openai/v1
```

---

## Menu Options

### main.py

```
SELECT MODE:
  ─────────────────────────────
  [1] QUICK     - Quick system info
  [2] NETWORK   - Network connections
  [3] USERS     - User audit
  [4] PROCESSES - Running processes
  [5] SERVICES  - System services
  [6] FULL      - Complete scan
  ─────────────────────────────
[A] ARTEMIS    - Interactive AI Assistant
  ─────────────────────────────
  [L] LOCAL     - Switch to local Ollama
  [A] API       - Switch to Groq API
  ─────────────────────────────
  [0] EXIT      - Quit
```

---

## ARTEMIS AI Assistant

### What You Can Ask

```
ARTEMIS > who is the president of usa
ARTEMIS > explain SQL injection
ARTEMIS > check open ports
ARTEMIS > CVE-2024-1234
ARTEMIS > 8.8.8.8
ARTEMIS > https://example.com
ARTEMIS > run full scan
ARTEMIS > list administrators
```

### Commands

| Command | Description |
|---------|-------------|
| `help` | Show help |
| `local` / `l` | Switch to local Ollama |
| `api` / `a` | Switch to Groq API |
| `clear` | Clear screen |
| `exit` | Exit |

### Security Scans

```
network      - Network connections
ports        - Open ports
processes    - Running processes
users        - List users
admins       - List admins
services     - Running services
startup      - Startup programs
firewall     - Firewall status
full scan    - Complete system scan
threat hunt  - Quick threat scan
```

### OSINT

```
CVE-2024-xxx - CVE vulnerability lookup
8.8.8.8      - IP geolocation
https://...  - Web scraping
```

---

## OSINT Tools

### CVE Lookup
- Uses NIST National Vulnerability Database
- Returns severity, CVSS score, description

### IP Lookup
- Returns geolocation, ISP, organization
- Threat intelligence checking

### Web Scraping
- Security-focused extraction
- Emails, IPs, tech stack detection

---

## Architecture

```
cyberllm/
├── core/
│   ├── artemis.py     # Main ARTEMIS controller
│   ├── scanner.py     # Cross-platform scanner
│   ├── intent.py      # Intent classifier
│   ├── memory.py      # SQLite memory
│   └── osint.py       # CVE, IP, web tools
├── main.py            # Menu interface
├── artemis.py          # AI assistant
└── .env              # Configuration
```

---

## Configuration

### Environment Variables

```bash
# Local LLM
USE_LOCAL_LLM=true
LOCAL_LLM_URL=http://localhost:11434/v1
LOCAL_LLM_MODEL=gpt-oss-20b

# API LLM
USE_LOCAL_LLM=false
GROQ_API_KEY=your_groq_api_key
OPENAI_API_BASE=https://api.groq.com/openai/v1
```

---

## Troubleshooting

### Ollama Not Detected

```bash
# Start Ollama
ollama serve
```

### API Key Issues

```bash
# Check .env file exists and has correct key
cat .env
```

### Model Not Found

```bash
# List available models
ollama list

# Pull model
ollama pull gpt-oss-20b
```

---

## License

MIT License

---

## Author

**DK CHAUHAN** - Lead Developer & Architect

---

<div align="center">
  <i>CyberLLM v2.0 - From Chatbot to Cyber Defense Grid</i>
</div>
