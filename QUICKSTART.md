# CyberLLM Quick Start Guide

## Installation

```bash
# Clone and install
git clone https://github.com/cyberllm/cyber-security-llm-agents.git
cd cyber-security-llm-agents
pip install -e .
```

## Quick Start

```bash
# Run the interactive menu
cyberllm
```

## Running Different Modes

| Command | Description |
|---------|-------------|
| `cyberllm` then select `3` | JARVIS AI Assistant |
| `python main.py 1` | Quick system info |
| `python main.py 2` | Full threat hunt |
| `python main.py 3` | JARVIS AI Assistant |
| `python main.py 4` | Network scan |
| `python main.py 5` | User audit |
| `python main.py 6` | Threat scan |
| `python main.py 7` | Complete scan |

## JARVIS Examples

### Web Scraping
```
JARVIS > https://example.com
```

### CVE Lookup
```
JARVIS > CVE-2024-1234
```

### IP Lookup
```
JARVIS > 8.8.8.8
```

### Security Commands
```
JARVIS > check open ports
JARVIS > list administrators
JARVIS > system info
JARVIS > scan for threats
```

### General Questions
```
JARVIS > what is Python?
JARVIS > explain SQL injection
```

## Environment Setup

Create `.env` file:
```
GROQ_API_KEY=your_api_key_here
```

Get free API key at https://groq.com
