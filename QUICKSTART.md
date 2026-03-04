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
| `cyberllm` then select `A` | ARTEMIS AI Assistant |
| `python main.py 1` | Quick system info |
| `python main.py 2` | Network scan |
| `python main.py 3` | User audit |
| `python main.py 4` | Process list |
| `python main.py 5` | Services |
| `python main.py 6` | Full scan |

## ARTEMIS Examples

### Web Scraping
```
ARTEMIS > https://example.com
```

### CVE Lookup
```
ARTEMIS > CVE-2024-1234
```

### IP Lookup
```
ARTEMIS > 8.8.8.8
```

### Security Commands
```
ARTEMIS > check open ports
ARTEMIS > list administrators
ARTEMIS > system info
ARTEMIS > scan for threats
```

### General Questions
```
ARTEMIS > what is Python?
ARTEMIS > explain SQL injection
```

## Environment Setup

Create `.env` file:
```
GROQ_API_KEY=your_api_key_here
```

Get free API key at https://groq.com
