#!/usr/bin/env python
"""
CyberLLM - Autonomous Cybersecurity AI Agent
Main entry point for the CLI tool
"""

import sys
import os

def main():
    """Main entry point for CyberLLM CLI."""
    from cyberllm.interactive_session import run_interactive
    run_interactive()

if __name__ == "__main__":
    main()
