import subprocess
import re
from typing import Dict, Any, Optional
from tools.code_tools import exec_shell_command


def extract_command(instruction: str) -> str:
    """Extract the actual command from instruction text.
    
    Handles formats like:
    - "Run 'netstat -ano'."
    - "Run 'systeminfo'"
    - "netstat -ano"
    - Just returns the instruction if no pattern matches
    """
    instruction = instruction.strip()
    
    # Try to extract from "Run 'command'" pattern
    match = re.search(r"Run\s+['\"](.+?)['\"]", instruction, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    
    # Try to extract from "command" without quotes
    match = re.search(r"^(netstat|systeminfo|dir|ipconfig|tasklist|net|reg|schtasks|arp|netsh|hostname|taskkill|wmic)\s+.+", instruction, re.IGNORECASE)
    if match:
        return instruction
    
    # If it's a simple command without arguments
    simple_cmds = ['systeminfo', 'netstat', 'dir', 'ipconfig', 'tasklist', 'net user', 'hostname', 'arp -a', 'net start']
    for cmd in simple_cmds:
        if instruction.lower() == cmd.lower():
            return cmd
    
    # Return as-is if no pattern matched
    return instruction


def run_cmd(cmd: str) -> str:
    """Execute a command locally via subprocess and return output."""
    result_dict = exec_shell_command(cmd)
    if result_dict.get("returncode") != 0:
        raise RuntimeError(result_dict.get("stderr", "Command failed"))
    out = result_dict.get("stdout", "")
    if not out:
        raise ValueError("Command returned empty output")
    return out


class CmdExecutor:
    """Simple command executor that runs OS commands directly without LLM."""
    
    def __init__(self, name: str = "cmd_exec_agent"):
        self.name = name
    
    def run(self, instruction: str) -> Dict[str, Any]:
        """Execute the command from instruction and return result."""
        try:
            # Extract the actual command
            command = extract_command(instruction)
            result = run_cmd(command)
            return {"status": "success", "output": result}
        except Exception as e:
            return {"status": "error", "error": str(e)}


cmd_exec_agent = CmdExecutor()

def register_tools():
    """Register tools (no-op since we use direct execution)."""
    pass
