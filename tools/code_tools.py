from typing_extensions import Annotated
import subprocess
import os
import utils.constants
import json
import platform

CODE_WORKING_FOLDER = utils.constants.LLM_WORKING_FOLDER + "/code"

def exec_shell_command(
    shell_command: Annotated[
        str,
        "The shell command to execute locally",
    ]
) -> Annotated[dict, "The output of the command execution including stdout, stderr, and returncode"]:

    # Use os.chdir for cross-platform compatibility instead of "cd &&"
    cwd = os.getcwd()
    try:
        shell = True
        executable = None
        
        # FIX: Do not force PowerShell. Use standard CMD for Windows compatibility.
        # This fixes [WinError 2] when running built-ins like 'reg' or 'dir'.
        if platform.system() == "Windows":
            # Enforce cmd.exe execution (not 'cmd' which may have PATH issues)
            shell_command = f"cmd.exe /c {shell_command}"
            
        result = subprocess.run(
            shell_command, 
            shell=shell, 
            executable=None, # Let OS choose (defaults to cmd.exe on Windows)
            capture_output=True, 
            text=True, 
            timeout=120
        )
        
        return {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()
        }
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e)
        }
