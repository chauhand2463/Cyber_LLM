#!/usr/bin/env python
"""
CyberLLM - Unified Entry Point
Single command to run the different framework in modes.
Uses Groq's free API (no OpenAI calls).
"""
import sys
import os
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_banner():
    print(r"""
   ______                  _          ____  ___     _____      
  / ____(_)__  ___   ____ (_)____   / __ \/   |   / ___/_____
 | |    / / _ \/ _ \ / __ \/ __ \_ / / / / /| |   \__ \/ ___/
 | |___/ /  __/  __// /_/ / / / // /_/ / ___ | |___ ___/ /__  
  \____/_/\___/\___/ \____/_/ /_/ \____/_/   |_/____/\___/   
                                                            
  [+] CyberLLM SECURITY AGENT v1.0
  [+] Free API Edition (Groq) - No OpenAI
""")

def print_menu():
    print("SELECT MODE:")
    print("  [1] INFO      - Quick system info")
    print("  [2] EXTREME  - Full threat hunt")
    print("  [3] JARVIS   - AI Assistant")
    print("  [4] NETWORK  - Network scan")
    print("  [5] AUDIT    - User audit")
    print("  [6] THREAT   - Threat scan")
    print("  [7] FULL     - Complete scan")
    print("  [0] EXIT     - Quit\n")

def run_simple():
    print("\n[MODE] INFO SCAN\n" + "-"*40)
    from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
    from agents.code_agents import cmd_exec_agent
    
    class S(Scenario):
        name = "Info"
        steps = [
            ScenarioStep(step_name="H", agent_name="cmd_exec_agent", instruction_template="hostname", save_output_to_context_key="h"),
            ScenarioStep(step_name="I", agent_name="cmd_exec_agent", instruction_template="ipconfig", save_output_to_context_key="i"),
            ScenarioStep(step_name="O", agent_name="cmd_exec_agent", instruction_template="ver", save_output_to_context_key="o"),
            ScenarioStep(step_name="U", agent_name="cmd_exec_agent", instruction_template="whoami", save_output_to_context_key="u"),
        ]
    
    ctx = ScenarioRunner({"cmd_exec_agent": cmd_exec_agent}).run(S())
    
    print(f"  HOSTNAME   : {ctx.get('h', 'N/A')}")
    print(f"  OS         : {ctx.get('o', 'N/A')}")
    print(f"  USER       : {ctx.get('u', 'N/A')}")
    ip = ctx.get('i', '')
    if ip:
        for line in ip.split('\n'):
            if 'IPv4' in line:
                print(f"  IP         : {line.split(':')[-1].strip()}")
                break
    print("-"*40)
    return ctx

def run_extreme():
    print("\n[MODE] EXTREME SCAN\n" + "-"*40)
    from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
    from agents.code_agents import cmd_exec_agent
    
    class S(Scenario):
        name = "Extreme"
        steps = [
            # System
            ScenarioStep(step_name="SYS", agent_name="cmd_exec_agent", instruction_template="systeminfo", save_output_to_context_key="sys"),
            # Network
            ScenarioStep(step_name="NET", agent_name="cmd_exec_agent", instruction_template="netstat -ano", save_output_to_context_key="net"),
            ScenarioStep(step_name="ARP", agent_name="cmd_exec_agent", instruction_template="arp -a", save_output_to_context_key="arp"),
            # Processes
            ScenarioStep(step_name="PROC", agent_name="cmd_exec_agent", instruction_template="tasklist", save_output_to_context_key="proc"),
            ScenarioStep(step_name="SERV", agent_name="cmd_exec_agent", instruction_template="sc query", save_output_to_context_key="serv"),
            # Persistence
            ScenarioStep(step_name="REG", agent_name="cmd_exec_agent", instruction_template="reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", save_output_to_context_key="reg"),
            ScenarioStep(step_name="TASK", agent_name="cmd_exec_agent", instruction_template="schtasks /query /fo LIST /v", save_output_to_context_key="task"),
            # Users
            ScenarioStep(step_name="USR", agent_name="cmd_exec_agent", instruction_template="net user", save_output_to_context_key="usr"),
            ScenarioStep(step_name="ADM", agent_name="cmd_exec_agent", instruction_template="net localgroup administrators", save_output_to_context_key="adm"),
            # Security
            ScenarioStep(step_name="FW", agent_name="cmd_exec_agent", instruction_template="netsh advfirewall show allprofiles", save_output_to_context_key="fw"),
            ScenarioStep(step_name="DRV", agent_name="cmd_exec_agent", instruction_template="driverquery", save_output_to_context_key="drv"),
        ]
    
    ctx = ScenarioRunner({"cmd_exec_agent": cmd_exec_agent}).run(S())
    
    # Extract key info
    print(f"  SYSTEM     : {len(ctx.get('sys',''))} bytes")
    print(f"  NETWORK    : {len(ctx.get('net',''))} bytes")
    print(f"  PROCESSES  : {len(ctx.get('proc',''))} bytes")
    print(f"  SERVICES   : {len(ctx.get('serv',''))} bytes")
    print(f"  REGISTRY   : {len(ctx.get('reg',''))} bytes")
    print(f"  TASKS      : {len(ctx.get('task',''))} bytes")
    print(f"  USERS      : {len(ctx.get('usr',''))} bytes")
    print(f"  DRIVERS    : {len(ctx.get('drv',''))} bytes")
    print("-"*40)
    return ctx

def run_jarvis():
    print("\n[MODE] JARVIS - AI Assistant\n")
    from interactive_session import run_interactive
    run_interactive()

def run_network():
    print("\n[MODE] NETWORK SCAN\n" + "-"*40)
    from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
    from agents.code_agents import cmd_exec_agent
    
    class S(Scenario):
        name = "Network"
        steps = [
            ScenarioStep(step_name="IP", agent_name="cmd_exec_agent", instruction_template="ipconfig", save_output_to_context_key="ip"),
            ScenarioStep(step_name="NET", agent_name="cmd_exec_agent", instruction_template="netstat -ano", save_output_to_context_key="net"),
            ScenarioStep(step_name="ARP", agent_name="cmd_exec_agent", instruction_template="arp -a", save_output_to_context_key="arp"),
            ScenarioStep(step_name="RT", agent_name="cmd_exec_agent", instruction_template="route print", save_output_to_context_key="rt"),
            ScenarioStep(step_name="DNS", agent_name="cmd_exec_agent", instruction_template="ipconfig /displaydns", save_output_to_context_key="dns"),
        ]
    
    ctx = ScenarioRunner({"cmd_exec_agent": cmd_exec_agent}).run(S())
    
    ip = ctx.get('ip', '')
    ipv4 = 'N/A'
    for line in ip.split('\n'):
        if 'IPv4' in line:
            ipv4 = line.split(':')[-1].strip()
            break
    
    print(f"  IP         : {ipv4}")
    print(f"  NETSTAT    : {len(ctx.get('net',''))} bytes")
    print(f"  ARP        : {len(ctx.get('arp',''))} bytes")
    print(f"  ROUTES     : {len(ctx.get('rt',''))} bytes")
    print("-"*40)
    return ctx

def run_user_audit():
    print("\n[MODE] USER AUDIT\n" + "-"*40)
    from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
    from agents.code_agents import cmd_exec_agent
    
    class S(Scenario):
        name = "UserAudit"
        steps = [
            ScenarioStep(step_name="USR", agent_name="cmd_exec_agent", instruction_template="net user", save_output_to_context_key="usr"),
            ScenarioStep(step_name="ADM", agent_name="cmd_exec_agent", instruction_template="net localgroup administrators", save_output_to_context_key="adm"),
            ScenarioStep(step_name="GST", agent_name="cmd_exec_agent", instruction_template="net user guest", save_output_to_context_key="gst"),
            ScenarioStep(step_name="POL", agent_name="cmd_exec_agent", instruction_template="net accounts", save_output_to_context_key="pol"),
        ]
    
    ctx = ScenarioRunner({"cmd_exec_agent": cmd_exec_agent}).run(S())
    
    adm = ctx.get('adm', '')
    admins = [l.strip() for l in adm.split('\n') if l.strip() and '----' not in l and 'Alias' not in l and 'Comment' not in l and 'Members' not in l]
    
    print(f"  USERS      : {len(ctx.get('usr','').splitlines())} accounts")
    print(f"  ADMINS     : {', '.join(admins[:5])}")
    print(f"  GUEST      : {'Disabled' if 'Account active               No' in ctx.get('gst','') else 'Active'}")
    print("-"*40)
    return ctx

def run_threat_scan():
    print("\n[MODE] THREAT SCAN\n" + "-"*40)
    from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
    from agents.code_agents import cmd_exec_agent
    
    class S(Scenario):
        name = "Threat"
        steps = [
            ScenarioStep(step_name="PROC", agent_name="cmd_exec_agent", instruction_template="tasklist", save_output_to_context_key="proc"),
            ScenarioStep(step_name="SERV", agent_name="cmd_exec_agent", instruction_template="sc query", save_output_to_context_key="serv"),
            ScenarioStep(step_name="NET", agent_name="cmd_exec_agent", instruction_template="netstat -ano", save_output_to_context_key="net"),
            ScenarioStep(step_name="REG", agent_name="cmd_exec_agent", instruction_template="reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", save_output_to_context_key="reg"),
            ScenarioStep(step_name="TASK", agent_name="cmd_exec_agent", instruction_template="schtasks /query /fo LIST /v", save_output_to_context_key="task"),
            ScenarioStep(step_name="FW", agent_name="cmd_exec_agent", instruction_template="netsh advfirewall show allprofiles", save_output_to_context_key="fw"),
        ]
    
    ctx = ScenarioRunner({"cmd_exec_agent": cmd_exec_agent}).run(S())
    
    print(f"  PROCESSES  : {len(ctx.get('proc',''))} bytes")
    print(f"  SERVICES   : {len(ctx.get('serv',''))} bytes")
    print(f"  NETWORK    : {len(ctx.get('net',''))} bytes")
    print(f"  REGISTRY   : {len(ctx.get('reg',''))} bytes")
    print(f"  TASKS      : {len(ctx.get('task',''))} bytes")
    print(f"  FIREWALL   : {len(ctx.get('fw',''))} bytes")
    print("-"*40)
    return ctx

def run_all_scan():
    print("\n[MODE] FULL SCAN\n" + "-"*40)
    from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
    from agents.code_agents import cmd_exec_agent
    
    class S(Scenario):
        name = "Full"
        steps = [
            ScenarioStep(step_name="SYS", agent_name="cmd_exec_agent", instruction_template="systeminfo", save_output_to_context_key="sys"),
            ScenarioStep(step_name="IP", agent_name="cmd_exec_agent", instruction_template="ipconfig", save_output_to_context_key="ip"),
            ScenarioStep(step_name="NET", agent_name="cmd_exec_agent", instruction_template="netstat -ano", save_output_to_context_key="net"),
            ScenarioStep(step_name="ARP", agent_name="cmd_exec_agent", instruction_template="arp -a", save_output_to_context_key="arp"),
            ScenarioStep(step_name="USR", agent_name="cmd_exec_agent", instruction_template="net user", save_output_to_context_key="usr"),
            ScenarioStep(step_name="ADM", agent_name="cmd_exec_agent", instruction_template="net localgroup administrators", save_output_to_context_key="adm"),
            ScenarioStep(step_name="PROC", agent_name="cmd_exec_agent", instruction_template="tasklist", save_output_to_context_key="proc"),
            ScenarioStep(step_name="SERV", agent_name="cmd_exec_agent", instruction_template="sc query", save_output_to_context_key="serv"),
            ScenarioStep(step_name="REG", agent_name="cmd_exec_agent", instruction_template="reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", save_output_to_context_key="reg"),
            ScenarioStep(step_name="TASK", agent_name="cmd_exec_agent", instruction_template="schtasks /query /fo LIST /v", save_output_to_context_key="task"),
            ScenarioStep(step_name="FW", agent_name="cmd_exec_agent", instruction_template="netsh advfirewall show allprofiles", save_output_to_context_key="fw"),
            ScenarioStep(step_name="DRV", agent_name="cmd_exec_agent", instruction_template="driverquery", save_output_to_context_key="drv"),
        ]
    
    ctx = ScenarioRunner({"cmd_exec_agent": cmd_exec_agent}).run(S())
    
    print(f"  SYSTEM     : {len(ctx.get('sys',''))} bytes")
    print(f"  NETWORK    : {len(ctx.get('net',''))} bytes")
    print(f"  USERS      : {len(ctx.get('usr',''))} bytes")
    print(f"  PROCESSES  : {len(ctx.get('proc',''))} bytes")
    print(f"  SERVICES   : {len(ctx.get('serv',''))} bytes")
    print(f"  REGISTRY   : {len(ctx.get('reg',''))} bytes")
    print(f"  TASKS      : {len(ctx.get('task',''))} bytes")
    print(f"  DRIVERS    : {len(ctx.get('drv',''))} bytes")
    print(f"  FIREWALL   : {len(ctx.get('fw',''))} bytes")
    print("-"*40)
    return ctx

def main():
    print_banner()
    modes = {1: run_simple, 2: run_extreme, 3: run_jarvis, 4: run_network, 
             5: run_user_audit, 6: run_threat_scan, 7: run_all_scan}
    while True:
        print_menu()
        choice = input("Select [0-7]: ").strip()
        if choice == "0":
            print("\n[+] Goodbye!\n")
            break
        try:
            warnings.filterwarnings("ignore")
            key = int(choice) if choice.isdigit() else 0
            if key in modes:
                modes[key]()
            else:
                print("[!] Invalid")
        except Exception as e:
            print(f"\n[ERROR] {e}\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', nargs='?', default='')
    args = parser.parse_args()
    
    if args.mode:
        print_banner()
        modes = {1: run_simple, 2: run_extreme, 3: run_jarvis, 4: run_network, 
                 5: run_user_audit, 6: run_threat_scan, 7: run_all_scan}
        try:
            key = int(args.mode) if args.mode.isdigit() else 0
            if key in modes:
                modes[key]()
            else:
                print("[!] Invalid mode")
        except Exception as e:
            print(f"[ERROR] {e}")
    else:
        main()
