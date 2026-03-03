#!/usr/bin/env python
"""
CyberLLM - Main Entry Point
Menu-based interface with Local/API LLM support
"""
import os
import sys
import urllib.request
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    except:
        pass

def check_ollama():
    try:
        urllib.request.urlopen('http://localhost:11434', timeout=2)
        return True
    except:
        return False

OLLAMA_AVAILABLE = check_ollama()

def print_banner():
    print(r"""
   ______                  _          ____  ___     _____      
  / ____(_)__  ___   ____ (_)____   / __ \/   |   / ___/_____
 | |    / / _ \/ _ \ / __ \/ __ \_ / / / / /| |   \__ \/ ___/
 | |___/ /  __/  __// /_/ / / / // /_/ / ___ | |___ ___/ /__  
  \____/_/\___/\___/ \____/_/ /_/ \____/_/   |_/____/\___/   
                                                            
  [+] CyberLLM SECURITY AGENT v2.0
  [+] Powered by GPT-OSS-20B
  """)
    print(f"  [+] Ollama: {'Available' if OLLAMA_AVAILABLE else 'Not running'}")
    print(f"  [+] Mode: LOCAL" if OLLAMA_AVAILABLE else "  [+] Mode: API")

def print_menu():
    print("""
SELECT MODE:
  ─────────────────────────────
  [1] QUICK     - Quick system info
  [2] NETWORK   - Network connections
  [3] USERS     - User audit
  [4] PROCESSES - Running processes
  [5] SERVICES  - System services
  [6] FULL      - Complete scan
  ─────────────────────────────
  [J] JARVIS    - Interactive AI Assistant
  ─────────────────────────────
  [L] LOCAL     - Switch to local Ollama
  [A] API       - Switch to Groq API
  ─────────────────────────────
  [0] EXIT      - Quit
""")

def run_quick():
    from cyberllm.core.scanner import Scanner
    s = Scanner()
    print("\n[QUICK INFO]")
    print("-" * 40)
    h = s.run_safe("hostname")
    w = s.run_safe("whoami")
    i = s.run_safe("ipconfig")
    print(f"  Hostname: {h['output'].strip()}")
    print(f"  User: {w['output'].strip()}")
    ip_lines = [l for l in i['output'].split('\n') if 'IPv4' in l]
    if ip_lines:
        print(f"  IP: {ip_lines[0].split(':')[-1].strip()}")
    print("-" * 40)

def run_network():
    from cyberllm.core.scanner import Scanner
    s = Scanner()
    print("\n[NETWORK SCAN]")
    print("-" * 40)
    net = s.run_safe("network")
    print(net['output'][:2000])
    print("-" * 40)

def run_users():
    from cyberllm.core.scanner import Scanner
    s = Scanner()
    print("\n[USER AUDIT]")
    print("-" * 40)
    users = s.run_safe("users")
    admins = s.run_safe("admins")
    print("USERS:")
    print(users['output'][:1000])
    print("\nADMINS:")
    print(admins['output'])
    print("-" * 40)

def run_processes():
    from cyberllm.core.scanner import Scanner
    s = Scanner()
    print("\n[PROCESSES]")
    print("-" * 40)
    procs = s.get_processes()[:20]
    for p in procs:
        print(f"  {p.get('pid', '?')}: {p.get('name', '?')} | CPU: {p.get('cpu_percent', 0)}% | MEM: {p.get('memory_percent', 0):.1f}%")
    print("-" * 40)

def run_services():
    from cyberllm.core.scanner import Scanner
    s = Scanner()
    print("\n[SERVICES]")
    print("-" * 40)
    serv = s.run_safe("services")
    print(serv['output'][:2000])
    print("-" * 40)

def run_full():
    from cyberllm.core.scanner import Scanner
    s = Scanner()
    print("\n[FULL SCAN] Running...")
    result = s.full_scan()
    print("\n[FULL SCAN COMPLETE]")
    print("-" * 40)
    for key, value in result.items():
        print(f"  {key}: {len(str(value))} bytes")
    print("-" * 40)

def run_jarvis():
    import jarvis
    jarvis.main()

def main():
    print_banner()
    print_menu()
    
    use_local = OLLAMA_AVAILABLE
    
    modes = {
        "1": ("QUICK", run_quick),
        "2": ("NETWORK", run_network),
        "3": ("USERS", run_users),
        "4": ("PROCESSES", run_processes),
        "5": ("SERVICES", run_services),
        "6": ("FULL", run_full),
        "J": ("JARVIS", run_jarvis),
    }
    
    while True:
        try:
            choice = input("Select [0/A/L/J]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] Goodbye!")
            break
        
        if choice == "0":
            print("\n[+] Goodbye!\n")
            break
        
        if choice == "L":
            use_local = True
            os.environ['USE_LOCAL_LLM'] = 'true'
            print("[+] Switched to LOCAL mode")
            continue
        
        if choice == "A":
            use_local = False
            os.environ['USE_LOCAL_LLM'] = 'false'
            print("[+] Switched to API mode")
            continue
        
        if choice == "J":
            run_jarvis()
            print_banner()
            print_menu()
            continue
        
        if choice in modes:
            try:
                modes[choice][1]()
            except Exception as e:
                print(f"[!] Error: {e}")
        else:
            print("[!] Invalid option")

if __name__ == "__main__":
    main()
