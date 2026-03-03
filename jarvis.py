#!/usr/bin/env python
"""
CyberLLM - JARVIS AI Assistant
Main entry point with Local/API LLM support
"""
import os
import sys
import urllib.request
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Fix Windows encoding
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
  [+] JARVIS AI Assistant
  """)
    if OLLAMA_AVAILABLE:
        print("  [+] Ollama: DETECTED")
    else:
        print("  [+] Ollama: Not running")

def print_help():
    print("""
AVAILABLE COMMANDS:
  system info     - Get system information
  whoami          - Current user details
  network         - Network connections
  ports           - Open ports
  processes       - Running processes
  users           - List users
  admins          - List administrators
  services        - Running services
  startup         - Startup programs
  firewall        - Firewall status
  full scan       - Complete system scan
  threat hunt     - Quick threat scan
  
  CVE-2024-xxx   - Lookup CVE
  8.8.8.8        - IP lookup
  https://...    - Web scrape
  
  help            - Show this help
  clear           - Clear screen
  exit            - Exit JARVIS
""")

def main():
    print_banner()
    
    use_local = OLLAMA_AVAILABLE
    os.environ['USE_LOCAL_LLM'] = 'true' if use_local else 'false'
    
    print(f"\n[+] Mode: {'LOCAL (Ollama)' if use_local else 'API (Groq)'}")
    print("[+] Type 'help' for commands\n")
    
    try:
        from cyberllm.core.jarvis import JarvisController
        jarvis = JarvisController(use_local=use_local)
    except Exception as e:
        print(f"[!] Failed to initialize JARVIS: {e}")
        return
    
    while True:
        try:
            user_input = input("JARVIS > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] Goodbye!")
            break
        
        if not user_input:
            continue
        
        cmd = user_input.lower()
        
        if cmd in ['exit', 'quit', 'q']:
            print("[+] Goodbye!")
            break
        
        if cmd in ['clear', 'cls']:
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            print_help()
            continue
        
        if cmd in ['help', '?']:
            print_help()
            continue
        
        if cmd in ['local', 'l']:
            use_local = True
            jarvis.set_llm_mode(True)
            print("[+] Switched to LOCAL mode")
            continue
        
        if cmd in ['api', 'a']:
            use_local = False
            jarvis.set_llm_mode(False)
            print("[+] Switched to API mode")
            continue
        
        print("\n" + "="*50)
        
        try:
            result = jarvis.process(user_input)
            
            intent = result.get('intent', 'UNKNOWN')
            print(f"  [{intent}]")
            print("="*50)
            
            if 'analysis' in result:
                print(str(result['analysis']))
            elif 'response' in result:
                print(str(result['response']))
            elif 'data' in result:
                import json
                print(json.dumps(result['data'], indent=2))
            elif 'error' in result:
                print(f"[!] {result['error']}")
            elif 'scan' in result:
                import json
                print(json.dumps(result['scan'], indent=2))
                
        except Exception as e:
            print(f"[!] Error: {str(e)}")
        
        print()

if __name__ == "__main__":
    main()
