import sys
import os

PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)

from engine.jarvis_controller import JarvisController

def print_banner():
    print("""
==================================================
     J A R V I S   A I   A S S I S T A N T
     CyberLLM Security Platform v1.0
==================================================
""")

def print_menu():
    print("""
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
""")

def print_help():
    print("""
================================================================================
                    JARVIS AI CAPABILITIES
================================================================================

[ BASIC SECURITY SCANS ]
--------------------------------------------------------------------------------
  * network ports     - Check open ports
  * netstat          - View all network connections
  * ipconfig         - View IP configuration
  * list admins      - List administrator accounts
  * users            - List all user accounts
  * system info      - Get system information
  * processes        - List running processes
  * services         - List Windows services
  * startup          - Check startup programs
  * registry         - Check registry run keys
  * firewall         - Check firewall rules
  * threats          - Scan for threats/malware
  * malware          - Check for malware indicators
  * persistence      - Check persistence mechanisms

[ ADVANCED SECURITY OPERATIONS ]
--------------------------------------------------------------------------------
  * risk assessment       - Identify assets, threats, vulnerabilities
  * vulnerability scan    - Scan for known vulnerabilities
  * security hardening    - Check security configuration
  * iam audit             - Identity & access management
  * patch management      - Check for missing patches
  * incident response     - Gather forensic artifacts
  * data protection       - Check encryption & backups
  * compliance check      - NIST/CIS/ISO compliance
  * third party risk     - Assess vendor risks
  * cloud security        - Check cloud configuration
  * web security          - Scan URL for vulnerabilities
  * pen test             - Penetration test simulation

[ WEB/OSINT TOOLS ]
--------------------------------------------------------------------------------
  * https://example.com  - Scrape and analyze any URL
  * CVE-2024-1234        - Lookup CVE vulnerability details
  * 8.8.8.8              - Lookup IP geolocation info

[ GENERAL AI ASSISTANT ]
--------------------------------------------------------------------------------
  * Ask any question about cybersecurity
  * Explain security concepts
  * Get recommendations and best practices
  * Learn about attack techniques
  * Understand security tools and frameworks

[ COMMANDS ]
--------------------------------------------------------------------------------
  * help, ?      - Show this menu
  * menu         - Return to main menu
  * clear, cls   - Clear screen
  * back, exit   - Exit JARVIS

================================================================================
""")

def format_output(data, intent):
    """Format output based on intent type."""
    if intent == "WEB_SCRAPE":
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list) and value:
                    print(f"  {key}:")
                    for item in value[:10]:
                        print(f"    - {item}")
                elif isinstance(value, str) and value:
                    print(f"  {key}: {value[:200]}")
                else:
                    print(f"  {key}: {value}")
        return
    
    if isinstance(data, dict):
        for key, value in data.items():
            if not value:
                continue
            if isinstance(value, list):
                if value:
                    print(f"  {key.replace('_', ' ').title()}:")
                    for item in value[:15]:
                        print(f"    - {item}")
            elif isinstance(value, dict):
                print(f"  {key.replace('_', ' ').title()}:")
                for k, v in value.items():
                    print(f"    {k}: {v}")
            else:
                val_str = str(value)[:300]
                print(f"  {key.replace('_', ' ').title()}: {val_str}")
    else:
        if isinstance(data, str):
            for line in data.split('\n')[:50]:
                if line.strip():
                    print(f"  {line}")
        else:
            print(f"  {data}")

def run_jarvis_mode():
    print("\nEntering JARVIS Assistant Mode...")
    print("Type 'back' to return to main menu\n")
    
    jarvis = JarvisController()
    
    while True:
        try:
            user_input = input("JARVIS > ").strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\nReturning to menu...")
            break
            
        if not user_input:
            continue
            
        cmd = user_input.lower()
        
        if cmd in ["exit", "quit", "q", "back", "menu"]:
            print("Returning to main menu...")
            break
        
        if cmd in ["clear", "cls"]:
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            print_help()
            continue
            
        if cmd in ["help", "?"]:
            print_help()
            continue
        
        try:
            result = jarvis.process_input(user_input)
            
            status = result.get('status')
            
            if status == 'error':
                print(f"[!] {result.get('message')}")
                continue
            
            if status == 'failure':
                print(f"[X] {result.get('message')}")
                if result.get('suggestion'):
                    print(f"    Suggestion: {result.get('suggestion')}")
                continue
            
            data = result.get('data')
            intent = result.get('intent', 'UNKNOWN')
            
            print(f"\n{'-'*50}")
            print(f"  {intent}")
            print(f"{'-'*50}\n")
            
            format_output(data, intent)
            
            print(f"\n{'-'*50}")
            
        except KeyboardInterrupt:
            print("\nReturning to menu...")
            break
        except Exception as e:
            print(f"[X] Error: {str(e)[:100]}")

def run_interactive():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    while True:
        print_menu()
        choice = input("Select mode [0-7]: ").strip()
        
        if choice == '0':
            print("\nGoodbye, Agent.")
            break
        
        elif choice == '1':
            print("\n[INFO] Running quick system scan...")
            os.system('cls' if os.name == 'nt' else 'clear')
            from main import run_simple
        
        elif choice == '2':
            print("\n[EXTREME] Running full threat hunt...")
            os.system('cls' if os.name == 'nt' else 'clear')
            from main import run_extreme
        
        elif choice == '3':
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            print_help()
            run_jarvis_mode()
        
        elif choice == '4':
            print("\n[NETWORK] Running network scan...")
            os.system('cls' if os.name == 'nt' else 'clear')
            from main import run_network
        
        elif choice == '5':
            print("\n[AUDIT] Running user audit...")
            os.system('cls' if os.name == 'nt' else 'clear')
            from main import run_user_audit
        
        elif choice == '6':
            print("\n[THREAT] Running threat scan...")
            os.system('cls' if os.name == 'nt' else 'clear')
            from main import run_threat_scan
        
        elif choice == '7':
            print("\n[FULL] Running complete scan...")
            os.system('cls' if os.name == 'nt' else 'clear')
            from main import run_all_scan
        
        else:
            print(f"\nInvalid option: {choice}\n")

if __name__ == "__main__":
    run_interactive()
