#!/usr/bin/env python
"""
ARTEMIS - Main Entry Point
Advanced Cybersecurity AI Assistant
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
   ___    ____  __  __  ____     ____  ____  __  __   ____   __    __ 
  / _ )  / __ \/ / / / / __ \   / __ \/ __ \/ / / /  /  _ \ / /   / / 
 / _  | / / / / /_/ / / / / /  / /_/ / / / / /_/ /   / /_/ / /   / /  
/ /_/ |/ /_/ \____/ / /_/ /  / ____// /_/ /____/   / _, _// /___/ /   
/_____/ \____/      /_____/  /_/   /_____/        /_/ |_|/_____/    

  [+] ARTEMIS SECURITY AGENT v2.0
  [+] Advanced AI-Powered Cybersecurity Assistant
  """)
    print(f"  [+] Ollama: {'Available' if OLLAMA_AVAILABLE else 'Not running'}")
    print(f"  [+] Model: gpt-oss-20b" if OLLAMA_AVAILABLE else "  [+] Model: Groq API")

def print_menu():
    print("""
================================================================================
                              MAIN MENU
================================================================================
  [1] SYSTEM SCANS      - Quick system information
  [2] NETWORK SCAN      - Network connections and ports
  [3] USER AUDIT        - User accounts and privileges
  [4] PROCESSES         - Running processes
  [5] SERVICES          - System services
  [6] FULL SCAN         - Complete security scan
--------------------------------------------------------------------------------
  [E] EXTREME MODE     - Full penetration testing suite
  [W] WEB SCAN         - Web application testing
  [P] PENTEST          - All penetration testing tools
--------------------------------------------------------------------------------
  [A] ARTEMIS          - Interactive AI Assistant
--------------------------------------------------------------------------------
  [L] LOCAL            - Switch to local Ollama
  [R] API              - Switch to Groq API
--------------------------------------------------------------------------------
  [D] DOCUMENTATION    - View complete documentation
  [F] FEATURES         - View all features
--------------------------------------------------------------------------------
  [0] EXIT             - Quit
================================================================================
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

def run_extreme():
    print("\n[EXTREME MODE] Starting comprehensive security assessment...")
    print("=" * 50)
    from cyberllm.core.scanner import Scanner
    from cyberllm.core.pentest import ArtemisPenTest
    
    s = Scanner()
    pt = ArtemisPenTest()
    
    print("\n[PHASE 1: SYSTEM RECONNAISSANCE]")
    print("-" * 40)
    print("[+] Gathering system information...")
    sys_info = s.run_safe("systeminfo")
    sys_out = str(sys_info.get('output', ''))
    print(f"  Done: {len(sys_out)} bytes")
    
    print("\n[PHASE 2: NETWORK ANALYSIS]")
    print("-" * 40)
    print("[+] Scanning network connections...")
    network = s.run_safe("network")
    net_out = str(network.get('output', ''))
    print(f"  Done: {len(net_out)} bytes")
    
    print("\n[PHASE 3: PROCESS ANALYSIS]")
    print("-" * 40)
    print("[+] Analyzing running processes...")
    procs = s.get_processes()[:50]
    print(f"  Found {len(procs)} processes")
    
    print("\n[PHASE 4: SERVICE ENUMERATION]")
    print("-" * 40)
    print("[+] Enumerating services...")
    services = s.run_safe("services")
    print(f"  Done: {len(str(services.get('output','')))} bytes")
    
    print("\n[PHASE 5: USER AUDIT]")
    print("-" * 40)
    print("[+] Auditing user accounts...")
    users = s.run_safe("users")
    admins = s.run_safe("admins")
    print(f"  Users checked, Admin group enumerated")
    
    print("\n[PHASE 6: PERSISTENCE CHECK]")
    print("-" * 40)
    print("[+] Checking persistence mechanisms...")
    startup = s.run_safe("startup")
    print(f"  Startup entries checked")
    
    print("\n[PHASE 7: FIREWALL STATUS]")
    print("-" * 40)
    print("[+] Checking firewall configuration...")
    firewall = s.run_safe("firewall")
    print(f"  Firewall status retrieved")
    
    print("\n" + "=" * 50)
    print("[EXTREME MODE COMPLETE]")
    print("=" * 50)
    print("\nSUMMARY:")
    print(f"  - System Info: {len(str(sys_info.get('output','')))} bytes")
    print(f"  - Network: {len(str(network.get('output','')))} bytes")
    print(f"  - Processes: {len(procs)}")
    print(f"  - Services: Checked")
    print(f"  - Users: Audited")
    print(f"  - Startup: Checked")
    print(f"  - Firewall: Reviewed")
    print("\n[+] Run 'A' for AI-powered analysis")

def run_web_scan():
    print("\n[WEB APPLICATION SCANNER]")
    print("=" * 50)
    url = input("Enter target URL: ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"\n[+] Target: {url}")
    print("[+] Select scan type:")
    print("  [1] Nikto - Web vulnerability scanner")
    print("  [2] Nuclei - Vulnerability scanner with templates")
    print("  [3] Full Web Assessment")
    
    choice = input("\nChoice [1-3]: ").strip()
    
    from cyberllm.core.pentest import ArtemisPenTest
    pt = ArtemisPenTest()
    
    if choice == "1":
        print("\n[+] Running Nikto...")
        result = pt.web.nikto_scan(url)
        print("\n[RESULTS]")
        print(result.get('output', 'No output')[:2000])
    elif choice == "2":
        print("\n[+] Running Nuclei...")
        result = pt.web.nuclei_scan(url)
        print(f"\n[+] Found {result.get('findings_count', 0)} issues")
    elif choice == "3":
        print("\n[+] Running full web assessment...")
        result = pt.web_assessment(url)
        print(f"\n[+] Assessment complete!")
    else:
        print("[!] Invalid choice")

def run_pentest():
    print("\n[PENETRATION TESTING SUITE]")
    print("=" * 50)
    print("Select tool:")
    print("  [1] Nmap - Port Scanner")
    print("  [2] Nikto - Web Vulnerability")
    print("  [3] Nuclei - Template Scanner")
    print("  [4] Enum4linux - SMB Enum")
    print("  [5] Exploit Search")
    print("  [6] Full Recon")
    
    choice = input("\nChoice: ").strip()
    target = input("Enter target (IP/URL): ").strip()
    
    from cyberllm.core.pentest import ArtemisPenTest
    pt = ArtemisPenTest()
    
    print(f"\n[+] Running on {target}...")
    
    if choice == "1":
        print("\n[Nmap Scan]")
        result = pt.network.nmap_scan(target)
    elif choice == "2":
        print("\n[Nikto Scan]")
        result = pt.web.nikto_scan(target)
    elif choice == "3":
        print("\n[Nuclei Scan]")
        result = pt.web.nuclei_scan(target)
    elif choice == "4":
        print("\n[Enum4linux]")
        result = pt.network.enum4linux(target)
    elif choice == "5":
        keyword = input("Enter CVE or keyword: ").strip()
        print("\n[Exploit Search]")
        result = pt.exploit.search_exploit(keyword=keyword)
    elif choice == "6":
        print("\n[Full Recon]")
        result = pt.full_recon(target)
    else:
        result = {"status": "error", "message": "Invalid choice"}
    
    import json
    print("\n[RESULTS]")
    print(json.dumps(result, indent=2)[:3000])

def run_artemis():
    import artemis
    artemis.main()

def print_documentation():
    print("""
================================================================================
                         ARTEMIS DOCUMENTATION
================================================================================
ARTEMIS - Advanced Research and Modeling for Ethical Intelligence System
Version 2.0

FEATURES:
- System Scanning
- Network Scanning
- User Auditing
- Penetration Testing
- CTI & Threat Intelligence
- AI-Powered Analysis

MODEL: gpt-oss-20b (Local) or llama-3.3-70b-versatile (API)
================================================================================
""")

def print_features():
    print("""
================================================================================
                         ARTEMIS FEATURES
================================================================================
[1] SYSTEM SCANS - network, ports, processes, services, startup, firewall
[2] USER AUDITING - users, admins
[3] PENTEST - scan, vuln, nikto, nuclei, exploit
[4] CTI - CVE lookup, threat intel, recent cves
[5] EXTREME MODE - Full penetration testing workflow
================================================================================
""")

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
        "E": ("EXTREME", run_extreme),
        "W": ("WEB", run_web_scan),
        "P": ("PENTEST", run_pentest),
        "A": ("ARTEMIS", run_artemis),
    }
    
    while True:
        try:
            choice = input("\nSelect option: ").strip().upper()
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
        
        if choice == "R":
            use_local = False
            os.environ['USE_LOCAL_LLM'] = 'false'
            print("[+] Switched to API mode")
            continue
        
        if choice == "D":
            print_documentation()
            continue
        
        if choice == "F":
            print_features()
            continue
        
        if choice == "A":
            run_artemis()
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
