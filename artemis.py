#!/usr/bin/env python
"""
ARTEMIS - AI Assistant
Interactive cybersecurity AI assistant
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

def print_help():
    print("""
COMMANDS:
  Scans:
    network, ports, processes, users, admins, services, startup, firewall, full scan
    
  PenTest:
    scan TARGET, vuln TARGET, nikto URL, nuclei URL, exploit SEARCH
    
  CTI:
    CVE-2024-xxx, cve enrich, recent cves, threat IP
    
  AI:
    plan TASK, history, audit
    
  General:
    feature, help, local/api, clear, exit
""")

def print_features():
    print("""
================================================================================
                         ARTEMIS FEATURES
================================================================================

[1] SYSTEM SCANS
  network, ports, processes, services, startup, firewall, full scan, whoami

[2] USER AUDITING  
  users, admins

[3] PENETRATION TESTING
  scan TARGET      - Nmap port scan
  vuln TARGET      - Vulnerability scan
  nikto URL        - Web vulnerability scan
  nuclei URL      
  exploit - nuclei vulnerability scanner SEARCH   - Search exploits
  payload TYPE     - Generate payload

[4] EXTREME MODE
  - Full system reconnaissance
  - Vulnerability assessment
  - Exploitation testing
  - Detailed reporting

[5] CTI & THREAT INTELLIGENCE
  CVE-2024-xxxx   - CVE lookup
  cve enrich CVE  - Enriched CVE
  recent cves     - Recent vulnerabilities
  threat IP       - IP reputation

[6] AI-PLANNED TASKS
  plan TASK       - AI generates security plan

[7] LLM MODE
  local / l       - Switch to local Ollama
  api / a         - Switch to Groq API

================================================================================
""")

def main():
    print_banner()
    print()
    
    use_local = OLLAMA_AVAILABLE
    os.environ['USE_LOCAL_LLM'] = 'true' if use_local else 'false'
    
    print(f"[+] Mode: {'LOCAL (Ollama)' if use_local else 'API (Groq)'}")
    print("[+] Type 'help' or 'feature' for more info\n")
    
    try:
        from cyberllm.core.jarvis import ArtemisController
        artemis = ArtemisController(use_local=use_local)
    except Exception as e:
        print(f"[!] Failed to initialize ARTEMIS: {e}")
        return
    
    while True:
        try:
            user_input = input("ARTEMIS > ").strip()
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
        
        if cmd in ['feature', 'features', 'f']:
            print_features()
            continue
        
        if cmd in ['local', 'l']:
            use_local = True
            artemis.set_llm_mode(True)
            print("[+] Switched to LOCAL mode")
            continue
        
        if cmd in ['api', 'a']:
            use_local = False
            artemis.set_llm_mode(False)
            print("[+] Switched to API mode")
            continue
        
        # PenTest commands
        if cmd.startswith('scan '):
            target = cmd.replace('scan ', '', 1).strip()
            from cyberllm.core.pentest import ArtemisPenTest
            pt = ArtemisPenTest()
            result = pt.network.nmap_scan(target)
            import json
            print(json.dumps(result, indent=2)[:2000])
            continue
        
        if cmd.startswith('nikto '):
            url = cmd.replace('nikto ', '', 1).strip()
            from cyberllm.core.pentest import ArtemisPenTest
            pt = ArtemisPenTest()
            result = pt.web.nikto_scan(url)
            import json
            print(json.dumps(result, indent=2)[:2000])
            continue
        
        if cmd.startswith('nuclei '):
            url = cmd.replace('nuclei ', '', 1).strip()
            from cyberllm.core.pentest import ArtemisPenTest
            pt = ArtemisPenTest()
            result = pt.web.nuclei_scan(url)
            import json
            print(json.dumps(result, indent=2)[:2000])
            continue
        
        if cmd.startswith('exploit '):
            search = cmd.replace('exploit ', '', 1).strip()
            from cyberllm.core.pentest import ArtemisPenTest
            pt = ArtemisPenTest()
            result = pt.exploit.search_exploit(keyword=search)
            import json
            print(json.dumps(result, indent=2)[:2000])
            continue
        
        if cmd.startswith('threat '):
            ip = cmd.replace('threat ', '', 1).strip()
            from cyberllm.core.cti import CTIFeeds
            cti = CTIFeeds()
            result = cti.threat_intel_ip(ip)
            import json
            print(json.dumps(result, indent=2))
            continue
        
        # CTI commands
        if cmd.startswith('cve enrich '):
            cve_id = cmd.replace('cve enrich ', '', 1).strip()
            from cyberllm.core.cti import CTIFeeds
            cti = CTIFeeds()
            result = cti.enrich_cve(cve_id)
            import json
            print(json.dumps(result, indent=2))
            continue
        
        if cmd == 'recent cves':
            from cyberllm.core.cti import CTIFeeds
            cti = CTIFeeds()
            result = cti.get_recent_cves(days=7, limit=10)
            for cve in result:
                print(f"  {cve.get('id')}: {cve.get('severity')} ({cve.get('cvss', 'N/A')})")
            continue
        
        # AI planning
        if cmd.startswith('plan '):
            task = user_input.replace('plan ', '', 1)
            from cyberllm.core.agent import AgentOrchestrator
            agent = AgentOrchestrator(llm_client=artemis.client)
            plan = agent.plan_task(task)
            import json
            print(json.dumps(plan, indent=2))
            continue
        
        print()
        
        try:
            result = artemis.process(user_input)
            
            intent = result.get('intent', 'UNKNOWN')
            print(f"[{intent}]")
            print("-" * 40)
            
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
