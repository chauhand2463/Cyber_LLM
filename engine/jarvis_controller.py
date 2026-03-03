import logging
import platform
import json
from typing import Dict, Any, Optional
from engine.intent_classifier import IntentClassifier
from engine.scenario_engine import ScenarioRunner, Scenario, ScenarioStep
from engine.memory_store import MemoryStore
from scenarios.definitions import (
    ThreatHuntScenario, SystemInfoScenario, NetworkCheckScenario
)
from scenarios.advanced_scenarios import (
    AdvancedThreatHuntScenario, AdvancedSystemInfoScenario, 
    AdvancedNetworkScan, AdvancedUserAudit, AdvancedPersistenceCheck
)
from agents.coordinator_agents import task_coordinator_agent, jarvis_analyst_agent
from agents.text_agents import text_analyst_agent
from agents.code_agents import cmd_exec_agent
from agents.intelligence_agents import ioc_extractor_agent, threat_classifier_agent

logger = logging.getLogger(__name__)

JARVIS_CYBER_PROMPT = """SYSTEM ROLE: RED-TEAM LEAD
MISSION: Penetration Test & Vulnerability Assessment

Identify:
- Crown Jewels: Admin accounts, sensitive files
- Entry Point: Open ports, weak services
- Exploit Path: How to escalate from User to Admin

OUTPUT FORMAT:
TARGET: [Service/Account]
VULNERABILITY: [CVE or config weakness]
EXPLOIT: [step 1, step 2]
MITIGATION: [CLI fix]

STRICT: Code-ready commands. Zero fluff. Max 30 words."""

JARVIS_REGULAR_PROMPT = """You are Jarvis, a helpful AI assistant. Be witty, charming, and efficient.
Keep response under 2 sentences. Answer directly."""

# Intent types that trigger CYBER mode
CYBER_INTENTS = {
    "THREAT_HUNT", "NETWORK_SCAN", "USER_AUDIT", "PERSISTENCE_CHECK", 
    "SYS_INFO", "FILE_SCAN", "WEB_SCRAPE", "RISK_ASSESSMENT",
    "VULNERABILITY_SCAN", "PEN_TEST", "INCIDENT_RESPONSE", 
    "SECURITY_HARDENING", "PATCH_MANAGEMENT", "MONITORING_DETECTION",
    "DATA_PROTECTION", "COMPLIANCE", "SECURITY_AWARENESS",
    "THIRD_PARTY_RISK", "CLOUD_SECURITY", "WEB_SECURITY"
}

# Safe to test - local only
SAFE_TARGETS = ("127.0.0.1", "localhost", "0.0.0.0")

def get_prompt_for_intent(intent: str) -> str:
    """Get the appropriate prompt based on intent type."""
    if intent in CYBER_INTENTS:
        return JARVIS_CYBER_PROMPT
    return JARVIS_REGULAR_PROMPT

def validate_target(target: str) -> bool:
    """Safety: Only allow local targets."""
    if not target:
        return True  # No target = safe
    target = target.strip().lower()
    return any(safe in target for safe in SAFE_TARGETS)

class JarvisController:
    """
    The central brain of the system.
    Orchestrates Intent Detection -> Scenario Selection -> Execution -> Recovery.
    """
    
    SCENARIO_MAP = {
        "FILE_SCAN": None,  # Handled specially
        "WEB_SCRAPE": None,  # Handled specially
        "THREAT_HUNT": AdvancedThreatHuntScenario,
        "NETWORK_SCAN": AdvancedNetworkScan,
        "USER_AUDIT": AdvancedUserAudit,
        "PERSISTENCE_CHECK": AdvancedPersistenceCheck,
        "SYS_INFO": AdvancedSystemInfoScenario
    }

    def __init__(self):
        self.classifier = IntentClassifier()
        self.memory = MemoryStore()
        self.os_type = platform.system()
        self._ai_client = None
        self._client_initialized = False
        
        # Initialize Agents
        self.agent_map = {
            "task_coordinator_agent": task_coordinator_agent,
            "jarvis_analyst_agent": jarvis_analyst_agent,
            "text_analyst_agent": text_analyst_agent,
            "cmd_exec_agent": cmd_exec_agent,
            "ioc_extractor_agent": ioc_extractor_agent,
            "threat_classifier_agent": threat_classifier_agent
        }
        self.runner = ScenarioRunner(self.agent_map)
    
    def _get_ai_client(self):
        """Get or initialize AI client with caching."""
        if self._client_initialized and self._ai_client:
            return self._ai_client
        
        try:
            from openai import OpenAI
            import os
            from dotenv import load_dotenv
            
            load_dotenv()
            
            # Auto-detect Ollama if available, or use explicit setting
            use_local = os.getenv('USE_LOCAL_LLM', 'false').lower() == 'true'
            
            # Auto-detect if Ollama is running
            if not use_local:
                try:
                    import urllib.request
                    urllib.request.urlopen('http://localhost:11434', timeout=2)
                    use_local = True
                except:
                    pass
            
            if use_local:
                local_base_url = os.getenv('LOCAL_LLM_URL', 'http://localhost:11434/v1')
                local_model = os.getenv('LOCAL_LLM_MODEL', 'gpt-oss-20b')
                # Convert to Ollama format: gpt-oss-20b -> gpt-oss:20b
                if ':' not in local_model and '-' in local_model:
                    # Extract the number suffix (e.g., 20b from gpt-oss-20b)
                    parts = local_model.rsplit('-', 1)
                    if len(parts) == 2 and parts[1].endswith(('b', 'B')):
                        local_model = f"{parts[0]}:{parts[1]}"
                self._ai_client = OpenAI(
                    base_url=local_base_url,
                    api_key=os.getenv('LOCAL_LLM_API_KEY', 'ollama')
                )
                self._local_model = local_model
                print(f"[JARVIS] Using local model: {local_model}")
            else:
                self._ai_client = OpenAI(
                    api_key=os.getenv('GROQ_API_KEY') or os.getenv('OPENAI_API_KEY'),
                    base_url=os.getenv('OPENAI_API_BASE', 'https://api.groq.com/openai/v1')
                )
                self._local_model = None
                
            self._client_initialized = True
            return self._ai_client
        except Exception as e:
            print(f"[JARVIS] LLM init error: {e}")
            return None
    
    def _answer_general_question(self, user_input: str) -> Dict[str, Any]:
        """Answer general questions using AI with enhanced capabilities."""
        try:
            client = self._get_ai_client()
            if not client:
                return {
                    "status": "error",
                    "message": "AI service unavailable. Please check GROQ_API_KEY."
                }
            
            # Detect question type for better response
            question_type = self._detect_question_type(user_input)
            system_prompt = self._get_system_prompt(question_type, user_input)
            
            # Use local model if configured, otherwise use Groq
            model = getattr(self, '_local_model', None) or "llama-3.3-70b-versatile"
            
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_input}
                ],
                max_tokens=1500,
                temperature=0.7
            )
            
            answer = response.choices[0].message.content
            
            return {
                "status": "success",
                "intent": question_type,
                "data": answer,
                "context": {"question_type": question_type}
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"AI service error: {str(e)}"
            }
        self.runner = ScenarioRunner(self.agent_map)

    def process_input(self, user_input: str) -> Dict[str, Any]:
        """
        Main entry point for user interaction.
        """
        import re
        
        # Check for CVE lookup
        if re.search(r'CVE-\d{4}-\d{4,}', user_input, re.IGNORECASE):
            return self._execute_cve_lookup(user_input)
        
        # Check for IP lookup
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input):
            return self._execute_ip_lookup(user_input)
        
        # 1. Intent Detection
        intent = self.classifier.detect_intent(user_input)
        
        # 2. Handle URL scraping
        if intent == "WEB_SCRAPE":
            return self._execute_web_scrape(user_input)
        
        # 3. Handle general questions with AI
        if intent == "UNKNOWN":
            return self._answer_general_question(user_input)
        
        # 4. Handle FILE_SCAN specially
        if intent == "FILE_SCAN":
            return self._execute_file_scan(user_input)
        
        # 5. Handle special intents with dedicated tools
        special_intents = {
            "RISK_ASSESSMENT": self._execute_risk_assessment,
            "VULNERABILITY_SCAN": self._execute_vuln_scan,
            "SECURITY_HARDENING": self._execute_hardening,
            "IAM_AUDIT": self._execute_iam_audit,
            "PATCH_MANAGEMENT": self._execute_patch_management,
            "INCIDENT_RESPONSE": self._execute_incident_response,
            "DATA_PROTECTION": self._execute_data_protection,
            "COMPLIANCE": self._execute_compliance_check,
            "THIRD_PARTY_RISK": self._execute_third_party_risk,
            "CLOUD_SECURITY": self._execute_cloud_security,
            "WEB_SECURITY": self._execute_web_security,
            "PEN_TEST": self._execute_pen_test,
        }
        
        if intent in special_intents:
            return special_intents[intent](user_input)
        
        # 6. Scenario Selection
        scenario_class = self.SCENARIO_MAP.get(intent)
        if not scenario_class:
             return self._answer_general_question(user_input)

        # 7. Execute using Jarvis-specific scenario with elite analysis
        return self._execute_jarvis_scenario(intent, user_input)

    def _detect_question_type(self, text: str) -> str:
        """Detect what type of question/user request it is."""
        text_lower = text.lower()
        
        # Code generation
        code_keywords = ['code', 'script', 'program', 'function', 'write', 'create', 'build', 'generate', 'implement']
        if any(kw in text_lower for kw in code_keywords):
            return "CODE_GENERATION"
        
        # Explain concept
        explain_keywords = ['what is', 'explain', 'how does', 'describe', 'define', 'what does', 'meaning of']
        if any(kw in text_lower for kw in explain_keywords):
            return "CONCEPT_EXPLANATION"
        
        # Comparison
        compare_keywords = ['compare', 'difference between', 'vs', 'versus', 'better', 'advantage', 'disadvantage']
        if any(kw in text_lower for kw in compare_keywords):
            return "COMPARISON"
        
        # Tutorial/How-to
        howto_keywords = ['how to', 'how do i', 'steps', 'guide', 'tutorial', 'learn', 'start']
        if any(kw in text_lower for kw in howto_keywords):
            return "HOWTO_GUIDE"
        
        # Security specific
        security_keywords = ['security', 'hack', 'attack', 'vulnerability', 'exploit', 'penetration', 'malware', 'phishing']
        if any(kw in text_lower for kw in security_keywords):
            return "SECURITY_QUESTION"
        
        # Recommendation
        recommend_keywords = ['recommend', 'suggest', 'best', 'should i', 'which', 'what should']
        if any(kw in text_lower for kw in recommend_keywords):
            return "RECOMMENDATION"
        
        # Troubleshooting
        troubleshoot_keywords = ['error', 'fix', 'problem', 'issue', 'not working', 'failed', 'debug']
        if any(kw in text_lower for kw in troubleshoot_keywords):
            return "TROUBLESHOOTING"
        
        return "GENERAL_QUESTION"
    
    def _get_system_prompt(self, question_type: str, user_input: str) -> str:
        """Get enhanced system prompt based on question type."""
        
        prompts = {
            "CODE_GENERATION": """You are JARVIS - an elite cybersecurity AI expert and programmer.

CAPABILITIES:
- Write production-ready, secure code in Python, Bash, PowerShell
- Network security, penetration testing, forensics, malware analysis
- API integrations, automation scripts, security tools

REQUIREMENTS:
- Use proper error handling
- Add security best practices (input validation, sanitization)
- Include comments and docstrings
- Make code modular and reusable

RESPONSE FORMAT:
1. Brief explanation (1-2 sentences)
2. Clean, working code
3. Usage examples
4. Security notes if applicable""",

            "CONCEPT_EXPLANATION": """You are JARVIS - an elite cybersecurity educator.

YOUR TASK:
Explain security concepts clearly, accurately, and thoroughly.

REQUIREMENTS:
- Start with simple definition
- Explain how it works
- Give real-world examples
- Include attack vectors and defenses
- Mention related concepts

BE DETAILED but CONCISE. Use bullet points.""",

            "COMPARISON": """You are JARVIS - a cybersecurity consultant.

YOUR TASK:
Compare security tools, techniques, or concepts objectively.

INCLUDE:
- Features comparison
- Pros and Cons
- Use cases
- Performance considerations
- Pricing if relevant

BE FAIR and IMPARTIAL.""",

            "HOWTO_GUIDE": """You are JARVIS - a cybersecurity mentor and guide.

YOUR TASK:
Provide clear, actionable step-by-step instructions.

FORMAT:
1. Overview (what we'll do)
2. Prerequisites
3. Step-by-step instructions (numbered)
4. Verification steps
5. Tips and best practices

BE PRACTICAL and DETAILED.""",

            "SECURITY_QUESTION": """You are JARVIS - an elite cybersecurity expert.

YOUR TASK:
Provide accurate, comprehensive security information.

COVER:
- Definition and explanation
- How it works/attack vectors
- Real-world examples (famous incidents)
- Prevention/mitigation strategies
- Latest trends if relevant

EDUCATE the user thoroughly.""",

            "RECOMMENDATION": """You are JARVIS - a cybersecurity consultant.

YOUR TASK:
Provide actionable recommendations.

FORMAT:
1. Recommended approach
2. Why this recommendation
3. Implementation steps
4. Alternatives
5. Expected outcomes

BE SPECIFIC and PRACTICAL.""",

            "TROUBLESHOOTING": """You are JARVIS - a cybersecurity support specialist.

YOUR TASK:
Help diagnose and fix security-related issues.

APPROACH:
1. List possible causes
2. Diagnostic steps to try
3. Solutions in order of likelihood
4. Prevention tips

BE METHODICAL and THOROUGH.""",

            "GENERAL_QUESTION": """You are JARVIS - an intelligent AI assistant specialized in cybersecurity.

GUIDELINES:
- Answer directly and accurately
- Be helpful and concise
- Prioritize security best practices
- Provide practical examples
- If unsure, say so

Keep responses focused and actionable."""
        }
        
        return prompts.get(question_type, prompts["GENERAL_QUESTION"])

    def _execute_file_scan(self, user_input: str) -> Dict[str, Any]:
        """Execute file listing scan."""
        
        # Determine which directories to scan
        scan_paths = []
        user_lower = user_input.lower()
        
        if "download" in user_lower:
            scan_paths.append(("%USERPROFILE%\\Downloads", "Downloads"))
        if "desktop" in user_lower:
            scan_paths.append(("%USERPROFILE%\\Desktop", "Desktop"))
        if "document" in user_lower:
            scan_paths.append(("%USERPROFILE%\\Documents", "Documents"))
        if "recent" in user_lower:
            scan_paths.append(("%USERPROFILE%\\AppData\\Local\\Recent", "Recent"))
        
        # Default: scan user home
        if not scan_paths:
            scan_paths = [
                ("%USERPROFILE%", "UserHome"),
                ("%USERPROFILE%\\Downloads", "Downloads"),
                ("%USERPROFILE%\\Desktop", "Desktop"),
            ]
        
        class FileScanScenario(Scenario):
            name = "JARVIS File Scan"
            steps = []
            
            for path, key in scan_paths[:3]:  # Max 3 directories
                steps.append(ScenarioStep(
                    step_name=f"Scan_{key}",
                    agent_name="cmd_exec_agent",
                    instruction_template=f"dir {path} /b 2>nul | findstr .",
                    save_output_to_context_key=f"files_{key}"
                ))
        
        try:
            print(f"JARVIS: Scanning files...")
            context = self.runner.run(FileScanScenario())
            
            # Format results
            result = "**FILE LISTING**\n\n"
            for path, key in scan_paths[:3]:
                files = context.get(f"files_{key}", "")
                if files:
                    file_list = [f.strip() for f in files.split('\n') if f.strip()][:20]
                    result += f"**{key}** ({len(file_list)} files):\n"
                    for f in file_list:
                        result += f"  - {f}\n"
                    result += "\n"
            
            return {
                "status": "success",
                "intent": "FILE_SCAN",
                "data": result,
                "context": context
            }
        except Exception as e:
            logger.error(f"File scan failed: {e}")
            return {
                "status": "failure",
                "message": f"File scan failed: {str(e)}"
            }

    def _execute_web_scrape(self, user_input: str) -> Dict[str, Any]:
        """Execute web scraping when URL is detected."""
        from tools.scraper_tool import scrape_basic, scrape_security_info
        
        url = user_input.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            print(f"JARVIS: Scraping {url}...")
            
            basic_result = scrape_basic(url)
            
            if basic_result.get("status") != "success":
                return {
                    "status": "error",
                    "intent": "WEB_SCRAPE",
                    "message": f"Failed to scrape: {basic_result.get('message', 'Unknown error')}"
                }
            
            security_result = scrape_security_info(url)
            
            findings = {}
            if security_result.get("status") == "success":
                findings = security_result.get("findings", {})
            
            output = {
                "URL": url,
                "Title": basic_result.get("title", "N/A"),
                "Server": basic_result.get("server", "N/A"),
                "Status": basic_result.get("status_code", "N/A"),
            }
            
            if findings.get("emails"):
                output["Emails"] = findings["emails"][:5]
            if findings.get("tech_stack"):
                output["Tech Stack"] = findings["tech_stack"]
            if findings.get("versions"):
                output["Versions"] = findings["versions"][:5]
            if findings.get("endpoints"):
                output["Endpoints"] = findings["endpoints"][:10]
            if findings.get("ipv4"):
                output["IPs Found"] = findings["ipv4"][:5]
            if findings.get("cve_mentions"):
                output["CVEs"] = findings["cve_mentions"][:5]
            
            output["Content"] = basic_result.get("text", "")[:1000] + "..."
            
            return {
                "status": "success",
                "intent": "WEB_SCRAPE",
                "data": output,
                "context": {"url": url, "basic": basic_result, "security": security_result}
            }
        except Exception as e:
            logger.error(f"Web scrape failed: {e}")
            return {
                "status": "failure",
                "message": f"Web scrape failed: {str(e)}"
            }
    
    def _execute_cve_lookup(self, user_input: str) -> Dict[str, Any]:
        """Execute CVE lookup."""
        from tools.scraper_tool import lookup_cve
        import re
        
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', user_input, re.IGNORECASE)
        if not cve_match:
            return {"status": "error", "message": "No CVE ID found in input"}
        
        cve_id = cve_match.group()
        print(f"JARVIS: Looking up {cve_id}...")
        
        result = lookup_cve(cve_id)
        
        if result.get("status") == "success":
            output = {
                "CVE": result.get("id"),
                "Description": result.get("description", "N/A")[:300],
                "Severity": result.get("severity", "N/A"),
                "CVSS Score": result.get("cvss_score", "N/A"),
                "Published": result.get("published", "N/A"),
            }
            return {"status": "success", "intent": "CVE_LOOKUP", "data": output}
        else:
            return {"status": "error", "message": result.get("message", "Lookup failed")}
    
    def _execute_ip_lookup(self, user_input: str) -> Dict[str, Any]:
        """Execute IP lookup."""
        from tools.scraper_tool import ip_info
        import re
        
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input)
        if not ip_match:
            return {"status": "error", "message": "No IP address found in input"}
        
        ip = ip_match.group()
        print(f"JARVIS: Looking up IP {ip}...")
        
        result = ip_info(ip)
        
        if result.get("status") == "success":
            output = {
                "IP": result.get("ip"),
                "Country": result.get("country"),
                "Region": result.get("region"),
                "City": result.get("city"),
                "ISP": result.get("isp"),
                "Organization": result.get("org"),
                "AS": result.get("as"),
            }
            return {"status": "success", "intent": "IP_LOOKUP", "data": output}
        else:
            return {"status": "error", "message": result.get("message", "Lookup failed")}

    def _execute_jarvis_scenario(self, intent: str, user_input: str) -> Dict[str, Any]:
        """Execute a scenario using Jarvis-style analysis."""
        
        # Create a custom scenario based on intent
        class JarvisScenario(Scenario):
            name = f"JARVIS {intent} Analysis"
            
            if intent == "NETWORK_SCAN":
                steps = [
                    ScenarioStep(step_name="Run Netstat", agent_name="cmd_exec_agent",
                               instruction_template="netstat -ano", save_output_to_context_key="raw_netstat"),
                    ScenarioStep(step_name="Run IPConfig", agent_name="cmd_exec_agent",
                               instruction_template="ipconfig /all", save_output_to_context_key="raw_ipconfig"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw Network Data:
=== NETSTAT ===
{{raw_netstat}}

=== IPCONFIG ===
{{raw_ipconfig}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
            elif intent == "USER_AUDIT":
                steps = [
                    ScenarioStep(step_name="List Admins", agent_name="cmd_exec_agent",
                               instruction_template="net localgroup administrators", save_output_to_context_key="raw_admins"),
                    ScenarioStep(step_name="List Users", agent_name="cmd_exec_agent",
                               instruction_template="net user", save_output_to_context_key="raw_users"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw User Data:
=== ADMIN GROUP ===
{{raw_admins}}

=== ALL USERS ===
{{raw_users}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
            elif intent == "PERSISTENCE_CHECK":
                steps = [
                    ScenarioStep(step_name="Check Registry", agent_name="cmd_exec_agent",
                               instruction_template="reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                               save_output_to_context_key="raw_registry"),
                    ScenarioStep(step_name="Check Services", agent_name="cmd_exec_agent",
                               instruction_template="sc query", save_output_to_context_key="raw_services"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw Persistence Data:
=== REGISTRY RUN KEYS ===
{{raw_registry}}

=== SERVICES ===
{{raw_services}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
            else:
                # Default: system info
                steps = [
                    ScenarioStep(step_name="Get SystemInfo", agent_name="cmd_exec_agent",
                               instruction_template="systeminfo", save_output_to_context_key="raw_sysinfo"),
                    ScenarioStep(step_name="Jarvis Analysis", agent_name="jarvis_analyst_agent",
                               instruction_template=f"""{get_prompt_for_intent(intent)}

Raw System Data:
{{raw_sysinfo}}

Provide your intelligence briefing now.""",
                               save_output_to_context_key="jarvis_report"),
                ]
        
        scenario = JarvisScenario()
        try:
            print(f"JARVIS: Initiating {scenario.name}...")
            context = self.runner.run(scenario)
            
            report = context.get('jarvis_report', context.get('final_report', {}))
            
            self._log_history(scenario.name, "success")
            
            return {
                "status": "success",
                "intent": scenario.name,
                "data": report,
                "context": context
            }
            
        except Exception as e:
            logger.error(f"JARVIS: Scenario failed: {e}")
            self._log_history(scenario.name, "failure", str(e))
            
            return {
                "status": "failure",
                "message": f"I couldn't complete the {scenario.name}. Error: {str(e)}",
                "suggestion": "Check your system configuration or try a different scan."
            }

    def _safe_execute_scenario(self, scenario_class) -> Dict[str, Any]:
        """
        Executes a scenario with error handling and recovery logic.
        """
        scenario = scenario_class()
        try:
            print(f"JARVIS: Initiating {scenario.name}...")
            context = self.runner.run(scenario)
            
            # Extract Report for simple return
            report = context.get('final_report', {})
            
            # Log success
            self._log_history(scenario.name, "success")
            
            return {
                "status": "success",
                "intent": scenario.name,
                "data": report,
                "context": context # Full context for advanced inspection
            }
            
        except Exception as e:
            logger.error(f"JARVIS: Scenario failed: {e}")
            self._log_history(scenario.name, "failure", str(e))
            
            return {
                "status": "failure",
                "message": f"I couldn't complete the {scenario.name}. Error: {str(e)}",
                "suggestion": "Check your system configuration or try a different scan."
            }

    def _log_history(self, action: str, status: str, error: str = ""):
        """
        Logs execution capability to memory (placeholder for now).
        """
        # In a full implementation, this would write to a 'history' table in DB.
        pass

    # ============================================================
    # Advanced Security Operations Handlers
    # ============================================================
    
    def _execute_risk_assessment(self, user_input: str) -> Dict[str, Any]:
        """Execute risk assessment."""
        try:
            from tools.security_tools_advanced import perform_risk_assessment
            print("JARVIS: Performing Risk Assessment...")
            result = perform_risk_assessment()
            return {"status": "success", "intent": "RISK_ASSESSMENT", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Risk assessment failed: {str(e)}"}
    
    def _execute_vuln_scan(self, user_input: str) -> Dict[str, Any]:
        """Execute vulnerability scan."""
        try:
            from tools.security_tools_advanced import vulnerability_scan
            print("JARVIS: Scanning for vulnerabilities...")
            result = vulnerability_scan()
            return {"status": "success", "intent": "VULNERABILITY_SCAN", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Vulnerability scan failed: {str(e)}"}
    
    def _execute_hardening(self, user_input: str) -> Dict[str, Any]:
        """Execute security hardening."""
        try:
            from tools.security_tools_advanced import security_hardening
            print("JARVIS: Performing security hardening assessment...")
            result = security_hardening()
            return {"status": "success", "intent": "SECURITY_HARDENING", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Hardening check failed: {str(e)}"}
    
    def _execute_iam_audit(self, user_input: str) -> Dict[str, Any]:
        """Execute IAM audit."""
        try:
            from tools.security_tools_advanced import iam_audit
            print("JARVIS: Performing IAM audit...")
            result = iam_audit()
            return {"status": "success", "intent": "IAM_AUDIT", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"IAM audit failed: {str(e)}"}
    
    def _execute_patch_management(self, user_input: str) -> Dict[str, Any]:
        """Execute patch management check."""
        try:
            from tools.security_tools_advanced import patch_management
            print("JARVIS: Checking patch management...")
            result = patch_management()
            return {"status": "success", "intent": "PATCH_MANAGEMENT", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Patch management check failed: {str(e)}"}
    
    def _execute_incident_response(self, user_input: str) -> Dict[str, Any]:
        """Execute incident response."""
        try:
            from tools.security_tools_advanced import incident_response
            print("JARVIS: Gathering incident response artifacts...")
            result = incident_response()
            return {"status": "success", "intent": "INCIDENT_RESPONSE", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Incident response failed: {str(e)}"}
    
    def _execute_data_protection(self, user_input: str) -> Dict[str, Any]:
        """Execute data protection check."""
        try:
            from tools.security_tools_advanced import data_protection
            print("JARVIS: Checking data protection status...")
            result = data_protection()
            return {"status": "success", "intent": "DATA_PROTECTION", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Data protection check failed: {str(e)}"}
    
    def _execute_compliance_check(self, user_input: str) -> Dict[str, Any]:
        """Execute compliance check."""
        try:
            from tools.security_tools_advanced import compliance_check
            print("JARVIS: Checking compliance status...")
            result = compliance_check()
            return {"status": "success", "intent": "COMPLIANCE", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Compliance check failed: {str(e)}"}
    
    def _execute_third_party_risk(self, user_input: str) -> Dict[str, Any]:
        """Execute third party risk assessment."""
        try:
            from tools.security_tools_advanced import third_party_risk
            print("JARVIS: Assessing third party risk...")
            result = third_party_risk()
            return {"status": "success", "intent": "THIRD_PARTY_RISK", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Third party risk check failed: {str(e)}"}
    
    def _execute_cloud_security(self, user_input: str) -> Dict[str, Any]:
        """Execute cloud security check."""
        try:
            from tools.security_tools_advanced import cloud_security_check
            print("JARVIS: Checking cloud security...")
            result = cloud_security_check()
            return {"status": "success", "intent": "CLOUD_SECURITY", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Cloud security check failed: {str(e)}"}
    
    def _execute_web_security(self, user_input: str) -> Dict[str, Any]:
        """Execute web security scan."""
        import re
        url_match = re.search(r'https?://[^\s]+', user_input)
        if url_match:
            url = url_match.group()
        else:
            url = "https://example.com"
        
        try:
            from tools.security_tools_advanced import web_security_scan
            print(f"JARVIS: Scanning {url} for security issues...")
            result = web_security_scan(url)
            return {"status": "success", "intent": "WEB_SECURITY", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Web security scan failed: {str(e)}"}
    
    def _execute_pen_test(self, user_input: str) -> Dict[str, Any]:
        """Execute penetration test simulation."""
        try:
            from tools.security_tools_advanced import vulnerability_scan, iam_audit, security_hardening
            print("JARVIS: Running penetration test simulation...")
            
            result = {
                "test_type": "Penetration Test Simulation",
                "findings": [],
                "recommendations": []
            }
            
            # Run multiple checks
            vulns = vulnerability_scan()
            result["vulnerabilities"] = vulns.get("findings", [])
            
            iam = iam_audit()
            result["access_issues"] = iam.get("risks", [])
            
            hardening = security_hardening()
            result["hardening_gaps"] = hardening.get("failed", [])
            
            return {"status": "success", "intent": "PEN_TEST", "data": result}
        except Exception as e:
            return {"status": "error", "message": f"Pen test failed: {str(e)}"}
