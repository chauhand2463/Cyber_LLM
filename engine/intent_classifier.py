from typing import Dict, Optional, List
from urllib.parse import urlparse
import re

class IntentClassifier:
    """
    Comprehensive intent classifier for CyberLLM ARTEMIS.
    Handles all cybersecurity domains including Risk Assessment, Vulnerability Management,
    Penetration Testing, Incident Response, Compliance, and more.
    """
    
    INTENTS = {
        # === File & Directory Operations ===
        "FILE_SCAN": [
            "file", "files", "directory", "folder", "list", "dir", "find", "search",
            "locate", "recent", "downloads", "desktop", "documents", "name", "extension",
            "size", "created", "modified", "accessed", "ls", "dir", "pwd", "find"
        ],
        
        # === Threat Detection & Hunting ===
        "THREAT_HUNT": [
            "hunt", "threat", "malware", "virus", "scan system", "compromise", "hack",
            "process", "rootkit", "suspicious", "infected", "ransomware", "trojan",
            "backdoor", "keylogger", "adware", "spyware", "worm", "botnet", "indicator",
            "ioc", "forensic", "analyze", "investigate", "detection", "payload", "exploit",
            "attack", "breach", "phishing", "malicious", "infection", "compromised"
        ],
        
        # === Network Scanning ===
        "NETWORK_SCAN": [
            "port", "netstat", "tcp", "udp", "connection", "listen", "network", "socket",
            "ip", "address", "scan", "nmap", "firewall", "router", "subnet", "dns", "dhcp",
            "http", "https", "ftp", "ssh", "telnet", "smb", "ldap", "remote", "bandwidth",
            "traffic", "packet", "arp", "route", "ping", "traceroute", "nslookup", "dig",
            "host", "whois", "ssl", "tls", "certificate", "open port", "close port"
        ],
        
        # === User & Access Management ===
        "USER_AUDIT": [
            "user", "users", "admin", "administrators", "group", "groups", "account", "accounts",
            "privilege", "role", "permission", "permissions", "access", "authentication", "auth",
            "authorization", "credential", "credentials", "password", "passwords", "localgroup",
            "domain", "ad", "active directory", "ldap", "sudoers", "wheel", "root access",
            "elevation", "privilege escalation", "mfa", "2fa", "multi-factor", "rbac", "iam",
            "access control", "identity", "authentication", "oauth", "saml", "single sign on",
            "login", "logon", "session", "token", "jwt", "api key", "secret"
        ],
        
        # === Persistence & Startup ===
        "PERSISTENCE_CHECK": [
            "registry", "startup", "run key", "boot", "persist", "autostart", "scheduled task",
            "service", "services", "cron", "systemd", "init", "rc.d", "task scheduler",
            "windows task", "launch agent", "login item", "scheduled job", "auto-run",
            "registry key", "HKLM", "HKCU", "HKU", "autorun", "bootkit", "rootkit"
        ],
        
        # === System Information ===
        "SYS_INFO": [
            "system", "info", "specs", "os", "hostname", "patch", "hotfix", "update", "updates",
            "version", "environment", "computer", "machine", "device", "windows", "linux", "macos",
            "mac os", "cpu", "memory", "ram", "disk", "storage", "bios", "uefi", "configuration",
            "settings", "config", "ver", "uname", "systeminfo", "lsb_release", "sw_vers"
        ],
        
        # === Risk Assessment ===
        "RISK_ASSESSMENT": [
            "risk", "assessment", "risk assessment", "asset", "assets", "threat", "threats",
            "vulnerability", "vulnerabilities", "vuln", "cve", "impact", "business impact",
            "likelihood", "probability", "severity", "criticality", "risk score", "risk rating",
            "risk matrix", "risk analysis", "risk management", "risk treatment", "risk acceptance",
            "risk mitigation", "risk transfer", "risk avoidance", "threat modeling", "strand",
            "attack surface", "exposure", "security posture", "security posture assessment"
        ],
        
        # === Vulnerability Management ===
        "VULNERABILITY_SCAN": [
            "vulnerability", "vuln", "vulns", "scan", "scanner", "nessus", "openvas", "qualys",
            "rapid7", "nexpose", "scanning", "vulnerability scan", "vulnerability assessment",
            "vulnerability scan", "cve", "cvss", "exploit", "exploitable", "patch", "patches",
            "remediation", "fix", "fixing", "security update", "security updates", "hotfix",
            "missing patch", "unpatched", "outdated", "vulnerable", "weakness", "weaknesses"
        ],
        
        # === Penetration Testing ===
        "PEN_TEST": [
            "pen test", "pentest", "penetration", "penetration test", "hacking", "ethical hacking",
            "red team", "blue team", "purple team", "attack simulation", "exploit", "exploitation",
            "pwn", "root", "privilege escalation", "lateral movement", "pivot", "persistence",
            "maintain access", "clear logs", "cover tracks", "metasploit", "burp", "sqlmap",
            "nikto", "dirb", "gobuster", "hydra", "john", "hashcat", "crack", "brute force",
            "dictionary attack", "rainbow table", "reverse shell", "bind shell", "web shell"
        ],
        
        # === Incident Response ===
        "INCIDENT_RESPONSE": [
            "incident", "incident response", "ir", "breach", "data breach", "security breach",
            "containment", "eradication", "recovery", "root cause", "root cause analysis",
            "forensics", "forensic", "evidence", "preserve evidence", "chain of custody",
            "triage", "investigation", "log analysis", "timeline", "mitre", "att&ck",
            "siem", "splunk", "arcsight", " QRadar", "logstash", "incident handling",
            "playbook", "runbook", "escalation", "notification", "reporting"
        ],
        
        # === Security Architecture & Hardening ===
        "SECURITY_HARDENING": [
            "hardening", "secure", "security", "baseline", "cis", "disa", "stig", "nist",
            "security benchmark", "secure configuration", "secure settings", "lockdown",
            "disable service", "disable protocol", "remove service", "stop service",
            "secure network", "network segmentation", "vlan", "dmz", "air gap", "zone",
            "firewall rule", "iptables", "ufw", "acl", "access control list", "security group",
            "port security", "protocol security", "disable protocol", "remove protocol"
        ],
        
        # === Patch Management ===
        "PATCH_MANAGEMENT": [
            "patch", "patches", "patching", "update", "updates", "update management",
            "patch management", "security update", "critical update", "windows update",
            "wsus", "sccm", "patch tuesday", "zero day", "zero-day", "cve patch",
            "patch deployment", "patch compliance", "missing update", "available update"
        ],
        
        # === Monitoring & Detection ===
        "MONITORING_DETECTION": [
            "monitor", "monitoring", "detect", "detection", "soc", "security operations",
            "siem", "splunk", "elastic", "sumologic", "log", "logs", "logging", "syslog",
            "event log", "event logs", "alert", "alerts", "alerting", "correlation",
            "rule", "detection rule", "sigma rule", "yara", "snort", "suricata", "zeek",
            "ids", "ips", "ids/ips", "edr", "endpoint detection", "crowdstrike", "carbon black",
            "mdr", "xdr", "threat hunting", "anomal", "anomaly", "behavior", "behavioral"
        ],
        
        # === Data Protection ===
        "DATA_PROTECTION": [
            "data protection", "encrypt", "encryption", "encrypt data", "decrypt", "decryption",
            "encryption at rest", "encryption in transit", "tls", "ssl", "aes", "rsa", "hash",
            "hashing", "sha", "md5", "backup", "backups", "backup strategy", "data backup",
            "restore", "recovery", "disaster recovery", "dr", "bcp", "business continuity",
            "data loss", "data leak", "data breach", "dlp", "data loss prevention",
            "tokenization", "masking", "obfuscation", "pseudonymization"
        ],
        
        # === Compliance & Governance ===
        "COMPLIANCE": [
            "compliance", "compliant", "regulation", "regulations", "standard", "standards",
            "audit", "auditing", "audits", "policy", "policies", "procedure", "procedures",
            "gdpr", "hipaa", "pci-dss", "pci", "soc2", "iso", "iso27001", "nist", "cis",
            "framework", "control", "controls", "evidence", "evidence collection", "certification",
            "attestation", "assessment", "gap analysis", "remediation plan"
        ],
        
        # === Security Awareness ===
        "SECURITY_AWARENESS": [
            "training", "awareness", "security training", "security awareness", "phishing",
            "phishing training", "phishing simulation", "social engineering", "spam", "spear phishing",
            "whaling", "vishing", "smishing", "security culture", "security education",
            "user training", "employee training", "security campaign", "security communication"
        ],
        
        # === Third Party Risk ===
        "THIRD_PARTY_RISK": [
            "third party", "third-party", "vendor", "vendors", "supplier", "suppliers",
            "supply chain", "supply-chain", "vendor risk", "vendor assessment", "vendor security",
            "third party risk", "vendor management", "supplier risk", "供应链", "contractor",
            "external access", "third party access", "vendor access", "fourth party"
        ],
        
        # === Cloud Security ===
        "CLOUD_SECURITY": [
            "cloud", "aws", "azure", "gcp", "google cloud", "amazon web services",
            "iam role", "s3", "bucket", "storage blob", "ec2", "lambda", "azure ad",
            "cloud security", "cloudtrail", "cloudwatch", "security group", "nacls",
            "cloud posture", "cspm", "cwpp", "casb", "cloud security posture"
        ],
        
        # === Web Application Security ===
        "WEB_SECURITY": [
            "web", "website", "web application", "appsec", "owasp", "sql injection", "xss",
            "cross site scripting", "csrf", "session hijacking", "web shell", "webshell",
            "http header", "csp", "hsts", "x-frame-options", "web vulnerability",
            "burp", "zap", "nikto", "web scan", "application security", "api security",
            "rest api", "graphql", "jwt", "authentication bypass", "authorization"
        ]
    }

    # Context keywords that boost confidence
    CONTEXT_BOOST = {
        "THREAT_HUNT": ["find", "search", "look for", "check for", "detect", "identify", "analyze"],
        "NETWORK_SCAN": ["check", "find", "list", "show", "get", "view", "scan"],
        "USER_AUDIT": ["check", "list", "show", "get", "find", "verify", "audit"],
        "PERSISTENCE_CHECK": ["check", "find", "list", "show", "detect", "verify"],
        "SYS_INFO": ["get", "show", "list", "check", "retrieve", "gather", "collect"],
        "RISK_ASSESSMENT": ["assess", "evaluate", "analyze", "identify", "determine"],
        "VULNERABILITY_SCAN": ["scan", "assess", "find", "check", "identify"],
        "PEN_TEST": ["test", "attempt", "exploit", "simulate", "try"],
        "INCIDENT_RESPONSE": ["handle", "respond", "contain", "investigate", "analyze"],
        "SECURITY_HARDENING": ["harden", "secure", "lock", "disable", "remove"],
        "PATCH_MANAGEMENT": ["apply", "install", "deploy", "update", "patch"],
        "MONITORING_DETECTION": ["monitor", "watch", "detect", "alert", "log"],
        "DATA_PROTECTION": ["protect", "encrypt", "backup", "secure"],
        "COMPLIANCE": ["comply", "audit", "assess", "verify", "check"],
        "SECURITY_AWARENESS": ["train", "educate", "teach", "inform"],
        "THIRD_PARTY_RISK": ["assess", "evaluate", "review", "audit"],
        "CLOUD_SECURITY": ["configure", "secure", "check", "audit"],
        "WEB_SECURITY": ["test", "scan", "audit", "assess"]
    }

    # Negative keywords that reduce intent confidence
    NEGATION_WORDS = ["not", "no", "don't", "never", "disable", "remove", "uninstall", "stop"]

    # Keywords that indicate general formatting/query requests
    FORMAT_QUERY_WORDS = ["json", "csv", "xml", "table", "format", "export", "output", 
                         "display", "show me", "give me", "list all", "what is", "how to", 
                         "why", "can you", "please", "convert", "explain", "describe",
                         "what's", "tell me", "learn", "understand", "definition",
                         "difference", "compare", "versus", "vs", "better", "recommend",
                         "suggest", "guide", "tutorial", "steps", "how does", "how do",
                         "meaning", "define", "explain", "examples", "sample"]
    
    # Keywords that indicate CODE GENERATION request (highest priority)
    CODE_GENERATION_WORDS = ["write code", "create script", "generate code", "implement",
                            "build script", "make code", "code for", "script to", 
                            "python code", "bash script", "powershell script", "java code",
                            "c++ code", "write python", "write bash", "write script",
                            "create tool", "build tool", "develop code", "develop script"]
    
    # Keywords that indicate ACTION (scan/execute) - these override questions
    ACTION_KEYWORDS = ["scan", "check", "run", "execute", "perform", "find", "list",
                       "show", "get", "view", "audit", "test", "detect", "analyze"]

    def detect_intent(self, text: str) -> str:
        """
        Detects the intent of the user input.
        Returns one of the INTENT keys or 'UNKNOWN'.
        """
        # First, check for URL pattern
        if self._is_url(text):
            return "WEB_SCRAPE"
        
        text_lower = text.lower()
        
        # Check for CODE GENERATION request first
        if any(kw in text_lower for kw in self.CODE_GENERATION_WORDS):
            return "UNKNOWN"
        
        # Check if this is a question/explanation request (not an action)
        is_question = any(kw in text_lower for kw in self.FORMAT_QUERY_WORDS)
        is_action = any(kw in text_lower for kw in self.ACTION_KEYWORDS)
        
        # If it's a question without action keywords, return UNKNOWN (will go to AI)
        if is_question and not is_action:
            return "UNKNOWN"
        
        # If it's asking to explain something about security concepts, return UNKNOWN
        explain_patterns = ['what is', 'explain', 'how does', 'describe', 'define', 
                          'tell me about', 'learn about', 'understand']
        if any(pattern in text_lower for pattern in explain_patterns):
            return "UNKNOWN"
        
        # Check if this is a general query/format request
        format_score = sum(1 for kw in self.FORMAT_QUERY_WORDS if kw in text_lower)
        if format_score >= 1:
            # Check if there are any strong security keywords (with word boundaries)
            security_keywords = 0
            for intent, keywords in self.INTENTS.items():
                for kw in keywords:
                    pattern = r'\b' + re.escape(kw) + r'\b'
                    if re.search(pattern, text_lower):
                        security_keywords += 1
            if security_keywords == 0:
                return "UNKNOWN"
        
        scores: Dict[str, float] = {}
        
        # Calculate base scores
        for intent, keywords in self.INTENTS.items():
            score = 0
            matched_keywords = []
            
            for keyword in keywords:
                pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(pattern, text_lower):
                    score += 1.0
                    matched_keywords.append(keyword)
                    
                    # Check for context boost
                    for boost_word in self.CONTEXT_BOOST.get(intent, []):
                        if boost_word in text_lower:
                            score += 0.5
            
            if score > 0:
                scores[intent] = score
        
        # Apply negation penalty
        has_negation = any(neg in text_lower for neg in self.NEGATION_WORDS)
        if has_negation and scores:
            for intent in scores:
                scores[intent] *= 0.5
        
        if not scores:
            return "UNKNOWN"
            
        # Return intent with highest score
        best_intent = max(scores, key=scores.get)
        return best_intent

    def detect_intent_with_confidence(self, text: str) -> Dict[str, any]:
        """Detects intent with confidence score."""
        if self._is_url(text):
            return {
                "intent": "WEB_SCRAPE",
                "confidence": 1.0,
                "all_scores": {"WEB_SCRAPE": 1.0},
                "matched_keywords": []
            }
        
        text_lower = text.lower()
        scores: Dict[str, float] = {}
        
        for intent, keywords in self.INTENTS.items():
            score = 0
            matched_keywords = []
            
            for keyword in keywords:
                pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(pattern, text_lower):
                    score += 1.0
                    matched_keywords.append(keyword)
                    
                    for boost_word in self.CONTEXT_BOOST.get(intent, []):
                        if boost_word in text_lower:
                            score += 0.3
            
            if score > 0:
                scores[intent] = score
        
        has_negation = any(neg in text_lower for neg in self.NEGATION_WORDS)
        if has_negation:
            for intent in scores:
                scores[intent] *= 0.4
        
        if not scores:
            return {
                "intent": "UNKNOWN",
                "confidence": 0.0,
                "all_scores": {},
                "matched_keywords": []
            }
        
        total_score = sum(scores.values())
        best_intent = max(scores, key=scores.get)
        confidence = scores[best_intent] / total_score if total_score > 0 else 0
        
        return {
            "intent": best_intent,
            "confidence": confidence,
            "all_scores": scores,
            "matched_keywords": self._get_matched_keywords(text_lower)
        }

    def _get_matched_keywords(self, text_lower: str) -> List[str]:
        """Get all matched keywords across all intents."""
        matched = []
        for keywords in self.INTENTS.values():
            for keyword in keywords:
                if keyword in text_lower and keyword not in matched:
                    matched.append(keyword)
        return matched

    def _is_url(self, text: str) -> bool:
        """Check if input is a URL."""
        text = text.strip()
        url_pattern = re.compile(
            r'^https?://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(url_pattern.match(text))
