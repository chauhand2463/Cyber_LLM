import re
from typing import Tuple, Dict, Any, Optional


class IntentClassifier:
    PATTERNS = {
        "CVE_LOOKUP": r'CVE-\d{4}-\d{4,}',
        "IP_LOOKUP": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "URL_SCRAPE": r'https?://[^\s]+',
        "NETWORK_SCAN": r'(open ports?|netstat|connections?|network|ports?|listening)',
        "USER_AUDIT": r'(admin|user|account|privilege|permission|whoami|localgroup)',
        "PROCESS_SCAN": r'(process|tasklist|ps aux|malware|suspicious|running)',
        "SERVICE_SCAN": r'(service|daemon|systemctl|sc query)',
        "SYSTEM_INFO": r'(system info|sysinfo|hostname|uname|computer)',
        "THREAT_HUNT": r'(threat|hunt|malware|virus|exploit|vulnerability|cve)',
        "FIREWALL": r'(firewall|iptables|netsh|pfctl)',
        "PERSISTENCE": r'(startup|autorun|registry|crontab|launchd|persistence)',
        "FULL_SCAN": r'(full scan|complete scan|deep scan|audit)',
        "WEB_ATTACK": r'(sql injection|xss|csrf|owasp|web vulnerability)',
    }
    
    KEYWORDS = {
        "scan": ["scan", "check", "find", "look", "search", "list"],
        "system": ["system", "computer", "machine", "device"],
        "network": ["network", "port", "connection", "netstat", "ip"],
        "security": ["security", "threat", "vulnerability", "exploit", "hack"],
        "info": ["info", "information", "details", "about"],
        "help": ["help", "?", "commands", "what can you do"],
    }
    
    def classify(self, text: str) -> Tuple[str, Optional[str]]:
        text_lower = text.lower()
        
        for intent, pattern in self.PATTERNS.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return intent, match.group()
        
        for keyword in self.KEYWORDS:
            if keyword in text_lower:
                if keyword == "scan":
                    return "SCAN_REQUEST", None
                elif keyword == "system":
                    return "SYSTEM_INFO", None
                elif keyword == "network":
                    return "NETWORK_SCAN", None
                elif keyword == "security":
                    return "SECURITY_QUERY", None
                elif keyword == "info":
                    return "INFO_REQUEST", None
                elif keyword == "help":
                    return "HELP", None
        
        return "GENERAL_QUERY", None
    
    def get_intent_response(self, intent: str) -> Dict[str, Any]:
        responses = {
            "CVE_LOOKUP": {
                "action": "cve_lookup",
                "description": "Looking up CVE vulnerability details"
            },
            "IP_LOOKUP": {
                "action": "ip_lookup", 
                "description": "Looking up IP address information"
            },
            "URL_SCRAPE": {
                "action": "web_scrape",
                "description": "Scraping website data"
            },
            "NETWORK_SCAN": {
                "action": "network_scan",
                "description": "Scanning network connections and ports"
            },
            "USER_AUDIT": {
                "action": "user_audit",
                "description": "Auditing user accounts and privileges"
            },
            "PROCESS_SCAN": {
                "action": "process_scan",
                "description": "Scanning running processes"
            },
            "SERVICE_SCAN": {
                "action": "service_scan",
                "description": "Scanning system services"
            },
            "SYSTEM_INFO": {
                "action": "system_info",
                "description": "Gathering system information"
            },
            "THREAT_HUNT": {
                "action": "threat_hunt",
                "description": "Hunting for threats and vulnerabilities"
            },
            "FIREWALL": {
                "action": "firewall_check",
                "description": "Checking firewall configuration"
            },
            "PERSISTENCE": {
                "action": "persistence_check",
                "description": "Checking for persistence mechanisms"
            },
            "FULL_SCAN": {
                "action": "full_scan",
                "description": "Running comprehensive system scan"
            },
            "SCAN_REQUEST": {
                "action": "generic_scan",
                "description": "Performing requested scan"
            },
            "GENERAL_QUERY": {
                "action": "ai_chat",
                "description": "Answering general question"
            },
        }
        return responses.get(intent, {"action": "ai_chat", "description": "Processing request"})
