from typing import Dict, Optional, List
import re

class IntentClassifier:
    """
    Classifies natural language text into actionable intents using keyword scoring.
    Enhanced with more comprehensive keyword patterns and context awareness.
    """
    
    INTENTS = {
        "FILE_SCAN": [
            "file", "files", "directory", "folder", "list", "directory", "dir",
            "find", "search", "locate", "recent", "downloads", "desktop", "documents",
            "name", "extension", "size", "created", "modified", "accessed"
        ],
        "THREAT_HUNT": [
            "hunt", "threat", "malware", "virus", "scan system", "compromise", "hack",
            "process", "rootkit", "suspicious", "infected", "ransomware",
            "trojan", "backdoor", "keylogger", "adware", "spyware", "worm", "botnet",
            "indicator", "ioc", "forensic", "analyze", "investigate", "detection",
            "payload", "exploit", "vulnerability", "cve", "attack", "breach"
        ],
        "NETWORK_SCAN": [
            "port", "netstat", "tcp", "udp", "connection", "listen", "network", 
            "socket", "ip", "address", "scan", "nmap", "firewall", "router",
            "subnet", "dns", "dhcp", "http", "https", "ftp", "ssh", "telnet",
            "smb", "ldap", "remote", "socket", "bandwidth", "traffic", "packet"
        ],
        "USER_AUDIT": [
            "user", "admin", "group", "account", "privilege", "role", "permission",
            "access", "authentication", "authorization", "credential", "password",
            "account", "localgroup", "domain", "ad", "active directory", "ldap",
            "sudoers", "wheel", "root access", "elevation", "privilege escalation"
        ],
        "PERSISTENCE_CHECK": [
            "registry", "startup", "run key", "boot", "persist", "autostart",
            "scheduled task", "service", "cron", "systemd", "init", "rc.d",
            "task scheduler", "windows task", "launch agent", "login item",
            "scheduled job", "auto-run", "registry key", "HKLM", "HKCU"
        ],
        "SYS_INFO": [
            "system", "info", "specs", "os", "hostname", "patch", "hotfix",
            "update", "version", "environment", "computer", "machine", "device",
            "windows", "linux", "macos", "cpu", "memory", "disk", "storage",
            "bios", "uefi", "configuration", "settings"
        ]
    }

    # Context keywords that boost confidence
    CONTEXT_BOOST = {
        "THREAT_HUNT": ["find", "search", "look for", "check for", "detect", "identify"],
        "NETWORK_SCAN": ["check", "find", "list", "show", "get", "view"],
        "USER_AUDIT": ["check", "list", "show", "get", "find", "verify"],
        "PERSISTENCE_CHECK": ["check", "find", "list", "show", "detect", "verify"],
        "SYS_INFO": ["get", "show", "list", "check", "retrieve", "gather"]
    }

    # Negative keywords that reduce intent confidence
    NEGATION_WORDS = ["not", "no", "don't", "never", "disable", "remove", "uninstall"]

    def detect_intent(self, text: str) -> str:
        """
        Detects the intent of the user input.
        Returns one of the INTENT keys or 'UNKNOWN'.
        """
        text_lower = text.lower()
        scores: Dict[str, float] = {}
        
        # Calculate base scores
        for intent, keywords in self.INTENTS.items():
            score = 0
            for keyword in keywords:
                if keyword in text_lower:
                    score += 1
                    
                    # Check for context boost
                    for boost_word in self.CONTEXT_BOOST.get(intent, []):
                        if boost_word in text_lower:
                            score += 0.5
                            
            if score > 0:
                scores[intent] = score
        
        # Apply negation penalty
        has_negation = any(neg in text_lower for neg in self.NEGATION_WORDS)
        if has_negation and scores:
            # If there's negation, reduce scores but don't zero them
            for intent in scores:
                scores[intent] *= 0.5
        
        if not scores:
            return "UNKNOWN"
            
        # Return intent with highest score
        best_intent = max(scores, key=scores.get)
        return best_intent

    def detect_intent_with_confidence(self, text: str) -> Dict[str, any]:
        """
        Detects intent with confidence score.
        Returns dict with intent, confidence, and all scores.
        """
        text_lower = text.lower()
        scores: Dict[str, float] = {}
        
        # Calculate scores with weighting
        for intent, keywords in self.INTENTS.items():
            score = 0
            matched_keywords = []
            
            for keyword in keywords:
                # Use word boundary matching for better accuracy
                pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(pattern, text_lower):
                    score += 1.0
                    matched_keywords.append(keyword)
                    
                    # Context boost
                    for boost_word in self.CONTEXT_BOOST.get(intent, []):
                        if boost_word in text_lower:
                            score += 0.3
            
            if score > 0:
                scores[intent] = score
        
        # Apply negation penalty
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
        
        # Normalize confidence
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
