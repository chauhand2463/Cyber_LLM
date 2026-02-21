from typing import List, Dict, Any
import re

class RiskScoringEngine:
    """
    Deterministic risk scoring based on weighted indicators.
    Enhanced with more comprehensive threat intelligence.
    """
    
    # High confidence threat indicators
    WEIGHTS = {
        # Critical - immediate attention required
        "mimikatz": 100,
        "password dump": 90,
        "credential theft": 90,
        "golden ticket": 90,
        "kerberoasting": 85,
        "pass-the-hash": 85,
        "lsass": 80,
        "sam database": 80,
        "lsass.exe": 80,
        
        # High risk
        "antigravity.exe": 60,
        "suspicious": 40,
        "malicious": 60,
        "unknown binary": 40,
        "root": 50,
        "password": 45,
        "reverse shell": 70,
        "bind shell": 70,
        "meterpreter": 75,
        "cobalt strike": 75,
        
        # Medium risk
        "high memory": 25,
        "multiple instances": 25,
        "execution of system commands": 25,
        "powershell encoded": 35,
        "base64 encoded": 30,
        "cmd.exe": 15,
        "powershell.exe": 15,
        "reg.exe": 15,
        
        # Low risk but suspicious
        "temp": 10,
        "appdata": 10,
        "startup": 20,
        "scheduled task": 20,
        "wmi": 20,
        "eventvwr": 25,
        "mshta": 30,
        "rundll32": 25,
        "regsvr32": 25,
        "certutil": 30,
        "bitsadmin": 30,
        
        # Network indicators
        "listening": 10,
        "established": 10,
        "external ip": 30,
        " suspicious port": 25,
        
        # File indicators
        ".vbs": 25,
        ".bat": 20,
        ".ps1": 15,
        ".exe": 10,
        ".dll": 10,
        "encodedcommand": 35,
        "downloadstring": 30,
        "invoke-expression": 30,
        "webclient": 25,
    }
    
    # Known malicious process patterns
    MALICIOUS_PROCESS_PATTERNS = [
        r"mimikatz",
        r"pwdump",
        r"procdump",
        r"lsass",
        r"credential",
        r"kekeo",
        r"rubeus",
        r"kerberoast",
        r"bloodhound",
        r"sharphound",
        r"meterssh",
        r"nc\.exe",
        r"netcat",
        r"psexec",
        r"wmiexec",
        r"smbexec",
        r"Responder",
        r"Inveigh",
        r"InveighZero",
        r"Responder",
        r"ntdsutil",
        r"dsquery",
        r"AdFind",
        r"PowerView",
        r"PowerUp",
        r"PrivescCheck",
        r"Seatbelt",
        r"SharpUp",
        r"WinPEAS",
        r"LinPEAS",
        r"m Covenant",
        r"Covenant",
        r"sliver",
        r"koadic",
        r"pupy",
        r"silenttrinity",
        r"merlin",
        r"goto",
    ]
    
    # Known benign processes (to filter false positives)
    BENIGN_PROCESSES = [
        r"System Idle Process",
        r"System",
        r"Registry",
        r"smss\.exe",
        r"csrss\.exe",
        r"wininit\.exe",
        r"services\.exe",
        r"lsass\.exe",  # May be legitimate
        r"svchost\.exe",
        r"fontdrvhost\.exe",
        r"dwm\.exe",
        r"explorer\.exe",
        r"taskhostw\.exe",
        r"sihost\.exe",
        r"RuntimeBroker\.exe",
        r"SearchIndexer\.exe",
        r"SecurityHealthService\.exe",
        r"MsMpEng\.exe",  # Windows Defender
        r"NisSrv\.exe",   # Windows Defender
    ]

    @staticmethod
    def calculate_score(indicators: List[str]) -> Dict:
        """
        Calculate risk score based on a list of indicator strings.
        """
        score = 0
        matches = []
        
        normalized_indicators = [i.lower() for i in indicators]
        combined_text = " ".join(normalized_indicators)
        
        # Check exact matches
        for key, weight in RiskScoringEngine.WEIGHTS.items():
            if key in combined_text:
                score += weight
                if key not in matches:
                    matches.append(key)
        
        # Check regex patterns for known malicious processes
        for pattern in RiskScoringEngine.MALICIOUS_PROCESS_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                score += 50
                if pattern not in matches:
                    matches.append(pattern)
        
        # Risk Level Logic
        risk_level = "BENIGN"
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        elif score > 0:
            risk_level = "LOW"

        return {
            "risk_score": min(score, 100),  # Cap at 100
            "risk_level": risk_level,
            "matched_factors": matches
        }

    @staticmethod
    def calculate_system_risk(sys_data: Dict) -> Dict:
        """
        Calculate risk based on system configuration.
        """
        score = 30  # Baseline
        factors = []

        # Security features that reduce risk
        if sys_data.get("vbs_enabled"):
            score -= 10
            factors.append("VBS Enabled (-10)")
        
        if "Windows 11" in sys_data.get("os_name", ""):
            score -= 5
            factors.append("Windows 11 (-5)")
            
        if sys_data.get("secure_boot"):
            score -= 10
            factors.append("Secure Boot (-10)")
        
        # Risk increases
        if not sys_data.get("hotfixes") or sys_data.get("hotfixes") == "None":
            score += 25
            factors.append("No Hotfixes Found (+25)")
        
        if sys_data.get("remote_desktop_enabled"):
            score += 20
            factors.append("RDP Enabled (+20)")
            
        if not sys_data.get("firewall_enabled"):
            score += 30
            factors.append("Firewall Disabled (+30)")

        # Ensure bounds 0-100
        score = max(0, min(100, score))
        
        risk_level = "LOW"
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "matched_factors": factors
        }

    @staticmethod
    def calculate_network_risk(connections: List[Dict]) -> Dict:
        score = 0
        factors = []
        risky_ports = {
            "21": "FTP",
            "23": "Telnet", 
            "25": "SMTP",
            "135": "RPC",
            "139": "NetBIOS",
            "445": "SMB",
            "3389": "RDP",
            "4444": "Meterpreter",
            "5555": "Android ADB",
            "6667": "IRC",
            "31337": "Back Orifice"
        }
        
        for conn in connections:
            state = conn.get('state', '').upper()
            port = str(conn.get('port', ''))
            
            if state in ['LISTENING', 'ESTABLISHED', 'LISTEN']:
                # Check known risky ports
                if port in risky_ports:
                    score += 25
                    factors.append(f"Risky Port {port} ({risky_ports[port]}) - {state}")
                
                # Check for high ports (often used by malware)
                try:
                    port_num = int(port)
                    if port_num > 10000 and state == 'LISTENING':
                        score += 15
                        factors.append(f"High port listening: {port}")
                except:
                    pass
                
                # Check for external connections
                if conn.get('external', False):
                    score += 20
                    factors.append(f"External connection to {conn.get('address', 'unknown')}")
        
        # Risk Logic
        score = min(100, score)
        
        risk_level = "LOW"
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
            
        return {
            "risk_score": score, 
            "risk_level": risk_level, 
            "matched_factors": list(set(factors))
        }

    @staticmethod
    def calculate_user_risk(admins: List[str]) -> Dict:
        score = 0
        factors = []
        
        # Known suspicious account patterns
        suspicious = [
            "guest", "defaultaccount", "test", "administrator", "admin",
            "support", "backup", "root", "svc_", "service_", "sql_",
            "postgres", "mysql", "oracle", "web", "ftp", "ssh"
        ]
        
        # Privileged groups
        privileged_groups = ["administrators", "domain admins", "enterprise admins", "schema admins"]
        
        for admin in admins:
            admin_lower = admin.lower()
            
            # Check for suspicious accounts
            for sus in suspicious:
                if sus in admin_lower:
                    score += 40
                    factors.append(f"Suspicious Account: {admin}")
                    break
            
            # Check for privileged groups
            for priv in privileged_groups:
                if priv in admin_lower:
                    score += 20
                    factors.append(f"Privileged Group: {admin}")
        
        # Number of admins factor
        if len(admins) > 5:
            score += 25
            factors.append(f"High number of admins ({len(admins)})")
        elif len(admins) > 3:
            score += 15
            factors.append(f"Moderate number of admins ({len(admins)})")
            
        score = min(100, score)
        
        risk_level = "LOW"
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
            
        return {
            "risk_score": score, 
            "risk_level": risk_level, 
            "matched_factors": factors
        }

    @staticmethod
    def calculate_persistence_risk(reg_values: List[Dict]) -> Dict:
        score = 0
        factors = []
        
        # High-risk persistence keywords
        high_risk_keywords = [
            "powershell", "cmd.exe", "cmd /c", "wscript", "cscript",
            "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
            "powershell -", "powershell.exe", "vbscript"
        ]
        
        # Medium-risk keywords
        medium_risk_keywords = [
            "temp", "appdata", "local\\temp", "downloads",
            "schedule", "task", "schtasks", "at job"
        ]
        
        # Path-based keywords indicating suspicious locations
        suspicious_paths = [
            "\\temp\\", "\\tmp\\", "\\downloads\\",
            "\\appdata\\local\\temp", "\\desktop\\"
        ]
        
        for val in reg_values:
            data = val.get('data', '')
            name = val.get('name', '')
            data_lower = data.lower()
            name_lower = name.lower()
            
            # Check high-risk keywords
            for key in high_risk_keywords:
                if key in data_lower:
                    score += 40
                    factors.append(f"High-Risk Persistence: {name} ({key})")
                    break
            
            # Check medium-risk keywords
            if score < 40:
                for key in medium_risk_keywords:
                    if key in data_lower:
                        score += 20
                        factors.append(f"Medium-Risk Persistence: {name}")
                        break
            
            # Check suspicious paths
            for path in suspicious_paths:
                if path in data_lower:
                    score += 15
                    factors.append(f"Suspicious Path: {name}")
                    break
        
        score = min(100, score)
        
        risk_level = "LOW"
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
            
        return {
            "risk_score": score, 
            "risk_level": risk_level, 
            "matched_factors": factors
        }
