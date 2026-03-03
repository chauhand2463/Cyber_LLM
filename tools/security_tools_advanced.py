"""
CyberLLM - Advanced Security Tools
Comprehensive security operations for all cybersecurity domains
"""

import subprocess
import platform
import re
import json
import requests
from typing import Dict, List, Optional
from datetime import datetime

OS_TYPE = platform.system()

def run_command(cmd: str, timeout: int = 30) -> str:
    """Execute local command and return output."""
    try:
        if OS_TYPE == "Windows":
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
        else:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {str(e)}"

# ============================================================
# RISK ASSESSMENT TOOLS
# ============================================================

def perform_risk_assessment() -> Dict:
    """Perform comprehensive risk assessment."""
    results = {
        "assessment_type": "Risk Assessment",
        "timestamp": datetime.now().isoformat(),
        "assets": [],
        "threats": [],
        "vulnerabilities": [],
        "risk_matrix": {},
        "recommendations": []
    }
    
    # Asset Discovery
    if OS_TYPE == "Windows":
        assets_cmd = "systeminfo | findstr /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Domain\""
        results["assets"].append({"type": "System", "data": run_command(assets_cmd)[:500]})
        
        # User assets
        users = run_command("net user")
        results["assets"].append({"type": "User Accounts", "count": len(users.splitlines())})
        
        # Network assets
        ipconfig = run_command("ipconfig")
        results["assets"].append({"type": "Network Interfaces", "data": ipconfig[:300]})
        
        # Processes
        procs = run_command("tasklist")
        results["assets"].append({"type": "Running Processes", "count": len(procs.splitlines())})
    else:
        results["assets"].append({"type": "System", "data": run_command("uname -a")})
        results["assets"].append({"type": "Users", "data": run_command("whoami")})
    
    # Common Threats
    results["threats"] = [
        {"id": "T1", "name": "Unauthorized Access", "likelihood": "Medium", "impact": "High"},
        {"id": "T2", "name": "Malware Infection", "likelihood": "High", "impact": "Medium"},
        {"id": "T3", "name": "Data Breach", "likelihood": "Low", "impact": "Critical"},
        {"id": "T4", "name": "Insider Threat", "likelihood": "Medium", "impact": "High"},
        {"id": "T5", "name": "Ransomware", "likelihood": "Medium", "impact": "Critical"},
    ]
    
    # Vulnerabilities found
    results["vulnerabilities"] = check_common_vulnerabilities()
    
    # Risk Matrix
    results["risk_matrix"] = {
        "critical": len([v for v in results["vulnerabilities"] if v.get("severity") == "Critical"]),
        "high": len([v for v in results["vulnerabilities"] if v.get("severity") == "High"]),
        "medium": len([v for v in results["vulnerabilities"] if v.get("severity") == "Medium"]),
        "low": len([v for v in results["vulnerabilities"] if v.get("severity") == "Low"])
    }
    
    # Recommendations
    results["recommendations"] = [
        "Implement multi-factor authentication (MFA)",
        "Enable disk encryption",
        "Regular patch management",
        "Network segmentation",
        "Backup strategy verification",
        "Security awareness training"
    ]
    
    return results

def check_common_vulnerabilities() -> List[Dict]:
    """Check for common vulnerabilities."""
    vulns = []
    
    if OS_TYPE == "Windows":
        # Check admin accounts
        admins = run_command("net localgroup administrators")
        if "Administrator" in admins:
            admin_list = [line.strip() for line in admins.split("\n") if line.strip()]
            vulns.append({
                "id": "VULN-001",
                "name": "Administrator Account Review",
                "severity": "Medium",
                "description": f"Admin group members: {admin_list[:5]}"
            })
        
        # Check firewall
        fw = run_command("netsh advfirewall show allprofiles state")
        if "ON" not in fw:
            vulns.append({
                "id": "VULN-002",
                "name": "Firewall Disabled",
                "severity": "Critical",
                "description": "Windows Firewall is not enabled"
            })
        
        # Check guest account
        guest = run_command("net user guest")
        if "Account active" in guest and "Yes" in guest:
            vulns.append({
                "id": "VULN-003",
                "name": "Guest Account Enabled",
                "severity": "Medium",
                "description": "Guest account is enabled"
            })
        
        # Check UAC
        uac = run_command("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA")
        if "0x0" in uac:
            vulns.append({
                "id": "VULN-004",
                "name": "UAC Disabled",
                "severity": "High",
                "description": "User Account Control is disabled"
            })
        
        # Check remote desktop
        rdp = run_command("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections")
        if "0x0" in rdp:
            vulns.append({
                "id": "VULN-005",
                "name": "Remote Desktop Enabled",
                "severity": "Medium",
                "description": "RDP is enabled"
            })
    
    return vulns

# ============================================================
# VULNERABILITY MANAGEMENT
# ============================================================

def vulnerability_scan() -> Dict:
    """Perform vulnerability scan."""
    results = {
        "scan_type": "Vulnerability Assessment",
        "timestamp": datetime.now().isoformat(),
        "os": OS_TYPE,
        "findings": [],
        "cvss_scores": [],
        "remediation": []
    }
    
    findings = check_common_vulnerabilities()
    results["findings"] = findings
    
    # Calculate overall risk
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        sev = finding.get("severity", "Low")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    results["severity_summary"] = severity_counts
    
    # CVSS scores
    cvss_mapping = {"Critical": 9.0, "High": 7.0, "Medium": 4.0, "Low": 1.0}
    for finding in findings:
        results["cvss_scores"].append({
            "cve": finding.get("id", "N/A"),
            "score": cvss_mapping.get(finding.get("severity", "Low"), 5.0),
            "severity": finding.get("severity", "Unknown")
        })
    
    # Remediation
    for finding in findings:
        name = finding.get("name", "")
        if "Firewall" in name:
            results["remediation"].append("Enable Windows Firewall: netsh advfirewall set allprofiles state on")
        elif "UAC" in name:
            results["remediation"].append("Enable UAC via Control Panel")
        elif "Guest" in name:
            results["remediation"].append("Disable Guest account: net user guest /active:no")
        elif "RDP" in name:
            results["remediation"].append("Disable RDP if not required: reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f")
    
    return results

# ============================================================
# SECURITY HARDENING
# ============================================================

def security_hardening() -> Dict:
    """Perform security hardening assessment."""
    results = {
        "assessment": "Security Hardening",
        "timestamp": datetime.now().isoformat(),
        "checks": [],
        "passed": [],
        "failed": [],
        "recommendations": []
    }
    
    checks = []
    
    if OS_TYPE == "Windows":
        # Firewall check
        fw = run_command("netsh advfirewall show allprofiles state")
        if "ON" in fw:
            results["passed"].append("Firewall Enabled")
        else:
            results["failed"].append("Firewall Disabled")
            results["recommendations"].append("Enable Firewall: netsh advfirewall set allprofiles state on")
        
        # UAC check
        uac = run_command("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA")
        if "0x1" in uac:
            results["passed"].append("UAC Enabled")
        else:
            results["failed"].append("UAC Disabled")
            results["recommendations"].append("Enable UAC")
        
        # Windows Defender
        def_status = run_command("powershell Get-MpComputerStatus | Select -ExpandProperty AntivirusEnabled")
        if "True" in def_status:
            results["passed"].append("Antivirus Enabled")
        else:
            results["failed"].append("Antivirus Disabled")
            results["recommendations"].append("Enable Windows Defender")
        
        # Guest account
        guest = run_command("net user guest")
        if "Account active               No" in guest:
            results["passed"].append("Guest Account Disabled")
        else:
            results["failed"].append("Guest Account Enabled")
            results["recommendations"].append("Disable Guest account")
        
        # RDP
        rdp = run_command("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections")
        if "0x1" in rdp:
            results["passed"].append("RDP Disabled")
        else:
            results["failed"].append("RDP Enabled")
            results["recommendations"].append("Disable RDP if not needed")
        
        # AutoUpdate
        au = run_command("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\" /v AUOptions")
        if not "Error" in au:
            results["passed"].append("Windows Update Configured")
        
        # SMBv1
        smb = run_command("Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select -ExpandProperty State")
        if "Disabled" in smb or "Disable" in smb:
            results["passed"].append("SMBv1 Disabled")
        else:
            results["failed"].append("SMBv1 Enabled")
            results["recommendations"].append("Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
        
        # Remote registry
        rr = run_command("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths")
        if "Error" in rr:
            results["passed"].append("Remote Registry Secured")
        
        # Admin shares
        shares = run_command("net share")
        if "$" not in shares:
            results["passed"].append("Admin Shares Checked")
    else:
        # Linux hardening checks
        ssh = run_command("grep \"^PermitRootLogin\" /etc/ssh/sshd_config")
        if "no" in ssh:
            results["passed"].append("Root SSH Disabled")
        else:
            results["failed"].append("Root SSH May Be Enabled")
        
        fw = run_command("ufw status")
        if "Status: active" in fw:
            results["passed"].append("UFW Firewall Enabled")
        
        results["recommendations"].append("Review sudo access: sudoers file")
        results["recommendations"].append("Disable unused services")
        results["recommendations"].append("Enable automatic security updates")
    
    return results

# ============================================================
# IDENTITY & ACCESS MANAGEMENT
# ============================================================

def iam_audit() -> Dict:
    """Identity and Access Management audit."""
    results = {
        "assessment": "IAM Audit",
        "timestamp": datetime.now().isoformat(),
        "users": [],
        "groups": [],
        "privileges": [],
        "risks": []
    }
    
    if OS_TYPE == "Windows":
        # List all users
        users = run_command("net user")
        user_list = [line.strip() for line in users.split("\n") if line.strip() and "---" not in line]
        results["users"] = user_list
        
        # Admin group
        admins = run_command("net localgroup administrators")
        admin_list = [line.strip() for line in admins.split("\n") if line.strip() and "---" not in line]
        results["privileges"].append({"group": "Administrators", "members": admin_list})
        
        # Check for risky configurations
        for user in user_list:
            if user.lower() == "guest":
                results["risks"].append({"user": "Guest", "risk": "Guest account may be enabled", "severity": "Medium"})
        
        # Domain info
        domain = run_command("wmic computersystem get domain")
        results["domain"] = domain.strip()
        
        # Last login info
        for user in user_list[:5]:
            info = run_command(f"net user {user}")
            if "Last logon" in info:
                results["users"].append({"name": user, "info": "Has account"})
    else:
        results["users"] = run_command("cat /etc/passwd").split("\n")[:10]
        results["groups"] = run_command("groups").split("\n")
    
    return results

# ============================================================
# PATCH MANAGEMENT
# ============================================================

def patch_management() -> Dict:
    """Check patch management status."""
    results = {
        "assessment": "Patch Management",
        "timestamp": datetime.now().isoformat(),
        "os": OS_TYPE,
        "patches": [],
        "missing_critical": 0,
        "recommendations": []
    }
    
    if OS_TYPE == "Windows":
        # Check hotfixes
        hotfixes = run_command("wmic qfe list")
        results["patches"] = hotfixes.split("\n")[:20]
        
        # Windows Update status
        update = run_command("powershell (New-Object -ComObject Microsoft.Update.AutoUpdate).Results")
        results["update_status"] = "Checked"
        
        # Check for missing updates
        results["recommendations"].append("Run Windows Update to install latest patches")
        results["recommendations"].append("Enable automatic updates")
        results["recommendations"].append("Review pending reboots")
    else:
        # Linux patch check
        if "Debian" in run_command("cat /etc/os-release") or "Ubuntu" in run_command("cat /etc/os-release"):
            results["patches"] = run_command("apt list --upgradable").split("\n")[:10]
        elif "RHEL" in run_command("cat /etc/os-release") or "CentOS" in run_command("cat /etc/os-release"):
            results["patches"] = run_command("yum list updates").split("\n")[:10]
        
        results["recommendations"].append("Run: sudo apt update && sudo apt upgrade (Debian/Ubuntu)")
        results["recommendations"].append("Run: sudo yum update (RHEL/CentOS)")
    
    return results

# ============================================================
# INCIDENT RESPONSE
# ============================================================

def incident_response() -> Dict:
    """Gather incident response artifacts."""
    results = {
        "assessment": "Incident Response Artifacts",
        "timestamp": datetime.now().isoformat(),
        "artifacts": {},
        "timeline": [],
        "recommendations": []
    }
    
    if OS_TYPE == "Windows":
        # Recent processes
        results["artifacts"]["processes"] = run_command("tasklist /v").split("\n")[:30]
        
        # Recent network connections
        results["artifacts"]["network"] = run_command("netstat -ano").split("\n")[:30]
        
        # Recent logs
        results["artifacts"]["security_logs"] = run_command("wevtutil qe Security /c:10 /rd:true").split("\n")[:20]
        
        # Startup items
        results["artifacts"]["startup"] = run_command("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run").split("\n")[:15]
        
        # Services
        results["artifacts"]["services"] = run_command("sc query state=all").split("\n")[:30]
        
        # Recent files
        results["artifacts"]["recent_files"] = run_command("dir %APPDATA%\\Microsoft\\Windows\\Recent /a /tc").split("\n")[:20]
    else:
        results["artifacts"]["processes"] = run_command("ps aux").split("\n")[:30]
        results["artifacts"]["network"] = run_command("netstat -tuln").split("\n")[:30]
        results["artifacts"]["auth_logs"] = run_command("tail -50 /var/log/auth.log").split("\n")
    
    results["recommendations"] = [
        "Preserve all logs and artifacts",
        "Document timeline of events",
        "Isolate affected systems if necessary",
        "Contact security team",
        "Review access logs"
    ]
    
    return results

# ============================================================
# DATA PROTECTION
# ============================================================

def data_protection() -> Dict:
    """Check data protection status."""
    results = {
        "assessment": "Data Protection",
        "timestamp": datetime.now().isoformat(),
        "encryption": {},
        "backups": [],
        "dlp": {},
        "recommendations": []
    }
    
    if OS_TYPE == "Windows":
        # BitLocker status
        bitlocker = run_command("manage-bde -status")
        results["encryption"]["bitlocker"] = bitlocker[:500] if bitlocker else "Not configured"
        
        # Check for sensitive files
        results["dlp"]["sensitive_files_check"] = "Manual review required"
        
        results["recommendations"].append("Enable BitLocker for all drives")
        results["recommendations"].append("Implement backup solution")
        results["recommendations"].append("Configure Windows Data Loss Prevention")
    else:
        results["encryption"]["luks"] = "Check: cryptsetup luksDump /dev/sdaX"
        results["encryption"]["files"] = "Use: gpg for file encryption"
        
        results["recommendations"].append("Enable LUKS for disk encryption")
        results["recommendations"].append("Configure automated backups")
        results["recommendations"].append("Use GPG for sensitive files")
    
    return results

# ============================================================
# COMPLIANCE CHECK
# ============================================================

def compliance_check() -> Dict:
    """Perform compliance check."""
    results = {
        "assessment": "Compliance Status",
        "timestamp": datetime.now().isoformat(),
        "frameworks": [],
        "controls": [],
        "gaps": [],
        "recommendations": []
    }
    
    # NIST CSF controls
    results["frameworks"] = ["NIST CSF", "CIS", "ISO 27001"]
    
    # Control checks
    controls = security_hardening()
    
    passed = len(controls.get("passed", []))
    failed = len(controls.get("failed", []))
    
    results["controls"] = {
        "implemented": passed,
        "missing": failed,
        "compliance_percentage": f"{(passed/(passed+failed)*100):.1f}%" if (passed+failed) > 0 else "N/A"
    }
    
    # Gaps
    results["gaps"] = controls.get("failed", [])
    
    # Recommendations
    results["recommendations"] = [
        "Complete missing controls",
        "Document security policies",
        "Conduct regular audits",
        "Implement continuous monitoring"
    ]
    
    return results

# ============================================================
# THIRD PARTY RISK
# ============================================================

def third_party_risk() -> Dict:
    """Third party risk assessment."""
    results = {
        "assessment": "Third Party Risk",
        "timestamp": datetime.now().isoformat(),
        "external_connections": [],
        "network_shares": [],
        "remote_access": [],
        "recommendations": []
    }
    
    if OS_TYPE == "Windows":
        # Network connections
        netstat = run_command("netstat -ano")
        results["external_connections"] = [line for line in netstat.split("\n") if "ESTABLISHED" in line][:20]
        
        # Shares
        shares = run_command("net share")
        results["network_shares"] = [s for s in shares.split("\n") if "Share" in s or "$" in s]
        
        # Remote access
        rdp = run_command("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections")
        vpn = run_command("netsh interface show interface")
        
        results["remote_access"] = {
            "rdp": "Enabled" if "0x0" in rdp else "Disabled",
            "vpn": "Check VPN configuration"
        }
        
        results["recommendations"] = [
            "Review all network shares",
            "Limit remote access",
            "Implement vendor risk management",
            "Review third-party access logs"
        ]
    else:
        results["recommendations"] = [
            "Check SSH keys",
            "Review sudo access",
            "Audit cron jobs"
        ]
    
    return results

# ============================================================
# CLOUD SECURITY
# ============================================================

def cloud_security_check() -> Dict:
    """Cloud security assessment (simulated)."""
    results = {
        "assessment": "Cloud Security",
        "timestamp": datetime.now().isoformat(),
        "provider": "Unknown",
        "checks": [],
        "recommendations": []
    }
    
    # Detect cloud provider
    if OS_TYPE == "Windows":
        cloud = run_command("wmic /namespace:\\\\root\\cimv2 path Win32_ComputerSystem get Manufacturer")
        results["provider"] = cloud.strip()
    else:
        results["provider"] = run_command("cloud-id").strip() if run_command("which cloud-id") else "Unknown"
    
    results["checks"] = [
        {"check": "IAM Policies", "status": "Manual review required"},
        {"check": "S3/Bucket Permissions", "status": "Manual review required"},
        {"check": "Security Groups", "status": "Manual review required"},
        {"check": "CloudTrail Logging", "status": "Manual review required"}
    ]
    
    results["recommendations"] = [
        "Review IAM roles and policies",
        "Enable cloudtrail/cloudwatch logging",
        "Configure security groups with least privilege",
        "Use VPC for network isolation",
        "Enable encryption at rest"
    ]
    
    return results

# ============================================================
# WEB APPLICATION SECURITY
# ============================================================

def web_security_scan(url: str) -> Dict:
    """Web application security scan."""
    results = {
        "assessment": "Web Security Scan",
        "timestamp": datetime.now().isoformat(),
        "target": url,
        "findings": [],
        "headers": {},
        "recommendations": []
    }
    
    try:
        resp = requests.get(url, timeout=10, verify=False)
        
        # Check security headers
        headers = resp.headers
        results["headers"] = {
            "server": headers.get("Server", "Unknown"),
            "content_security_policy": headers.get("Content-Security-Policy", "Missing"),
            "strict_transport_security": headers.get("Strict-Transport-Security", "Missing"),
            "x_frame_options": headers.get("X-Frame-Options", "Missing"),
            "x_content_type_options": headers.get("X-Content-Type-Options", "Missing")
        }
        
        # Check for missing headers
        if "Missing" in results["headers"]["strict_transport_security"]:
            results["findings"].append({"severity": "High", "issue": "HSTS not configured"})
        if "Missing" in results["headers"]["x_frame_options"]:
            results["findings"].append({"severity": "Medium", "issue": "Clickjacking protection missing"})
        if "Missing" in results["headers"]["x_content_type_options"]:
            results["findings"].append({"severity": "Low", "issue": "MIME sniffing protection missing"})
            
        results["recommendations"] = [
            "Implement HSTS (HTTP Strict Transport Security)",
            "Add X-Frame-Options header",
            "Configure Content-Security-Policy",
            "Enable X-Content-Type-Options",
            "Regular penetration testing"
        ]
        
    except Exception as e:
        results["error"] = str(e)

    return results


# ============================================================
# CROSS-PLATFORM COMMANDS
# ============================================================

def get_os_info() -> Dict:
    """Get comprehensive OS information."""
    results = {
        "os": OS_TYPE,
        "hostname": "",
        "ip": "",
        "users": [],
        "processes": 0,
        "uptime": ""
    }
    
    if OS_TYPE == "Windows":
        results["hostname"] = run_command("hostname").strip()
        results["ip"] = run_command("ipconfig | findstr /i \"IPv4\"").split(":")[-1].strip()
        results["uptime"] = run_command("systeminfo | findstr /i \"Boot\"").split(":")[-1].strip()
    else:
        results["hostname"] = run_command("hostname").strip()
        results["ip"] = run_command("hostname -I").strip()
        results["uptime"] = run_command("uptime").strip()
    
    return results
