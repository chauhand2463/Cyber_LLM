import platform
import subprocess
import psutil
import os
import json
from typing import Dict, List, Optional, Any


class Scanner:
    def __init__(self):
        self.os_name = platform.system()
        self.is_admin = self._check_admin()
    
    def _check_admin(self) -> bool:
        try:
            if self.os_name == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                import os
                return os.geteuid() == 0
        except:
            return False
    
    def get_command(self, task: str) -> str:
        commands = {
            "network": {
                "Windows": "netstat -ano",
                "Linux": "ss -tulpn",
                "Darwin": "netstat -an"
            },
            "network_extended": {
                "Windows": "netstat -ano | findstr ESTABLISHED",
                "Linux": "ss -tulpn | grep ESTAB",
                "Darwin": "netstat -an | grep ESTABLISHED"
            },
            "processes": {
                "Windows": "tasklist /v",
                "Linux": "ps aux",
                "Darwin": "ps aux"
            },
            "users": {
                "Windows": "net user",
                "Linux": "cat /etc/passwd",
                "Darwin": "dscl . list /Users"
            },
            "admins": {
                "Windows": "net localgroup administrators",
                "Linux": "getent group sudo wheel admin",
                "Darwin": "dscl . -read /Groups/admin"
            },
            "services": {
                "Windows": "sc query",
                "Linux": "systemctl list-units --type=service --state=running",
                "Darwin": "launchctl list"
            },
            "systeminfo": {
                "Windows": "systeminfo",
                "Linux": "uname -a && cat /etc/os-release",
                "Darwin": "system_profiler"
            },
            "ipconfig": {
                "Windows": "ipconfig /all",
                "Linux": "ip addr && ip route",
                "Darwin": "ifconfig -a"
            },
            "arp": {
                "Windows": "arp -a",
                "Linux": "arp -a",
                "Darwin": "arp -a"
            },
            "firewall": {
                "Windows": "netsh advfirewall show allprofiles",
                "Linux": "iptables -L -n",
                "Darwin": "pfctl -s all"
            },
            "routes": {
                "Windows": "route print",
                "Linux": "ip route",
                "Darwin": "netstat -rn"
            },
            "dns": {
                "Windows": "ipconfig /displaydns",
                "Linux": "cat /etc/resolv.conf",
                "Darwin": "scutil --dns"
            },
            "tasks": {
                "Windows": "schtasks /query /fo LIST /v",
                "Linux": "crontab -l",
                "Darwin": "crontab -l"
            },
            "startup": {
                "Windows": 'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
                "Linux": "ls -la /etc/init.d/ /etc/rc.local",
                "Darwin": "launchctl list | grep -i auto"
            },
            "drivers": {
                "Windows": "driverquery /v",
                "Linux": "lsmod",
                "Darwin": "kextstat"
            },
            "hostname": {
                "Windows": "hostname",
                "Linux": "hostname",
                "Darwin": "hostname"
            },
            "whoami": {
                "Windows": "whoami",
                "Linux": "id",
                "Darwin": "id"
            },
        }
        return commands.get(task, {}).get(self.os_name, f"echo 'unsupported: {task}'")
    
    def run_command(self, command: str, timeout: int = 30) -> str:
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            return result.stdout if result.stdout else result.stderr
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def run_safe(self, task: str, timeout: int = 30) -> Dict[str, Any]:
        cmd = self.get_command(task)
        output = self.run_command(cmd, timeout)
        return {
            "task": task,
            "command": cmd,
            "output": output[:10000],
            "os": self.os_name,
            "admin": self.is_admin
        }
    
    def get_processes(self) -> List[Dict]:
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            return [{"error": str(e)}]
        return processes
    
    def get_network_connections(self) -> List[Dict]:
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    connections.append({
                        "pid": conn.pid,
                        "local_addr": conn.laddr.ip if conn.laddr else None,
                        "local_port": conn.laddr.port if conn.laddr else None,
                        "remote_addr": conn.raddr.ip if conn.raddr else None,
                        "remote_port": conn.raddr.port if conn.raddr else None,
                        "status": conn.status,
                        "family": "IPv4" if conn.family == 2 else "IPv6"
                    })
                except:
                    pass
        except Exception as e:
            return [{"error": str(e)}]
        return connections
    
    def quick_scan(self) -> Dict[str, Any]:
        return {
            "hostname": self.run_safe("hostname"),
            "whoami": self.run_safe("whoami"),
            "ipconfig": self.run_safe("ipconfig"),
            "network": self.run_safe("network"),
            "processes": self.run_safe("processes"),
            "users": self.run_safe("users"),
        }
    
    def full_scan(self) -> Dict[str, Any]:
        return {
            "systeminfo": self.run_safe("systeminfo"),
            "ipconfig": self.run_safe("ipconfig"),
            "network": self.run_safe("network"),
            "network_extended": self.run_safe("network_extended"),
            "processes": self.run_safe("processes"),
            "services": self.run_safe("services"),
            "users": self.run_safe("users"),
            "admins": self.run_safe("admins"),
            "startup": self.run_safe("startup"),
            "tasks": self.run_safe("tasks"),
            "firewall": self.run_safe("firewall"),
            "routes": self.run_safe("routes"),
            "arp": self.run_safe("arp"),
            "drivers": self.run_safe("drivers"),
        }
