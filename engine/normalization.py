import re
from typing import List, Dict

def parse_tasklist(output: str) -> List[Dict]:
    """
    Parses 'tasklist' output into structured JSON.
    """
    processes = []
    # Skip header lines
    lines = output.strip().splitlines()
    for line in lines:
        if line.startswith("Image Name") or line.startswith("==") or not line.strip():
            continue
            
        # Regex to handle tasklist output (FixedWidth columns usually)
        # Image Name                     PID Session Name        Session#    Mem Usage
        # System Idle Process              0 Services                   0          8 K
        
        # Simple split by whitespace might fail if spaces in Image Name.
        # But for 'tasklist', the Image Name is usually the first column.
        # Let's use a robust regex or fixed width slicing if possible.
        # Regex: (Image Name) (PID) (Session Name) (Session#) (Mem Usage)
        
        # Try finding the PID (digits) and split around it.
        match = re.search(r'^(.*?)\s+(\d+)\s+(.*?)\s+(\d+)\s+([\d,.]+\s+[K|M|G]?)$', line)
        if match:
            processes.append({
                "name": match.group(1).strip(),
                "pid": int(match.group(2)),
                "session_name": match.group(3).strip(),
                "session_num": int(match.group(4)),
                "memory": match.group(5).strip().replace(",", "")
            })
        else:
            # Fallback for CSV format if user used /FO CSV (we didn't, but good to have)
            pass
            
    return processes

def parse_dir_output(output: str) -> List[Dict]:
    """
    Parses 'dir' output into structured JSON.
    """
    files = []
    lines = output.strip().splitlines()
    for line in lines:
        # 01/24/2026  03:50 PM                66 suspicious_log.txt
        match = re.search(r'^(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}\s+[AP]M)\s+(<DIR>|[\d,]+)\s+(.*)$', line)
        if match:
            date = match.group(1)
            time = match.group(2)
            size_type = match.group(3)
            name = match.group(4)
            
            if name == "." or name == "..":
                continue
                
            files.append({
                "name": name,
                "date": date,
                "time": time,
                "type": "DIR" if size_type == "<DIR>" else "FILE",
                "size": size_type if size_type != "<DIR>" else "0"
            })
    return files

def parse_systeminfo(output: str) -> Dict:
    """
    Parses 'systeminfo' output into structured JSON.
    """
    info = {
        "host_name": "",
        "os_name": "",
        "os_version": "",
        "manufacturer": "",
        "processor": "",
        "memory_mb": 0,
        "hotfixes": [],
        "vbs_enabled": False,
        "secure_boot": False,
        "network_cards": []
    }
    
    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("Host Name:"):
            info["host_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("OS Name:"):
            info["os_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("OS Version:"):
            info["os_version"] = line.split(":", 1)[1].strip()
        elif line.startswith("System Manufacturer:"):
            info["manufacturer"] = line.split(":", 1)[1].strip()
        elif line.startswith("Processor(s):"):
             # Sometimes multi-line, but first line often says count
             pass
        elif "GenuineIntel" in line or "AuthenticAMD" in line:
            info["processor"] = line.strip()
        elif line.startswith("Total Physical Memory:"):
            mem_str = line.split(":", 1)[1].strip().replace(",", "").replace(" MB", "")
            try: info["memory_mb"] = int(mem_str)
            except: pass
        elif line.startswith("["): # Hotfix line
            info["hotfixes"].append(line.strip())
        elif "Virtualization-based security" in line:
             if "Running" in line or "Enabled" in line:
                 info["vbs_enabled"] = True
        elif "Secure Boot" in line:
             if "Enabled" in line:
                 info["secure_boot"] = True
        elif "Network Card(s):" in line:
             pass # complex parsing, skip for now or just count text lines if needed

    return info

def parse_netstat(output: str) -> List[Dict]:
    """
    Parses 'netstat -ano' output.
    """
    connections = []
    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            continue
            
        # TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1132
        parts = line.split()
        if len(parts) >= 4:
            proto = parts[0]
            local = parts[1]
            foreign = parts[2]
            state = parts[3] if len(parts) > 4 else "UNKNOWN"
            pid = parts[-1] 
            
            # Simple port extraction
            port = local.split(':')[-1] if ':' in local else "0"
            
            connections.append({
                "proto": proto,
                "local_addr": local,
                "foreign_addr": foreign,
                "state": state,
                "pid": pid,
                "port": port
            })
    return connections

def parse_localgroup_admins(output: str) -> List[str]:
    """
    Parses 'net localgroup administrators'.
    """
    admins = []
    lines = output.strip().splitlines()
    capturing = False
    for line in lines:
        line = line.strip()
        if line.startswith("-----"):
             capturing = True
             continue
        if line.startswith("The command completed successfully"):
             break
        if capturing and line:
             admins.append(line)
    return admins

def parse_reg_query(output: str) -> List[Dict]:
    """
    Parses 'reg query' output.
    """
    values = []
    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("HKEY"):
            continue
            
        # ValueName    REG_SZ    Data
        # Split by 4 spaces often used in Reg Output
        parts = re.split(r'\s{4,}', line)
        if len(parts) >= 3:
            values.append({
                "name": parts[0],
                "type": parts[1],
                "data": parts[2]
            })
    return values

def normalize_data(context: Dict) -> Dict:
    """
    Legacy normalization function.
    """
    raw_data = context.get('raw_data', "")
    structured_data = {
        "processes": parse_tasklist(raw_data),
        "files": parse_dir_output(raw_data)
    }
    return structured_data

def preprocess_threat_hunt_data(context: Dict) -> Dict:
    """
    Summarizes raw data into a compact format to avoid Rate Limits.
    """
    raw_proc = context.get('raw_process_data', "")
    raw_file = context.get('raw_file_data', "")
    
    processes = parse_tasklist(raw_proc)
    files = parse_dir_output(raw_file)
    
    # Filter for suspicious items locally
    suspicious_keywords = ["mimikatz", "ncat", "netcat", "psexec", "powershell", "cmd.exe", "nc.exe"]
    suspicious_procs = [p for p in processes if p['name'].lower() in suspicious_keywords]
    
    # Get top 5 relevant files (e.g. recent logs or scripts)
    recent_files = files[:10] if len(files) > 10 else files
    
    summary = {
        "process_count": len(processes),
        "file_count": len(files),
        "suspicious_processes": suspicious_procs,
        "sample_files": recent_files,
        "note": "Data summarized locally to optimize token usage."
    }
    return summary
