import requests
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path


class CTIFeeds:
    def __init__(self, cache_dir: str = "cti_cache"):
        self.cache_dir = cache_dir
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberLLM-CTI/1.0'})
        os.makedirs(cache_dir, exist_ok=True)
    
    def _get_cached(self, key: str, max_age_hours: int = 24) -> Optional[Dict]:
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        if os.path.exists(cache_file):
            mtime = datetime.fromtimestamp(os.path.getmtime(cache_file))
            if datetime.now() - mtime < timedelta(hours=max_age_hours):
                with open(cache_file, 'r') as f:
                    return json.load(f)
        return None
    
    def _save_cache(self, key: str, data: Dict):
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        with open(cache_file, 'w') as f:
            json.dump(data, f)
    
    def get_cve(self, cve_id: str) -> Dict[str, Any]:
        cache_key = f"cve_{cve_id}"
        cached = self._get_cached(cache_key, max_age_hours=24)
        if cached:
            return cached
        
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    result = {
                        "status": "success",
                        "id": vuln.get('id'),
                        "description": vuln.get('descriptions', [{}])[0].get('value', '')[:1000],
                        "published": vuln.get('published'),
                        "last_modified": vuln.get('lastModified'),
                        "severity": self._extract_severity(vuln),
                        "cvss": self._extract_cvss(vuln),
                        "references": [r.get('url') for r in vuln.get('references', [])[:10]],
                        "weaknesses": [w.get('description', [{}])[0].get('value') for w in vuln.get('weaknesses', [])],
                    }
                    self._save_cache(cache_key, result)
                    return result
            return {"status": "error", "message": f"CVE {cve_id} not found"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _extract_severity(self, vuln: Dict) -> str:
        metrics = vuln.get('metrics', {})
        for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if key in metrics:
                return metrics[key][0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
        return 'UNKNOWN'
    
    def _extract_cvss(self, vuln: Dict) -> Optional[float]:
        metrics = vuln.get('metrics', {})
        for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if key in metrics:
                return metrics[key][0].get('cvssData', {}).get('baseScore')
        return None
    
    def get_recent_cves(self, days: int = 7, limit: int = 20) -> List[Dict]:
        cache_key = f"recent_cves_{days}d"
        cached = self._get_cached(cache_key, max_age_hours=1)
        if cached:
            return cached
        
        try:
            pub_start = (datetime.now() - timedelta(days=days)).isoformat()
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={pub_start}&resultsPerPage={limit}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get('vulnerabilities', []):
                    vuln = item['cve']
                    results.append({
                        "id": vuln.get('id'),
                        "description": vuln.get('descriptions', [{}])[0].get('value', '')[:200],
                        "published": vuln.get('published'),
                        "severity": self._extract_severity(vuln),
                        "cvss": self._extract_cvss(vuln),
                    })
                self._save_cache(cache_key, results)
                return results
            return []
        except Exception as e:
            return [{"error": str(e)}]
    
    def search_cve_keyword(self, keyword: str, limit: int = 10) -> List[Dict]:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={limit}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get('vulnerabilities', []):
                    vuln = item['cve']
                    results.append({
                        "id": vuln.get('id'),
                        "description": vuln.get('descriptions', [{}])[0].get('value', '')[:200],
                        "published": vuln.get('published'),
                        "severity": self._extract_severity(vuln),
                    })
                return results
            return []
        except Exception as e:
            return [{"error": str(e)}]
    
    def get_exploit_db(self, cve_id: str = None, keyword: str = None) -> List[Dict]:
        try:
            if cve_id:
                url = f"https://exploit-db.com/search?cve={cve_id}"
            elif keyword:
                url = f"https://exploit-db.com/search?description={keyword}"
            else:
                return []
            
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                return [{"status": "success", "message": "Exploit-DB lookup requires API key"}]
            return []
        except Exception as e:
            return [{"error": str(e)}]
    
    def threat_intel_ip(self, ip: str) -> Dict[str, Any]:
        cache_key = f"threat_{ip}"
        cached = self._get_cached(cache_key, max_age_hours=1)
        if cached:
            return cached
        
        results = {"ip": ip, "sources": []}
        
        try:
            resp = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                if pulse_count > 0:
                    results["sources"].append({
                        "name": "AlienVault OTX",
                        "malicious": True,
                        "pulses": pulse_count,
                        "tags": data.get('pulse_info', {}).get('pulse', [{}])[0].get('tags', [])[:5]
                    })
        except:
            pass
        
        try:
            resp = self.session.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                headers={"Key": "demo", "Accept": "application/json"},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                score = data.get('data', {}).get('abuseConfidenceScore', 0)
                if score > 0:
                    results["sources"].append({
                        "name": "AbuseIPDB",
                        "malicious": True,
                        "confidence": score
                    })
        except:
            pass
        
        if not results["sources"]:
            results["sources"].append({"name": "Clean", "malicious": False})
        
        self._save_cache(cache_key, results)
        return results
    
    def get_cwe_details(self, cwe_id: str) -> Dict[str, Any]:
        try:
            url = f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"
            resp = self.session.get(url, timeout=10)
            return {
                "id": cwe_id,
                "url": url,
                "description": "See MITRE CWE for full details"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def enrich_cve(self, cve_id: str) -> Dict[str, Any]:
        cve_data = self.get_cve(cve_id)
        if cve_data.get('status') != 'success':
            return cve_data
        
        cve_id = cve_data['id']
        threats = self.threat_intel_ip(cve_id)
        
        return {
            **cve_data,
            "threat_intel": threats,
            "risk_assessment": self._assess_risk(cve_data),
            "remediation": self._get_remediation(cve_data)
        }
    
    def _assess_risk(self, cve_data: Dict) -> Dict:
        cvss = cve_data.get('cvss', 0)
        severity = cve_data.get('severity', 'UNKNOWN')
        
        if cvss >= 9.0 or severity == 'CRITICAL':
            risk = "CRITICAL"
        elif cvss >= 7.0 or severity == 'HIGH':
            risk = "HIGH"
        elif cvss >= 4.0 or severity == 'MEDIUM':
            risk = "MEDIUM"
        else:
            risk = "LOW"
        
        return {"level": risk, "cvss": cvss, "severity": severity}
    
    def _get_remediation(self, cve_data: Dict) -> Dict:
        severity = cve_data.get('severity', '').upper()
        
        if severity == 'CRITICAL' or severity == 'HIGH':
            return {
                "priority": "IMMEDIATE",
                "actions": [
                    "Apply available patches immediately",
                    "Implement compensating controls",
                    "Disable affected service if possible",
                    "Monitor for indicators of compromise"
                ]
            }
        elif severity == 'MEDIUM':
            return {
                "priority": "WITHIN WEEK",
                "actions": [
                    "Schedule patch deployment",
                    "Review vulnerability context",
                    "Implement monitoring"
                ]
            }
        else:
            return {
                "priority": "STANDARD",
                "actions": [
                    "Include in next maintenance window",
                    "Review for relevance to environment"
                ]
            }


class DataCollector:
    def __init__(self, output_dir: str = "data"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.cti = CTIFeeds()
    
    def collect_recent_vulns(self, days: int = 30) -> List[Dict]:
        print(f"[+] Collecting CVEs from last {days} days...")
        cves = self.cti.get_recent_cves(days=days, limit=50)
        
        output_file = os.path.join(self.output_dir, f"cves_{datetime.now().strftime('%Y%m%d')}.json")
        with open(output_file, 'w') as f:
            json.dump(cves, f, indent=2)
        
        print(f"[+] Saved {len(cves)} CVEs to {output_file}")
        return cves
    
    def collect_cve_details(self, cve_ids: List[str]) -> List[Dict]:
        results = []
        for cve_id in cve_ids:
            print(f"[+] Fetching {cve_id}...")
            data = self.cti.enrich_cve(cve_id)
            results.append(data)
        
        output_file = os.path.join(self.output_dir, "cve_details.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def prepare_training_data(self, cve_ids: List[str], output_file: str = "train.jsonl") -> str:
        print(f"[+] Preparing training data for {len(cve_ids)} CVEs...")
        
        with open(output_file, 'w') as f:
            for cve_id in cve_ids:
                cve_data = self.cti.get_cve(cve_id)
                if cve_data.get('status') == 'success':
                    prompt = f"Explain vulnerability {cve_id} and provide remediation steps"
                    completion = f"CVE: {cve_id}\nSeverity: {cve_data.get('severity')}\nCVSS: {cve_data.get('cvss')}\nDescription: {cve_data.get('description')}\nRemediation: {self.cti._get_remediation(cve_data)}"
                    
                    record = {"prompt": prompt, "completion": completion}
                    f.write(json.dumps(record) + '\n')
        
        print(f"[+] Training data saved to {output_file}")
        return output_file
