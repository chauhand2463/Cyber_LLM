import requests
import re
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup


class OSINT:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberLLM-S/1.0ecurity-Agent'
        })
    
    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    return {
                        "status": "success",
                        "id": vuln.get('id'),
                        "description": vuln.get('descriptions', [{}])[0].get('value', 'N/A')[:500],
                        "published": vuln.get('published'),
                        "severity": self._get_severity(vuln),
                        "cvss_score": self._get_cvss(vuln),
                        "references": [r.get('url') for r in vuln.get('references', [])[:5]]
                    }
            
            return {"status": "error", "message": f"CVE {cve_id} not found"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _get_severity(self, vuln: Dict) -> str:
        metrics = vuln.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
        elif 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
        return 'UNKNOWN'
    
    def _get_cvss(self, vuln: Dict) -> Optional[float]:
        metrics = vuln.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore')
        elif 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore')
        return None
    
    def ip_info(self, ip: str) -> Dict[str, Any]:
        try:
            resp = self.session.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    return {
                        "status": "success",
                        "ip": data.get('query'),
                        "country": data.get('country'),
                        "region": data.get('regionName'),
                        "city": data.get('city'),
                        "isp": data.get('isp'),
                        "org": data.get('org'),
                        "as": data.get('as')
                    }
            return {"status": "error", "message": "IP lookup failed"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def scrape_url(self, url: str) -> Dict[str, Any]:
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            resp = self.session.get(url, timeout=15)
            soup = BeautifulSoup(resp.text, 'lxml')
            
            title = soup.title.string if soup.title else "N/A"
            
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', resp.text)
            emails = list(set(emails))[:10]
            
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text)
            ips = list(set([ip for ip in ips if not ip.startswith(('0.', '127.', '255.', '255.'))]))[:10]
            
            return {
                "status": "success",
                "url": url,
                "title": title,
                "status_code": resp.status_code,
                "server": resp.headers.get('Server', 'N/A'),
                "emails": emails,
                "ips_found": ips,
                "content_length": len(resp.text)
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def check_threat_intel(self, indicator: str) -> Dict[str, Any]:
        findings = {"indicator": indicator, "sources": []}
        
        try:
            resp = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('pulse_info', {}).get('count', 0) > 0:
                    findings["sources"].append({
                        "name": "AlienVault OTX",
                        "malicious": True,
                        "pulses": data['pulse_info']['count']
                    })
        except:
            pass
        
        try:
            resp = self.session.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={indicator}",
                headers={"Key": "demo", "Accept": "application/json"},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('data', {}).get('abuseConfidenceScore', 0) > 0:
                    findings["sources"].append({
                        "name": "AbuseIPDB",
                        "malicious": True,
                        "confidence": data['data']['abuseConfidenceScore']
                    })
        except:
            pass
        
        if not findings["sources"]:
            findings["sources"].append({"name": "Clean", "malicious": False})
        
        return {"status": "success", "findings": findings}
