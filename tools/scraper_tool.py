"""
CyberLLM - Enhanced Web Scraping & OSINT Tools
Fast, efficient web scraping for security research
"""

import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import quote, urlparse, urljoin
from datetime import datetime
from typing import Optional, List, Dict

DEFAULT_TIMEOUT = 15
MAX_TEXT_LENGTH = 10000
MAX_LINKS = 50

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}


def validate_url(url: str) -> Optional[str]:
    """Validate and normalize URL."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        result = urlparse(url)
        if result.netloc:
            return url
    except:
        pass
    return None


def check_robots_txt(url: str) -> dict:
    """Check robots.txt for allowed paths."""
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        resp = requests.get(robots_url, timeout=5, headers=HEADERS)
        if resp.status_code == 200:
            return {"allowed": True, "content": resp.text[:500]}
        return {"allowed": None, "status": resp.status_code}
    except Exception as e:
        return {"allowed": None, "error": str(e)}


def scrape_basic(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fast static HTML scraping with comprehensive extraction."""
    validated = validate_url(url)
    if not validated:
        return {"status": "error", "message": "Invalid URL"}
    url = validated
    
    try:
        session = requests.Session()
        response = session.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        
        final_url = response.url
        status = response.status_code
        
        if status == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            
            title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
            
            meta = {}
            for tag in soup.find_all('meta'):
                name = tag.get('name', tag.get('property', ''))
                content = tag.get('content', '')
                if name and content:
                    meta[name.lower()] = content
            
            for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'iframe']):
                tag.decompose()
            
            text = soup.get_text(separator='\n', strip=True)
            lines = [line.strip() for line in text.split('\n') if line.strip()]
            text = '\n'.join(lines[:500])
            
            links = []
            for a in soup.find_all('a', href=True)[:MAX_LINKS]:
                href = a['href']
                text = a.get_text(strip=True)[:50]
                if href.startswith('http'):
                    links.append({"url": href, "text": text})
                else:
                    links.append({"url": urljoin(final_url, href), "text": text})
            
            images = [img.get('src', '') for img in soup.find_all('img', src=True)[:20] if img.get('src')]
            
            return {
                "status": "success",
                "url": final_url,
                "title": title,
                "meta": meta,
                "text": text[:MAX_TEXT_LENGTH],
                "text_length": len(text),
                "links": links,
                "images": images[:10],
                "status_code": status,
                "content_type": response.headers.get('Content-Type', ''),
                "server": response.headers.get('Server', ''),
                "cookies": list(session.cookies.keys())
            }
        else:
            return {"status": "error", "message": f"HTTP {status}", "status_code": status}
    except requests.exceptions.Timeout:
        return {"status": "error", "message": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "message": "Connection failed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def scrape_security_info(url: str) -> dict:
    """Scrape and extract security-relevant information."""
    result = scrape_basic(url)
    
    if result.get("status") != "success":
        return result
    
    text = result.get("text", "")
    html_lower = text.lower()
    
    findings = {
        "emails": [],
        "ipv4": [],
        "urls": [],
        "api_keys": [],
        "aws_keys": [],
        "versions": [],
        "tech_stack": [],
        "endpoints": [],
        "forms": [],
        "inputs": [],
        "interesting_files": [],
        "social_media": [],
        "cve_mentions": []
    }
    
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    findings["emails"] = list(set(emails))[:15]
    
    ipv4 = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    findings["ipv4"] = list(set(ipv4))[:15]
    
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
    findings["urls"] = list(set(urls))[:15]
    
    aws_keys = re.findall(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}', text)
    findings["aws_keys"] = list(set(aws_keys))[:5]
    
    api_keys = re.findall(r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', text, re.IGNORECASE)
    findings["api_keys"] = list(set(api_keys))[:5]
    
    versions = re.findall(r'(?:v|version|ver)[\s.:]*(\d+[\.\d]+[\.\d]*)', text, re.IGNORECASE)
    findings["versions"] = list(set(versions))[:15]
    
    cves = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
    findings["cve_mentions"] = list(set(cves))[:10]
    
    tech_keywords = {
        'php': 'PHP', 'python': 'Python', 'node': 'Node.js', 'react': 'React',
        'angular': 'Angular', 'vue': 'Vue.js', 'django': 'Django', 'flask': 'Flask',
        'express': 'Express', 'laravel': 'Laravel', 'wordpress': 'WordPress',
        'apache': 'Apache', 'nginx': 'Nginx', 'mysql': 'MySQL', 'postgresql': 'PostgreSQL',
        'mongodb': 'MongoDB', 'redis': 'Redis', 'elasticsearch': 'Elasticsearch',
        'docker': 'Docker', 'kubernetes': 'Kubernetes', 'aws': 'AWS', 'azure': 'Azure',
        'gatsby': 'Gatsby', 'nextjs': 'Next.js', 'svelte': 'Svelte', 'tailwind': 'Tailwind',
        'bootstrap': 'Bootstrap', 'jquery': 'jQuery', 'typescript': 'TypeScript'
    }
    for keyword, name in tech_keywords.items():
        if keyword in html_lower:
            findings["tech_stack"].append(name)
    
    endpoints = re.findall(r'/api/v?\d*/?[\w/-]+|/admin/[\w/]+|/login|/register|/upload|/download|/config|/debug|/test', text)
    findings["endpoints"] = list(set(endpoints))[:20]
    
    interesting_exts = ['.env', '.git', '.config', '.ini', '.yml', '.yaml', '.json', '.xml', '.sql', '.db', '.zip', '.tar', '.gz', '.bak', '.tmp']
    for ext in interesting_exts:
        if ext in html_lower:
            findings["interesting_files"].append(ext)
    
    social = re.findall(r'(?:twitter|facebook|instagram|linkedin|github|youtube|tiktok)[.\s]*(?:com[/@])?[a-zA-Z0-9_/]+', text, re.IGNORECASE)
    findings["social_media"] = list(set(social))[:10]
    
    try:
        soup = BeautifulSoup(requests.get(url, headers=HEADERS, timeout=10).text, 'html.parser')
        for form in soup.find_all('form'):
            form_info = {
                "action": form.get('action', ''),
                "method": form.get('method', 'get'),
            }
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_type = inp.get('type', 'text')
                inp_name = inp.get('name', '')
                if inp_type not in ['submit', 'button', 'hidden']:
                    inputs.append({"type": inp_type, "name": inp_name})
            form_info["inputs"] = inputs
            findings["forms"].append(form_info)
    except:
        pass
    
    return {
        "status": "success",
        "url": url,
        "title": result.get("title"),
        "meta": result.get("meta", {}),
        "findings": findings,
        "snippet": text[:1500],
        "links_count": len(result.get("links", [])),
        "server": result.get("server", ""),
        "cookies": result.get("cookies", [])
    }


def scrape_full(url: str) -> dict:
    """Complete scrape with all info."""
    security = scrape_security_info(url)
    basic = scrape_basic(url)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "basic": {k: v for k, v in basic.items() if k != 'text'},
        "security": security.get("findings", {}),
        "security_status": "success" if security.get("status") == "success" else "partial"
    }


def google_dork(query: str) -> dict:
    """Google Dork - returns manual search URL."""
    return {
        "status": "limited",
        "message": "Dorking requires browser automation",
        "query": query,
        "manual_url": f"https://www.google.com/search?q={quote(query)}",
        "alternative": f"https://duckduckgo.com/?q={quote(query)}"
    }


DORKS = {
    "exposed_configs": "site:target.com filetype:env OR filetype:config OR filetype:ini",
    "exposed_database": "site:target.com filetype:sql OR filetype:db OR filetype:sqlite",
    "exposed_credentials": "site:target.com \"password\" OR \"api_key\" OR \"secret\"",
    "vulnerable_php": "site:target.com filetype:php \"id=\" OR \"page=\"",
    "exposed_git": "site:target.com \".git\" OR \"gitignore\"",
    "admin_panels": "site:target.com inurl:admin OR inurl:login OR inurl:dashboard",
    "exposed_docs": "site:target.com filetype:xlsx OR filetype:csv OR filetype:pdf OR filetype:doc",
}


def run_dork(target: str, dork_type: str = "exposed_configs") -> dict:
    """Run predefined dork against target."""
    query = DORKS.get(dork_type, DORKS["exposed_configs"]).replace("target.com", target)
    return google_dork(query)


def lookup_cve(cve_id: str) -> dict:
    """Lookup CVE details from NIST API."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
        response = requests.get(url, headers=HEADERS, timeout=20)
        
        if response.status_code == 200:
            data = response.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            
            metrics = vuln.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            
            return {
                "status": "success",
                "id": vuln.get("id"),
                "description": vuln.get("descriptions", [{}])[0].get("value", "")[:500],
                "severity": cvss.get("baseSeverity", "N/A"),
                "cvss_score": cvss.get("baseScore", "N/A"),
                "published": vuln.get("published"),
                "last_modified": vuln.get("lastModified")
            }
        return {"status": "error", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def ip_info(ip: str) -> dict:
    """Get IP information."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,timezone,currency"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "status": "success",
                    "ip": ip,
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "timezone": data.get("timezone"),
                    "currency": data.get("currency")
                }
        return {"status": "error", "message": "IP not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def domain_info(domain: str) -> dict:
    """Get domain information."""
    try:
        url = f"https://dns.google/resolve?name={domain}&type=A"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            answers = data.get("Answer", [])
            ips = [r.get("data") for r in answers if r.get("type") == 1]
            return {
                "status": "success",
                "domain": domain,
                "ips": ips,
                "nameservers": []
            }
        return {"status": "error", "message": "Domain lookup failed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def quick_scan(target: str) -> dict:
    """Quick OSINT scan."""
    results = {"target": target, "timestamp": datetime.now().isoformat()}
    
    is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', target)
    
    if is_ip:
        results["ip_info"] = ip_info(target)
    else:
        results["domain_info"] = domain_info(target)
    
    results["dorks"] = {
        "configs": run_dork(target, "exposed_configs"),
        "admin": run_dork(target, "admin_panels"),
    }
    
    return results
