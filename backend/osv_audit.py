import requests
import base64
import os
import json

GITHUB_API_URL = "https://api.github.com"
OSV_API_URL = "https://api.osv.dev/v1/query"

def get_headers():
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def check_dependencies(owner: str, repo: str, dependency_files: list):
    headers = get_headers()
    vulnerabilities = []
    
    for file_info in dependency_files:
        path = file_info['path']
        sha = file_info['sha']
        
        # Limit to main requirements.txt and package.json to avoid too many requests
        if not (('requirements' in path.lower() and path.endswith('.txt')) or path.endswith('package.json')):
            continue
            
        blob_resp = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/blobs/{sha}", headers=headers)
        if blob_resp.status_code != 200:
            continue
            
        content_base64 = blob_resp.json().get('content', '')
        if not content_base64:
            continue
            
        try:
            content = base64.b64decode(content_base64).decode('utf-8', errors='ignore')
            
            if 'requirements' in path.lower() and path.endswith('.txt'):
                vulns = check_requirements_txt(content)
                vulnerabilities.extend(vulns)
            elif path.endswith('package.json'):
                vulns = check_package_json(content)
                vulnerabilities.extend(vulns)
        except Exception:
            pass
            
    # Deduplicate and limit to top 10 for UI
    unique_vulns = {}
    for v in vulnerabilities:
        key = f"{v['package']}-{v['id']}"
        unique_vulns[key] = v
        
    return list(unique_vulns.values())[:10]

def check_osv(package: str, version: str, ecosystem: str):
    query = {
        "version": version,
        "package": {
            "name": package,
            "ecosystem": ecosystem
        }
    }
    try:
        resp = requests.post(OSV_API_URL, json=query)
        if resp.status_code == 200:
            data = resp.json()
            if 'vulns' in data:
                results = []
                for v in data['vulns']:
                    fixed_version = "No patch available"
                    try:
                        events = v['affected'][0]['ranges'][0]['events']
                        for event in events:
                            if 'fixed' in event:
                                fixed_version = event['fixed']
                                break
                    except (KeyError, IndexError, TypeError):
                        pass
                    
                    results.append({
                        "id": v['id'],
                        "package": package,
                        "version": version,
                        "summary": v.get('summary', 'Unknown vulnerability'),
                        "severity": get_severity(v),
                        "fixed_version": fixed_version
                    })
                return results
    except Exception:
        pass
    return []

def get_severity(vuln):
    try:
        # Just grab the first severity score we can find
        return vuln['severity'][0].get('score', 'HIGH')
    except (KeyError, IndexError, TypeError):
         return "HIGH" # default to high if not specified to be safe/visible

def check_requirements_txt(content: str):
    vulns = []
    lines = content.split('\n')
    checked = 0
    for line in lines:
        line = line.split('#')[0].strip()
        if not line:
            continue
            
        if '==' in line:
            parts = line.split('==')
            if len(parts) >= 2:
                package = parts[0].strip()
                version = parts[1].split(';')[0].strip()
                res = check_osv(package, version, "PyPI")
                vulns.extend(res)
                checked += 1
                if checked >= 50: break
    return vulns

def check_package_json(content: str):
    vulns = []
    try:
        data = json.loads(content)
        deps = data.get('dependencies', {})
        checked = 0
        for package, version in deps.items():
            # Clean up version string (remove ^, ~, etc. simple version)
            version = version.replace('^', '').replace('~', '').strip()
            # simple validation that it looks like a version
            if version and version[0].isdigit():
                res = check_osv(package, version, "npm")
                vulns.extend(res)
                checked += 1
                if checked >= 5: break
    except json.JSONDecodeError:
        pass
    return vulns
