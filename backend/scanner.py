import requests
import re
import os
import base64

GITHUB_API_URL = "https://api.github.com"
MAX_FILES = 50
TARGET_EXTENSIONS = ('.env', '.txt', '.json', '.yml', '.yaml', '.py', '.js', '.pem')

# Common patterns for secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic API Key": r"(?i)(api[_-]?key|secret[_-]?key)[\s:=]+['\"]?([A-Za-z0-9_-]{16,})['\"]?"
}

def get_headers():
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def scan_repository(owner: str, repo: str):
    headers = get_headers()
    
    # Get default branch
    repo_info_resp = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}", headers=headers)
    if repo_info_resp.status_code != 200:
         return {"secrets": [], "dependency_files": [], "gitignore": "", "error": f"Failed to fetch repo: {repo_info_resp.status_code}"}
    
    default_branch = repo_info_resp.json().get('default_branch', 'master')
    
    # Get tree
    tree_resp = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1", headers=headers)
    
    # Fallback to 'main' if default branch fetch failed
    if tree_resp.status_code != 200:
        if default_branch != 'main':
            tree_resp = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/main?recursive=1", headers=headers)
        
        if tree_resp.status_code != 200:
            return {"secrets": [], "dependency_files": [], "gitignore": "", "error": f"Failed to fetch tree: {tree_resp.status_code}"}
         
    tree = tree_resp.json().get('tree', [])
    
    secrets_found = []
    dependency_files = []
    tech_stack = set()
    
    # Smart Filtering
    filtered_tree = [
        item for item in tree 
        if item.get('type') == 'blob' and item.get('path', '').endswith(TARGET_EXTENSIONS)
    ]
    
    files_scanned = 0
    
    for item in filtered_tree:
        path = item['path']
        
        # Identify tech stack
        if path.endswith('.py'):
            tech_stack.add('python')
        elif path.endswith('.js') or path.endswith('.jsx') or path.endswith('.ts') or path.endswith('.tsx'):
            tech_stack.add('node')
        elif path.endswith('.go'):
            tech_stack.add('go')
            
        # Identify dependency files
        if ('requirements' in path.lower() and path.endswith('.txt')) or path.endswith('package.json'):
            dependency_files.append({"path": path, "sha": item['sha']})
            
        # Files to deeply scan for secrets
        if files_scanned >= MAX_FILES:
            continue  # Still loop to find dependency files & tech stack, just don't download blob
            
        # Fetch file content
        blob_resp = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/blobs/{item['sha']}", headers=headers)
        if blob_resp.status_code == 200:
            files_scanned += 1
            content_base64 = blob_resp.json().get('content', '')
            if content_base64:
                try:
                    content = base64.b64decode(content_base64).decode('utf-8', errors='ignore')
                    for name, pattern in SECRET_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            remediation = "Revoke this token immediately in the provider's dashboard. Remove from git history and add to .gitignore."
                            if "AWS" in name:
                                remediation = "CRITICAL: Log into AWS Console and Deactivate this Access Key immediately. Do not just delete the file. Use 'BFG Repo-Cleaner' or 'git filter-repo' to wipe it from git history."
                            elif "RSA" in name or "Private" in name:
                                remediation = "CRITICAL: Consider this key compromised. Generate a new keypair and rotate it on your servers. Wipe this file from git history."
                            
                            secrets_found.append({
                                "file": path,
                                "type": name,
                                "matches": len(matches),
                                "remediation": remediation
                            })
                except Exception:
                    pass

    # Generate gitignore
    gitignore = generate_gitignore(tech_stack)
    
    return {
        "secrets": secrets_found,
        "dependency_files": dependency_files,
        "gitignore": gitignore
    }

def generate_gitignore(tech_stack: set):
    lines = [
        "# Common exclusions",
        ".env",
        ".DS_Store",
        "*.pem"
    ]
    if 'python' in tech_stack:
        lines.extend([
            "\n# Python",
            "__pycache__/",
            "*.py[cod]",
            "*$py.class",
            "venv/",
            ".venv/"
        ])
    if 'node' in tech_stack:
        lines.extend([
            "\n# Node",
            "node_modules/",
            "npm-debug.log",
            "yarn-error.log"
        ])
    if 'go' in tech_stack:
        lines.extend([
             "\n# Go",
             "bin/",
             "pkg/"
        ])
    return "\n".join(lines)
