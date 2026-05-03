from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()

from scanner import scan_repository
from osv_audit import check_dependencies

app = FastAPI(title="Repo Guardian API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    risk_score: str
    secrets: list
    vulnerabilities: list
    gitignore: str

@app.post("/scan", response_model=ScanResponse)
async def perform_scan(request: ScanRequest):
    if not request.url.startswith("https://github.com/"):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    
    parts = request.url.rstrip('/').split('/')
    if len(parts) < 5:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL format. Expected: https://github.com/owner/repo")
        
    owner = parts[-2]
    repo = parts[-1]
    
    # 1. Run Secret Scanner & File Analysis
    scan_results = scan_repository(owner, repo)
    if "error" in scan_results:
         raise HTTPException(status_code=500, detail=scan_results["error"])
    
    # 2. Run OSV Audit
    vulns = check_dependencies(owner, repo, scan_results.get('dependency_files', []))
    
    # 3. Calculate Risk Score
    # Simple scoring logic: A is clean, F is very bad
    score = "A"
    num_secrets = len(scan_results.get('secrets', []))
    num_vulns = len(vulns)
    
    if num_secrets > 5 or num_vulns > 10:
        score = "F"
    elif num_secrets > 2 or num_vulns > 5:
        score = "D"
    elif num_secrets > 0 or num_vulns > 2:
        score = "C"
    elif num_vulns > 0:
        score = "B"
        
    return ScanResponse(
        risk_score=score,
        secrets=scan_results.get('secrets', []),
        vulnerabilities=vulns,
        gitignore=scan_results.get('gitignore', '')
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
