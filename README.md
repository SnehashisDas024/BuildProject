# Repo Guardian

Repo Guardian is a lightweight, API-driven GitHub security scanning application. It performs static analysis on public GitHub repositories to detect exposed secrets, audit dependency vulnerabilities against the Open Source Vulnerability (OSV) database, and provide actionable remediation advice to secure your applications. 

## Architecture

The system is designed as a unified, decoupled-yet-integrated service:

*   **Backend & File Server:** A Python REST API built with FastAPI. It handles the orchestration of GitHub API requests, applies regular expressions for secret detection, queries the OSV API, and seamlessly serves the static frontend interface.
*   **Frontend:** A static web interface developed using vanilla HTML, CSS (Tailwind CSS via CDN), and JavaScript. It provides a user-friendly dashboard for reviewing scan results, risk scores, and remediation playbooks.
*   **Deployment:** The application includes a `Dockerfile` specifically tuned for serverless container deployment on Google Cloud Run.

## Features

1.  **Secret Scanner:** Fetches the repository file tree via the GitHub REST API and applies pattern matching to identify high-risk exposed secrets, including AWS Access Keys, Bearer Tokens, and RSA Private Keys.
2.  **Dependency Audit:** Identifies and parses package management files (`requirements.txt`, `package.json` across subdirectories). Dependencies are extracted and cross-referenced with the free OSV API to report known vulnerabilities.
3.  **Remediation Playbooks:** Automatically extracts patched versions for vulnerable dependencies and attaches specific, actionable remediation playbooks for compromised secrets (e.g., advising the use of `git filter-repo`).
4.  **Smart Scanner Logic:** Implements an optimized scanning algorithm to prevent API rate limiting and timeouts on massive repositories. It filters the file tree to only download high-value targets and enforces a blob download limit.
5.  **Dynamic .gitignore Generation:** Analyzes the file extensions present in the repository to determine the primary technology stack and generates a recommended `.gitignore` configuration.

## Prerequisites

*   Python 3.11 or higher
*   A GitHub Personal Access Token (PAT) to prevent API rate limiting.

## Installation & Local Development

1.  Navigate to the `backend` directory:
    ```bash
    cd backend
    ```

2.  Create and activate a Python virtual environment:
    ```bash
    python -m venv venv
    
    # Windows
    .\venv\Scripts\Activate.ps1
    
    # Unix/macOS
    source venv/bin/activate
    ```

3.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4.  Configure your environment variables. Open or create the `.env` file in the `backend` directory and insert your GitHub Personal Access Token:
    ```
    GITHUB_TOKEN=your_personal_access_token_here
    ```

5.  Start the unified server:
    ```bash
    uvicorn main:app --host 127.0.0.1 --port 8080 --reload
    ```

6.  Access the application by navigating to `http://127.0.0.1:8080` in your web browser. 

## Google Cloud Run Deployment

This application is structurally optimized for deployment as a single container on Google Cloud Run.

1.  From the project root directory, deploy to Cloud Run:
    ```bash
    gcloud run deploy repo-guardian --source . --region us-central1
    ```
    *(Alternatively, use the Google Cloud Console or your IDE's Cloud Run integration).*

2.  **Configure Authentication:** For security reasons, the `.env` file is intentionally ignored by the deployment. To prevent GitHub API rate limits in production, you must manually add your `GITHUB_TOKEN` to your Cloud Run service:
    * Go to your Cloud Run dashboard.
    * Click **Edit & Deploy New Revision**.
    * Under the **Variables & Secrets** tab, add `GITHUB_TOKEN` with your access token.
    * *(Optional)* To prevent cold starts, set **Minimum instances** to `1` under the Autoscaling tab.
    * Click **Deploy**.

## File Structure

```text
/
├── Dockerfile                  # Containerization instructions for unified deployment
├── README.md                   # Project documentation
├── .gitignore                  # Comprehensive git exclusions
├── backend/
│   ├── .env                    # Local environment variables (do not commit)
│   ├── main.py                 # FastAPI application, routing, and static file server
│   ├── osv_audit.py            # OSV API integration, dependency parsing, and remediation extraction
│   ├── requirements.txt        # Python package dependencies
│   └── scanner.py              # GitHub API integration, secret detection, and playbooks
└── frontend/
    ├── app.js                  # Frontend logic and DOM manipulation
    ├── dashboard.html          # Scan results visualization interface
    └── index.html              # Landing page and scan initiation interface
```
