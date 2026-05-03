# Repo Guardian

Repo Guardian is a lightweight, API-driven GitHub security scanning application. It performs static analysis on public GitHub repositories to detect exposed secrets, audit dependency vulnerabilities against the Open Source Vulnerability (OSV) database, and generate tailored `.gitignore` templates based on the repository's technology stack.

## Architecture

The system is designed with a decoupled architecture:

*   **Backend:** A Python REST API built with FastAPI. It handles the orchestration of GitHub API requests, applies regular expressions for secret detection, and queries the OSV API. 
*   **Frontend:** A static web interface developed using vanilla HTML, CSS (Tailwind CSS via CDN), and JavaScript. It consumes the FastAPI endpoints and provides a user-friendly dashboard for reviewing scan results.
*   **Deployment:** The application includes a `Dockerfile` for containerized deployment of the backend environment.

## Features

1.  **Secret Scanner:** Fetches the repository file tree via the GitHub REST API and applies pattern matching to identify high-risk exposed secrets, including AWS Access Keys, Bearer Tokens, and RSA Private Keys.
2.  **Dependency Audit:** Identifies and parses package management files (`requirements.txt`, `package.json`). Dependencies are extracted and cross-referenced with the free OSV API to report known vulnerabilities.
3.  **Smart Scanner Logic:** Implements an optimized scanning algorithm to prevent API rate limiting and timeouts on massive repositories. It filters the file tree to only download and scan high-value targets (`.env`, `.pem`, `.json`, `.yml`, `.py`, `.js`, etc.) and enforces a hard limit of 50 blob downloads per scan.
4.  **Dynamic .gitignore Generation:** Analyzes the file extensions present in the repository to determine the primary technology stack (e.g., Python, Node.js, Go) and generates a recommended `.gitignore` configuration.

## Prerequisites

*   Python 3.11 or higher
*   A GitHub Personal Access Token (PAT) to prevent API rate limiting.

## Installation

### Local Setup

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

4.  Configure the environment variables. Open the `.env` file in the `backend` directory and insert your GitHub Personal Access Token:
    ```
    GITHUB_TOKEN=your_personal_access_token_here
    ```

### Docker Setup

To build and run the backend using Docker:

1.  Build the Docker image from the root directory:
    ```bash
    docker build -t repo-guardian-backend .
    ```

2.  Run the container:
    ```bash
    docker run -p 8080:8080 repo-guardian-backend
    ```

## Usage

1.  Start the backend server (if running locally):
    ```bash
    cd backend
    uvicorn main:app --host 127.0.0.1 --port 8080 --reload
    ```

2.  Start the frontend server. Navigate to the `frontend` directory and start a static file server:
    ```bash
    cd frontend
    python -m http.server 3000 --bind 127.0.0.1
    ```

3.  Access the application by navigating to `http://127.0.0.1:3000` in a web browser. Enter a public GitHub repository URL (e.g., `https://github.com/owner/repo`) and initiate the scan.

## File Structure

```text
/
├── Dockerfile                  # Containerization instructions for the backend
├── README.md                   # Project documentation
├── backend/
│   ├── .env                    # Environment variable configuration
│   ├── main.py                 # FastAPI application entry point and routing
│   ├── osv_audit.py            # OSV database integration and dependency parsing
│   ├── requirements.txt        # Python package dependencies
│   └── scanner.py              # GitHub API integration and secret detection logic
└── frontend/
    ├── app.js                  # Frontend application logic and API communication
    ├── dashboard.html          # Scan results visualization interface
    └── index.html              # Landing page and scan initiation interface
```
