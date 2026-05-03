const API_BASE_URL = '';

document.addEventListener('DOMContentLoaded', () => {
    
    // Index Page Logic
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const repoUrl = document.getElementById('repoUrl').value;
            const scanBtn = document.getElementById('scanBtn');
            const btnText = document.getElementById('btnText');
            const btnIcon = document.getElementById('btnIcon');
            const btnSpinner = document.getElementById('btnSpinner');
            const statusContainer = document.getElementById('statusContainer');
            const displayUrl = document.getElementById('displayUrl');
            const statusText = document.getElementById('statusText');
            const errorContainer = document.getElementById('errorContainer');
            
            // Reset UI
            errorContainer.classList.add('hidden');
            scanBtn.disabled = true;
            btnText.textContent = 'Scanning...';
            btnIcon.classList.add('hidden');
            btnSpinner.classList.remove('hidden');
            
            statusContainer.classList.remove('hidden');
            displayUrl.textContent = repoUrl;
            
            const statuses = [
                "Cloning repository metadata...",
                "Scanning file tree for sensitive extensions...",
                "Running regex engines on configuration files...",
                "Auditing dependencies against OSV database...",
                "Compiling security report..."
            ];
            
            let statusIdx = 0;
            const statusInterval = setInterval(() => {
                if (statusIdx < statuses.length) {
                    statusText.textContent = statuses[statusIdx];
                    statusIdx++;
                }
            }, 1200);

            try {
                const response = await fetch(`${API_BASE_URL}/scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: repoUrl })
                });

                clearInterval(statusInterval);

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Scan failed');
                }

                const data = await response.json();
                
                // Store results
                localStorage.setItem('repoGuardianResults', JSON.stringify({
                    url: repoUrl,
                    data: data
                }));
                
                // Redirect
                window.location.href = 'dashboard.html';
                
            } catch (error) {
                clearInterval(statusInterval);
                errorContainer.textContent = `Error: ${error.message}`;
                errorContainer.classList.remove('hidden');
                
                // Reset button
                scanBtn.disabled = false;
                btnText.textContent = 'Scan';
                btnIcon.classList.remove('hidden');
                btnSpinner.classList.add('hidden');
                statusContainer.classList.add('hidden');
            }
        });
    }

    // Dashboard Page Logic
    const riskScoreEl = document.getElementById('riskScore');
    if (riskScoreEl) {
        const stored = localStorage.getItem('repoGuardianResults');
        if (!stored) {
            window.location.href = 'index.html';
            return;
        }

        const { url, data } = JSON.parse(stored);
        
        // Repo Name
        document.getElementById('repoName').textContent = url.replace('https://github.com/', '');
        
        // Risk Score
        riskScoreEl.textContent = data.risk_score;
        riskScoreEl.className = `text-8xl font-black mb-4 font-mono leading-none score-${data.risk_score}`;
        
        // Gitignore
        const gitignoreBlock = document.getElementById('gitignoreBlock');
        gitignoreBlock.textContent = data.gitignore || '# No specific gitignore generated';
        
        // Secrets
        const secretsCount = document.getElementById('secretsCount');
        const secretsList = document.getElementById('secretsList');
        secretsCount.textContent = `${data.secrets.length} Found`;
        
        if (data.secrets.length === 0) {
            secretsList.innerHTML = `<div class="text-slate-500 text-sm italic p-4 bg-slate-900/50 rounded-lg border border-slate-800 text-center">No exposed secrets detected.</div>`;
        } else {
            secretsList.innerHTML = data.secrets.map(s => `
                <div class="p-4 bg-slate-900/80 rounded-lg border border-red-900/30 flex flex-col gap-2">
                    <div class="flex items-center justify-between">
                        <span class="text-red-400 font-mono text-sm font-semibold">${s.type}</span>
                        <span class="text-xs bg-red-900/50 text-red-300 px-2 py-0.5 rounded border border-red-800">${s.matches} matches</span>
                    </div>
                    <div class="text-slate-300 font-mono text-xs break-all bg-slate-950 p-2 rounded border border-slate-800">
                        <span class="text-slate-500">File:</span> ${s.file}
                    </div>
                    <div class="mt-2 text-xs font-mono text-slate-400 bg-slate-800/50 p-2 rounded border border-slate-700">
                        <span class="text-blue-400 mr-1">💡 Hint:</span> ${s.remediation}
                    </div>
                </div>
            `).join('');
        }

        // Vulnerabilities
        const vulnsCount = document.getElementById('vulnsCount');
        const vulnsList = document.getElementById('vulnsList');
        vulnsCount.textContent = `${data.vulnerabilities.length} Found`;
        
        if (data.vulnerabilities.length === 0) {
            vulnsList.innerHTML = `<div class="text-slate-500 text-sm italic p-4 bg-slate-900/50 rounded-lg border border-slate-800 text-center">No known vulnerabilities detected in dependencies.</div>`;
        } else {
            vulnsList.innerHTML = data.vulnerabilities.map(v => {
                let severityColor = 'text-yellow-400';
                if (v.severity === 'HIGH' || (parseFloat(v.severity) >= 7.0)) severityColor = 'text-red-400';
                
                let fixBadge = v.fixed_version !== 'No patch available' 
                    ? `<span class="text-xs bg-emerald-900/50 text-emerald-400 px-2 py-0.5 rounded border border-emerald-800 font-mono ml-2">Fix: Upgrade to v${v.fixed_version}</span>`
                    : `<span class="text-xs bg-slate-800/50 text-slate-500 px-2 py-0.5 rounded border border-slate-700 font-mono ml-2">No patch available</span>`;
                
                return `
                <div class="p-4 bg-slate-900/80 rounded-lg border border-orange-900/30 flex flex-col gap-2">
                    <div class="flex items-start justify-between">
                        <div>
                            <span class="text-orange-300 font-mono text-sm font-semibold">${v.package}</span>
                            <span class="text-slate-500 text-xs ml-2">v${v.version}</span>
                            ${fixBadge}
                        </div>
                        <span class="text-xs bg-slate-800 px-2 py-0.5 rounded border border-slate-700 font-mono ${severityColor}">${v.id}</span>
                    </div>
                    <div class="text-slate-400 text-sm mt-1">
                        ${v.summary}
                    </div>
                </div>
            `}).join('');
        }
    }
});
