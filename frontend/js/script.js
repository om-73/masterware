document.addEventListener('DOMContentLoaded', () => {
    // Configuration: Set this to your Render Backend URL after deployment
    const PROD_API = 'https://your-render-backend-name.onrender.com';

    // Auto-switch based on hostname
    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const API_BASE = isLocal ? 'http://localhost:5050' : PROD_API;
    // Tabs
    const tabs = {
        file: document.getElementById('tab-file'),
        url: document.getElementById('tab-url'),
        history: document.getElementById('tab-history'),
        protect: document.getElementById('tab-protect')
    };

    // Forms & Views
    const views = {
        file: document.getElementById('file-form'),
        url: document.getElementById('url-form'),
        history: document.getElementById('history-view'),
        protect: document.getElementById('protect-view')
    };

    // Elements
    const fileInput = document.getElementById('file-input');
    const dropArea = document.getElementById('drop-area');
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const loadingText = document.getElementById('loading-text');
    const resultSection = document.getElementById('result-section');
    const errorMsg = document.getElementById('error-msg');
    const riskBadge = document.getElementById('risk-badge');

    let activeMode = 'file';
    let myChart = null;
    let monitorInterval = null;

    // --- Tab Logic ---
    function switchTab(mode) {
        activeMode = mode;
        // Reset active states
        Object.values(tabs).forEach(t => t.classList.remove('active'));
        tabs[mode].classList.add('active');

        // Hide all views
        Object.values(views).forEach(v => v.style.display = 'none');
        views[mode].style.display = 'block';

        // Toggle Scan Button
        if (mode === 'history' || mode === 'protect') {
            scanBtn.style.display = 'none';
            if (monitorInterval) clearInterval(monitorInterval);

            if (mode === 'history') loadHistory();
            if (mode === 'protect') startMonitorPolling();
        } else {
            scanBtn.style.display = 'block';
            if (monitorInterval) clearInterval(monitorInterval);
        }

        resetUI();
    }

    tabs.file.addEventListener('click', () => switchTab('file'));
    tabs.url.addEventListener('click', () => switchTab('url'));
    tabs.history.addEventListener('click', () => switchTab('history'));
    tabs.protect.addEventListener('click', () => switchTab('protect'));

    // --- File Input ---
    dropArea.addEventListener('click', () => fileInput.click());
    dropArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropArea.style.borderColor = 'var(--accent)';
        dropArea.style.background = 'rgba(139, 92, 246, 0.1)';
    });
    dropArea.addEventListener('dragleave', () => {
        dropArea.style.borderColor = 'var(--glass-border)';
        dropArea.style.background = 'transparent';
    });
    dropArea.addEventListener('drop', (e) => {
        e.preventDefault();
        dropArea.style.borderColor = 'var(--glass-border)';
        dropArea.style.background = 'transparent';

        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            updateFileLabel();
        }
    });

    fileInput.addEventListener('change', updateFileLabel);

    function updateFileLabel() {
        if (fileInput.files.length > 0) {
            dropArea.querySelector('p').textContent = `📄 ${fileInput.files[0].name}`;
            dropArea.classList.add('has-file');
        }
    }

    // --- Scan Logic ---
    scanBtn.addEventListener('click', async () => {
        resetUI();
        let formData = new FormData();

        if (activeMode === 'file') {
            if (!fileInput.files[0]) {
                showError("Please select a file first.");
                return;
            }
            formData.append('file', fileInput.files[0]);
        } else {
            const url = urlInput.value.trim();
            if (!url) {
                showError("Please enter a URL.");
                return;
            }
            formData.append('url', url);
        }

        toggleLoading(true, "Authenticating & Initialyzing Local Engine...");

        try {
            const response = await fetch(`${API_BASE}/api/scan`, { method: 'POST', body: formData });
            const data = await response.json();

            // Check for Local Only mode or Error
            if (!data.success) throw new Error(data.error || "Scan failed");

            // Handle Local-Only analysis immediately if present
            if (data.type === 'local_only' || data.local_analysis) {
                // We can render local results here if we want, but for now we proceed to polling
                // or just showing the cloud result if available.
                // If type is local-only, we skip polling and render strictly local data
                if (data.type === 'local_only') {
                    renderLocalResult(data.local_analysis);
                    toggleLoading(false);
                    return;
                }
            }

            let pollLabel = data.cached ? "Result found in cache..." : "Analyzing Cloud Sandbox...";
            window.currentResourceId = data.id; // Store ID for PDF download
            pollResult(data.id, activeMode, activeMode === 'file' ? (fileInput.files[0]?.name) : data.url, pollLabel);

        } catch (err) {
            toggleLoading(false);
            showError(err.message);
        }
    });

    async function pollResult(id, type, name, loadingMsg) {
        toggleLoading(true, loadingMsg);

        const reportUrl = `${API_BASE}/api/report/${id}?type=${type}&filename=${encodeURIComponent(name || 'unknown')}`;

        const pollInterval = setInterval(async () => {
            try {
                const res = await fetch(reportUrl);
                const data = await res.json();

                if (data.status === 'completed') {
                    clearInterval(pollInterval);
                    toggleLoading(false);
                    renderResults(data.data);
                } else if (data.status === 'error') {
                    clearInterval(pollInterval);
                    toggleLoading(false);
                    showError(data.error);
                }
            } catch (e) {
                clearInterval(pollInterval);
                toggleLoading(false);
                showError("Connection interrupted. Retrying...");
            }
        }, 3000);
    }

    // --- Visualization & Results ---
    function renderLocalResult(data) {
        resultSection.style.display = 'block';
        document.getElementById('download-pdf-btn').style.display = 'none'; // No PDF for local yet

        // Map local score to stats format
        const malicious = data.risk === 'Critical' ? 1 : 0;
        const suspicious = data.risk === 'Suspicious' ? 1 : 0;

        // Update Risk Badge
        riskBadge.textContent = data.risk.toUpperCase();
        if (data.risk === 'Critical') riskBadge.className = "risk-badge risk-danger";
        else if (data.risk === 'Suspicious') riskBadge.className = "risk-badge risk-warning";
        else riskBadge.className = "risk-badge risk-safe";

        // Render Chart (Simplified for local)
        renderChart(malicious, suspicious, 1);

        const tbody = document.getElementById('result-body');
        tbody.innerHTML = '';

        data.details.forEach(detail => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>Local Heuristics Engine</td>
                <td><span class="badge malicious">Alert</span></td>
                <td>${detail}</td>
            `;
            tbody.appendChild(row);
        });
    }

    function renderResults(data) {
        resultSection.style.display = 'block';

        const stats = data.stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = (stats.harmless || 0) + (stats.undetected || 0);

        // Update Risk Badge
        if (malicious > 0) {
            riskBadge.textContent = "THREAT DETECTED";
            riskBadge.className = "risk-badge risk-danger";
        } else if (suspicious > 0) {
            riskBadge.textContent = "SUSPICIOUS ACTIVITY";
            riskBadge.className = "risk-badge risk-warning";
        } else {
            riskBadge.textContent = "CLEAN & SAFE";
            riskBadge.className = "risk-badge risk-safe";
        }

        // Show/Hide PDF Button
        const pdfBtn = document.getElementById('download-pdf-btn');
        if (window.currentResourceId) {
            pdfBtn.style.display = 'inline-block';
            pdfBtn.onclick = () => {
                window.open(`${API_BASE}/api/report/${window.currentResourceId}/pdf`, '_blank');
            };
        } else {
            pdfBtn.style.display = 'none';
        }

        renderChart(malicious, suspicious, harmless);

        const tbody = document.getElementById('result-body');
        tbody.innerHTML = '';

        const results = Object.entries(data.results).sort((a, b) => {
            const catA = a[1].category;
            const catB = b[1].category;
            const priority = { 'malicious': 3, 'suspicious': 2, 'harmless': 1, 'undetected': 0 };
            return (priority[catB] || 0) - (priority[catA] || 0);
        });

        results.slice(0, 50).forEach(([engine, info]) => {
            const row = document.createElement('tr');
            let badgeClass = 'clean';
            if (info.category === 'malicious') badgeClass = 'malicious';
            if (info.category === 'suspicious') badgeClass = 'suspicious';

            row.innerHTML = `
                <td>${engine}</td>
                <td><span class="badge ${badgeClass}">${info.result || 'Clean'}</span></td>
                <td>${info.category}</td>
            `;
            tbody.appendChild(row);
        });
    }

    function renderChart(malicious, suspicious, harmless) {
        const ctx = document.getElementById('scoreChart').getContext('2d');
        if (myChart) myChart.destroy();
        myChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Malicious', 'Suspicious', 'Safe'],
                datasets: [{
                    data: [malicious, suspicious, harmless],
                    backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                    borderColor: 'rgba(30, 41, 59, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
            }
        });
    }

    // --- History & Protection Logic ---
    async function loadHistory() {
        const historyList = document.getElementById('history-list');
        historyList.innerHTML = '<p style="text-align:center; color: var(--text-secondary);">Loading records...</p>';
        try {
            const res = await fetch(`${API_BASE}/api/history`);
            const data = await res.json();
            if (data.length === 0) { historyList.innerHTML = '<p style="text-align:center;">No history.</p>'; return; }
            historyList.innerHTML = '';
            data.forEach(item => {
                const el = document.createElement('div');
                el.className = 'history-item';
                let borderColor = '#10b981';
                if (item.score_malicious > 0) borderColor = '#ef4444';
                el.style.borderLeft = `4px solid ${borderColor}`;
                el.innerHTML = `
                    <div class="history-meta">
                        <span class="history-filename">${item.filename || 'Unknown'}</span>
                        <span class="history-date">${item.timestamp}</span>
                    </div>
                    <div><span class="badge ${item.score_malicious > 0 ? 'malicious' : 'clean'}">${item.score_malicious} detections</span></div>
                `;
                el.addEventListener('click', () => {
                    tabs.file.click();
                    window.currentResourceId = item.resource_id; // Store ID for PDF
                    pollResult(item.resource_id, item.resource_type, item.filename, "Loading...");
                });
                historyList.appendChild(el);
            });
        } catch (e) { historyList.innerHTML = "<p>Error loading history</p>"; }
    }

    function startMonitorPolling() {
        updateMonitorLogs();
        updateQuarantineList();
        monitorInterval = setInterval(() => {
            updateMonitorLogs();
            updateQuarantineList();
        }, 3000);
    }

    async function updateMonitorLogs() {
        try {
            const res = await fetch(`${API_BASE}/api/monitor/logs`);
            const logs = await res.json();
            const container = document.getElementById('monitor-logs');
            container.innerHTML = logs.map(l => `<div class="monitor-log-item">[${l.time}] ${l.file}: ${l.info}</div>`).join('');
            // Scroll to bottom
            container.scrollTop = container.scrollHeight;
        } catch (e) { }
    }

    async function updateQuarantineList() {
        try {
            const res = await fetch(`${API_BASE}/api/quarantine`);
            const items = await res.json();
            const container = document.getElementById('quarantine-list');
            if (items.length === 0) { container.innerHTML = "<p>No quarantined items.</p>"; return; }

            container.innerHTML = items.map(item => `
                <div class="quarantine-item">
                    <div>
                        <strong>${item.original_name}</strong><br>
                        <small>${item.timestamp}</small>
                    </div>
                    <div class="q-actions">
                        <button onclick="restoreItem('${item.id}')">Restore</button>
                        <button onclick="deleteItem('${item.id}')">Delete</button>
                    </div>
                </div>
            `).join('');
        } catch (e) { }
    }

    // Global functions for inline onclicks
    window.restoreItem = async (id) => {
        if (!confirm("Restore this file? It may be dangerous.")) return;
        await fetch(`${API_BASE}/api/quarantine/restore`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
        updateQuarantineList();
    };
    window.deleteItem = async (id) => {
        if (!confirm("Permanently delete?")) return;
        await fetch(`${API_BASE}/api/quarantine/delete`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
        updateQuarantineList();
    };

    // --- Utils ---
    function resetUI() {
        resultSection.style.display = 'none';
        errorMsg.style.display = 'none';
        document.getElementById('download-pdf-btn').style.display = 'none'; // Hide by default
        window.currentResourceId = null; // Reset ID
        toggleLoading(false);
    }

    function toggleLoading(show, text = "") {
        loader.style.display = show ? 'block' : 'none';
        loadingText.style.display = show ? 'block' : 'none';
        loadingText.textContent = text;
        scanBtn.disabled = show;
    }

    function showError(msg) {
        errorMsg.textContent = `⚠️ ${msg}`;
        errorMsg.style.display = 'block';
        errorMsg.style.color = 'var(--danger)';
        errorMsg.style.textAlign = 'center';
        errorMsg.style.marginTop = '1rem';
    }
});
