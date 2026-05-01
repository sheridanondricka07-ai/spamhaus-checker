document.addEventListener('DOMContentLoaded', () => {
    // --- Elements ---
    const btnDomains = document.getElementById('btn-domains');
    const btnIps = document.getElementById('btn-ips');
    const targetInput = document.getElementById('target-input');
    
    const btnCheck = document.getElementById('btn-check');
    const checkSpinner = document.getElementById('check-spinner');
    const checkText = document.getElementById('check-text');
    checkText.textContent = "Check Domains/IPs"; // Initial state
    
    const btnClear = document.getElementById('btn-clear');
    const btnExport = document.getElementById('btn-export');
    
    const progressContainer = document.getElementById('progress-container');
    const progressText = document.getElementById('progress-text');
    const progressFill = document.getElementById('progress-fill');
    
    const resultsTbody = document.getElementById('results-tbody');
    
    const statusBtns = document.querySelectorAll('.status-btn');
    const scoreMin = document.getElementById('score-min');
    const scoreMax = document.getElementById('score-max');
    let currentStatusFilter = 'All';

    // --- State ---
    let currentMode = 'domains'; // 'domains' | 'ips'
    let isChecking = false;
    let checkAbortController = null;
    let resultsData = []; // Store raw results for sorting/filtering

    // --- Event Listeners ---

    // Toggles
    btnDomains.addEventListener('click', () => {
        if(isChecking) return;
        currentMode = 'domains';
        btnDomains.classList.add('active');
        btnIps.classList.remove('active');
        targetInput.placeholder = "Enter domains here, one per line...";
    });

    btnIps.addEventListener('click', () => {
        if(isChecking) return;
        currentMode = 'ips';
        btnIps.classList.add('active');
        btnDomains.classList.remove('active');
        targetInput.placeholder = "Enter IP addresses here, one per line...";
    });

    // Clear
    btnClear.addEventListener('click', () => {
        if(isChecking) return;
        targetInput.value = '';
        resultsTbody.innerHTML = '';
        progressContainer.classList.add('hidden');
        resultsData = [];
        scoreMin.value = '';
        scoreMax.value = '';
        currentStatusFilter = 'All';
        statusBtns.forEach(b => {
            b.classList.toggle('active', b.dataset.status === 'All');
        });
    });

    // Status Filter
    statusBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            statusBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentStatusFilter = e.target.dataset.status;
            applyFilters();
        });
    });

    // Score Range Filter
    scoreMin.addEventListener('input', applyFilters);
    scoreMax.addEventListener('input', applyFilters);

    function applyFilters() {
        const min = parseFloat(scoreMin.value);
        const max = parseFloat(scoreMax.value);

        Array.from(resultsTbody.querySelectorAll('tr')).forEach(row => {
            const statusCell = row.querySelector('td:nth-child(4)').textContent;
            const scoreText = row.querySelector('td:nth-child(2)').textContent;
            const score = parseFloat(scoreText);

            let show = true;

            // Status Check
            if (currentStatusFilter !== 'All' && !statusCell.includes(currentStatusFilter)) {
                show = false;
            }

            // Score Range Check
            if (show && !isNaN(score)) {
                if (!isNaN(min) && score < min) show = false;
                if (!isNaN(max) && score > max) show = false;
            }

            if (show) {
                row.classList.remove('hidden');
            } else {
                row.classList.add('hidden');
            }
        });
    }

    // Check Action
    btnCheck.addEventListener('click', async () => {
        if (isChecking) {
            // Cancel operation
            if (checkAbortController) {
                checkAbortController.abort();
            }
            return;
        }

        const rawText = targetInput.value;
        const targets = rawText.split('\n')
            .map(t => t.trim())
            .filter(t => t.length > 0);

        if (targets.length === 0) return;

        // Start checking UI state
        isChecking = true;
        checkAbortController = new AbortController();
        
        btnCheck.classList.add('checking');
        checkSpinner.classList.remove('hidden');
        checkSpinner.classList.add('spin');
        checkText.textContent = "Cancel...";
        
        progressContainer.classList.remove('hidden');
        progressFill.style.width = '0%';
        progressText.textContent = `0 / ${targets.length}`;
        resultsTbody.innerHTML = ''; // reset table
        resultsData = [];

        try {
            await processTargets(targets, checkAbortController.signal);
        } catch (err) {
            if (err.name !== 'AbortError') {
                console.error("Checking error:", err);
            }
        } finally {
            // Reset UI state
            isChecking = false;
            checkSpinner.classList.add('hidden');
            checkSpinner.classList.remove('spin');
            checkText.textContent = "Check Domains/IPs";
            checkAbortController = null;
        }
    });

    // Export CSV
    btnExport.addEventListener('click', () => {
        if (resultsData.length === 0) return;
        
        let csvContent = "data:text/csv;charset=utf-8,DOMAIN,SCORE,CREATION DATE,STATUS\n";
        resultsData.forEach(row => {
            csvContent += `${row.domain},${row.score},${row.date},${row.status}\n`;
        });
        
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement('a');
        link.setAttribute('href', encodedUri);
        link.setAttribute('download', `spamhaus_results.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });

    // --- Core Logic ---
    async function processTargets(targets, signal) {
        try {
            const response = await fetch('/api/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets: targets, type: currentMode }),
                signal: signal
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            const results = data.results || [];
            
            for (let i = 0; i < results.length; i++) {
                if (signal.aborted) throw new DOMException("Aborted", 'AbortError');
                
                const result = results[i];
                resultsData.push(result);
                appendResultRow(result);
                applyFilters(); // Re-apply filters as rows are added
                
                const processed = i + 1;
                progressText.textContent = `${processed} / ${targets.length}`;
                progressFill.style.width = `${(processed / targets.length) * 100}%`;
                
                // Keep a tiny delay to allow UI to render cleanly
                await new Promise(r => setTimeout(r, 50));
            }
            
        } catch (err) {
            if (err.name !== 'AbortError') {
                console.error("API Error:", err);
                for (let i = 0; i < targets.length; i++) {
                    const errorResult = {
                        domain: targets[i], 
                        score: "Server Err", 
                        date: "-", 
                        status: "Error", 
                        statusClass: "status-error"
                    };
                    resultsData.push(errorResult);
                    appendResultRow(errorResult);
                }
                progressText.textContent = `Error / ${targets.length}`;
                progressFill.style.width = `100%`;
            }
            throw err;
        }
    }

    function appendResultRow(result) {
        const tr = document.createElement('tr');
        
        const tdDomain = document.createElement('td');
        tdDomain.textContent = result.domain;
        
        const tdScore = document.createElement('td');
        tdScore.textContent = result.score;
        
        const tdSmtp = document.createElement('td');
        tdSmtp.textContent = result.smtp_score !== undefined && result.smtp_score !== null ? result.smtp_score : '-';
        
        const tdStatus = document.createElement('td');
        tdStatus.textContent = result.status;
        if (result.statusClass) {
            tdStatus.classList.add(result.statusClass);
        }

        tr.appendChild(tdDomain);
        tr.appendChild(tdScore);
        tr.appendChild(tdSmtp);
        tr.appendChild(tdStatus);

        resultsTbody.appendChild(tr);
    }
});
