document.addEventListener('DOMContentLoaded', () => {
    // --- Elements ---
    const btnDomains = document.getElementById('btn-domains');
    const btnIps = document.getElementById('btn-ips');
    const targetInput = document.getElementById('target-input');
    const appContainer = document.querySelector('.app-container');
    
    // Initialize container mode
    appContainer.classList.add('mode-domains');
    
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
    const filterInput = document.getElementById('filter-input');

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
        appContainer.classList.add('mode-domains');
        appContainer.classList.remove('mode-ips');
        targetInput.placeholder = "Enter domains here, one per line...";
    });

    btnIps.addEventListener('click', () => {
        if(isChecking) return;
        currentMode = 'ips';
        btnIps.classList.add('active');
        btnDomains.classList.remove('active');
        appContainer.classList.add('mode-ips');
        appContainer.classList.remove('mode-domains');
        targetInput.placeholder = "Enter IP addresses here, one per line...";
    });

    // Clear
    btnClear.addEventListener('click', () => {
        if(isChecking) return;
        targetInput.value = '';
        resultsTbody.innerHTML = '';
        progressContainer.classList.add('hidden');
        resultsData = [];
        filterInput.value = '';
    });

    // Filter
    filterInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        Array.from(resultsTbody.querySelectorAll('tr')).forEach(row => {
            const domainCellText = row.querySelector('td:first-child').textContent.toLowerCase();
            if (domainCellText.includes(query)) {
                row.classList.remove('hidden');
            } else {
                row.classList.add('hidden');
            }
        });
    });

    const btnCopy = document.getElementById('btn-copy');
    
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

    // Copy Results
    btnCopy.addEventListener('click', () => {
        if (resultsData.length === 0) return;
        
        // Format results as TAB separated text (similar to Excel copy/paste)
        let copyText = "TARGET\tSCORE\tSTATUS\tTYPE\tREASON\n";
        resultsData.forEach(row => {
            copyText += `${row.domain}\t${row.score}\t${row.status}\t${row.type}\t${row.reason}\n`;
        });
        
        navigator.clipboard.writeText(copyText).then(() => {
            const originalText = btnCopy.innerHTML;
            btnCopy.innerHTML = '<i data-lucide="check"></i> Copied!';
            lucide.createIcons();
            setTimeout(() => {
                btnCopy.innerHTML = originalText;
                lucide.createIcons();
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy: ', err);
        });
    });

    // Export CSV
    btnExport.addEventListener('click', () => {
        if (resultsData.length === 0) return;
        
        let csvContent = "data:text/csv;charset=utf-8,TARGET,SCORE,SMTP,TYPE,LISTED,EXPIRES,REASON,STATUS\n";
        resultsData.forEach(row => {
            csvContent += `${row.domain},${row.score},${row.smtp},${row.type},${row.listed_date},${row.expiry_date},${row.reason},${row.status}\n`;
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
    const CHUNK_SIZE = 10; // Increased chunk size for better throughput now that tokens are cached

    function chunkArray(arr, size) {
        const chunks = [];
        for (let i = 0; i < arr.length; i += size) {
            chunks.push(arr.slice(i, i + size));
        }
        return chunks;
    }

    async function processTargets(targets, signal) {
        const chunks = chunkArray(targets, CHUNK_SIZE);
        let processed = 0;

        for (const chunk of chunks) {
            if (signal.aborted) throw new DOMException("Aborted", 'AbortError');

            try {
                const response = await fetch('/api/index', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targets: chunk, type: currentMode }),
                    signal: signal
                });

                if (!response.ok) {
                    // Mark all in chunk as error and continue
                    chunk.forEach(t => {
                        const errResult = { domain: t, score: `HTTP ${response.status}`, smtp: "-", date: "-", type: "-", listed_date: "-", expiry_date: "-", reason: "-", status: "Error", statusClass: "status-error" };
                        resultsData.push(errResult);
                        appendResultRow(errResult);
                    });
                    processed += chunk.length;
                    progressText.textContent = `${processed} / ${targets.length}`;
                    progressFill.style.width = `${(processed / targets.length) * 100}%`;
                    continue;
                }

                const data = await response.json();
                const results = Array.isArray(data) ? data : (data.results || []);

                for (const result of results) {
                    if (signal.aborted) throw new DOMException("Aborted", 'AbortError');
                    resultsData.push(result);
                    appendResultRow(result);
                    processed++;
                    progressText.textContent = `${processed} / ${targets.length}`;
                    progressFill.style.width = `${(processed / targets.length) * 100}%`;
                    // Tiny yield to let browser paint the new row
                    await new Promise(r => setTimeout(r, 20));
                }

            } catch (err) {
                if (err.name === 'AbortError') throw err;
                // Network error for this chunk — mark all as error and keep going
                chunk.forEach(t => {
                    const errResult = { domain: t, score: "Net Err", smtp: "-", date: "-", type: "-", listed_date: "-", expiry_date: "-", reason: "-", status: "Error", statusClass: "status-error" };
                    resultsData.push(errResult);
                    appendResultRow(errResult);
                });
                processed += chunk.length;
                progressText.textContent = `${processed} / ${targets.length}`;
                progressFill.style.width = `${(processed / targets.length) * 100}%`;
            }
        }
    }

    function appendResultRow(result) {
        const tr = document.createElement('tr');
        
        const tdDomain = document.createElement('td');
        tdDomain.textContent = result.domain;
        
        const tdScore = document.createElement('td');
        tdScore.textContent = result.score;
        tdScore.classList.add('col-score');
        
        const tdSMTP = document.createElement('td');
        tdSMTP.textContent = result.smtp || "-";
        tdSMTP.classList.add('col-smtp');
        
        const tdType = document.createElement('td');
        tdType.textContent = result.type || "-";
        tdType.classList.add('col-type');
        
        const tdListedDate = document.createElement('td');
        tdListedDate.textContent = result.listed_date || "-";
        tdListedDate.classList.add('col-listed');
        
        const tdExpiryDate = document.createElement('td');
        tdExpiryDate.textContent = result.expiry_date || "-";
        tdExpiryDate.classList.add('col-expiry');
        
        const tdReason = document.createElement('td');
        tdReason.textContent = result.reason || "-";
        tdReason.classList.add('reason-cell', 'col-reason');
        
        const tdStatus = document.createElement('td');
        tdStatus.textContent = result.status;
        if (result.statusClass) {
            tdStatus.classList.add(result.statusClass);
        }

        tr.appendChild(tdDomain);
        tr.appendChild(tdScore);
        tr.appendChild(tdSMTP);
        tr.appendChild(tdType);
        tr.appendChild(tdListedDate);
        tr.appendChild(tdExpiryDate);
        tr.appendChild(tdReason);
        tr.appendChild(tdStatus);

        resultsTbody.appendChild(tr);
    }
});
