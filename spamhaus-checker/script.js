document.addEventListener('DOMContentLoaded', () => {
    // --- Elements ---
    const btnDomains = document.getElementById('btn-domains');
    const btnIps = document.getElementById('btn-ips');
    const targetInput = document.getElementById('target-input');
    
    const btnCheck = document.getElementById('btn-check');
    const checkSpinner = document.getElementById('check-spinner');
    const checkText = document.getElementById('check-text');
    checkText.textContent = "Check Domains/IPs";
    
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
    let currentGradeFilter = 'All';
    const gradeBtns = document.querySelectorAll('.grade-btn');

    // Modal
    const modalOverlay = document.getElementById('modal-overlay');
    const modalContainer = document.getElementById('modal-container');
    const modalClose = document.getElementById('modal-close');
    const modalDomainTitle = document.getElementById('modal-domain-title');
    const modalBody = document.getElementById('modal-body');

    // --- State ---
    let currentMode = 'domains';
    let isChecking = false;
    let checkAbortController = null;
    let resultsData = [];

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
        currentGradeFilter = 'All';
        statusBtns.forEach(b => {
            b.classList.toggle('active', b.dataset.status === 'All');
        });
        gradeBtns.forEach(b => {
            b.classList.toggle('active', b.dataset.grade === 'All');
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

    // Grade Filter
    gradeBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            gradeBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentGradeFilter = e.target.dataset.grade;
            applyFilters();
        });
    });

    // Score Range Filter (now filters by email score)
    scoreMin.addEventListener('input', applyFilters);
    scoreMax.addEventListener('input', applyFilters);

    function applyFilters() {
        const min = parseFloat(scoreMin.value);
        const max = parseFloat(scoreMax.value);

        Array.from(resultsTbody.querySelectorAll('tr')).forEach(row => {
            const statusCell = row.querySelector('td:nth-child(5)');
            const emailScoreCell = row.querySelector('.email-score-num');
            
            if (!statusCell) return;
            
            const statusText = statusCell.textContent;
            const emailScore = emailScoreCell ? parseFloat(emailScoreCell.dataset.score) : NaN;
            const rowGrade = row.dataset.emailGrade || '';

            let show = true;

            // Status Check
            if (currentStatusFilter !== 'All' && !statusText.includes(currentStatusFilter)) {
                show = false;
            }

            // Grade Check
            if (show && currentGradeFilter !== 'All' && rowGrade !== currentGradeFilter) {
                show = false;
            }

            // Email Score Range Check
            if (show && !isNaN(emailScore)) {
                if (!isNaN(min) && emailScore < min) show = false;
                if (!isNaN(max) && emailScore > max) show = false;
            }

            if (show) {
                row.classList.remove('hidden');
            } else {
                row.classList.add('hidden');
            }
        });
    }

    // Modal Close
    modalClose.addEventListener('click', closeModal);
    modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) closeModal();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });

    function closeModal() {
        modalOverlay.classList.add('hidden');
    }

    function openDetailsModal(result) {
        const domain = result.domain;
        const checks = result.email_checks || {};
        const score = result.email_score || 0;
        const grade = result.email_grade || 'F';
        const gradeClass = result.email_grade_class || 'grade-fail';

        modalDomainTitle.textContent = domain;
        
        // Build modal content
        const circumference = 2 * Math.PI * 30; // r=30 for the modal ring
        const offset = circumference - (score / 10) * circumference;

        let html = `
            <div class="modal-score-summary">
                <div class="modal-score-ring">
                    <svg viewBox="0 0 72 72">
                        <circle class="ring-bg" cx="36" cy="36" r="30"></circle>
                        <circle class="ring-fill ${gradeClass}" cx="36" cy="36" r="30"
                            style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset};">
                        </circle>
                    </svg>
                    <span class="score-value">${score}</span>
                </div>
                <div class="modal-score-info">
                    <h3 class="${gradeClass}" style="color: var(--${gradeClass.replace('grade-', 'grade-')})">${grade}</h3>
                    <p>Email Deliverability Score: <strong>${score}/10</strong></p>
                </div>
            </div>
            <div class="check-grid">
        `;

        // SPF
        const spf = checks.spf || {};
        html += buildCheckItem(
            'SPF Record',
            spf.exists,
            spf.exists 
                ? `${spf.strictness} — <code>${truncate(spf.record, 80)}</code>` 
                : 'No SPF record found',
            spf.score, 1.5
        );

        // DKIM
        const dkim = checks.dkim || {};
        html += buildCheckItem(
            'DKIM Signing',
            dkim.exists,
            dkim.exists 
                ? `Selector: <code>${dkim.selector}</code>` 
                : 'No DKIM selector found (checked 20+ common selectors)',
            dkim.score, 1.5
        );

        // DMARC
        const dmarc = checks.dmarc || {};
        html += buildCheckItem(
            'DMARC Policy',
            dmarc.exists,
            dmarc.exists 
                ? `Policy: <strong>${dmarc.policy}</strong>${dmarc.has_rua ? ' · Reporting ✓' : ''}` 
                : 'No DMARC record found',
            dmarc.score, 2.0
        );

        // MX
        const mx = checks.mx || {};
        html += buildCheckItem(
            'MX Records',
            mx.exists,
            mx.exists 
                ? mx.records.map(r => `<code>${r.host}</code> (pri: ${r.priority})`).join('<br>') 
                : 'No MX records found',
            mx.score, 1.5
        );

        // BIMI
        const bimi = checks.bimi || {};
        html += buildCheckItem(
            'BIMI (Gmail Blue Check)',
            bimi.exists,
            bimi.exists 
                ? `<code>${truncate(bimi.record, 80)}</code>` 
                : 'No BIMI record — not required but helps Gmail trust',
            bimi.score, 0.5
        );

        // PTR
        const ptr = checks.ptr || {};
        html += buildCheckItem(
            'Reverse DNS (PTR)',
            ptr.exists,
            ptr.exists 
                ? `IP: <code>${ptr.ip}</code> → <code>${ptr.ptr}</code>` 
                : 'No PTR / reverse DNS found for mail server',
            ptr.score, 0.5
        );

        // Domain Age
        const age = checks.domain_age || {};
        html += buildCheckItem(
            'Domain Age',
            age.exists,
            age.exists 
                ? `Created: <strong>${age.creation_date}</strong> — ${age.age_years} years old` 
                : 'Could not determine domain age (WHOIS private)',
            age.score, 1.0
        );

        // SMTP TLS
        const tls = checks.smtp_tls || {};
        html += buildCheckItem(
            'SMTP TLS Encryption',
            tls.exists && tls.tls,
            tls.exists 
                ? (tls.tls ? `<code>${tls.host}</code> supports STARTTLS ✓` : `<code>${tls.host}</code> does NOT support TLS`)
                : 'Could not connect to mail server on port 25',
            tls.score, 1.0
        );

        html += '</div>';
        
        modalBody.innerHTML = html;
        modalOverlay.classList.remove('hidden');

        // Trigger ring animation
        requestAnimationFrame(() => {
            const ringFill = modalBody.querySelector('.ring-fill');
            if (ringFill) {
                ringFill.style.strokeDashoffset = offset;
            }
        });

        // Re-init lucide icons in modal
        lucide.createIcons();
    }

    function buildCheckItem(title, passed, detail, score, maxScore) {
        const statusClass = passed ? 'pass' : (score > 0 ? 'partial' : 'fail');
        const icon = passed ? 'check' : (score > 0 ? 'minus' : 'x');
        const pts = `${score || 0}/${maxScore}`;
        
        return `
            <div class="check-item">
                <div class="check-icon ${statusClass}">
                    <i data-lucide="${icon}"></i>
                </div>
                <div class="check-info">
                    <div class="check-title">
                        ${title}
                        <span class="check-pts">${pts} pts</span>
                    </div>
                    <div class="check-detail">${detail}</div>
                </div>
            </div>
        `;
    }

    function truncate(str, len) {
        if (!str) return '';
        return str.length > len ? str.substring(0, len) + '…' : str;
    }

    // Check Action
    btnCheck.addEventListener('click', async () => {
        if (isChecking) {
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
        resultsTbody.innerHTML = '';
        resultsData = [];

        try {
            await processTargets(targets, checkAbortController.signal);
        } catch (err) {
            if (err.name !== 'AbortError') {
                console.error("Checking error:", err);
            }
        } finally {
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
        
        let csvContent = "data:text/csv;charset=utf-8,DOMAIN,SPAMHAUS_SCORE,EMAIL_SCORE,EMAIL_GRADE,SMTP,STATUS\n";
        resultsData.forEach(row => {
            const emailScore = row.email_score !== undefined ? row.email_score : '-';
            const emailGrade = row.email_grade || '-';
            csvContent += `${row.domain},${row.score},${emailScore},${emailGrade},${row.smtp_score || '-'},${row.status}\n`;
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
                applyFilters();
                
                const processed = i + 1;
                progressText.textContent = `${processed} / ${targets.length}`;
                progressFill.style.width = `${(processed / targets.length) * 100}%`;
                
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
                        statusClass: "status-error",
                        email_score: 0,
                        email_grade: "F",
                        email_grade_class: "grade-fail",
                        email_checks: {}
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

    function createScoreRing(score, gradeClass) {
        const circumference = 2 * Math.PI * 18; // r=18 for small ring
        const offset = circumference - (score / 10) * circumference;
        
        const container = document.createElement('div');
        container.className = 'email-score-cell';
        
        // Ring
        const ring = document.createElement('div');
        ring.className = 'score-ring';
        ring.innerHTML = `
            <svg viewBox="0 0 42 42">
                <circle class="ring-bg" cx="21" cy="21" r="18"></circle>
                <circle class="ring-fill ${gradeClass}" cx="21" cy="21" r="18"
                    style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${circumference};">
                </circle>
            </svg>
            <span class="score-value">${score}</span>
        `;
        
        container.appendChild(ring);
        
        // Animate the ring fill after a short delay
        requestAnimationFrame(() => {
            setTimeout(() => {
                const fill = ring.querySelector('.ring-fill');
                if (fill) fill.style.strokeDashoffset = offset;
            }, 100);
        });
        
        return container;
    }

    function appendResultRow(result) {
        const tr = document.createElement('tr');
        tr.dataset.emailGrade = result.email_grade || '';
        
        // TARGET
        const tdDomain = document.createElement('td');
        tdDomain.textContent = result.domain;
        
        // SPAMHAUS SCORE
        const tdScore = document.createElement('td');
        tdScore.textContent = result.score;
        
        // EMAIL SCORE (ring badge)
        const tdEmailScore = document.createElement('td');
        if (currentMode === 'domains' && result.email_score !== undefined) {
            const ringEl = createScoreRing(result.email_score, result.email_grade_class || 'grade-fail');
            
            // Add grade info
            const gradeDiv = document.createElement('div');
            gradeDiv.className = 'score-grade';
            gradeDiv.innerHTML = `
                <span class="grade-letter ${result.email_grade_class || ''}">${result.email_grade || 'F'}</span>
                <span class="grade-label">${getGradeLabel(result.email_grade)}</span>
            `;
            ringEl.appendChild(gradeDiv);
            
            // Hidden element for filtering
            const hiddenScore = document.createElement('span');
            hiddenScore.className = 'email-score-num';
            hiddenScore.style.display = 'none';
            hiddenScore.dataset.score = result.email_score;
            ringEl.appendChild(hiddenScore);
            
            tdEmailScore.appendChild(ringEl);
        } else {
            tdEmailScore.textContent = '-';
        }
        
        // SMTP
        const tdSmtp = document.createElement('td');
        tdSmtp.textContent = result.smtp_score !== undefined && result.smtp_score !== null ? result.smtp_score : '-';
        
        // STATUS
        const tdStatus = document.createElement('td');
        tdStatus.textContent = result.status;
        if (result.statusClass) {
            tdStatus.classList.add(result.statusClass);
        }

        // DETAILS button
        const tdDetails = document.createElement('td');
        if (currentMode === 'domains' && result.email_checks) {
            const btn = document.createElement('button');
            btn.className = 'btn-details';
            btn.innerHTML = '<i data-lucide="eye"></i> View';
            btn.addEventListener('click', () => openDetailsModal(result));
            tdDetails.appendChild(btn);
        } else {
            tdDetails.textContent = '-';
        }

        tr.appendChild(tdDomain);
        tr.appendChild(tdScore);
        tr.appendChild(tdEmailScore);
        tr.appendChild(tdSmtp);
        tr.appendChild(tdStatus);
        tr.appendChild(tdDetails);

        resultsTbody.appendChild(tr);
        
        // Re-init lucide icons for new elements
        lucide.createIcons();
    }

    function getGradeLabel(grade) {
        switch(grade) {
            case 'A+': return 'Excellent';
            case 'A': return 'Good';
            case 'B': return 'Average';
            case 'C': return 'Below Avg';
            case 'D': return 'Poor';
            case 'F': return 'Failing';
            default: return '';
        }
    }
});
