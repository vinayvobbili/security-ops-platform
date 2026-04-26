/* ═══════════════════════════════════════════════════════════════════
   Cribl Edge Diagnostics — workbench controller
   ═══════════════════════════════════════════════════════════════════ */
(function () {
    'use strict';

    /* ── State ──────────────────────────────────────────────────── */
    let sessionId = null;
    let currentPage = 1;
    let lastSummary = null;
    let lastTable = null;
    let activeFilters = {};
    let completedSteps = new Set();
    const perPage = 100;

    /* ── DOM refs ───────────────────────────────────────────────── */
    const $  = (s) => document.querySelector(s);
    const $$ = (s) => document.querySelectorAll(s);

    const uploadZone   = $('#cdUploadZone');
    const fileInput     = $('#cdFileInput');
    const workbench     = $('#cdWorkbench');
    const progressBox   = $('#cdProgress');
    const progressLabel = $('#cdProgressLabel');
    const progressCount = $('#cdProgressCount');
    const progressFill  = $('#cdProgressFill');
    const actionLog     = $('#cdActionLog');
    const tableHead     = $('#cdTableHead');
    const tableBody     = $('#cdTableBody');
    const pagerPrev     = $('#cdPagerPrev');
    const pagerNext     = $('#cdPagerNext');
    const pagerInfo     = $('#cdPagerInfo');

    const btnDedup      = $('#cdBtnDedup');
    const btnFilterDisc = $('#cdBtnFilterDisc');
    const btnReset      = $('#cdBtnReset');
    const btnPing       = $('#cdBtnPing');
    const btnSnow       = $('#cdBtnSnow');
    const btnDiagnose   = $('#cdBtnDiagnose');
    const btnExport     = $('#cdBtnExport');
    const btnRunAll     = $('#cdBtnRunAll');
    const presetsBar    = $('#cdPresets');
    let activePreset    = 'all';

    /* ── Upload handling ────────────────────────────────────────── */
    uploadZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) uploadFile(fileInput.files[0]);
    });
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('cd-drag-over');
    });
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('cd-drag-over');
    });
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('cd-drag-over');
        if (e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);
    });

    async function uploadFile(file) {
        if (!file.name.endsWith('.csv')) {
            addLog('Please upload a .csv file', 'error');
            return;
        }
        uploadZone.querySelector('.cd-upload-label').textContent = 'Uploading...';

        const form = new FormData();
        form.append('file', file);

        try {
            const res = await fetch('/api/cribl-diagnostics/upload', { method: 'POST', body: form });
            const data = await res.json();
            if (!data.success) {
                addLog(data.error || 'Upload failed', 'error');
                uploadZone.querySelector('.cd-upload-label').textContent = 'Drop your Cribl edgeNodes CSV file here';
                return;
            }
            sessionId = data.session_id;
            activeFilters = {};
            completedSteps = new Set();
            actionLog.innerHTML = '';
            addLog(`Uploaded ${file.name} — ${data.summary.total_rows.toLocaleString()} rows`, 'success');
            updateSummary(data.summary);
            renderTable(data.table);
            updateButtonStates();
            updateStepStates();
            uploadZone.style.display = 'none';
            workbench.style.display = 'block';
        } catch (err) {
            addLog(`Upload error: ${err.message}`, 'error');
            uploadZone.querySelector('.cd-upload-label').textContent = 'Drop your Cribl edgeNodes CSV file here';
        }
    }

    /* ── Summary cards ──────────────────────────────────────────── */
    function updateSummary(s) {
        lastSummary = s;
        $('#cdTotalRows').textContent     = s.total_rows.toLocaleString();
        $('#cdUniqueHosts').textContent   = s.unique_hosts.toLocaleString();
        $('#cdConnected').textContent     = s.connected.toLocaleString();
        $('#cdDisconnected').textContent  = s.disconnected.toLocaleString();
        $('#cdDuplicates').textContent    = s.duplicate_hosts.toLocaleString();
    }

    /* ── Smart button states ────────────────────────────────────── */
    function updateButtonStates() {
        if (!lastSummary) return;
        const s = lastSummary;
        btnDedup.disabled = s.duplicate_hosts === 0;
        btnFilterDisc.disabled = s.connected === 0 || s.disconnected === 0;
    }

    /* ── Step highlighting ──────────────────────────────────────── */
    function updateStepStates() {
        for (let i = 1; i <= 6; i++) {
            const el = $(`#cdStep${i}`);
            if (!el) continue;
            el.classList.remove('cd-step--done', 'cd-step--active');
            if (completedSteps.has(i)) {
                el.classList.add('cd-step--done');
            }
        }
        // Highlight next incomplete step
        for (let i = 1; i <= 6; i++) {
            if (!completedSteps.has(i)) {
                const el = $(`#cdStep${i}`);
                if (el) el.classList.add('cd-step--active');
                break;
            }
        }
    }

    function markStepDone(stepNum) {
        completedSteps.add(stepNum);
        updateStepStates();
        // Show presets bar once diagnose (step 5) is done
        if (stepNum === 5 && presetsBar) {
            presetsBar.style.display = 'flex';
        }
    }

    /* ── Quick filter presets ───────────────────────────────────── */
    presetsBar.querySelectorAll('.cd-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            activePreset = btn.dataset.preset;
            // Update active styling
            presetsBar.querySelectorAll('.cd-preset').forEach(b => b.classList.remove('cd-preset--active'));
            btn.classList.add('cd-preset--active');
            // Re-render with filter
            if (lastTable) renderTable(lastTable);
        });
    });

    /* ── Data table rendering ───────────────────────────────────── */
    const SPECIAL_COLS = {
        'Connection': (v) => {
            if (v === 'Connected')    return `<span class="cd-cell-connected">${v}</span>`;
            if (v === 'Disconnected') return `<span class="cd-cell-disconnected">${v}</span>`;
            return v || '';
        },
        'Ping Reachable': (v) => {
            if (v === 'Yes') return `<span class="cd-cell-yes">Yes</span>`;
            if (v === 'No')  return `<span class="cd-cell-no">No</span>`;
            return v || '';
        },
        'Diagnosis': (v) => {
            if (!v) return '';
            let cls = 'cd-diag--unknown';
            if (v.includes('Agent Down'))    cls = 'cd-diag--agent-down';
            else if (v === 'Host Down')      cls = 'cd-diag--host-down';
            else if (v === 'Decommissioned') cls = 'cd-diag--decom';
            else if (v === 'Online')         cls = 'cd-diag--online';
            return `<span class="cd-diag ${cls}">${v}</span>`;
        },
    };

    const HIDE_COLS = new Set(['Connected at', 'Disconnected at', 'Last Heartbeat', 'GUID', 'Config Version']);

    const FILTERABLE_COLS = new Set([
        'Connection', 'Sources', 'Destinations', 'Fleet', 'Edge Version',
        'Ping Reachable', 'Diagnosis', 'SNOW Status', 'SNOW Lifecycle',
        'SNOW Environment', 'SNOW CI Class', 'SNOW Country',
    ]);

    function renderTable(table) {
        lastTable = table;
        const cols = table.columns.filter(c => !HIDE_COLS.has(c));
        currentPage = table.page;

        const colValues = {};
        for (const c of cols) {
            if (FILTERABLE_COLS.has(c)) {
                const vals = new Set();
                for (const rec of table.records) {
                    const v = rec[c];
                    if (v != null && v !== '') vals.add(String(v));
                }
                colValues[c] = [...vals].sort();
            }
        }

        let headerRow = '<tr>' + cols.map(c => `<th>${esc(c)}</th>`).join('') + '</tr>';

        let filterRow = '<tr class="cd-filter-row">' + cols.map(c => {
            if (!FILTERABLE_COLS.has(c) || !colValues[c] || colValues[c].length < 1) {
                return '<th class="cd-filter-cell"></th>';
            }
            const active = activeFilters[c];
            const activeClass = active && active.size > 0 ? ' cd-filter-active' : '';
            return `<th class="cd-filter-cell">
                <button class="cd-filter-btn${activeClass}" data-col="${esc(c)}" title="Filter ${esc(c)}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
                    ${active && active.size > 0 ? `<span class="cd-filter-count">${active.size}</span>` : ''}
                </button>
            </th>`;
        }).join('') + '</tr>';

        tableHead.innerHTML = headerRow + filterRow;

        tableHead.querySelectorAll('.cd-filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                openFilterDropdown(btn, btn.dataset.col, colValues[btn.dataset.col] || []);
            });
        });

        let records = table.records;

        /* Apply preset filter */
        if (activePreset !== 'all' && cols.includes('Diagnosis')) {
            const PRESET_MAP = {
                'host-down': 'Host Down',
                'agent-down': 'Agent Down (Host Reachable)',
                'decommissioned': 'Decommissioned',
                'online': 'Online',
                'unknown': 'Unknown',
            };
            const target = PRESET_MAP[activePreset];
            if (target) {
                records = records.filter(rec => rec['Diagnosis'] === target);
            }
        }

        /* Apply column filters */
        if (Object.keys(activeFilters).length > 0) {
            records = records.filter(rec => {
                for (const [col, vals] of Object.entries(activeFilters)) {
                    if (vals.size === 0) continue;
                    const v = rec[col] == null ? '' : String(rec[col]);
                    if (!vals.has(v)) return false;
                }
                return true;
            });
        }

        if (records.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="${cols.length}" style="text-align:center;padding:30px;color:var(--cd-text-dim)">No data matching filters</td></tr>`;
        } else {
            tableBody.innerHTML = records.map(rec => {
                return '<tr>' + cols.map(c => {
                    const val = rec[c];
                    const display = SPECIAL_COLS[c] ? SPECIAL_COLS[c](val) : esc(val);
                    return `<td>${display}</td>`;
                }).join('') + '</tr>';
            }).join('');
        }

        const hasClientFilter = activePreset !== 'all' || Object.values(activeFilters).some(s => s.size > 0);
        const filterNote = hasClientFilter ? ` (${records.length} shown)` : '';
        pagerInfo.textContent = `Page ${table.page} of ${table.total_pages} (${table.total.toLocaleString()} rows)${filterNote}`;
        pagerPrev.disabled = table.page <= 1;
        pagerNext.disabled = table.page >= table.total_pages;

        /* Update preset badge counts from the full page of records (before filters) */
        if (cols.includes('Diagnosis')) {
            const diagCounts = {};
            for (const rec of table.records) {
                const d = rec['Diagnosis'] || '';
                diagCounts[d] = (diagCounts[d] || 0) + 1;
            }
            const PRESET_DIAG = {
                'host-down': 'Host Down',
                'agent-down': 'Agent Down (Host Reachable)',
                'decommissioned': 'Decommissioned',
                'online': 'Online',
                'unknown': 'Unknown',
            };
            presetsBar.querySelectorAll('.cd-preset[data-preset]').forEach(btn => {
                const p = btn.dataset.preset;
                if (p === 'all') {
                    btn.textContent = `Show All (${table.records.length})`;
                } else if (PRESET_DIAG[p]) {
                    const cnt = diagCounts[PRESET_DIAG[p]] || 0;
                    btn.textContent = `${PRESET_DIAG[p]} (${cnt})`;
                }
            });
        }
    }

    /* ── Filter dropdown ────────────────────────────────────────── */
    function openFilterDropdown(anchorBtn, col, values) {
        closeFilterDropdown();
        const dropdown = document.createElement('div');
        dropdown.className = 'cd-filter-dropdown';
        dropdown.id = 'cdFilterDropdown';
        const current = activeFilters[col] || new Set();

        let html = `<div class="cd-filter-dropdown-header">
            <span class="cd-filter-dropdown-title">${esc(col)}</span>
            <div class="cd-filter-dropdown-actions">
                <button class="cd-filter-action" data-action="all">All</button>
                <button class="cd-filter-action" data-action="none">None</button>
            </div>
        </div><div class="cd-filter-dropdown-list">`;
        for (const val of values) {
            const checked = current.size === 0 || current.has(val) ? 'checked' : '';
            html += `<label class="cd-filter-option"><input type="checkbox" value="${esc(val)}" ${checked}><span>${esc(val)}</span></label>`;
        }
        html += '</div><div class="cd-filter-dropdown-footer"><button class="cd-filter-apply">Apply Filter</button></div>';
        dropdown.innerHTML = html;

        const rect = anchorBtn.getBoundingClientRect();
        dropdown.style.position = 'fixed';
        dropdown.style.top = (rect.bottom + 4) + 'px';
        dropdown.style.left = Math.max(4, rect.left - 60) + 'px';
        dropdown.style.zIndex = '9000';
        document.body.appendChild(dropdown);

        dropdown.querySelectorAll('.cd-filter-action').forEach(btn => {
            btn.addEventListener('click', () => {
                const check = btn.dataset.action === 'all';
                dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => { cb.checked = check; });
            });
        });
        dropdown.querySelector('.cd-filter-apply').addEventListener('click', () => {
            const selected = new Set();
            dropdown.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => { selected.add(cb.value); });
            if (selected.size === values.length) {
                delete activeFilters[col];
            } else {
                activeFilters[col] = selected;
            }
            closeFilterDropdown();
            renderTable(lastTable);
        });
        setTimeout(() => { document.addEventListener('click', _outsideClickClose); }, 0);
    }
    function _outsideClickClose(e) {
        const dd = document.getElementById('cdFilterDropdown');
        if (dd && !dd.contains(e.target)) closeFilterDropdown();
    }
    function closeFilterDropdown() {
        const dd = document.getElementById('cdFilterDropdown');
        if (dd) dd.remove();
        document.removeEventListener('click', _outsideClickClose);
    }

    function esc(v) {
        if (v == null) return '';
        return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    /* ── Pagination ─────────────────────────────────────────────── */
    pagerPrev.addEventListener('click', () => fetchPage(currentPage - 1));
    pagerNext.addEventListener('click', () => fetchPage(currentPage + 1));

    async function fetchPage(page) {
        try {
            const res = await fetch(`/api/cribl-diagnostics/data?session_id=${sessionId}&page=${page}&per_page=${perPage}`);
            const data = await res.json();
            if (data.success) {
                renderTable(data.table);
                updateSummary(data.summary);
                updateButtonStates();
            }
        } catch (err) {
            addLog(`Error fetching page: ${err.message}`, 'error');
        }
    }

    /* ── Action buttons ─────────────────────────────────────────── */
    btnDedup.addEventListener('click', () => {
        postAction('/api/cribl-diagnostics/deduplicate', 1);
    });
    btnFilterDisc.addEventListener('click', () => {
        postAction('/api/cribl-diagnostics/filter-disconnected', 2);
    });
    btnReset.addEventListener('click', () => {
        activeFilters = {};
        completedSteps = new Set();
        activePreset = 'all';
        presetsBar.style.display = 'none';
        presetsBar.querySelectorAll('.cd-preset').forEach(b => b.classList.remove('cd-preset--active'));
        postAction('/api/cribl-diagnostics/reset', null);
    });
    btnDiagnose.addEventListener('click', () => {
        postAction('/api/cribl-diagnostics/diagnose', 5);
    });

    async function postAction(url, stepNum) {
        try {
            setToolbarBusy(true);
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionId }),
            });
            const data = await res.json();
            if (!data.success) {
                addLog(data.error || 'Action failed', 'error');
                return;
            }
            if (data.message) addLog(data.message, 'success');
            if (data.summary) updateSummary(data.summary);
            if (data.table) renderTable(data.table);
            if (stepNum) markStepDone(stepNum);
            updateButtonStates();
        } catch (err) {
            addLog(`Error: ${err.message}`, 'error');
        } finally {
            setToolbarBusy(false);
        }
    }

    /* ── Ping (SSE) ─────────────────────────────────────────────── */
    btnPing.addEventListener('click', () => {
        runSSE(
            `/api/cribl-diagnostics/ping?session_id=${sessionId}`,
            'Pinging hosts — checking which machines are reachable on the network...',
            (d) => `${d.completed} of ${d.total} pinged — ${d.reachable || 0} reachable so far`,
            (d) => `Ping complete: ${d.reachable} reachable, ${d.unreachable} unreachable`,
            3
        );
    });

    /* ── SNOW Enrich (SSE) ──────────────────────────────────────── */
    btnSnow.addEventListener('click', () => {
        runSSE(
            `/api/cribl-diagnostics/enrich-snow?session_id=${sessionId}`,
            'Looking up hosts in ServiceNow CMDB...',
            (d) => `${d.completed} of ${d.total} looked up — ${d.found || 0} found so far`,
            (d) => `ServiceNow lookup complete: ${d.found} found, ${d.not_found} not found`,
            4
        );
    });

    function runSSE(url, label, progressFmt, completeFmt, stepNum) {
        setToolbarBusy(true);
        showProgress(label, '');

        const es = new EventSource(url);
        es.onmessage = (e) => {
            const d = JSON.parse(e.data);
            if (d.status === 'started') {
                updateProgress(0, `0 of ${d.total}`);
            } else if (d.status === 'progress') {
                const pct = Math.round((d.completed / d.total) * 100);
                updateProgress(pct, progressFmt(d));
            } else if (d.status === 'complete') {
                updateProgress(100, 'Done!');
                hideProgress();
                addLog(completeFmt(d), 'success');
                es.close();
                setToolbarBusy(false);
                if (stepNum) markStepDone(stepNum);
                fetchPage(1);
            } else if (d.status === 'error') {
                hideProgress();
                addLog(d.error, 'error');
                es.close();
                setToolbarBusy(false);
            }
        };
        es.onerror = () => {
            hideProgress();
            addLog('Connection lost during processing', 'error');
            es.close();
            setToolbarBusy(false);
            fetchPage(1);
        };
    }

    /* ── Run All — automated full pipeline ──────────────────────── */
    btnRunAll.addEventListener('click', runAll);

    async function runAll() {
        if (!sessionId) return;
        btnRunAll.disabled = true;
        btnRunAll.textContent = 'Running...';
        setToolbarBusy(true);

        try {
            // Step 1: Deduplicate
            addLog('Step 1/5: Removing duplicate rows...', 'info');
            await postActionSilent('/api/cribl-diagnostics/deduplicate', 1);

            // Step 2: Filter disconnected
            addLog('Step 2/5: Filtering to disconnected hosts only...', 'info');
            await postActionSilent('/api/cribl-diagnostics/filter-disconnected', 2);

            // Step 3: Ping
            addLog('Step 3/5: Pinging hosts (this takes a minute)...', 'info');
            await runSSEAsync(
                `/api/cribl-diagnostics/ping?session_id=${sessionId}`,
                'Pinging hosts...',
                (d) => `${d.completed} of ${d.total} pinged — ${d.reachable || 0} reachable`,
                (d) => `Ping complete: ${d.reachable} reachable, ${d.unreachable} unreachable`,
                3
            );

            // Step 4: SNOW
            addLog('Step 4/5: Looking up hosts in ServiceNow...', 'info');
            await runSSEAsync(
                `/api/cribl-diagnostics/enrich-snow?session_id=${sessionId}`,
                'ServiceNow lookup...',
                (d) => `${d.completed} of ${d.total} looked up — ${d.found || 0} found`,
                (d) => `ServiceNow complete: ${d.found} found, ${d.not_found} not found`,
                4
            );

            // Step 5: Diagnose
            addLog('Step 5/5: Diagnosing hosts...', 'info');
            await postActionSilent('/api/cribl-diagnostics/diagnose', 5);

            // Mark export as ready
            markStepDone(6);
            addLog('All done! Click "Export Excel" to download your report.', 'success');

        } catch (err) {
            addLog(`Run All stopped: ${err.message}`, 'error');
        } finally {
            btnRunAll.disabled = false;
            btnRunAll.textContent = 'Run Full Diagnostics';
            setToolbarBusy(false);
            fetchPage(1);
        }
    }

    /** Post action and return a promise (no UI log — Run All manages its own logs) */
    async function postActionSilent(url, stepNum) {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId }),
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Action failed');
        if (data.summary) updateSummary(data.summary);
        if (data.table) renderTable(data.table);
        if (stepNum) markStepDone(stepNum);
        updateButtonStates();
    }

    /** SSE wrapped in a promise for Run All */
    function runSSEAsync(url, label, progressFmt, completeFmt, stepNum) {
        return new Promise((resolve, reject) => {
            showProgress(label, '');
            const es = new EventSource(url);
            es.onmessage = (e) => {
                const d = JSON.parse(e.data);
                if (d.status === 'started') {
                    updateProgress(0, `0 of ${d.total}`);
                } else if (d.status === 'progress') {
                    const pct = Math.round((d.completed / d.total) * 100);
                    updateProgress(pct, progressFmt(d));
                } else if (d.status === 'complete') {
                    updateProgress(100, 'Done!');
                    hideProgress();
                    addLog(completeFmt(d), 'success');
                    if (stepNum) markStepDone(stepNum);
                    es.close();
                    resolve();
                } else if (d.status === 'error') {
                    hideProgress();
                    es.close();
                    reject(new Error(d.error));
                }
            };
            es.onerror = () => {
                hideProgress();
                es.close();
                reject(new Error('Connection lost'));
            };
        });
    }

    /* ── Export ──────────────────────────────────────────────────── */
    btnExport.addEventListener('click', () => {
        if (!sessionId) return;
        window.location.href = `/api/cribl-diagnostics/export?session_id=${sessionId}`;
        addLog('Excel report downloaded!', 'info');
        markStepDone(6);
    });

    /* ── New upload ─────────────────────────────────────────────── */
    $('#cdBtnNewUpload').addEventListener('click', () => {
        workbench.style.display = 'none';
        uploadZone.style.display = 'block';
        uploadZone.querySelector('.cd-upload-label').textContent = 'Drop your Cribl edgeNodes CSV file here';
        fileInput.value = '';
        sessionId = null;
        activeFilters = {};
        completedSteps = new Set();
        activePreset = 'all';
        presetsBar.style.display = 'none';
        presetsBar.querySelectorAll('.cd-preset').forEach(b => b.classList.remove('cd-preset--active'));
        actionLog.innerHTML = '';
    });

    /* ── Progress helpers ───────────────────────────────────────── */
    function showProgress(label, count) {
        progressBox.style.display = 'block';
        progressLabel.textContent = label;
        progressCount.textContent = count;
        progressFill.style.width = '0%';
    }
    function updateProgress(pct, countText) {
        progressFill.style.width = pct + '%';
        progressCount.textContent = countText;
    }
    function hideProgress() {
        setTimeout(() => { progressBox.style.display = 'none'; }, 600);
    }

    /* ── Toolbar busy state ─────────────────────────────────────── */
    function setToolbarBusy(busy) {
        $$('.cd-step-btn').forEach(btn => { btn.disabled = busy; });
        if (busy) {
            btnRunAll.disabled = true;
        } else {
            btnRunAll.disabled = false;
            updateButtonStates();
        }
    }

    /* ── Action log ─────────────────────────────────────────────── */
    function addLog(msg, type) {
        const chip = document.createElement('span');
        chip.className = `cd-log-chip cd-log-chip--${type || 'info'}`;
        chip.textContent = msg;
        actionLog.appendChild(chip);
        while (actionLog.children.length > 12) {
            actionLog.removeChild(actionLog.firstChild);
        }
    }

})();
