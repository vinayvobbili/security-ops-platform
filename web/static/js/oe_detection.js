/**
 * OE Detection Dashboard — fetch, render, filter, theme.
 */
(function () {
    'use strict';

    // ── State ──────────────────────────────────────────
    let currentDays = 30;
    let allScores = [];
    let sortCol = 'normalized_score';
    let sortAsc = false;

    // ── DOM refs ───────────────────────────────────────
    const $cardTotal = document.getElementById('oeCardTotal');
    const $cardCritical = document.getElementById('oeCardCritical');
    const $cardHigh = document.getElementById('oeCardHigh');
    const $cardMedium = document.getElementById('oeCardMedium');
    const $cardLow = document.getElementById('oeCardLow');
    const $cardLastScan = document.getElementById('oeCardLastScan');
    const $cardRules = document.getElementById('oeCardRules');
    const $emptyState = document.getElementById('oeEmptyState');
    const $tableSection = document.getElementById('oeTableSection');
    const $scoresBody = document.getElementById('oeScoresBody');
    const $tableCount = document.getElementById('oeTableCount');
    const $scanHistory = document.getElementById('oeScanHistory');
    const $scanHistoryBody = document.getElementById('oeScanHistoryBody');
    const $scanHistoryRows = document.getElementById('oeScanHistoryRows');
    const $scanHistoryToggle = document.getElementById('oeScanHistoryToggle');
    const $detailOverlay = document.getElementById('oeDetailOverlay');
    const $detailTitle = document.getElementById('oeDetailTitle');
    const $detailContent = document.getElementById('oeDetailContent');
    const $detailClose = document.getElementById('oeDetailClose');
    const $detailSparkline = document.getElementById('oeDetailSparkline');
    const $detailSignals = document.getElementById('oeDetailSignals');
    const $detailNarrativeSection = document.getElementById('oeDetailNarrativeSection');
    const $detailNarrative = document.getElementById('oeDetailNarrative');

    // ── Helpers ────────────────────────────────────────
    function dateRange(days) {
        if (!days) return {};
        const end = new Date();
        const start = new Date();
        start.setDate(start.getDate() - days);
        return {
            start_date: start.toISOString().slice(0, 10),
            end_date: end.toISOString().slice(0, 10),
        };
    }

    function fmtDate(iso) {
        if (!iso) return '--';
        const d = new Date(iso);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    function badgeHtml(level) {
        return `<span class="oe-badge oe-badge--${level}">${level}</span>`;
    }

    function domainTags(domains) {
        if (!domains || !domains.length) return '--';
        return domains.map(d => `<span class="oe-domain-tag">${d}</span>`).join(' ');
    }

    // ── API Calls ──────────────────────────────────────
    async function fetchDashboard() {
        const range = dateRange(currentDays);
        const params = new URLSearchParams(range).toString();
        const url = '/api/oe-detection/dashboard' + (params ? '?' + params : '');

        try {
            const resp = await fetch(url);
            const data = await resp.json();
            if (data.success) {
                renderDashboard(data);
            }
        } catch (e) {
            console.error('Failed to fetch OE dashboard:', e);
        }
    }

    async function fetchScanHistory() {
        try {
            const resp = await fetch('/api/oe-detection/scans');
            const data = await resp.json();
            if (data.success) {
                renderScanHistory(data.scans);
            }
        } catch (e) {
            console.error('Failed to fetch scan history:', e);
        }
    }

    async function fetchEmployeeDetail(employeeId) {
        try {
            const resp = await fetch(`/api/oe-detection/employee/${encodeURIComponent(employeeId)}`);
            const data = await resp.json();
            if (data.success) {
                renderDetail(data, employeeId);
            }
        } catch (e) {
            console.error('Failed to fetch employee detail:', e);
        }
    }

    async function triggerScan() {
        const btn = document.getElementById('oeBtnScan');
        if (!confirm('Start an OE detection scan? (MCP servers must be running for signals)')) return;
        btn.disabled = true;
        btn.textContent = 'Scanning...';

        try {
            const resp = await fetch('/api/oe-detection/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dry_run: false }),
            });
            const data = await resp.json();
            if (data.success) {
                btn.textContent = 'Scan Started';
                // Poll for results after a short delay
                setTimeout(() => {
                    btn.disabled = false;
                    btn.textContent = 'Run Scan';
                    fetchDashboard();
                    fetchScanHistory();
                }, 5000);
            } else {
                alert(data.error || 'Scan failed');
                btn.disabled = false;
                btn.textContent = 'Run Scan';
            }
        } catch (e) {
            console.error('Scan trigger failed:', e);
            btn.disabled = false;
            btn.textContent = 'Run Scan';
        }
    }

    async function exportScores() {
        const range = dateRange(currentDays);
        try {
            const resp = await fetch('/api/oe-detection/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(range),
            });
            if (resp.ok) {
                const blob = await resp.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'oe_detection_scores.xlsx';
                a.click();
                URL.revokeObjectURL(url);
            }
        } catch (e) {
            console.error('Export failed:', e);
        }
    }

    // ── Render Functions ───────────────────────────────
    function renderDashboard(data) {
        const stats = data.stats || {};
        const scores = data.scores || [];
        allScores = scores;

        // Cards
        $cardTotal.textContent = stats.total_scanned || 0;
        const dist = stats.risk_distribution || {};
        $cardCritical.textContent = dist.critical || 0;
        $cardHigh.textContent = dist.high || 0;
        $cardMedium.textContent = dist.medium || 0;
        $cardLow.textContent = dist.low || 0;
        $cardLastScan.textContent = fmtDate(stats.last_scan);
        $cardRules.textContent = stats.active_rules || 0;

        // Toggle empty state vs table
        if (!data.has_data || scores.length === 0) {
            $emptyState.style.display = '';
            $tableSection.style.display = 'none';
        } else {
            $emptyState.style.display = 'none';
            $tableSection.style.display = '';
            renderScoresTable(scores);
        }
    }

    function renderScoresTable(scores) {
        // Sort
        const sorted = [...scores].sort((a, b) => {
            let va = a[sortCol], vb = b[sortCol];
            if (typeof va === 'string') va = va.toLowerCase();
            if (typeof vb === 'string') vb = vb.toLowerCase();
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
        });

        $tableCount.textContent = `${sorted.length} employee${sorted.length !== 1 ? 's' : ''}`;

        $scoresBody.innerHTML = sorted.map(s => `
            <tr>
                <td><strong>${esc(s.employee_name)}</strong><br><span style="font-size:0.75rem;color:#94a3b8;">${esc(s.employee_id)}</span></td>
                <td><strong>${s.normalized_score.toFixed(1)}</strong></td>
                <td>${badgeHtml(s.risk_level)}</td>
                <td>${domainTags(s.domains_hit)}</td>
                <td>${s.signal_count}</td>
                <td>${fmtDate(s.calculated_at)}</td>
                <td><span class="oe-detail-link" data-emp="${esc(s.employee_id)}">Details</span></td>
            </tr>
        `).join('');
    }

    function renderScanHistory(scans) {
        if (!scans || scans.length === 0) {
            $scanHistory.style.display = 'none';
            return;
        }
        $scanHistory.style.display = '';
        $scanHistoryRows.innerHTML = scans.map(s => `
            <tr>
                <td><code>${s.scan_id}</code></td>
                <td>${fmtDate(s.started_at)}</td>
                <td>${fmtDate(s.completed_at)}</td>
                <td>${s.employee_count}</td>
                <td>${s.dry_run ? '<span class="oe-badge oe-badge--medium">Dry Run</span>' : 'Live'}</td>
            </tr>
        `).join('');
    }

    function renderDetail(data, employeeId) {
        $detailTitle.textContent = employeeId;
        $detailOverlay.style.display = '';

        // Sparkline from history
        const history = (data.history || []).slice().reverse(); // oldest first
        $detailSparkline.innerHTML = '';
        if (history.length > 0) {
            const maxScore = Math.max(...history.map(h => h.normalized_score), 1);
            history.forEach(h => {
                const bar = document.createElement('div');
                bar.className = 'oe-spark-bar';
                const pct = (h.normalized_score / maxScore) * 100;
                bar.style.height = Math.max(pct, 4) + '%';
                bar.style.background = riskColor(h.risk_level);
                bar.title = `${h.normalized_score.toFixed(1)} (${h.risk_level}) - ${fmtDate(h.calculated_at)}`;
                $detailSparkline.appendChild(bar);
            });
        }

        // Signals
        const signals = data.signals || [];
        if (signals.length === 0) {
            $detailSignals.innerHTML = '<div style="color:#94a3b8;font-size:0.85rem;">No signals</div>';
        } else {
            $detailSignals.innerHTML = signals.map(s => `
                <div class="oe-signal-card">
                    <div class="oe-signal-header">
                        <span class="oe-signal-rule">${esc(s.rule_id)}</span>
                        <span class="oe-signal-weight">+${s.weight}</span>
                    </div>
                    <div class="oe-signal-desc">${esc(s.description)}</div>
                    <div class="oe-domain-tag" style="margin-top:6px;">${esc(s.domain)}</div>
                    ${Object.keys(s.evidence || {}).length ? `<div class="oe-signal-evidence">${esc(JSON.stringify(s.evidence, null, 2))}</div>` : ''}
                </div>
            `).join('');
        }

        // Narrative
        const latest = (data.history && data.history[0]) || {};
        if (latest.narrative) {
            $detailNarrativeSection.style.display = '';
            $detailNarrative.textContent = latest.narrative;
        } else {
            $detailNarrativeSection.style.display = 'none';
        }
    }

    function riskColor(level) {
        const colors = { critical: '#b91c1c', high: '#ea580c', medium: '#ca8a04', low: '#16a34a' };
        return colors[level] || '#94a3b8';
    }

    function esc(str) {
        if (!str) return '';
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    // ── Event Listeners ────────────────────────────────
    function setupListeners() {
        // Date filter buttons
        document.querySelectorAll('.oe-date-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.oe-date-btn').forEach(b => b.classList.remove('oe-date-btn--active'));
                btn.classList.add('oe-date-btn--active');
                currentDays = parseInt(btn.dataset.days) || null;
                fetchDashboard();
            });
        });

        // Scan button
        document.getElementById('oeBtnScan').addEventListener('click', triggerScan);

        // Export button
        document.getElementById('oeBtnExport').addEventListener('click', exportScores);

        // Table sort
        document.querySelectorAll('.oe-sortable').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.dataset.col;
                if (sortCol === col) {
                    sortAsc = !sortAsc;
                } else {
                    sortCol = col;
                    sortAsc = false;
                }
                renderScoresTable(allScores);
            });
        });

        // Detail links (delegated)
        document.getElementById('oeScoresBody').addEventListener('click', e => {
            const link = e.target.closest('.oe-detail-link');
            if (link) {
                fetchEmployeeDetail(link.dataset.emp);
            }
        });

        // Detail close
        $detailClose.addEventListener('click', () => {
            $detailOverlay.style.display = 'none';
        });
        $detailOverlay.addEventListener('click', e => {
            if (e.target === $detailOverlay) {
                $detailOverlay.style.display = 'none';
            }
        });

        // Scan history toggle
        $scanHistoryToggle.addEventListener('click', () => {
            const body = $scanHistoryBody;
            const arrow = $scanHistoryToggle.querySelector('.oe-collapse-arrow');
            if (body.style.display === 'none') {
                body.style.display = '';
                arrow.classList.add('oe-collapse-arrow--open');
            } else {
                body.style.display = 'none';
                arrow.classList.remove('oe-collapse-arrow--open');
            }
        });

        // Theme change
        window.addEventListener('themechange', () => {
            // Re-render sparkline if detail panel is open
            if ($detailOverlay.style.display !== 'none') {
                // Sparkline colors update automatically via CSS
            }
        });
    }

    // ── Init ───────────────────────────────────────────
    function init() {
        setupListeners();
        fetchDashboard();
        fetchScanHistory();
    }

    document.addEventListener('DOMContentLoaded', init);
})();
