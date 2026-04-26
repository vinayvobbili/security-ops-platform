/* Database Security dashboard — client logic */

(function () {
    'use strict';

    let _data = null;

    // ── Bootstrap ──
    document.addEventListener('DOMContentLoaded', () => {
        initTabs();
        initFilters();
        loadDashboard();
    });

    // ── Data loading ──
    async function loadDashboard() {
        const loading = document.getElementById('loadingState');
        const error = document.getElementById('errorState');
        try {
            const res = await fetch('/api/db-security/overview');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            _data = await res.json();
            loading.style.display = 'none';

            if (_data.demo) {
                document.getElementById('demoBanner').style.display = 'block';
            }

            renderKPIs(_data.kpis);
            renderRisk(_data.kpis);
            renderInventory(_data.databases);
            renderAudit(_data.audit_events);
            renderAccess(_data.privileged_accounts);
        } catch (err) {
            loading.style.display = 'none';
            error.style.display = 'block';
            error.textContent = 'Failed to load dashboard: ' + err.message;
        }
    }

    // ── KPIs ──
    function renderKPIs(kpis) {
        document.getElementById('kpiTotal').textContent = kpis.total_dbs;
        document.getElementById('kpiCompliant').textContent = kpis.compliant_pct + '%';
        document.getElementById('kpiFindings').textContent = kpis.total_findings;
        document.getElementById('kpiCritical').textContent = kpis.critical_findings;
        document.getElementById('kpiScore').textContent = kpis.avg_score;
    }

    // ── Risk indicators ──
    function renderRisk(kpis) {
        document.querySelector('#riskUnencrypted .dbs-risk-count').textContent = kpis.unencrypted;
        document.querySelector('#riskNoAudit .dbs-risk-count').textContent = kpis.no_audit;
        document.querySelector('#riskPublic .dbs-risk-count').textContent = kpis.public_access;
    }

    // ── Database inventory table ──
    function renderInventory(databases) {
        const tbody = document.getElementById('dbTableBody');
        tbody.innerHTML = '';
        databases.forEach(db => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${esc(db.name)}</strong></td>
                <td>${esc(db.engine)}</td>
                <td>${envTag(db.env)}</td>
                <td>${esc(db.owner)}</td>
                <td>${db.encryption === 'None' ? '<span class="badge-no">None</span>' : esc(db.encryption)}</td>
                <td>${patchAge(db.last_patched)}</td>
                <td>${db.audit_enabled ? '<span class="badge-yes">Yes</span>' : '<span class="badge-no">No</span>'}</td>
                <td>${db.public_access ? '<span class="badge-no">Yes</span>' : '<span class="badge-yes">No</span>'}</td>
                <td>${db.findings > 0 ? '<span class="badge-warn">' + db.findings + '</span>' : '<span class="badge-yes">0</span>'}</td>
                <td>${scorePill(db.score)}</td>
            `;
            // Store data attributes for filtering
            tr.dataset.env = db.env;
            tr.dataset.score = db.score;
            tr.dataset.search = (db.name + ' ' + db.engine + ' ' + db.owner).toLowerCase();
            tbody.appendChild(tr);
        });
    }

    // ── Audit timeline ──
    function renderAudit(events) {
        const timeline = document.getElementById('auditTimeline');
        timeline.innerHTML = '';
        events.forEach(ev => {
            const div = document.createElement('div');
            div.className = 'dbs-event sev-' + ev.severity;
            div.innerHTML = `
                <div class="dbs-event-time">${esc(ev.ts)}</div>
                <div class="dbs-event-body">
                    <div class="dbs-event-header">
                        <span class="dbs-event-action">${esc(ev.action)}</span>
                        <span class="dbs-event-db">${esc(ev.db)}</span>
                        <span class="dbs-event-user">${esc(ev.user)}</span>
                        <span class="dbs-event-sev-tag sev-tag-${ev.severity}">${esc(ev.severity)}</span>
                    </div>
                    <div class="dbs-event-detail">${esc(ev.detail)}</div>
                </div>
            `;
            timeline.appendChild(div);
        });
    }

    // ── Privileged access table ──
    function renderAccess(accounts) {
        const tbody = document.getElementById('accessTableBody');
        tbody.innerHTML = '';
        accounts.forEach(a => {
            const reviewAge = daysSince(a.last_review);
            const reviewClass = reviewAge > 90 ? 'badge-no' : reviewAge > 60 ? 'badge-warn' : '';
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${esc(a.user)}</strong></td>
                <td>${esc(a.role)}</td>
                <td style="max-width:260px;font-size:0.8rem;">${esc(a.databases)}</td>
                <td>${a.mfa ? '<span class="badge-yes">Yes</span>' : '<span class="badge-no">No</span>'}</td>
                <td><span class="${reviewClass}">${esc(a.last_review)}</span></td>
                <td>${esc(a.last_login)}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ── Tabs ──
    function initTabs() {
        document.querySelectorAll('.dbs-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.dbs-tab').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.dbs-tab-content').forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
            });
        });
    }

    // ── Filters ──
    function initFilters() {
        const search = document.getElementById('dbSearch');
        const envSel = document.getElementById('envFilter');
        const scoreSel = document.getElementById('scoreFilter');

        const apply = () => applyFilters(search.value, envSel.value, scoreSel.value);
        search.addEventListener('input', apply);
        envSel.addEventListener('change', apply);
        scoreSel.addEventListener('change', apply);
    }

    function applyFilters(text, env, scoreRange) {
        const rows = document.querySelectorAll('#dbTableBody tr');
        const q = text.toLowerCase().trim();
        rows.forEach(tr => {
            let show = true;
            if (q && !tr.dataset.search.includes(q)) show = false;
            if (env && tr.dataset.env !== env) show = false;
            const s = parseInt(tr.dataset.score);
            if (scoreRange === 'high' && s < 80) show = false;
            if (scoreRange === 'mid' && (s < 50 || s >= 80)) show = false;
            if (scoreRange === 'low' && s >= 50) show = false;
            tr.style.display = show ? '' : 'none';
        });
    }

    // ── Helpers ──
    function esc(s) {
        const d = document.createElement('div');
        d.textContent = String(s ?? '');
        return d.innerHTML;
    }

    function scorePill(score) {
        const cls = score >= 80 ? 'score-good' : score >= 50 ? 'score-mid' : 'score-low';
        return `<span class="score-pill ${cls}">${score}</span>`;
    }

    function envTag(env) {
        const cls = env === 'Production' ? 'env-prod' : env === 'Staging' ? 'env-stg' : 'env-dev';
        return `<span class="env-tag ${cls}">${esc(env)}</span>`;
    }

    function patchAge(dateStr) {
        if (!dateStr || dateStr === 'N/A (managed)') return esc(dateStr);
        const days = daysSince(dateStr);
        const cls = days > 90 ? 'badge-no' : days > 45 ? 'badge-warn' : '';
        return `<span class="${cls}">${esc(dateStr)}</span>`;
    }

    function daysSince(dateStr) {
        try {
            const d = new Date(dateStr);
            return Math.floor((Date.now() - d.getTime()) / 86400000);
        } catch { return 0; }
    }
})();
