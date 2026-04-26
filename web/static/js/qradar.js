/* QRadar Explorer — offense list + detail panel */

(function () {
    "use strict";

    const $ = (s) => document.querySelector(s);
    const $$ = (s) => document.querySelectorAll(s);

    // Elements
    const fetchBtn      = $("#fetchBtn");
    const statusDot     = $(".qr-dot");
    const statusText    = $("#statusText");
    const statsRow      = $("#statsRow");
    const loadingState  = $("#loadingState");
    const errorState    = $("#errorState");
    const emptyState    = $("#emptyState");
    const tableWrapper  = $("#tableWrapper");
    const tbody         = $("#offenseTableBody");
    const detailPanel   = $("#detailPanel");
    const detailOverlay = $("#detailOverlay");
    const detailTitle   = $("#detailTitle");
    const detailBody    = $("#detailBody");
    const detailClose   = $("#detailClose");

    // ── Helpers ──

    function sevClass(sev) {
        if (sev >= 7) return "high";
        if (sev >= 4) return "med";
        return "low";
    }

    function statusClass(s) {
        return "status-" + (s || "open").toLowerCase();
    }

    function fmtNumber(n) {
        return (n || 0).toLocaleString();
    }

    function escHtml(s) {
        const d = document.createElement("div");
        d.textContent = s || "";
        return d.innerHTML;
    }

    function fmtEpochMs(ms) {
        if (!ms) return "—";
        const d = new Date(ms);
        return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
    }

    function shortTime(display) {
        // "2026-04-02 13:26 UTC" → "13:26 UTC" if today, else full
        if (!display) return "—";
        const today = new Date().toISOString().slice(0, 10);
        if (display.startsWith(today)) return display.slice(11);
        return display;
    }

    // ── State management ──

    function showOnly(el) {
        [loadingState, errorState, emptyState, tableWrapper].forEach((e) => {
            e.style.display = "none";
        });
        if (el) el.style.display = "";
    }

    function setStatus(text, state) {
        statusText.textContent = text;
        statusDot.className = "qr-dot" + (state ? " " + state : "");
    }

    // ── Fetch offenses ──

    async function fetchOffenses() {
        const status    = $("#statusFilter").value;
        const hoursBack = $("#timeFilter").value;
        const limit     = $("#limitFilter").value;

        showOnly(loadingState);
        statsRow.style.display = "none";
        setStatus("Fetching...", "loading");
        fetchBtn.disabled = true;

        try {
            const url = `/api/qradar/offenses?status=${status}&hours_back=${hoursBack}&limit=${limit}`;
            const resp = await fetch(url);
            const data = await resp.json();

            if (!resp.ok || data.error) {
                throw new Error(data.error || `HTTP ${resp.status}`);
            }

            const offenses = data.offenses || [];

            if (offenses.length === 0) {
                showOnly(emptyState);
                statsRow.style.display = "none";
                setStatus("No results", "");
                return;
            }

            renderStats(offenses);
            renderTable(offenses);
            showOnly(tableWrapper);
            statsRow.style.display = "";
            setStatus(`${offenses.length} offense${offenses.length !== 1 ? "s" : ""}`, "");
        } catch (err) {
            showOnly(errorState);
            errorState.textContent = "Failed to fetch offenses: " + err.message;
            setStatus("Error", "error");
        } finally {
            fetchBtn.disabled = false;
        }
    }

    // ── Render stats ──

    function renderStats(offenses) {
        let high = 0, med = 0, low = 0;
        offenses.forEach((o) => {
            const s = o.severity || 0;
            if (s >= 7) high++;
            else if (s >= 4) med++;
            else low++;
        });
        $("#statTotal").textContent = offenses.length;
        $("#statHigh").textContent = high;
        $("#statMed").textContent = med;
        $("#statLow").textContent = low;
    }

    // ── Render table ──

    function renderTable(offenses) {
        tbody.innerHTML = offenses.map((o) => {
            const sev = o.severity || 0;
            const mag = o.magnitude || 0;
            const cats = (o.categories || []).slice(0, 3);
            const desc = (o.description || "").replace(/^_[A-Z_]+_/, "").trim();
            const statusPill = `<span class="status-pill ${statusClass(o.status)}">${escHtml(o.status)}</span>`;
            const timeDisplay = shortTime(o.start_time_display);

            return `<tr data-id="${o.id}">
                <td class="col-id"><strong>${o.id}</strong></td>
                <td class="col-sev"><span class="sev-badge sev-${sevClass(sev)}">${sev}</span></td>
                <td class="col-mag"><span class="sev-badge sev-${sevClass(mag)}">${mag}</span></td>
                <td class="col-desc">${escHtml(desc)}</td>
                <td class="col-source"><span class="source-text">${escHtml(o.offense_source || "—")}</span></td>
                <td class="col-events" style="text-align:right;">${fmtNumber(o.event_count)}</td>
                <td class="col-categories"><div class="cat-tags">${cats.map((c) => `<span class="cat-tag">${escHtml(c)}</span>`).join("")}</div></td>
                <td class="col-status">${statusPill}</td>
                <td class="col-time">${escHtml(timeDisplay)}</td>
            </tr>`;
        }).join("");
    }

    // ── Detail panel ──

    function openDetail(offenseId) {
        detailTitle.textContent = `Offense #${offenseId}`;
        detailBody.innerHTML = `<div class="qr-loading"><div class="qr-spinner"></div><div>Loading details...</div></div>`;
        detailPanel.classList.add("open");
        detailOverlay.classList.add("open");
        document.body.style.overflow = "hidden";

        fetchDetail(offenseId);
    }

    function closeDetail() {
        detailPanel.classList.remove("open");
        detailOverlay.classList.remove("open");
        document.body.style.overflow = "";
    }

    async function fetchDetail(offenseId) {
        try {
            const resp = await fetch(`/api/qradar/offense/${offenseId}`);
            const data = await resp.json();

            if (!resp.ok || data.error) {
                throw new Error(data.error || `HTTP ${resp.status}`);
            }

            renderDetail(data);
        } catch (err) {
            detailBody.innerHTML = `<div class="qr-error">Failed to load details: ${escHtml(err.message)}</div>`;
        }
    }

    function renderDetail(data) {
        const o = data.offense;
        const sev = o.severity || 0;

        let html = "";

        // Overview
        html += `<div class="qr-detail-section">
            <div class="qr-detail-section-title">Overview</div>
            <div class="qr-detail-grid">
                <span class="qr-detail-label">Description</span>
                <span class="qr-detail-value">${escHtml(o.description)}</span>
                <span class="qr-detail-label">Severity</span>
                <span class="qr-detail-value"><span class="sev-badge sev-${sevClass(sev)}">${sev}</span> / 10</span>
                <span class="qr-detail-label">Magnitude</span>
                <span class="qr-detail-value"><span class="sev-badge sev-${sevClass(o.magnitude || 0)}">${o.magnitude || 0}</span> / 10</span>
                <span class="qr-detail-label">Status</span>
                <span class="qr-detail-value"><span class="status-pill ${statusClass(o.status)}">${escHtml(o.status)}</span></span>
                <span class="qr-detail-label">Offense Source</span>
                <span class="qr-detail-value">${escHtml(o.offense_source || "—")}</span>
                ${data.rule_name ? `<span class="qr-detail-label">Rule</span><span class="qr-detail-value">${escHtml(data.rule_name)}</span>` : ""}
                <span class="qr-detail-label">Event Count</span>
                <span class="qr-detail-value">${fmtNumber(o.event_count)}</span>
                <span class="qr-detail-label">Flow Count</span>
                <span class="qr-detail-value">${fmtNumber(o.flow_count)}</span>
                <span class="qr-detail-label">Source IPs</span>
                <span class="qr-detail-value">${o.source_count || 0}</span>
                <span class="qr-detail-label">Destination IPs</span>
                <span class="qr-detail-value">${o.destination_count || 0}</span>
                <span class="qr-detail-label">Categories</span>
                <span class="qr-detail-value">${(o.categories || []).join(", ") || "—"}</span>
                <span class="qr-detail-label">Created</span>
                <span class="qr-detail-value">${escHtml(o.start_time_display || fmtEpochMs(o.start_time))}</span>
                <span class="qr-detail-label">Last Updated</span>
                <span class="qr-detail-value">${escHtml(o.last_updated_display || fmtEpochMs(o.last_updated_time))}</span>
            </div>
        </div>`;

        // Notes
        const notes = data.notes || [];
        if (notes.length > 0) {
            html += `<div class="qr-detail-section">
                <div class="qr-detail-section-title">Notes (${notes.length})</div>`;
            notes.forEach((n) => {
                const noteTime = n.create_time ? fmtEpochMs(n.create_time) : "";
                html += `<div class="qr-note">
                    <div class="qr-note-text">${escHtml(n.note_text || "")}</div>
                    <div class="qr-note-meta">${escHtml(n.username || "")}${noteTime ? " &mdash; " + escHtml(noteTime) : ""}</div>
                </div>`;
            });
            html += `</div>`;
        }

        // Events
        const events = data.events || [];
        if (events.length > 0) {
            html += `<div class="qr-detail-section">
                <div class="qr-detail-section-title">Sample Events (${events.length})</div>
                <div style="overflow-x:auto;">
                <table class="qr-events-table"><thead><tr>
                    <th>Time</th><th>Event</th><th>Source IP</th><th>Dest IP</th><th>Log Source</th><th>Mag</th>
                </tr></thead><tbody>`;
            events.forEach((e) => {
                html += `<tr>
                    <td>${escHtml(e.event_time || "")}</td>
                    <td>${escHtml(e.event_name || "")}</td>
                    <td>${escHtml(e.sourceip || "")}</td>
                    <td>${escHtml(e.destinationip || "")}</td>
                    <td>${escHtml(e.log_source || "")}</td>
                    <td>${e.magnitude || ""}</td>
                </tr>`;
            });
            html += `</tbody></table></div></div>`;
        } else {
            html += `<div class="qr-detail-section">
                <div class="qr-detail-section-title">Sample Events</div>
                <div style="color:#94a3b8;font-size:0.85rem;">No events retrieved (query may have timed out).</div>
            </div>`;
        }

        detailBody.innerHTML = html;
    }

    // ── Event listeners ──

    fetchBtn.addEventListener("click", fetchOffenses);

    tbody.addEventListener("click", (e) => {
        const row = e.target.closest("tr[data-id]");
        if (row) openDetail(row.dataset.id);
    });

    detailClose.addEventListener("click", closeDetail);
    detailOverlay.addEventListener("click", closeDetail);
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeDetail();
    });

    // Auto-fetch on load
    if (typeof initTheme === "function") initTheme();
    fetchOffenses();
})();
