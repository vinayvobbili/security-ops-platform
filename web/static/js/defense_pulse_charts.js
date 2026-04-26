/**
 * control-efficacy analytics Interactive Charts, Drill-downs & Cross-filtering
 *
 * Provides Chart.js-powered interactive charts, click-to-drill-down
 * panels, cross-filtering across all dashboard sections, and deep
 * links to Meaningful Metrics for ticket-level drill-through.
 */
window.DPCharts = (function () {
    'use strict';

    var _instances = {};
    var _excludeTop = {};
    var _chartData = null;
    var _kpis = null;
    var _activeFilter = null;   // {field: 'category', value: 'Email Security'}
    var _originalKpis = null;   // full KPIs before any filter
    var _originalChartData = null;

    var COLORS = {
        blocked: '#2e7d32',
        escalated: '#b71c1c',
        humanError: '#FF8F00',
        socialEng: '#b71c1c',
        palette: [
            '#1A237E', '#283593', '#303F9F', '#3949AB', '#3F51B5',
            '#5C6BC0', '#7986CB', '#9FA8DA', '#C5CAE9', '#E8EAF6',
            '#0D47A1', '#1565C0', '#1976D2', '#1E88E5', '#2196F3',
            '#42A5F5', '#64B5F6', '#90CAF9',
        ],
    };

    /* ── helpers ─────────────────────────────────────────────────── */

    function _destroy(id) {
        if (_instances[id]) { _instances[id].destroy(); delete _instances[id]; }
    }

    function _isDark() { return document.body.classList.contains('dark-mode'); }

    function _colors() {
        var dk = _isDark();
        return {
            text: dk ? '#cbd5e1' : '#333',
            grid: dk ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.06)',
            primary: dk ? '#93b5ff' : '#1A237E',
        };
    }

    function _esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

    /* ══════════════════════════════════════════════════════════════
       Cross-filtering
       ══════════════════════════════════════════════════════════════ */

    function _setFilter(field, value) {
        // Toggle off if clicking the same filter
        if (_activeFilter && _activeFilter.field === field && _activeFilter.value === value) {
            _clearFilter();
            return;
        }
        _activeFilter = {field: field, value: value};
        _closeDrilldown();
        _renderFilterBar(field, value);
        _fetchFilteredData(field, value);
    }

    function _clearFilter() {
        _activeFilter = null;
        _hideFilterBar();
        _closeDrilldown();
        if (_originalChartData && _originalKpis) {
            _chartData = _originalChartData;
            _kpis = _originalKpis;
            _renderAllCharts(_chartData);
            if (window._dpRenderSections) window._dpRenderSections(_originalKpis);
        }
    }

    function _fetchFilteredData(field, value) {
        var params = encodeURIComponent(field) + '=' + encodeURIComponent(value);
        var countEl = document.getElementById('dpFilterCount');
        if (countEl) countEl.textContent = 'Loading\u2026';

        fetch('/api/defense-pulse/filter?' + params)
            .then(function (r) { return r.json(); })
            .then(function (json) {
                if (!json.success || !json.data) { _clearFilter(); return; }
                var d = json.data;
                if (countEl) countEl.textContent = '(' + (d.total_incidents || 0).toLocaleString() + ' incidents)';
                var cd = d.chart_data || {};
                _chartData = cd;
                _renderAllCharts(cd);
                if (window._dpRenderSections) window._dpRenderSections(d);
            })
            .catch(function () { _clearFilter(); });
    }

    function _renderAllCharts(cd) {
        if (cd.dashboard) renderDashboard('chartDashboardCanvas', cd.dashboard);
        if (cd.heatmap) renderHeatmap('heatmapTable', cd.heatmap, _excludeTop.heatmap);
        if (cd.root_cause) renderRootCause('chartRootCauseCanvas', cd.root_cause, _excludeTop.rootCause);
        if (cd.awareness && cd.awareness.weeks && cd.awareness.weeks.length) {
            renderAwareness('chartAwarenessCanvas', cd.awareness);
        } else {
            var awarenessEl = document.getElementById('chartAwarenessInteractive');
            if (awarenessEl) awarenessEl.innerHTML = '<div style="padding:2rem;text-align:center;color:var(--dp-text-muted);">No awareness-related incidents in this filter.</div>';
        }
    }

    function _renderFilterBar(field, value) {
        var bar = document.getElementById('dpFilterBar');
        if (!bar) return;
        var labelMap = {category: 'Category', impact: 'Impact', source: 'Source', vector: 'Attack Vector', root_cause: 'Root Cause'};
        document.getElementById('dpFilterLabel').textContent = (labelMap[field] || field) + ': ' + value;
        document.getElementById('dpFilterCount').textContent = '';

        var mmLink = document.getElementById('dpFilterMMLink');
        if (mmLink) {
            var href = _buildMMLink(field, value);
            if (href) { mmLink.href = href; mmLink.style.display = ''; }
            else { mmLink.style.display = 'none'; }
        }
        bar.style.display = '';
        bar.scrollIntoView({behavior: 'smooth', block: 'nearest'});
    }

    function _hideFilterBar() {
        var bar = document.getElementById('dpFilterBar');
        if (bar) bar.style.display = 'none';
    }

    /* ── Meaningful Metrics deep-link builder ─────────────────── */

    function _buildMMLink(field, value) {
        // Use original (unfiltered) mappings for type lookups
        var origCd = _originalChartData || _chartData || {};
        if (field === 'impact') {
            return '/meaningful-metrics?impact=' + encodeURIComponent(value) + '&dateRange=90';
        }
        var types = [];
        if (field === 'category' && origCd.category_to_types) {
            types = origCd.category_to_types[value] || [];
        } else if (field === 'source' && origCd.source_to_types) {
            types = origCd.source_to_types[value] || [];
        } else if (field === 'vector' && origCd.category_to_types) {
            // Vectors map to multiple categories; collect all types
            var catBreakdown = origCd.category_breakdown || [];
            // Approximate: use category_to_types for all categories (the filter endpoint handles accuracy)
        }
        if (types.length > 0) {
            return '/meaningful-metrics?' + types.map(function (t) { return 'type=' + encodeURIComponent(t); }).join('&') + '&dateRange=90';
        }
        return '';
    }

    /** Build a small "View incidents" link for drill-down panels */
    function _mmLinkHtml(field, value) {
        var href = _buildMMLink(field, value);
        if (!href) return '';
        return '<div class="dp-dd-mm-link"><a href="' + _esc(href) + '" target="_blank" rel="noopener">View incidents in Meaningful Metrics \u2192</a></div>';
    }

    /* ══════════════════════════════════════════════════════════════
       Chart renderers
       ══════════════════════════════════════════════════════════════ */

    /* ── Dashboard: blocked vs escalated horizontal stacked bar ── */

    function renderDashboard(canvasId, data) {
        _destroy(canvasId);
        var ctx = document.getElementById(canvasId);
        if (!ctx) return;
        var c = _colors();
        var height = Math.max(300, data.sources.length * 38 + 80);
        ctx.parentElement.style.height = height + 'px';

        _instances[canvasId] = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.sources,
                datasets: [
                    { label: 'Blocked by Controls', data: data.blocked, backgroundColor: COLORS.blocked },
                    { label: 'Escalated to Human', data: data.escalated, backgroundColor: COLORS.escalated },
                ],
            },
            options: {
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                scales: {
                    x: { stacked: true, ticks: { color: c.text }, grid: { color: c.grid },
                         title: { display: true, text: 'Incident Count', color: c.primary } },
                    y: { stacked: true, ticks: { color: c.text, font: { size: 11 } }, grid: { display: false } },
                },
                plugins: {
                    legend: { labels: { color: c.text } },
                    tooltip: {
                        callbacks: {
                            afterBody: function (ctx2) {
                                var i = ctx2[0].dataIndex;
                                var b = data.blocked[i], e = data.escalated[i], t = b + e;
                                return t > 0 ? 'Block rate: ' + Math.round(b / t * 100) + '% \u2022 Click to filter' : '';
                            },
                        },
                    },
                },
                onClick: function (_ev, els) {
                    if (els.length) _setFilter('source', data.sources[els[0].index]);
                },
            },
        });
    }

    /* ── Root Cause: horizontal stacked bar ──────────────────────── */

    function renderRootCause(canvasId, data, excludeTop) {
        _destroy(canvasId);
        var ctx = document.getElementById(canvasId);
        if (!ctx) return;
        var c = _colors();

        var rootCauses = data.root_causes.slice();
        var matrix = data.matrix.map(function (r) { return r.slice(); });
        if (excludeTop && rootCauses.length > 1) { rootCauses.shift(); matrix.shift(); }

        var height = Math.max(300, rootCauses.length * 38 + 80);
        ctx.parentElement.style.height = height + 'px';

        var datasets = data.sources.map(function (src, i) {
            return {
                label: src,
                data: matrix.map(function (row) { return row[i]; }),
                backgroundColor: COLORS.palette[i % COLORS.palette.length],
            };
        });

        _instances[canvasId] = new Chart(ctx, {
            type: 'bar',
            data: { labels: rootCauses, datasets: datasets },
            options: {
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                scales: {
                    x: { stacked: true, ticks: { color: c.text }, grid: { color: c.grid },
                         title: { display: true, text: 'Incident Count', color: c.primary } },
                    y: { stacked: true, ticks: { color: c.text, font: { size: 11 } }, grid: { display: false } },
                },
                plugins: {
                    legend: { position: 'bottom', labels: { color: c.text, font: { size: 10 }, boxWidth: 14 } },
                    tooltip: {
                        callbacks: {
                            afterBody: function (ctx2) {
                                var idx = ctx2[0].dataIndex;
                                var total = matrix[idx].reduce(function (a, b) { return a + b; }, 0);
                                return 'Total: ' + total + ' \u2022 Click to filter';
                            },
                        },
                    },
                },
                onClick: function (_ev, els) {
                    if (els.length) _setFilter('root_cause', rootCauses[els[0].index]);
                },
            },
        });
    }

    /* ── Awareness: line chart ──────────────────────────────────── */

    function renderAwareness(canvasId, data) {
        _destroy(canvasId);
        var ctx = document.getElementById(canvasId);
        if (!ctx) return;
        var c = _colors();
        ctx.parentElement.style.height = '360px';

        var labels = data.weeks.map(function (w) {
            var d = new Date(w); return (d.getMonth() + 1) + '/' + d.getDate();
        });

        var spikeAnnotations = [];
        [data.human_error, data.social_engineering].forEach(function (vals, si) {
            var lbl = si === 0 ? 'Human Error' : 'Social Engineering';
            for (var i = 4; i < vals.length; i++) {
                var avg = (vals[i-1] + vals[i-2] + vals[i-3] + vals[i-4]) / 4;
                if (avg > 0 && vals[i] > avg * 1.5) {
                    spikeAnnotations.push({ index: i, value: vals[i], label: lbl });
                }
            }
        });

        _instances[canvasId] = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Human Error', data: data.human_error,
                        borderColor: COLORS.humanError, backgroundColor: COLORS.humanError + '20',
                        fill: true, tension: 0.3, pointRadius: 4, pointHoverRadius: 7,
                    },
                    {
                        label: 'Social Engineering', data: data.social_engineering,
                        borderColor: COLORS.socialEng, backgroundColor: COLORS.socialEng + '20',
                        fill: true, tension: 0.3, pointRadius: 4, pointHoverRadius: 7,
                    },
                ],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: c.text, maxRotation: 45 }, grid: { color: c.grid },
                         title: { display: true, text: 'Week', color: c.primary } },
                    y: { beginAtZero: true, ticks: { color: c.text }, grid: { color: c.grid },
                         title: { display: true, text: 'Incident Count', color: c.primary } },
                },
                plugins: {
                    legend: { labels: { color: c.text } },
                    tooltip: {
                        mode: 'index', intersect: false,
                        callbacks: {
                            afterBody: function (ctx2) {
                                var idx = ctx2[0].dataIndex;
                                var spike = spikeAnnotations.find(function (s) { return s.index === idx; });
                                return spike ? '\u26a0 Spike detected (' + spike.label + ')' : '';
                            },
                        },
                    },
                },
                interaction: { mode: 'nearest', axis: 'x', intersect: false },
            },
        });
    }

    /* ── Heatmap: interactive HTML table ─────────────────────────── */

    function renderHeatmap(containerId, data, excludeTop) {
        var container = document.getElementById(containerId);
        if (!container) return;

        var categories = data.categories.slice();
        var impacts = data.impacts.slice();
        var matrix = data.matrix.map(function (r) { return r.slice(); });
        if (excludeTop && categories.length > 1) { categories.shift(); matrix.shift(); }

        var maxVal = 0;
        matrix.forEach(function (row) {
            row.forEach(function (v) { if (v > maxVal) maxVal = v; });
        });

        var html = '<table class="dp-heatmap-table"><thead><tr><th class="dp-heatmap-corner">Category</th>';
        impacts.forEach(function (imp) {
            html += '<th class="dp-heatmap-col-header">' + (imp || '(empty)') + '</th>';
        });
        html += '<th class="dp-heatmap-col-header dp-heatmap-total-col">Total</th></tr></thead><tbody>';

        categories.forEach(function (cat, i) {
            var rowTotal = matrix[i].reduce(function (a, b) { return a + b; }, 0);
            var isActive = _activeFilter && _activeFilter.field === 'category' && _activeFilter.value === cat;
            html += '<tr class="dp-heatmap-row' + (isActive ? ' dp-heatmap-row-active' : '') + '" data-category="' + _esc(cat) + '">';
            html += '<td class="dp-heatmap-row-label">' + _esc(cat) + '</td>';
            matrix[i].forEach(function (val, j) {
                var intensity = maxVal > 0 ? val / maxVal : 0;
                var bg = _heatColor(intensity);
                var fg = intensity > 0.55 ? '#fff' : (_isDark() ? '#cbd5e1' : '#333');
                html += '<td class="dp-heatmap-cell' + (val > 0 ? ' dp-heatmap-has-value' : '') +
                    '" style="background:' + bg + ';color:' + fg + '" ' +
                    'title="' + _esc(cat) + ' \u00d7 ' + _esc(impacts[j] || '(empty)') + ': ' + val + ' \u2022 Click to filter">' +
                    (val > 0 ? val : '') + '</td>';
            });
            html += '<td class="dp-heatmap-total">' + rowTotal + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        container.querySelectorAll('.dp-heatmap-row').forEach(function (row) {
            row.addEventListener('click', function () {
                _setFilter('category', this.getAttribute('data-category'));
            });
        });
    }

    function _heatColor(intensity) {
        if (intensity <= 0) return 'transparent';
        var r = 255;
        var g = Math.max(Math.round(255 - intensity * 200), 30);
        var b = Math.max(Math.round(60 - intensity * 60), 0);
        var a = 0.15 + intensity * 0.85;
        return 'rgba(' + r + ',' + g + ',' + b + ',' + a.toFixed(2) + ')';
    }

    /* ══════════════════════════════════════════════════════════════
       Drill-down panels
       ══════════════════════════════════════════════════════════════ */

    function _showDrilldown(title, bodyHtml) {
        var panel = document.getElementById('dpKpiDrilldown');
        if (!panel) return;
        document.getElementById('dpDrilldownTitle').textContent = title;
        document.getElementById('dpDrilldownBody').innerHTML = bodyHtml;
        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function _closeDrilldown() {
        var panel = document.getElementById('dpKpiDrilldown');
        if (panel) panel.style.display = 'none';
    }

    /* ── KPI card drill-down handlers ────────────────────────────── */

    function _handleKpiDrilldown(type) {
        if (!_chartData) return;
        switch (type) {
            case 'total': _drilldownTotal(); break;
            case 'blocked': _drilldownBlocked(); break;
            case 'mtp': _drilldownMtp(); break;
            case 'attack_vector': _drilldownAttackVector(); break;
        }
    }

    function _drilldownTotal() {
        var bd = _chartData.category_breakdown || [];
        if (!bd.length) return;
        var maxCount = bd[0].count;
        var html = '<table class="dp-drilldown-table"><thead><tr><th>Security Category</th><th>Count</th><th>%</th><th></th></tr></thead><tbody>';
        bd.forEach(function (item) {
            var w = maxCount > 0 ? (item.count / maxCount * 100) : 0;
            html += '<tr class="dp-dd-row-clickable" data-field="category" data-value="' + _esc(item.category) + '">' +
                '<td>' + _esc(item.category) + '</td><td>' + item.count.toLocaleString() + '</td>' +
                '<td>' + item.pct + '%</td>' +
                '<td><div class="dp-dd-bar" style="width:' + w + '%"></div></td></tr>';
        });
        html += '</tbody></table>';
        _showDrilldown('Incidents by Security Category', html);
        _wireDrilldownRows();
    }

    function _drilldownBlocked() {
        var eff = _chartData.source_efficiency || [];
        if (!eff.length) return;
        var html = '<table class="dp-drilldown-table"><thead><tr><th>Source</th><th>Blocked</th><th>Escalated</th><th>Block Rate</th><th>MTP</th><th>Signal</th></tr></thead><tbody>';
        eff.forEach(function (s) {
            var cls = s.block_rate >= 60 ? 'dp-dd-good' : s.block_rate >= 30 ? 'dp-dd-warn' : 'dp-dd-bad';
            html += '<tr class="dp-dd-row-clickable" data-field="source" data-value="' + _esc(s.source) + '">' +
                '<td>' + _esc(s.source) + '</td><td>' + s.blocked.toLocaleString() + '</td><td>' + s.escalated.toLocaleString() + '</td>' +
                '<td class="' + cls + '">' + s.block_rate + '%</td>' +
                '<td>' + s.mtp + '</td><td>' + s.signal_ratio + '%</td></tr>';
        });
        html += '</tbody></table>';
        _showDrilldown('Control Effectiveness by Detection Source', html);
        _wireDrilldownRows();
    }

    function _drilldownMtp() {
        var bd = _chartData.mtp_breakdown || [];
        if (!bd.length) return;
        var total = bd.reduce(function (a, b) { return a + b.count; }, 0);
        var maxCount = bd[0].count;
        var html = '<table class="dp-drilldown-table"><thead><tr><th>Security Category</th><th>MTP Count</th><th>% of MTP</th><th></th></tr></thead><tbody>';
        bd.forEach(function (item) {
            var pct = total > 0 ? (item.count / total * 100).toFixed(1) : '0';
            var w = maxCount > 0 ? (item.count / maxCount * 100) : 0;
            html += '<tr class="dp-dd-row-clickable" data-field="category" data-value="' + _esc(item.category) + '">' +
                '<td>' + _esc(item.category) + '</td><td>' + item.count + '</td>' +
                '<td>' + pct + '%</td>' +
                '<td><div class="dp-dd-bar dp-dd-bar-red" style="width:' + w + '%"></div></td></tr>';
        });
        html += '</tbody></table>' + _mmLinkHtml('impact', 'Malicious True Positive');
        _showDrilldown('Malicious True Positives by Category (' + total + ' total)', html);
        _wireDrilldownRows();
    }

    function _drilldownAttackVector() {
        var vecs = (_kpis && _kpis.attack_vectors) || [];
        if (!vecs.length) return;
        var html = '<table class="dp-drilldown-table"><thead><tr><th>Attack Vector</th><th>Count</th><th>%</th><th>Blocked %</th><th>MTP</th></tr></thead><tbody>';
        vecs.forEach(function (v) {
            var cls = v.blocked_pct >= 60 ? 'dp-dd-good' : v.blocked_pct >= 30 ? 'dp-dd-warn' : 'dp-dd-bad';
            html += '<tr class="dp-dd-row-clickable" data-field="vector" data-value="' + _esc(v.vector) + '">' +
                '<td>' + _esc(v.vector) + '</td><td>' + v.count.toLocaleString() + '</td>' +
                '<td>' + v.pct + '%</td><td class="' + cls + '">' + v.blocked_pct.toFixed(0) + '%</td>' +
                '<td>' + v.mtp + '</td></tr>';
        });
        html += '</tbody></table>';
        _showDrilldown('All Attack Vectors', html);
        _wireDrilldownRows();
    }

    /** Wire drill-down table rows: click to cross-filter */
    function _wireDrilldownRows() {
        document.querySelectorAll('.dp-dd-row-clickable').forEach(function (row) {
            row.addEventListener('click', function () {
                var field = this.getAttribute('data-field');
                var value = this.getAttribute('data-value');
                if (field && value) _setFilter(field, value);
            });
        });
    }

    /* ── Re-render with exclude-top toggled ──────────────────────── */

    function _rerenderChart(chartId) {
        if (!_chartData) return;
        var excl = _excludeTop[chartId] || false;
        if (chartId === 'heatmap' && _chartData.heatmap) {
            renderHeatmap('heatmapTable', _chartData.heatmap, excl);
        } else if (chartId === 'rootCause' && _chartData.root_cause) {
            renderRootCause('chartRootCauseCanvas', _chartData.root_cause, excl);
        }
    }

    /* ══════════════════════════════════════════════════════════════
       Initialization
       ══════════════════════════════════════════════════════════════ */

    function initDrilldowns(chartData, kpis) {
        _chartData = chartData;
        _kpis = kpis;
        _originalChartData = chartData;
        _originalKpis = kpis;

        // Close button
        var closeBtn = document.getElementById('dpDrilldownClose');
        if (closeBtn) closeBtn.addEventListener('click', _closeDrilldown);

        // Filter bar clear button
        var clearBtn = document.getElementById('dpFilterClear');
        if (clearBtn) clearBtn.addEventListener('click', function () { _clearFilter(); });

        // KPI card click handlers
        document.querySelectorAll('.dp-kpi-clickable').forEach(function (card) {
            card.addEventListener('click', function () {
                _handleKpiDrilldown(this.getAttribute('data-drilldown'));
            });
        });

        // View toggle handlers (Interactive / Static)
        document.querySelectorAll('.dp-view-toggle').forEach(function (toggle) {
            toggle.querySelectorAll('.dp-view-btn').forEach(function (btn) {
                btn.addEventListener('click', function (e) {
                    e.stopPropagation();
                    var mode = this.getAttribute('data-mode');
                    var card = this.closest('.dp-chart-card');
                    toggle.querySelectorAll('.dp-view-btn').forEach(function (b) { b.classList.remove('active'); });
                    this.classList.add('active');
                    var interactive = card.querySelector('.dp-interactive-chart');
                    var staticImg = card.querySelector('.dp-chart-img');
                    if (mode === 'interactive') {
                        if (interactive) interactive.style.display = '';
                        if (staticImg) staticImg.style.display = 'none';
                    } else {
                        if (interactive) interactive.style.display = 'none';
                        if (staticImg) staticImg.style.display = '';
                    }
                });
            });
        });

        // "Exclude #1" toggle handlers
        document.querySelectorAll('.dp-exclude-top-btn').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                var chartId = this.getAttribute('data-chart');
                _excludeTop[chartId] = !_excludeTop[chartId];
                this.classList.toggle('active', _excludeTop[chartId]);
                this.textContent = _excludeTop[chartId] ? 'Show All' : 'Exclude #1';
                _rerenderChart(chartId);
            });
        });

        // Make attack-vector cards clickable for cross-filtering
        document.querySelectorAll('.dp-av-card').forEach(function (card) {
            card.style.cursor = 'pointer';
            card.addEventListener('click', function () {
                var name = this.querySelector('.dp-av-name');
                if (name) _setFilter('vector', name.textContent);
            });
        });
    }

    /* ── Public API ──────────────────────────────────────────────── */

    return {
        renderDashboard: renderDashboard,
        renderRootCause: renderRootCause,
        renderAwareness: renderAwareness,
        renderHeatmap: renderHeatmap,
        initDrilldowns: initDrilldowns,
        setFilter: function (f, v) { _setFilter(f, v); },
        clearFilter: function () { _clearFilter(); },
        buildMMLink: function (f, v) { return _buildMMLink(f, v); },
    };
})();
