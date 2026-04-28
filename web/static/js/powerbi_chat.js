/**
 * Power BI Explorer — sidebar datasets, collapsible charts, chat with history.
 */
(function() {
    // DOM refs
    var msgBox        = document.getElementById('pbiMessages');
    var inputEl       = document.getElementById('pbiInput');
    var sendBtn       = document.getElementById('pbiSend');
    var loadingOverlay = document.getElementById('pbiLoadingOverlay');
    var loadingText    = document.getElementById('pbiLoadingText');
    var schemaDetails  = document.getElementById('pbiSchemaDetails');
    var schemaText     = document.getElementById('pbiSchemaText');
    var chipsEl       = document.getElementById('pbiChips');

    // State
    var sending       = false;
    var currentDatasetId   = '';
    var currentDatasetName = '';
    var chartInstances     = [];
    var transcript         = [];
    var activeAbort        = null;
    var activeReader       = null;
    var userStopped        = false;

    // Session ID
    var sessionId = localStorage.getItem('pbi_session_id');
    if (!sessionId) {
        sessionId = 'pbi_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('pbi_session_id', sessionId);
    }

    // ── Clipboard fallback for non-HTTPS contexts ──
    function fallbackCopy(text, onSuccess) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); if (onSuccess) onSuccess(); }
        catch(e) {}
        document.body.removeChild(ta);
    }

    // ══════════════════════ SIDEBAR ══════════════════════

    // Emoji mapping by keyword
    var DATASET_EMOJIS = {
        'ssl': '\uD83D\uDD12', 'certificate': '\uD83D\uDD12', 'cert': '\uD83D\uDD12', 'venafi': '\uD83D\uDD12',
        'endpoint': '\uD83D\uDDA5\uFE0F', 'workstation': '\uD83D\uDDA5\uFE0F', 'client': '\uD83D\uDDA5\uFE0F', 'desktop': '\uD83D\uDDA5\uFE0F',
        'server': '\uD83D\uDDA5\uFE0F',
        'patch': '\uD83D\uDEE1\uFE0F', 'patching': '\uD83D\uDEE1\uFE0F',
        'vulnerability': '\u26A0\uFE0F', 'vuln': '\u26A0\uFE0F', 'log4j': '\u26A0\uFE0F',
        'crowdstrike': '\uD83E\uDD85', 'falcon': '\uD83E\uDD85',
        'incident': '\uD83D\uDEA8', 'alert': '\uD83D\uDEA8',
        'dns': '\uD83C\uDF10', 'infoblox': '\uD83C\uDF10', 'network': '\uD83C\uDF10',
        'firewall': '\uD83D\uDD25', 'proxy': '\uD83D\uDD25',
        'health': '\uD83D\uDC9A', 'agent': '\uD83D\uDC9A',
        'usage': '\uD83D\uDCCA', 'metric': '\uD83D\uDCCA', 'report': '\uD83D\uDCCA', 'dashboard': '\uD83D\uDCCA', 'scorecard': '\uD83D\uDCCA',
        'cmdb': '\uD83D\uDDC3\uFE0F', 'consolidation': '\uD83D\uDDC3\uFE0F', 'sacm': '\uD83D\uDDC3\uFE0F',
        'os': '\u2699\uFE0F', 'currency': '\u2699\uFE0F',
        'tanium': '\uD83D\uDD0D',
        'bluevoyant': '\uD83D\uDC41\uFE0F', 'snare': '\uD83D\uDC41\uFE0F',
        'eai': '\uD83D\uDD17',
        'hva': '\u2B50',
    };
    var DEFAULT_EMOJI = '\uD83D\uDCE6'; // package box

    function getDatasetEmoji(name) {
        var lower = name.toLowerCase();
        for (var keyword in DATASET_EMOJIS) {
            if (lower.indexOf(keyword) !== -1) return DATASET_EMOJIS[keyword];
        }
        return DEFAULT_EMOJI;
    }

    function humanizeName(name) {
        // Replace underscores with spaces, keep existing spaces
        return name.replace(/_/g, ' ');
    }

    function formatDatasetLabel(name) {
        return getDatasetEmoji(name) + '  ' + humanizeName(name);
    }

    var datasetItems = document.querySelectorAll('.pbi-dataset-item');
    var searchInput  = document.getElementById('pbiSearch');
    var dsCountEl    = document.getElementById('pbiDsCount');

    // Apply human-readable labels + emojis + zebra striping
    datasetItems.forEach(function(item, idx) {
        item.textContent = formatDatasetLabel(item.getAttribute('data-name'));
        item.classList.add(idx % 2 === 0 ? 'pbi-zebra-even' : 'pbi-zebra-odd');
    });

    // Show count
    dsCountEl.textContent = datasetItems.length;

    // Search/filter
    searchInput.addEventListener('input', function() {
        var q = this.value.toLowerCase();
        var visible = 0;
        datasetItems.forEach(function(item) {
            var match = item.getAttribute('data-name').toLowerCase().indexOf(q) !== -1
                || humanizeName(item.getAttribute('data-name')).toLowerCase().indexOf(q) !== -1;
            item.style.display = match ? '' : 'none';
            if (match) visible++;
        });
        dsCountEl.textContent = visible;
    });

    // Click dataset
    datasetItems.forEach(function(item) {
        item.addEventListener('click', function() { selectDataset(item); });
    });

    function selectDataset(item) {
        var dsId = item.getAttribute('data-id');
        var dsName = item.getAttribute('data-name');
        if (dsId === currentDatasetId) return;

        // Confirm if switching away from a loaded dataset
        if (currentDatasetName) {
            var ok = confirm('Are you sure you want to unload ' + humanizeName(currentDatasetName) + ' and load ' + humanizeName(dsName) + '?');
            if (!ok) return;
        }

        // Highlight active
        datasetItems.forEach(function(el) { el.classList.remove('active'); });
        item.classList.add('active');

        currentDatasetId = dsId;
        currentDatasetName = dsName;

        // Clear previous chat and start fresh for new dataset
        msgBox.querySelectorAll('.pbi-msg').forEach(function(el) { el.remove(); });
        var welcome = document.getElementById('pbiWelcome');
        if (welcome) welcome.style.display = '';
        transcript = [];
        saveChatToStorage();

        // Save to recent
        addToRecent(dsId, dsName);

        // Load schema + charts
        loadDataset(dsId, dsName);
    }

    function showLoading(text) {
        loadingText.textContent = text;
        loadingOverlay.style.display = '';
    }
    function hideLoading() {
        loadingOverlay.style.display = 'none';
    }

    function highlightSchema(raw) {
        // Parse schema into collapsible <details> per table so all names visible at a glance
        var lines = raw.split('\n');
        var html = '';
        var tableName = '';
        var cols = '';
        var colCount = 0;

        function flushTable() {
            if (!tableName) return;
            html += '<details class="schema-table-details">' +
                    '<summary class="schema-table-summary"><span class="schema-table">' +
                    escapeHtml(tableName) + '</span>' +
                    '<span class="schema-col-count">' + colCount + ' col' + (colCount !== 1 ? 's' : '') + '</span></summary>' +
                    '<div class="schema-table-cols">' + cols + '</div></details>';
            cols = '';
            colCount = 0;
        }

        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            var tableMatch = line.match(/^Table:\s+(.+)$/);
            if (tableMatch) {
                flushTable();
                tableName = tableMatch[1];
            } else if (line.match(/^\s+-\s+/)) {
                colCount++;
                var colLine = escapeHtml(line)
                    .replace(/^(\s+-\s+)([^\s(]+)/, '$1<span class="schema-col">$2</span>')
                    .replace(/(\([^)]+\))/g, '<span class="schema-hint">$1</span>');
                cols += '<div class="schema-col-line">' + colLine + '</div>';
            }
        }
        flushTable();
        return html;
    }

    var SCHEMA_CACHE_KEY = 'pbi_schema_cache';

    function getCachedSchema(dsId) {
        try {
            var cache = JSON.parse(sessionStorage.getItem(SCHEMA_CACHE_KEY)) || {};
            return cache[dsId] || null;
        } catch(e) { return null; }
    }

    function setCachedSchema(dsId, schema) {
        try {
            var cache = JSON.parse(sessionStorage.getItem(SCHEMA_CACHE_KEY)) || {};
            cache[dsId] = schema;
            sessionStorage.setItem(SCHEMA_CACHE_KEY, JSON.stringify(cache));
        } catch(e) {}
    }

    function loadDataset(dsId, dsName) {
        var hName = humanizeName(dsName);
        destroyCharts();

        var cached = getCachedSchema(dsId);
        if (cached) {
            applySchema(cached, dsId, dsName);
            return;
        }

        showLoading(getDatasetEmoji(dsName) + '  Loading ' + hName + '...');
        fetch('/api/powerbi/schema/' + dsId)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            hideLoading();
            if (data.success) {
                setCachedSchema(dsId, data.schema);
                applySchema(data.schema, dsId, dsName);
            } else {
                schemaDetails.style.display = 'none';
            }
        })
        .catch(function(err) {
            hideLoading();
        });
    }

    function applySchema(schema, dsId, dsName) {
        schemaText.innerHTML = highlightSchema(schema);
        schemaDetails.style.display = '';
        inputEl.disabled = false;
        sendBtn.disabled = false;
        inputEl.focus();
        inputEl.classList.remove('pbi-pulse');
        void inputEl.offsetWidth;
        inputEl.classList.add('pbi-pulse');
        fetchAndRenderCharts(dsId);
        fetchRefreshInfo(dsId);
        document.getElementById('pbiExportPptx').style.display = '';
    }

    // ── Data freshness ──
    var refreshInfoEl = document.getElementById('pbiRefreshInfo');

    function fetchRefreshInfo(dsId) {
        refreshInfoEl.style.display = 'none';
        fetch('/api/powerbi/refresh/' + dsId)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success && data.refresh && data.refresh.endTime) {
                var dt = new Date(data.refresh.endTime);
                var ago = timeAgo(dt);
                refreshInfoEl.textContent = '\uD83D\uDD04 Refreshed ' + ago;
                refreshInfoEl.style.display = '';
            }
        })
        .catch(function() {});
    }

    function timeAgo(date) {
        var diff = Math.floor((Date.now() - date.getTime()) / 1000);
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
    }

    // ── PPTX export ──
    var currentChartData = null; // stored when charts render

    document.getElementById('pbiExportPptx').addEventListener('click', function() {
        if (!currentChartData) return;
        fetch('/api/powerbi/export/pptx', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                dataset_name: currentDatasetName,
                kpis: currentChartData.kpis || [],
                charts: currentChartData.charts || [],
            }),
        })
        .then(function(resp) {
            if (!resp.ok) throw new Error('Export failed');
            return resp.blob();
        })
        .then(function(blob) {
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'PowerBI - ' + (currentDatasetName || 'Dashboard').replace(/_/g, ' ') + ' Dashboard.pptx';
            a.click();
            URL.revokeObjectURL(a.href);
        })
        .catch(function(err) { alert('PPTX export failed: ' + err.message); });
    });

    // ══════════════════════ RECENT DATASETS (localStorage) ══════════════════════

    var RECENT_KEY = 'pbi_recent_datasets';
    var MAX_RECENT = 5;

    function getRecent() {
        try { return JSON.parse(localStorage.getItem(RECENT_KEY)) || []; }
        catch(e) { return []; }
    }

    function addToRecent(id, name) {
        var recent = getRecent().filter(function(r) { return r.id !== id; });
        recent.unshift({id: id, name: name});
        if (recent.length > MAX_RECENT) recent = recent.slice(0, MAX_RECENT);
        localStorage.setItem(RECENT_KEY, JSON.stringify(recent));
        renderRecent();
    }

    function renderRecent() {
        var recent = getRecent();
        var section = document.getElementById('pbiRecentSection');
        var list = document.getElementById('pbiRecentList');
        if (!recent.length) { section.style.display = 'none'; return; }
        section.style.display = '';
        list.innerHTML = '';
        recent.forEach(function(r) {
            var btn = document.createElement('button');
            btn.className = 'pbi-dataset-item recent-badge';
            btn.setAttribute('data-id', r.id);
            btn.setAttribute('data-name', r.name);
            btn.textContent = formatDatasetLabel(r.name);
            if (r.id === currentDatasetId) btn.classList.add('active');
            btn.addEventListener('click', function() {
                if (currentDatasetName && r.id !== currentDatasetId) {
                    var ok = confirm('Are you sure you want to unload ' + humanizeName(currentDatasetName) + ' and load ' + humanizeName(r.name) + '?');
                    if (!ok) return;
                }
                // Also highlight in main list
                datasetItems.forEach(function(el) {
                    el.classList.toggle('active', el.getAttribute('data-id') === r.id);
                });
                list.querySelectorAll('.pbi-dataset-item').forEach(function(el) { el.classList.remove('active'); });
                btn.classList.add('active');
                currentDatasetId = r.id;
                currentDatasetName = r.name;
                // Clear previous chat for new dataset
                msgBox.querySelectorAll('.pbi-msg').forEach(function(el) { el.remove(); });
                var w = document.getElementById('pbiWelcome');
                if (w) w.style.display = '';
                transcript = [];
                saveChatToStorage();
                loadDataset(r.id, r.name);
            });
            list.appendChild(btn);
        });
    }
    renderRecent(); // init on page load

    // ══════════════════════ CHARTS ══════════════════════

    function isDark() { return document.body.classList.contains('dark-mode'); }

    function chartTheme() {
        var dk = isDark();
        return {
            text: dk ? '#cbd5e1' : '#475569',
            grid: dk ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)',
            legend: dk ? '#94a3b8' : '#64748b',
        };
    }

    function destroyCharts() {
        chartInstances.forEach(function(c) { c.destroy(); });
        chartInstances = [];
        document.getElementById('pbiChartGrid').innerHTML = '';
        document.getElementById('pbiKpiRow').innerHTML = '';
        document.getElementById('pbiChartsContent').style.display = 'none';
        document.getElementById('pbiChartsEmpty').style.display = 'flex';
    }

    function showChartSkeletons() {
        document.getElementById('pbiChartsEmpty').style.display = 'none';
        var content = document.getElementById('pbiChartsContent');
        content.style.display = 'block';
        document.getElementById('pbiKpiRow').innerHTML =
            '<div class="pbi-skeleton-kpi-row">' +
            '<div class="pbi-skeleton-kpi"></div>'.repeat(4) +
            '</div>';
        document.getElementById('pbiChartGrid').innerHTML =
            '<div class="pbi-skeleton-grid">' +
            '<div class="pbi-skeleton-chart"></div>'.repeat(3) +
            '</div>';
        chipsEl.innerHTML =
            '<div class="pbi-skeleton-chips">' +
            '<div class="pbi-skeleton-chip"></div>'.repeat(5) +
            '</div>';
    }

    function fetchAndRenderCharts(datasetId) {
        showChartSkeletons();
        // Expand charts if collapsed
        var panel = document.getElementById('pbiChartsPanel');
        var toggle = document.getElementById('pbiChartsToggle');
        panel.classList.remove('collapsed');
        toggle.classList.remove('collapsed');

        fetch('/api/powerbi/charts/' + datasetId + '?name=' + encodeURIComponent(currentDatasetName || ''))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data.success) return;
            currentChartData = data;
            renderKpis(data.kpis || []);
            renderChartCards(data.charts || []);
            renderChips(data.chips || []);

            // Fetch smarter LLM-generated chips (replaces auto-generated ones when ready)
            fetch('/api/powerbi/chips/' + datasetId + '?name=' + encodeURIComponent(currentDatasetName || ''))
            .then(function(r2) { return r2.json(); })
            .then(function(chipData) {
                if (chipData.success && chipData.chips && chipData.chips.length > 0) {
                    renderChips(chipData.chips);
                }
            })
            .catch(function() {});
        })
        .catch(function(err) { console.error('Charts fetch failed:', err); });
    }

    function renderKpis(kpis) {
        var row = document.getElementById('pbiKpiRow');
        row.innerHTML = '';
        kpis.forEach(function(kpi) {
            var card = document.createElement('div');
            card.className = 'pbi-kpi-card';
            card.style.borderLeftColor = kpi.color || '#0046ad';
            var valEl = document.createElement('div');
            valEl.className = 'pbi-kpi-value';
            valEl.style.color = kpi.color || '#1a237e';
            var labelEl = document.createElement('div');
            labelEl.className = 'pbi-kpi-label';
            labelEl.textContent = kpi.label;
            card.appendChild(valEl);
            card.appendChild(labelEl);
            row.appendChild(card);
            // Animate number counting up
            animateKpiValue(valEl, kpi.value);
        });
    }

    function animateKpiValue(el, finalText) {
        // Extract numeric part for animation
        var cleaned = finalText.replace(/[,%$]/g, '').replace(/,/g, '');
        var num = parseFloat(cleaned);
        if (isNaN(num) || finalText.match(/[a-zA-Z]{2,}/)) {
            // Non-numeric (e.g. "4.2h", "Active") — just set it
            el.textContent = finalText;
            return;
        }
        var hasPercent = finalText.indexOf('%') !== -1;
        var hasDollar = finalText.indexOf('$') !== -1;
        var isDecimal = finalText.indexOf('.') !== -1;
        var duration = 800;
        var startTime = performance.now();

        function tick(now) {
            var progress = Math.min((now - startTime) / duration, 1);
            // Ease out cubic
            var eased = 1 - Math.pow(1 - progress, 3);
            var current = num * eased;
            var display;
            if (isDecimal) {
                display = current.toLocaleString(undefined, {minimumFractionDigits: 1, maximumFractionDigits: 1});
            } else {
                display = Math.round(current).toLocaleString();
            }
            if (hasDollar) display = '$' + display;
            if (hasPercent) display = display + '%';
            el.textContent = display;
            if (progress < 1) requestAnimationFrame(tick);
            else el.textContent = finalText; // ensure exact final value
        }
        requestAnimationFrame(tick);
    }

    function renderChartCards(charts) {
        var grid = document.getElementById('pbiChartGrid');
        grid.innerHTML = '';
        var t = chartTheme();

        charts.forEach(function(chart) {
            var card = document.createElement('div');
            card.className = 'pbi-chart-card';
            card.innerHTML = '<div class="pbi-chart-title">' + escapeHtml(chart.title) + '</div>' +
                '<div class="pbi-chart-canvas-wrap"><canvas></canvas></div>' +
                (chart.insight ? '<div class="pbi-chart-insight">' + escapeHtml(chart.insight) + '</div>' : '');
            grid.appendChild(card);

            var canvas = card.querySelector('canvas');
            var isHBar = chart.type === 'horizontalBar';
            var chartType = isHBar ? 'bar' : chart.type;
            var isDoughnut = chart.type === 'doughnut' || chart.type === 'pie';

            var datasets = chart.datasets.map(function(ds) {
                var cfg = {
                    label: ds.label,
                    data: ds.data,
                    backgroundColor: ds.colors || ds.color,
                };
                if (chart.type === 'line') {
                    cfg.borderColor = ds.color;
                    cfg.backgroundColor = ds.color + '22';
                    cfg.fill = true;
                    cfg.tension = 0.35;
                    cfg.pointRadius = 4;
                    cfg.pointBackgroundColor = ds.color;
                    cfg.borderWidth = 2.5;
                }
                return cfg;
            });

            var options = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: datasets.length > 1 || isDoughnut,
                        position: isDoughnut ? 'right' : 'top',
                        labels: { color: t.legend, font: { size: 9 }, boxWidth: 10, padding: 6 },
                    },
                },
            };

            if (!isDoughnut) {
                var xLabel = chart.xLabel || (chart.labels ? '' : '');
                var yLabel = chart.yLabel || '';
                options.indexAxis = isHBar ? 'y' : 'x';
                options.scales = {
                    x: {
                        ticks: { color: t.text, font: { size: 8 }, maxRotation: 45 },
                        grid: { color: t.grid },
                        stacked: !!chart.stacked,
                        title: xLabel ? { display: true, text: xLabel, color: t.text, font: { size: 9, weight: 'bold' } } : undefined,
                    },
                    y: {
                        ticks: { color: t.text, font: { size: 8 } },
                        grid: { color: t.grid },
                        stacked: !!chart.stacked,
                        title: yLabel ? { display: true, text: yLabel, color: t.text, font: { size: 9, weight: 'bold' } } : undefined,
                    },
                };
            }

            var instance = new Chart(canvas, {
                type: chartType,
                data: { labels: chart.labels, datasets: datasets },
                options: options,
            });
            chartInstances.push(instance);

            // Click chart card -> send question
            if (chart.clickQuery) {
                card.addEventListener('click', function() {
                    if (currentDatasetId) sendQuestion(chart.clickQuery);
                });
            }
        });
    }

    // ── Collapsible charts ──
    var chartsToggle = document.getElementById('pbiChartsToggle');
    var chartsBar = document.getElementById('pbiChartsBar');
    var chartsPanel = document.getElementById('pbiChartsPanel');
    var CHARTS_COLLAPSED_KEY = 'pbi_charts_collapsed';

    // Restore collapsed state
    if (localStorage.getItem(CHARTS_COLLAPSED_KEY) === '1') {
        chartsPanel.classList.add('collapsed');
        chartsToggle.classList.add('collapsed');
    }

    chartsBar.addEventListener('click', function() {
        var collapsed = chartsPanel.classList.toggle('collapsed');
        chartsToggle.classList.toggle('collapsed', collapsed);
        localStorage.setItem(CHARTS_COLLAPSED_KEY, collapsed ? '1' : '0');
    });

    // ── Collapse DAX blocks ──
    function collapseDaxBlocks(container) {
        var pres = container.querySelectorAll('pre');
        for (var i = 0; i < pres.length; i++) {
            var code = pres[i].querySelector('code');
            if (!code) continue;
            var text = code.textContent || '';
            if (!/^\s*EVALUATE/i.test(text)) continue;
            var details = document.createElement('details');
            details.className = 'pbi-dax-toggle';
            var summary = document.createElement('summary');
            summary.textContent = 'Show DAX';
            details.appendChild(summary);
            pres[i].parentNode.insertBefore(details, pres[i]);
            details.appendChild(pres[i]);
        }
    }

    // ── Dynamic chips ──

    function renderChips(chips) {
        chipsEl.innerHTML = '';
        chips.forEach(function(chip) {
            var el = document.createElement('div');
            el.className = 'pbi-example-chip';
            el.textContent = chip.label;
            el.setAttribute('data-q', chip.query);
            el.addEventListener('click', function() {
                if (currentDatasetId) sendQuestion(chip.query);
            });
            chipsEl.appendChild(el);
        });
    }

    // ══════════════════════ CHAT HELPERS ══════════════════════

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function appendMsg(role, html) {
        var welcome = msgBox.querySelector('.pbi-welcome');
        if (welcome) welcome.style.display = 'none';
        var wrap = document.createElement('div');
        wrap.className = 'pbi-msg pbi-' + role;
        var bubble = document.createElement('div');
        bubble.className = 'pbi-bubble';
        bubble.innerHTML = html;
        wrap.appendChild(bubble);
        if (role === 'user') {
            var del = document.createElement('button');
            del.className = 'pbi-delete-msg';
            del.title = 'Remove from context';
            del.innerHTML = '&#128465;';
            del.addEventListener('click', function() { deleteQAPair(wrap); });
            wrap.appendChild(del);
        }
        if (chipsEl && chipsEl.parentNode === msgBox) {
            msgBox.insertBefore(wrap, chipsEl);
        } else {
            msgBox.appendChild(wrap);
        }
        msgBox.scrollTop = msgBox.scrollHeight;
        return wrap;
    }

    function deleteQAPair(userWrap) {
        // Find the assistant response (next .pbi-msg sibling)
        var assistantWrap = userWrap.nextElementSibling;
        while (assistantWrap && !assistantWrap.classList.contains('pbi-msg')) {
            assistantWrap = assistantWrap.nextElementSibling;
        }

        // Determine pair index from DOM order
        var allUserMsgs = msgBox.querySelectorAll('.pbi-msg.pbi-user');
        var pairIndex = -1;
        for (var i = 0; i < allUserMsgs.length; i++) {
            if (allUserMsgs[i] === userWrap) { pairIndex = i; break; }
        }

        // Remove from DOM
        if (assistantWrap && assistantWrap.classList.contains('pbi-assistant')) {
            assistantWrap.remove();
        }
        userWrap.remove();

        // Remove from transcript and save — server uses client history on next request
        if (pairIndex >= 0 && pairIndex * 2 < transcript.length) {
            transcript.splice(pairIndex * 2, 2);
            saveChatToStorage();
        }
    }

    // ── Response action buttons (copy, CSV) ──

    function addResponseActions(wrap, rawText) {
        var row = document.createElement('div');
        row.className = 'pbi-response-actions';

        // Copy button
        var copyBtn = document.createElement('button');
        copyBtn.className = 'pbi-small-btn';
        copyBtn.innerHTML = '&#128203; Copy';
        copyBtn.addEventListener('click', function() {
            function onSuccess() {
                copyBtn.classList.add('copied');
                copyBtn.innerHTML = '&#10003; Copied';
                setTimeout(function() {
                    copyBtn.classList.remove('copied');
                    copyBtn.innerHTML = '&#128203; Copy';
                }, 2000);
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(rawText).then(onSuccess).catch(function() { fallbackCopy(rawText, onSuccess); });
            } else {
                fallbackCopy(rawText, onSuccess);
            }
        });
        row.appendChild(copyBtn);

        // Excel export if response has a table
        var tableData = extractTableFromMarkdown(rawText);
        if (tableData) {
            var xlsxBtn = document.createElement('button');
            xlsxBtn.className = 'pbi-small-btn';
            xlsxBtn.innerHTML = '&#128229; Export Excel';
            xlsxBtn.addEventListener('click', function() { downloadXlsx(tableData); });
            row.appendChild(xlsxBtn);
        }

        // Save/bookmark button — find the user question that preceded this response
        var userQuestion = '';
        var prev = wrap.previousElementSibling;
        while (prev) {
            if (prev.classList.contains('pbi-user')) {
                var ub = prev.querySelector('.pbi-bubble');
                if (ub) userQuestion = ub.textContent;
                break;
            }
            prev = prev.previousElementSibling;
        }
        if (userQuestion) {
            var saveBtn = document.createElement('button');
            saveBtn.className = 'pbi-small-btn pbi-save-btn';
            var alreadySaved = isSavedQuery(userQuestion);
            saveBtn.innerHTML = alreadySaved ? '&#11088; Saved' : '&#9734; Save';
            if (alreadySaved) saveBtn.classList.add('saved');
            saveBtn.addEventListener('click', function() {
                if (saveBtn.classList.contains('saved')) {
                    removeSavedQuery(userQuestion);
                    saveBtn.classList.remove('saved');
                    saveBtn.innerHTML = '&#9734; Save';
                } else {
                    addSavedQuery(userQuestion);
                    saveBtn.classList.add('saved');
                    saveBtn.innerHTML = '&#11088; Saved';
                }
            });
            row.appendChild(saveBtn);
        }

        wrap.appendChild(row);
    }

    // ══════════════════════ SAVED QUERIES (localStorage) ══════════════════════

    var SAVED_KEY = 'pbi_saved_queries';

    function getSavedQueries() {
        try { return JSON.parse(localStorage.getItem(SAVED_KEY)) || []; }
        catch(e) { return []; }
    }

    function isSavedQuery(question) {
        return getSavedQueries().some(function(q) { return q.text === question && q.dataset_id === currentDatasetId; });
    }

    function addSavedQuery(question) {
        var saved = getSavedQueries();
        saved.unshift({text: question, dataset_id: currentDatasetId, dataset_name: currentDatasetName, time: new Date().toLocaleString()});
        localStorage.setItem(SAVED_KEY, JSON.stringify(saved));
    }

    function removeSavedQuery(question) {
        var saved = getSavedQueries().filter(function(q) { return !(q.text === question && q.dataset_id === currentDatasetId); });
        localStorage.setItem(SAVED_KEY, JSON.stringify(saved));
    }

    var savedBtn = document.getElementById('pbiSavedBtn');
    var savedDropdown = document.getElementById('pbiSavedDropdown');

    savedBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        var visible = savedDropdown.style.display !== 'none';
        if (visible) { savedDropdown.style.display = 'none'; return; }
        historyDropdown.style.display = 'none'; // close other dropdown

        var saved = getSavedQueries();
        savedDropdown.innerHTML = '';
        if (!saved.length) {
            savedDropdown.innerHTML = '<div class="pbi-history-empty">No saved queries yet</div>';
        } else {
            saved.forEach(function(item) {
                var btn = document.createElement('button');
                btn.className = 'pbi-history-item';
                btn.textContent = '\u2B50 ' + item.text;
                btn.title = humanizeName(item.dataset_name) + ' \u2014 ' + item.time;
                btn.addEventListener('click', function() {
                    savedDropdown.style.display = 'none';
                    if (currentDatasetId) sendQuestion(item.text);
                });
                savedDropdown.appendChild(btn);
            });
        }
        savedDropdown.style.display = '';
    });

    document.addEventListener('click', function() { savedDropdown.style.display = 'none'; });
    savedDropdown.addEventListener('click', function(e) { e.stopPropagation(); });

    // ── Excel/CSV Export ──

    function extractTableFromMarkdown(text) {
        // Find markdown table in text
        var lines = text.split('\n');
        var headerIdx = -1;
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].trim().match(/^\|.*\|$/) && i + 1 < lines.length && lines[i+1].trim().match(/^\|[\s\-:|]+\|$/)) {
                headerIdx = i;
                break;
            }
        }
        if (headerIdx === -1) return null;

        var headers = lines[headerIdx].split('|').map(function(s) { return s.trim(); }).filter(Boolean);
        var rows = [];
        for (var j = headerIdx + 2; j < lines.length; j++) {
            var line = lines[j].trim();
            if (!line.match(/^\|.*\|$/)) break;
            var cells = line.split('|').map(function(s) { return s.trim(); }).filter(Boolean);
            rows.push(cells);
        }
        return {headers: headers, rows: rows};
    }

    function downloadXlsx(tableData) {
        fetch('/api/powerbi/export/xlsx', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                headers: tableData.headers,
                rows: tableData.rows,
                dataset_name: currentDatasetName || 'Results',
            }),
        })
        .then(function(resp) {
            if (!resp.ok) throw new Error('Export failed');
            return resp.blob();
        })
        .then(function(blob) {
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'PowerBI - ' + (currentDatasetName || 'Results') + '.xlsx';
            a.click();
            URL.revokeObjectURL(a.href);
        })
        .catch(function(err) { alert('Export failed: ' + err.message); });
    }

    // ── Auto-chart from results ──

    function tryAutoChart(wrap, rawText) {
        var td = extractTableFromMarkdown(rawText);
        if (!td || td.rows.length < 2 || td.rows.length > 30) return;
        if (td.headers.length < 2) return;

        // Find first numeric column
        var numIdx = -1;
        for (var c = 0; c < td.headers.length; c++) {
            var allNum = td.rows.every(function(row) {
                return row[c] && !isNaN(row[c].replace(/[,%$]/g, '').replace(/,/g, ''));
            });
            if (allNum) { numIdx = c; break; }
        }
        if (numIdx === -1) return;

        // Use first non-numeric column as labels
        var labelIdx = numIdx === 0 ? 1 : 0;
        var labels = td.rows.map(function(r) { return r[labelIdx] || ''; });
        var values = td.rows.map(function(r) {
            return parseFloat(r[numIdx].replace(/[,%$]/g, '').replace(/,/g, ''));
        });

        var chartWrap = document.createElement('div');
        chartWrap.className = 'pbi-result-chart-wrap';
        var canvas = document.createElement('canvas');
        chartWrap.appendChild(canvas);

        // Insert after bubble
        var bubble = wrap.querySelector('.pbi-bubble');
        if (bubble && bubble.nextSibling) {
            wrap.insertBefore(chartWrap, bubble.nextSibling);
        } else {
            wrap.appendChild(chartWrap);
        }

        var t = chartTheme();
        var colors = ['#0046ad','#00a651','#f6be00','#6a1b9a','#dc2626','#0891b2','#d946ef','#ea580c','#4f46e5','#059669'];
        var bgColors = labels.map(function(_, i) { return colors[i % colors.length]; });

        var chartType = td.rows.length <= 8 ? 'bar' : 'bar';
        new Chart(canvas, {
            type: chartType,
            data: {
                labels: labels,
                datasets: [{
                    label: td.headers[numIdx],
                    data: values,
                    backgroundColor: bgColors.map(function(c) { return c + '99'; }),
                    borderColor: bgColors,
                    borderWidth: 1.5,
                }],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        ticks: { color: t.text, font: { size: 8 }, maxRotation: 45 },
                        grid: { color: t.grid },
                        title: { display: true, text: td.headers[labelIdx], color: t.text, font: { size: 9, weight: 'bold' } },
                    },
                    y: {
                        ticks: { color: t.text, font: { size: 8 } },
                        grid: { color: t.grid },
                        title: { display: true, text: td.headers[numIdx], color: t.text, font: { size: 9, weight: 'bold' } },
                    },
                },
            },
        });
    }

    // ── Transcript ──

    var CHAT_STORAGE_KEY = 'pbi_chat_history';

    function addToTranscript(role, text) {
        transcript.push({role: role, text: text, time: new Date().toLocaleString()});
        document.getElementById('pbiDownloadTranscript').style.display = '';
        saveChatToStorage();
    }

    function saveChatToStorage() {
        if (!currentDatasetId) return;
        try {
            localStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify({
                dataset_id: currentDatasetId,
                dataset_name: currentDatasetName,
                transcript: transcript,
            }));
        } catch(e) {}
    }

    function loadChatFromStorage() {
        try { return JSON.parse(localStorage.getItem(CHAT_STORAGE_KEY)); }
        catch(e) { return null; }
    }

    function clearChatStorage() {
        localStorage.removeItem(CHAT_STORAGE_KEY);
    }

    function downloadTranscript() {
        if (!transcript.length) return;
        var lines = ['Power BI Explorer Chat Transcript', 'Dataset: ' + currentDatasetName, 'Date: ' + new Date().toLocaleString(), ''];
        transcript.forEach(function(t) {
            lines.push('[' + t.time + '] ' + (t.role === 'user' ? 'USER' : 'ASSISTANT') + ':');
            lines.push(t.text);
            lines.push('');
        });
        var blob = new Blob([lines.join('\n')], {type: 'text/plain'});
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'powerbi-chat-' + new Date().toISOString().slice(0, 10) + '.txt';
        a.click();
        URL.revokeObjectURL(a.href);
    }

    // ══════════════════════ QUERY HISTORY (localStorage) ══════════════════════

    var HISTORY_KEY = 'pbi_query_history';
    var MAX_HISTORY_ITEMS = 30;

    function getHistory() {
        try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
        catch(e) { return []; }
    }

    function addToHistory(question) {
        var h = getHistory().filter(function(q) { return q.text !== question; });
        h.unshift({text: question, dataset: currentDatasetName, time: new Date().toLocaleString()});
        if (h.length > MAX_HISTORY_ITEMS) h = h.slice(0, MAX_HISTORY_ITEMS);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(h));
    }

    var historyBtn = document.getElementById('pbiHistoryBtn');
    var historyDropdown = document.getElementById('pbiHistoryDropdown');

    historyBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        var visible = historyDropdown.style.display !== 'none';
        if (visible) { historyDropdown.style.display = 'none'; return; }

        var h = getHistory();
        historyDropdown.innerHTML = '';
        if (!h.length) {
            historyDropdown.innerHTML = '<div class="pbi-history-empty">No query history yet</div>';
        } else {
            h.forEach(function(item) {
                var btn = document.createElement('button');
                btn.className = 'pbi-history-item';
                btn.textContent = item.text;
                btn.title = item.dataset + ' — ' + item.time;
                btn.addEventListener('click', function() {
                    historyDropdown.style.display = 'none';
                    if (currentDatasetId) sendQuestion(item.text);
                });
                historyDropdown.appendChild(btn);
            });
        }
        historyDropdown.style.display = '';
    });

    // Close dropdown on outside click
    document.addEventListener('click', function() { historyDropdown.style.display = 'none'; });
    historyDropdown.addEventListener('click', function(e) { e.stopPropagation(); });

    // ── Audio ──
    var audioCtx = null;
    function playDing() {
        try {
            if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            var osc = audioCtx.createOscillator();
            var gain = audioCtx.createGain();
            osc.connect(gain); gain.connect(audioCtx.destination);
            osc.type = 'sine';
            osc.frequency.setValueAtTime(880, audioCtx.currentTime);
            osc.frequency.setValueAtTime(660, audioCtx.currentTime + 0.1);
            gain.gain.setValueAtTime(0.3, audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.4);
            osc.start(audioCtx.currentTime); osc.stop(audioCtx.currentTime + 0.4);
        } catch(e) {}
    }

    // ══════════════════════ SEND QUESTION ══════════════════════

    function setStopMode(on) {
        if (on) {
            sendBtn.disabled = false;
            sendBtn.textContent = 'Stop';
            sendBtn.classList.add('pbi-stop-mode');
        } else {
            sendBtn.textContent = 'Send \u00BB';
            sendBtn.classList.remove('pbi-stop-mode');
        }
    }

    function stopGeneration() {
        userStopped = true;
        if (activeReader) { try { activeReader.cancel(); } catch(e) {} activeReader = null; }
        if (activeAbort) { activeAbort.abort(); activeAbort = null; }
    }

    function addRetryButton(container, questionText) {
        var btn = document.createElement('button');
        btn.className = 'pbi-retry-btn';
        btn.innerHTML = '&#x21bb; Retry';
        btn.onclick = function() { sendQuestion(questionText); };
        container.appendChild(btn);
    }

    function sendQuestion(text) {
        if (!text || !currentDatasetId) return;
        if (sending) return;
        sending = true;
        inputEl.value = '';
        setStopMode(true);
        userStopped = false;
        chipsEl.style.display = 'none';
        appendMsg('user', escapeHtml(text));
        addToTranscript('user', text);
        addToHistory(text);
        activeAbort = new AbortController();

        var dsn = humanizeName(currentDatasetName || 'dataset');
        var loadingMsgs = [
            'Generating DAX query for ' + dsn + '\u2026',
            'Analyzing ' + dsn + ' schema\u2026',
            'Translating to Power BI query\u2026',
            'Running query against ' + dsn + '\u2026',
            'Crunching the ' + dsn + ' numbers\u2026',
            'Formatting results\u2026',
            'Almost there\u2026'
        ];
        var loadingHtml = '<div class="pbi-loading-indicator">' +
            '<div class="pbi-loading-top">' +
                '<span class="pbi-loading-spinner"></span>' +
                '<span class="pbi-loading-msg">' + loadingMsgs[0] + '</span>' +
            '</div>' +
            '<div class="pbi-loading-bottom"><span class="pbi-loading-timer">0s</span></div>' +
        '</div>';
        var wrap = appendMsg('assistant', loadingHtml);
        var bubble = wrap.querySelector('.pbi-bubble');
        var timerEl = bubble.querySelector('.pbi-loading-timer');
        var msgEl = bubble.querySelector('.pbi-loading-msg');
        var loadStart = Date.now();
        var msgIdx = 0;
        var loadTimer = setInterval(function() {
            timerEl.textContent = Math.floor((Date.now() - loadStart) / 1000) + 's';
        }, 1000);
        var loadingRotator = setInterval(function() {
            msgIdx = (msgIdx + 1) % loadingMsgs.length;
            if (msgEl) msgEl.textContent = loadingMsgs[msgIdx];
        }, 8000);

        fetch('/api/powerbi/chat/stream', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: text, dataset_id: currentDatasetId, dataset_name: currentDatasetName || '', session_id: sessionId, history: transcript.map(function(t) { return {role: t.role, text: t.text}; })}),
            signal: activeAbort ? activeAbort.signal : undefined
        }).then(function(resp) {
            if (!resp.ok) throw new Error('Server error ' + resp.status);
            var reader = resp.body.getReader();
            activeReader = reader;
            var decoder = new TextDecoder();
            var fullText = '';
            var loadingCleared = false;

            function pump() {
                return reader.read().then(function(result) {
                    if (result.done) { finish(userStopped); return; }
                    var chunk = decoder.decode(result.value, {stream: true});
                    var lines = chunk.split('\n');
                    for (var i = 0; i < lines.length; i++) {
                        var line = lines[i];
                        if (!line.startsWith('data: ')) continue;
                        try {
                            var data = JSON.parse(line.slice(6));
                            if (data.token && !loadingCleared) {
                                loadingCleared = true;
                                clearInterval(loadTimer); clearInterval(loadingRotator);
                                bubble.innerHTML = '';
                            }
                            if (data.token) {
                                fullText += data.token;
                                bubble.innerHTML = marked.parse(fullText) + '<span class="pbi-cursor">\u258B</span>';
                            }
                            if (data.error) {
                                if (!loadingCleared) {
                                    loadingCleared = true;
                                    clearInterval(loadTimer); clearInterval(loadingRotator);
                                    bubble.innerHTML = '';
                                }
                                bubble.innerHTML += '<em style="color:#ef4444">' + escapeHtml(data.error) + '</em>';
                                addRetryButton(bubble, text);
                                finish();
                                return;
                            }
                            if (data.done) {
                                bubble.innerHTML = marked.parse(fullText);
                                collapseDaxBlocks(bubble);
                                var m = data.metrics || {};
                                var parts = [];
                                if (m.time != null) {
                                    var timeStr = m.time + 's';
                                    if (m.eval_time != null && m.gen_time != null) {
                                        timeStr += ' (' + m.eval_time + 's eval + ' + m.gen_time + 's gen)';
                                    }
                                    parts.push(timeStr);
                                }
                                if (m.input_tokens != null && m.output_tokens != null)
                                    parts.push(m.input_tokens + '\u2192' + m.output_tokens + ' tokens');
                                if (m.speed != null && m.speed > 0) parts.push('TPS: ' + m.speed);
                                if (m.eval_time != null) parts.push('TTFT ' + m.eval_time + 's');
                                if (parts.length) {
                                    var metaDiv = document.createElement('div');
                                    metaDiv.className = 'pbi-meta';
                                    metaDiv.textContent = '\u26A1 ' + parts.join(' | ');
                                    wrap.appendChild(metaDiv);
                                }
                                // Stats for nerds — per-stage timing
                                if (m.stages) {
                                    var sp = [];
                                    if (m.stages.dax_gen != null) sp.push('NL\u2192DAX: ' + m.stages.dax_gen + 's');
                                    if (m.stages.dax_exec != null) sp.push('Execute: ' + m.stages.dax_exec + 's');
                                    if (m.stages.explain != null) sp.push('Explain: ' + m.stages.explain + 's');
                                    if (sp.length) {
                                        var stagesDiv = document.createElement('div');
                                        stagesDiv.className = 'pbi-meta pbi-stages';
                                        stagesDiv.textContent = '\uD83D\uDD2C ' + sp.join(' \u2192 ');
                                        wrap.appendChild(stagesDiv);
                                    }
                                }
                                addResponseActions(wrap, fullText);
                                tryAutoChart(wrap, fullText);
                                addToTranscript('assistant', fullText);
                            }
                        } catch(e) {}
                    }
                    msgBox.scrollTop = msgBox.scrollHeight;
                    return pump();
                });
            }

            function finish(stopped) {
                clearInterval(loadTimer); clearInterval(loadingRotator);
                var cursor = bubble.querySelector('.pbi-cursor');
                if (cursor) cursor.remove();
                if (stopped) {
                    if (fullText) {
                        bubble.innerHTML = marked.parse(fullText) + '<br><em style="color:#f59e0b">(Stopped)</em>';
                        collapseDaxBlocks(bubble);
                        addResponseActions(wrap, fullText);
                        addToTranscript('assistant', fullText + '\n(Stopped)');
                    } else {
                        bubble.innerHTML = '<em style="color:#f59e0b">(Stopped)</em>';
                    }
                    var elapsed = ((Date.now() - loadStart) / 1000).toFixed(1);
                    var metaDiv = document.createElement('div');
                    metaDiv.className = 'pbi-meta';
                    metaDiv.textContent = '\u26A1 ' + elapsed + 's (stopped by user)';
                    wrap.appendChild(metaDiv);
                }
                sending = false; activeReader = null; activeAbort = null;
                setStopMode(false); sendBtn.disabled = false;
                chipsEl.style.display = '';
                inputEl.focus(); playDing();
            }
            pump().catch(function(err) {
                if (err && err.name === 'AbortError') {
                    bubble.innerHTML = marked.parse(fullText || '') + '<br><em style="color:#f59e0b">(Stopped)</em>';
                    if (fullText) { addResponseActions(wrap, fullText); addToTranscript('assistant', fullText + '\n(Stopped)'); }
                } else {
                    bubble.innerHTML += '<br><em style="color:#ef4444">LLM connection dropped.</em>';
                    addRetryButton(bubble, text);
                }
                finish();
            });
        }).catch(function(err) {
            clearInterval(loadTimer); clearInterval(loadingRotator);
            if (err && err.name === 'AbortError') {
                bubble.innerHTML = '<em style="color:#f59e0b">(Stopped)</em>';
            } else {
                bubble.innerHTML = '<em style="color:#ef4444">LLM connection dropped.</em>';
                addRetryButton(bubble, text);
            }
            sending = false; activeReader = null; activeAbort = null;
            setStopMode(false); sendBtn.disabled = false;
            chipsEl.style.display = '';
        });
    }

    sendBtn.addEventListener('click', function() {
        if (sending) { stopGeneration(); return; }
        sendQuestion(inputEl.value.trim());
    });
    inputEl.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); if (!sending) sendQuestion(inputEl.value.trim()); }
    });

    // ── Clear chat ──
    document.getElementById('pbiClearChat').addEventListener('click', function() {
        fetch('/api/powerbi/chat/clear', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({session_id: sessionId})
        });
        msgBox.querySelectorAll('.pbi-msg').forEach(function(el) { el.remove(); });
        var welcome = document.getElementById('pbiWelcome');
        if (welcome) welcome.style.display = '';
        transcript = [];
        clearChatStorage();
        document.getElementById('pbiDownloadTranscript').style.display = 'none';
    });

    // ── Download transcript ──
    document.getElementById('pbiDownloadTranscript').addEventListener('click', downloadTranscript);

    // ══════════════════════ TIME-BASED GREETING ══════════════════════
    (function() {
        var h = new Date().getHours();
        var greeting = h < 12 ? 'Good Morning' : h < 17 ? 'Good Afternoon' : 'Good Evening';
        var greetEl = document.getElementById('pbiGreeting');
        if (greetEl) greetEl.textContent = greeting + ' — Ask About Your Data';
    })();

    // ══════════════════════ KEYBOARD SHORTCUTS ══════════════════════
    document.addEventListener('keydown', function(e) {
        // Ctrl+K or Cmd+K → focus dataset search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        }
        // Escape → clear search, close history dropdown
        if (e.key === 'Escape') {
            if (document.activeElement === searchInput) {
                searchInput.value = '';
                searchInput.dispatchEvent(new Event('input'));
                searchInput.blur();
            }
            historyDropdown.style.display = 'none';
        }
    });

    // ══════════════════════ RESTORE LAST SESSION ══════════════════════
    (function restoreSession() {
        var saved = loadChatFromStorage();
        if (!saved || !saved.dataset_id) return;

        // Find the sidebar item for this dataset
        var target = null;
        datasetItems.forEach(function(el) {
            if (el.getAttribute('data-id') === saved.dataset_id) target = el;
        });
        if (!target) return;

        // Select dataset without confirm dialog (skip selectDataset which prompts)
        datasetItems.forEach(function(el) { el.classList.remove('active'); });
        target.classList.add('active');
        currentDatasetId = saved.dataset_id;
        currentDatasetName = saved.dataset_name;
        loadDataset(saved.dataset_id, saved.dataset_name);

        // Restore chat messages if any
        var msgs = saved.transcript || [];
        if (msgs.length) {
            transcript = msgs;
            document.getElementById('pbiDownloadTranscript').style.display = '';
            transcript.forEach(function(t) {
                if (t.role === 'user') {
                    appendMsg('user', escapeHtml(t.text));
                } else {
                    var wrap = appendMsg('assistant', marked.parse(t.text));
                    collapseDaxBlocks(wrap.querySelector('.pbi-bubble'));
                }
            });
        }
    })();
})();
