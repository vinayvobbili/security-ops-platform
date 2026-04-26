/**
 * QRadar AQL Explorer — sidebar categories, schema view, chat with AQL generation.
 */
(function() {
    // DOM refs
    var msgBox        = document.getElementById('qrcMessages');
    var inputEl       = document.getElementById('qrcInput');
    var sendBtn       = document.getElementById('qrcSend');
    var loadingOverlay = document.getElementById('qrcLoadingOverlay');
    var loadingText    = document.getElementById('qrcLoadingText');
    var schemaDetails  = document.getElementById('qrcSchemaDetails');
    var schemaText     = document.getElementById('qrcSchemaText');
    var chipsEl       = document.getElementById('qrcChips');

    // State
    var sending       = false;
    var currentCategoryId   = '';
    var currentCategoryName = '';
    var activeAbort        = null;
    var activeReader       = null;
    var userStopped        = false;
    var transcript         = [];

    // Session ID
    var sessionId = localStorage.getItem('qrc_session_id');
    if (!sessionId) {
        sessionId = 'qrc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('qrc_session_id', sessionId);
    }

    // ── Clipboard fallback ──
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

    var categoryItems = document.querySelectorAll('.qrc-category-item');

    categoryItems.forEach(function(item) {
        item.addEventListener('click', function() { selectCategory(item); });
    });

    function selectCategory(item) {
        var catId = item.getAttribute('data-id');
        var catName = item.getAttribute('data-name');
        if (catId === currentCategoryId) return;

        if (currentCategoryName) {
            var ok = confirm('Switch from ' + currentCategoryName + ' to ' + catName + '?');
            if (!ok) return;
        }

        categoryItems.forEach(function(el) { el.classList.remove('active'); });
        item.classList.add('active');

        currentCategoryId = catId;
        currentCategoryName = catName;

        // Clear previous chat
        msgBox.querySelectorAll('.qrc-msg').forEach(function(el) { el.remove(); });
        var welcome = document.getElementById('qrcWelcome');
        if (welcome) welcome.style.display = '';
        transcript = [];
        saveChatToStorage();

        loadCategory(catId);
    }

    function showLoading(text) {
        loadingText.textContent = text;
        loadingOverlay.style.display = '';
    }
    function hideLoading() {
        loadingOverlay.style.display = 'none';
    }

    function loadCategory(catId) {
        showLoading('Loading ' + currentCategoryName + ' schema...');
        fetch('/api/qradar-chat/schema/' + catId)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            hideLoading();
            if (data.success) {
                schemaText.innerHTML = highlightSchema(data.schema);
                schemaDetails.style.display = '';
                inputEl.disabled = false;
                sendBtn.disabled = false;
                inputEl.focus();
                inputEl.classList.remove('qrc-pulse');
                void inputEl.offsetWidth;
                inputEl.classList.add('qrc-pulse');
                renderChips(data.chips || []);
            }
        })
        .catch(function() { hideLoading(); });
    }

    function highlightSchema(raw) {
        var lines = raw.split('\n');
        var html = '';
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            if (line.match(/^Log Source/i) || line.match(/^Operations?:/i) || line.match(/^Key Fields:/i) || line.match(/^Common Fields/i) || line.match(/^Available Fields/i)) {
                html += '<div class="schema-section-title">' + escapeHtml(line) + '</div>';
            } else if (line.match(/^\s+-\s+/)) {
                var colLine = escapeHtml(line)
                    .replace(/^(\s+-\s+)([^\s\u2014(]+)/, '$1<span class="schema-col">$2</span>')
                    .replace(/(\u2014.+)$/, '<span class="schema-hint">$1</span>');
                html += '<div class="schema-col-line">' + colLine + '</div>';
            } else if (line.match(/^Time Filter:|^Log Source Filter:|^You can query/i)) {
                html += '<div class="schema-note">' + escapeHtml(line) + '</div>';
            } else if (line.trim()) {
                html += '<div class="schema-line">' + escapeHtml(line) + '</div>';
            }
        }
        return html;
    }

    // ── Dynamic chips ──

    function renderChips(chips) {
        chipsEl.innerHTML = '';
        chips.forEach(function(chip) {
            var el = document.createElement('div');
            el.className = 'qrc-example-chip';
            el.textContent = chip.label;
            el.setAttribute('data-q', chip.query);
            el.addEventListener('click', function() {
                if (currentCategoryId) sendQuestion(chip.query);
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
        var welcome = msgBox.querySelector('.qrc-welcome');
        if (welcome) welcome.style.display = 'none';
        var wrap = document.createElement('div');
        wrap.className = 'qrc-msg qrc-' + role;
        var bubble = document.createElement('div');
        bubble.className = 'qrc-bubble';
        bubble.innerHTML = html;
        wrap.appendChild(bubble);
        if (role === 'user') {
            var del = document.createElement('button');
            del.className = 'qrc-delete-msg';
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
        var assistantWrap = userWrap.nextElementSibling;
        while (assistantWrap && !assistantWrap.classList.contains('qrc-msg')) {
            assistantWrap = assistantWrap.nextElementSibling;
        }

        var allUserMsgs = msgBox.querySelectorAll('.qrc-msg.qrc-user');
        var pairIndex = -1;
        for (var i = 0; i < allUserMsgs.length; i++) {
            if (allUserMsgs[i] === userWrap) { pairIndex = i; break; }
        }

        if (assistantWrap && assistantWrap.classList.contains('qrc-assistant')) {
            assistantWrap.remove();
        }
        userWrap.remove();

        if (pairIndex >= 0 && pairIndex * 2 < transcript.length) {
            transcript.splice(pairIndex * 2, 2);
            saveChatToStorage();
        }
    }

    // ── Response action buttons (copy, Excel) ──

    function addResponseActions(wrap, rawText) {
        var row = document.createElement('div');
        row.className = 'qrc-response-actions';

        var copyBtn = document.createElement('button');
        copyBtn.className = 'qrc-small-btn';
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
            xlsxBtn.className = 'qrc-small-btn';
            xlsxBtn.innerHTML = '&#128229; Export Excel';
            xlsxBtn.addEventListener('click', function() { downloadXlsx(tableData); });
            row.appendChild(xlsxBtn);
        }

        // Save button
        var userQuestion = '';
        var prev = wrap.previousElementSibling;
        while (prev) {
            if (prev.classList.contains('qrc-user')) {
                var ub = prev.querySelector('.qrc-bubble');
                if (ub) userQuestion = ub.textContent;
                break;
            }
            prev = prev.previousElementSibling;
        }
        if (userQuestion) {
            var saveBtn = document.createElement('button');
            saveBtn.className = 'qrc-small-btn qrc-save-btn';
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

    // ── Collapse AQL blocks ──
    function collapseAqlBlocks(container) {
        var pres = container.querySelectorAll('pre');
        for (var i = 0; i < pres.length; i++) {
            var code = pres[i].querySelector('code');
            if (!code) continue;
            var text = code.textContent || '';
            if (!/^\s*SELECT/i.test(text)) continue;
            var details = document.createElement('details');
            details.className = 'qrc-aql-toggle';
            var summary = document.createElement('summary');
            summary.textContent = 'Show AQL';
            details.appendChild(summary);
            pres[i].parentNode.insertBefore(details, pres[i]);
            details.appendChild(pres[i]);
        }
    }

    // ══════════════════════ SAVED QUERIES ══════════════════════

    var SAVED_KEY = 'qrc_saved_queries';

    function getSavedQueries() {
        try { return JSON.parse(localStorage.getItem(SAVED_KEY)) || []; }
        catch(e) { return []; }
    }

    function isSavedQuery(question) {
        return getSavedQueries().some(function(q) { return q.text === question && q.category_id === currentCategoryId; });
    }

    function addSavedQuery(question) {
        var saved = getSavedQueries();
        saved.unshift({text: question, category_id: currentCategoryId, category_name: currentCategoryName, time: new Date().toLocaleString()});
        localStorage.setItem(SAVED_KEY, JSON.stringify(saved));
    }

    function removeSavedQuery(question) {
        var saved = getSavedQueries().filter(function(q) { return !(q.text === question && q.category_id === currentCategoryId); });
        localStorage.setItem(SAVED_KEY, JSON.stringify(saved));
    }

    var savedBtn = document.getElementById('qrcSavedBtn');
    var savedDropdown = document.getElementById('qrcSavedDropdown');

    savedBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        var visible = savedDropdown.style.display !== 'none';
        if (visible) { savedDropdown.style.display = 'none'; return; }
        historyDropdown.style.display = 'none';

        var saved = getSavedQueries();
        savedDropdown.innerHTML = '';
        if (!saved.length) {
            savedDropdown.innerHTML = '<div class="qrc-history-empty">No saved queries yet</div>';
        } else {
            saved.forEach(function(item) {
                var btn = document.createElement('button');
                btn.className = 'qrc-history-item';
                btn.textContent = '\u2B50 ' + item.text;
                btn.title = item.category_name + ' \u2014 ' + item.time;
                btn.addEventListener('click', function() {
                    savedDropdown.style.display = 'none';
                    if (currentCategoryId) sendQuestion(item.text);
                });
                savedDropdown.appendChild(btn);
            });
        }
        savedDropdown.style.display = '';
    });

    document.addEventListener('click', function() { savedDropdown.style.display = 'none'; });
    savedDropdown.addEventListener('click', function(e) { e.stopPropagation(); });

    // ══════════════════════ EXCEL EXPORT ══════════════════════

    function extractTableFromMarkdown(text) {
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
        fetch('/api/qradar-chat/export/xlsx', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                headers: tableData.headers,
                rows: tableData.rows,
                category_name: currentCategoryName || 'Results',
            }),
        })
        .then(function(resp) {
            if (!resp.ok) throw new Error('Export failed');
            return resp.blob();
        })
        .then(function(blob) {
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'QRadar - ' + (currentCategoryName || 'Results') + '.xlsx';
            a.click();
            URL.revokeObjectURL(a.href);
        })
        .catch(function(err) { alert('Export failed: ' + err.message); });
    }

    // ── Auto-chart from results ──

    function isDark() { return document.body.classList.contains('dark-mode'); }

    function chartTheme() {
        var dk = isDark();
        return {
            text: dk ? '#cbd5e1' : '#475569',
            grid: dk ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)',
            legend: dk ? '#94a3b8' : '#64748b',
        };
    }

    function tryAutoChart(wrap, rawText) {
        var td = extractTableFromMarkdown(rawText);
        if (!td || td.rows.length < 2 || td.rows.length > 30) return;
        if (td.headers.length < 2) return;

        var numIdx = -1;
        for (var c = 0; c < td.headers.length; c++) {
            var allNum = td.rows.every(function(row) {
                return row[c] && !isNaN(row[c].replace(/[,%$]/g, '').replace(/,/g, ''));
            });
            if (allNum) { numIdx = c; break; }
        }
        if (numIdx === -1) return;

        var labelIdx = numIdx === 0 ? 1 : 0;
        var labels = td.rows.map(function(r) { return r[labelIdx] || ''; });
        var values = td.rows.map(function(r) {
            return parseFloat(r[numIdx].replace(/[,%$]/g, '').replace(/,/g, ''));
        });

        var chartWrap = document.createElement('div');
        chartWrap.className = 'qrc-result-chart-wrap';
        var canvas = document.createElement('canvas');
        chartWrap.appendChild(canvas);

        var bubble = wrap.querySelector('.qrc-bubble');
        if (bubble && bubble.nextSibling) {
            wrap.insertBefore(chartWrap, bubble.nextSibling);
        } else {
            wrap.appendChild(chartWrap);
        }

        var t = chartTheme();
        var colors = ['#0046ad','#00a651','#f6be00','#6a1b9a','#dc2626','#0891b2','#d946ef','#ea580c','#4f46e5','#059669'];
        var bgColors = labels.map(function(_, i) { return colors[i % colors.length]; });

        new Chart(canvas, {
            type: 'bar',
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

    // ══════════════════════ TRANSCRIPT ══════════════════════

    var CHAT_STORAGE_KEY = 'qrc_chat_history';

    function addToTranscript(role, text) {
        transcript.push({role: role, text: text, time: new Date().toLocaleString()});
        document.getElementById('qrcDownloadTranscript').style.display = '';
        saveChatToStorage();
    }

    function saveChatToStorage() {
        if (!currentCategoryId) return;
        try {
            localStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify({
                category_id: currentCategoryId,
                category_name: currentCategoryName,
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
        var lines = ['QRadar AQL Explorer Chat Transcript', 'Category: ' + currentCategoryName, 'Date: ' + new Date().toLocaleString(), ''];
        transcript.forEach(function(t) {
            lines.push('[' + t.time + '] ' + (t.role === 'user' ? 'USER' : 'ASSISTANT') + ':');
            lines.push(t.text);
            lines.push('');
        });
        var blob = new Blob([lines.join('\n')], {type: 'text/plain'});
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'qradar-chat-' + new Date().toISOString().slice(0, 10) + '.txt';
        a.click();
        URL.revokeObjectURL(a.href);
    }

    // ══════════════════════ QUERY HISTORY ══════════════════════

    var HISTORY_KEY = 'qrc_query_history';
    var MAX_HISTORY_ITEMS = 30;

    function getHistory() {
        try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
        catch(e) { return []; }
    }

    function addToHistory(question) {
        var h = getHistory().filter(function(q) { return q.text !== question; });
        h.unshift({text: question, category: currentCategoryName, time: new Date().toLocaleString()});
        if (h.length > MAX_HISTORY_ITEMS) h = h.slice(0, MAX_HISTORY_ITEMS);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(h));
    }

    var historyBtn = document.getElementById('qrcHistoryBtn');
    var historyDropdown = document.getElementById('qrcHistoryDropdown');

    historyBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        var visible = historyDropdown.style.display !== 'none';
        if (visible) { historyDropdown.style.display = 'none'; return; }

        var h = getHistory();
        historyDropdown.innerHTML = '';
        if (!h.length) {
            historyDropdown.innerHTML = '<div class="qrc-history-empty">No query history yet</div>';
        } else {
            h.forEach(function(item) {
                var btn = document.createElement('button');
                btn.className = 'qrc-history-item';
                btn.textContent = item.text;
                btn.title = item.category + ' \u2014 ' + item.time;
                btn.addEventListener('click', function() {
                    historyDropdown.style.display = 'none';
                    if (currentCategoryId) sendQuestion(item.text);
                });
                historyDropdown.appendChild(btn);
            });
        }
        historyDropdown.style.display = '';
    });

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
            sendBtn.classList.add('qrc-stop-mode');
        } else {
            sendBtn.textContent = 'Send \u00BB';
            sendBtn.classList.remove('qrc-stop-mode');
        }
    }

    function stopGeneration() {
        userStopped = true;
        if (activeReader) { try { activeReader.cancel(); } catch(e) {} activeReader = null; }
        if (activeAbort) { activeAbort.abort(); activeAbort = null; }
    }

    function addRetryButton(container, questionText) {
        var btn = document.createElement('button');
        btn.className = 'qrc-retry-btn';
        btn.innerHTML = '&#x21bb; Retry';
        btn.onclick = function() { sendQuestion(questionText); };
        container.appendChild(btn);
    }

    function sendQuestion(text) {
        if (!text || !currentCategoryId) return;
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

        var catName = currentCategoryName || 'QRadar';
        var loadingMsgs = [
            'Generating AQL query for ' + catName + '\u2026',
            'Analyzing ' + catName + ' schema\u2026',
            'Translating to AQL\u2026',
            'Executing AQL against QRadar\u2026',
            'QRadar is searching events\u2026',
            'Still searching \u2014 AQL queries can take a few minutes\u2026',
            'Still working \u2014 large time ranges take longer\u2026',
            'Processing results\u2026',
            'Almost there\u2026'
        ];
        var loadingHtml = '<div class="qrc-loading-indicator">' +
            '<div class="qrc-loading-top">' +
                '<span class="qrc-loading-spinner"></span>' +
                '<span class="qrc-loading-msg">' + loadingMsgs[0] + '</span>' +
            '</div>' +
            '<div class="qrc-loading-bottom"><span class="qrc-loading-timer">0s</span></div>' +
            '<div class="qrc-aql-progress" style="display:none;"></div>' +
        '</div>';
        var wrap = appendMsg('assistant', loadingHtml);
        var bubble = wrap.querySelector('.qrc-bubble');
        var timerEl = bubble.querySelector('.qrc-loading-timer');
        var msgEl = bubble.querySelector('.qrc-loading-msg');
        var loadStart = Date.now();
        var msgIdx = 0;
        var loadTimer = setInterval(function() {
            timerEl.textContent = Math.floor((Date.now() - loadStart) / 1000) + 's';
        }, 1000);
        var loadingRotator = setInterval(function() {
            msgIdx = (msgIdx + 1) % loadingMsgs.length;
            if (msgEl) msgEl.textContent = loadingMsgs[msgIdx];
        }, 6000);

        fetch('/api/qradar-chat/stream', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                message: text,
                category_id: currentCategoryId,
                session_id: sessionId,
                history: transcript.map(function(t) { return {role: t.role, text: t.text}; })
            }),
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
                            if (data.progress) {
                                // Live AQL execution progress from QRadar polling
                                var progEl = bubble.querySelector('.qrc-aql-progress');
                                if (progEl) {
                                    progEl.style.display = '';
                                    progEl.textContent = '\uD83D\uDD0D ' + data.progress;
                                }
                                // Also stop the generic rotating messages — real status is better
                                clearInterval(loadingRotator);
                                if (msgEl) msgEl.textContent = 'QRadar is processing\u2026';
                                continue;
                            }
                            if (data.token && !loadingCleared) {
                                loadingCleared = true;
                                clearInterval(loadTimer); clearInterval(loadingRotator);
                                bubble.innerHTML = '';
                            }
                            if (data.token) {
                                fullText += data.token;
                                bubble.innerHTML = marked.parse(fullText) + '<span class="qrc-cursor">\u258B</span>';
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
                                collapseAqlBlocks(bubble);
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
                                    metaDiv.className = 'qrc-meta';
                                    metaDiv.textContent = '\u26A1 ' + parts.join(' | ');
                                    wrap.appendChild(metaDiv);
                                }
                                // Per-stage timing
                                if (m.stages) {
                                    var sp = [];
                                    if (m.stages.aql_gen != null) sp.push('NL\u2192AQL: ' + m.stages.aql_gen + 's');
                                    if (m.stages.aql_exec != null) sp.push('Execute: ' + m.stages.aql_exec + 's');
                                    if (m.stages.explain != null) sp.push('Explain: ' + m.stages.explain + 's');
                                    if (sp.length) {
                                        var stagesDiv = document.createElement('div');
                                        stagesDiv.className = 'qrc-meta qrc-stages';
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
                var cursor = bubble.querySelector('.qrc-cursor');
                if (cursor) cursor.remove();
                if (stopped) {
                    if (fullText) {
                        bubble.innerHTML = marked.parse(fullText) + '<br><em style="color:#f59e0b">(Stopped)</em>';
                        collapseAqlBlocks(bubble);
                        addResponseActions(wrap, fullText);
                        addToTranscript('assistant', fullText + '\n(Stopped)');
                    } else {
                        bubble.innerHTML = '<em style="color:#f59e0b">(Stopped)</em>';
                    }
                    var elapsed = ((Date.now() - loadStart) / 1000).toFixed(1);
                    var metaDiv = document.createElement('div');
                    metaDiv.className = 'qrc-meta';
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
                    bubble.innerHTML += '<br><em style="color:#ef4444">Connection dropped.</em>';
                    addRetryButton(bubble, text);
                }
                finish();
            });
        }).catch(function(err) {
            clearInterval(loadTimer); clearInterval(loadingRotator);
            if (err && err.name === 'AbortError') {
                bubble.innerHTML = '<em style="color:#f59e0b">(Stopped)</em>';
            } else {
                bubble.innerHTML = '<em style="color:#ef4444">Connection failed: ' + escapeHtml(err.message) + '</em>';
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
    document.getElementById('qrcClearChat').addEventListener('click', function() {
        fetch('/api/qradar-chat/clear', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({session_id: sessionId})
        });
        msgBox.querySelectorAll('.qrc-msg').forEach(function(el) { el.remove(); });
        var welcome = document.getElementById('qrcWelcome');
        if (welcome) welcome.style.display = '';
        transcript = [];
        clearChatStorage();
        document.getElementById('qrcDownloadTranscript').style.display = 'none';
    });

    // ── Download transcript ──
    document.getElementById('qrcDownloadTranscript').addEventListener('click', downloadTranscript);

    // ══════════════════════ TIME-BASED GREETING ══════════════════════
    (function() {
        var h = new Date().getHours();
        var greeting = h < 12 ? 'Good Morning' : h < 17 ? 'Good Afternoon' : 'Good Evening';
        var greetEl = document.getElementById('qrcGreeting');
        if (greetEl) greetEl.textContent = greeting + ' \u2014 Ask About Your SIEM Data';
    })();

    // ══════════════════════ RESTORE LAST SESSION ══════════════════════
    (function restoreSession() {
        var saved = loadChatFromStorage();
        if (!saved || !saved.category_id) return;

        var target = null;
        categoryItems.forEach(function(el) {
            if (el.getAttribute('data-id') === saved.category_id) target = el;
        });
        if (!target) return;

        categoryItems.forEach(function(el) { el.classList.remove('active'); });
        target.classList.add('active');
        currentCategoryId = saved.category_id;
        currentCategoryName = saved.category_name;
        loadCategory(saved.category_id);

        var msgs = saved.transcript || [];
        if (msgs.length) {
            transcript = msgs;
            document.getElementById('qrcDownloadTranscript').style.display = '';
            transcript.forEach(function(t) {
                if (t.role === 'user') {
                    appendMsg('user', escapeHtml(t.text));
                } else {
                    var wrap = appendMsg('assistant', marked.parse(t.text));
                    collapseAqlBlocks(wrap.querySelector('.qrc-bubble'));
                }
            });
        }
    })();
})();
