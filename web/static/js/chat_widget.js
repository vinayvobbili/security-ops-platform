/**
 * Reusable page-context chat widget.
 *
 * Usage:
 *   initChatWidget({
 *       getContext: function() { return "plain-text page context for the LLM"; },
 *       greeting:  "Hi! Ask me anything about ...",
 *       title:     "Ask about this report",
 *       chips:     [
 *           {label: "Key findings", q: "What are the key findings?"},
 *           ...
 *       ]
 *   });
 *
 * Requires: marked.min.js loaded before this script.
 */
function initChatWidget(opts) {
    var fab      = document.getElementById('cwToggle');
    var win      = document.getElementById('cwWindow');
    var closeBtn = document.getElementById('cwClose');
    var clearBtn = document.getElementById('cwClear');
    var input    = document.getElementById('cwInput');
    var sendBtn  = document.getElementById('cwSend');
    var msgBox   = document.getElementById('cwMessages');
    var header   = document.getElementById('cwHeader');
    var sending  = false;

    // Endpoint URLs — allow per-widget overrides
    var streamUrl = opts.stream_url || '/api/page-chat/stream';
    var clearUrl  = opts.clear_url  || '/api/page-chat/clear';

    // Per-page key prefix so each page gets its own session + history
    var pageKey = window.location.pathname.replace(/\//g, '_') || '_root';

    // Session ID — persisted in localStorage, scoped per page
    var sessionStorageKey = 'cw_session_id' + pageKey;
    var sessionId = localStorage.getItem(sessionStorageKey);
    if (!sessionId) {
        sessionId = 'cw_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem(sessionStorageKey, sessionId);
    }

    // Apply config
    if (opts.title) document.getElementById('cwTitle').textContent = opts.title;
    if (opts.greeting) document.getElementById('cwGreeting').textContent = opts.greeting;

    // Build suggestion chips
    var chipsEl = document.getElementById('cwChips');
    if (opts.chips && opts.chips.length) {
        opts.chips.forEach(function(c) {
            var btn = document.createElement('button');
            btn.className = 'cw-chip';
            btn.textContent = c.label;
            btn.setAttribute('data-q', c.q);
            btn.addEventListener('click', function() { sendQuestion(this.getAttribute('data-q')); });
            chipsEl.appendChild(btn);
        });
    }

    // ── Audio notification ──
    var audioCtx = null;
    function playDing() {
        try {
            if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            var osc = audioCtx.createOscillator();
            var gain = audioCtx.createGain();
            osc.connect(gain);
            gain.connect(audioCtx.destination);
            osc.type = 'sine';
            osc.frequency.setValueAtTime(880, audioCtx.currentTime);
            osc.frequency.setValueAtTime(660, audioCtx.currentTime + 0.1);
            gain.gain.setValueAtTime(0.3, audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.4);
            osc.start(audioCtx.currentTime);
            osc.stop(audioCtx.currentTime + 0.4);
        } catch(e) {}
    }

    // ── Drag to move ──
    (function initDrag() {
        var dragging = false, startX, startY, origLeft, origTop;
        header.addEventListener('mousedown', function(e) {
            if (e.target.tagName === 'BUTTON') return;
            dragging = true;
            startX = e.clientX; startY = e.clientY;
            var rect = win.getBoundingClientRect();
            origLeft = rect.left; origTop = rect.top;
            win.style.left = origLeft + 'px';
            win.style.top = origTop + 'px';
            win.style.bottom = 'auto';
            win.style.right = 'auto';
            e.preventDefault();
        });
        document.addEventListener('mousemove', function(e) {
            if (!dragging) return;
            win.style.left = Math.max(0, origLeft + e.clientX - startX) + 'px';
            win.style.top = Math.max(0, origTop + e.clientY - startY) + 'px';
        });
        document.addEventListener('mouseup', function() { dragging = false; });
    })();

    // ── Toggle / close ──
    fab.addEventListener('click', function() {
        var open = win.style.display !== 'none';
        win.style.display = open ? 'none' : 'flex';
        fab.style.display = open ? '' : 'none';
        if (!open) {
            win.style.bottom = '88px';
            win.style.right = '24px';
            win.style.top = 'auto';
            win.style.left = 'auto';
            input.focus();
        }
    });
    closeBtn.addEventListener('click', function() {
        win.style.display = 'none';
        fab.style.display = '';
    });

    // ── Clear ──
    clearBtn.addEventListener('click', function() {
        fetch(clearUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({session_id: sessionId})
        });
        clearSavedHistory();
        // Rebuild initial state: greeting bubble + chips
        var greetingText = opts.greeting || 'Hi! Ask me anything about this page.';
        msgBox.innerHTML = '<div class="cw-msg cw-assistant"><div class="cw-bubble" id="cwGreeting">' + escapeHtml(greetingText) + '</div></div>';
        if (chipsEl) { msgBox.appendChild(chipsEl); showChips(); }
    });

    // ── Response time tracking ──
    var TIMING_KEY = 'cw_resp_times' + pageKey;
    var MAX_TIMING_SAMPLES = 10;

    function getExpectedTime() {
        try {
            var raw = localStorage.getItem(TIMING_KEY);
            if (!raw) return null;
            var samples = JSON.parse(raw);
            if (!samples.length) return null;
            var sum = 0;
            for (var i = 0; i < samples.length; i++) sum += samples[i];
            return Math.round(sum / samples.length);
        } catch(e) { return null; }
    }

    function recordResponseTime(secs) {
        try {
            var raw = localStorage.getItem(TIMING_KEY);
            var samples = raw ? JSON.parse(raw) : [];
            samples.push(secs);
            if (samples.length > MAX_TIMING_SAMPLES) samples = samples.slice(-MAX_TIMING_SAMPLES);
            localStorage.setItem(TIMING_KEY, JSON.stringify(samples));
        } catch(e) {}
    }

    // ── Chat history persistence ──
    var HISTORY_KEY = 'cw_chat_history' + pageKey;
    var MAX_STORED = 50;
    var HISTORY_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

    function loadChatHistory() {
        try {
            var raw = localStorage.getItem(HISTORY_KEY);
            if (!raw) return;
            var entries = JSON.parse(raw);
            var cutoff = Date.now() - HISTORY_TTL_MS;
            entries = entries.filter(function(e) { return e.ts >= cutoff; });
            if (!entries.length) { localStorage.removeItem(HISTORY_KEY); return; }
            // Hide greeting since we have history
            var greeting = document.getElementById('cwGreeting');
            if (greeting) greeting.style.display = 'none';
            entries.forEach(function(e) {
                appendMsg(e.role, e.role === 'user' ? escapeHtml(e.text) : marked.parse(e.text));
            });
        } catch(e) {}
    }

    function saveMessage(role, text) {
        try {
            var raw = localStorage.getItem(HISTORY_KEY);
            var entries = raw ? JSON.parse(raw) : [];
            entries.push({role: role, text: text, ts: Date.now()});
            if (entries.length > MAX_STORED) entries = entries.slice(-MAX_STORED);
            localStorage.setItem(HISTORY_KEY, JSON.stringify(entries));
        } catch(e) {}
    }

    function clearSavedHistory() {
        localStorage.removeItem(HISTORY_KEY);
    }

    // ── Helpers ──
    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function appendMsg(role, html) {
        var wrap = document.createElement('div');
        wrap.className = 'cw-msg cw-' + role;
        var bubble = document.createElement('div');
        bubble.className = 'cw-bubble';
        bubble.innerHTML = html;
        wrap.appendChild(bubble);
        // Keep chips at bottom by inserting messages before them
        if (chipsEl && chipsEl.parentNode === msgBox) {
            msgBox.insertBefore(wrap, chipsEl);
        } else {
            msgBox.appendChild(wrap);
        }
        msgBox.scrollTop = msgBox.scrollHeight;
        return wrap;
    }

    function hideChips() {
        if (chipsEl) chipsEl.style.display = 'none';
    }

    function showChips() {
        if (chipsEl) chipsEl.style.display = '';
    }

    // ── Send ──
    function sendQuestion(text) {
        if (!text || sending) return;
        var ctx = opts.getContext ? opts.getContext() : null;
        if (opts.getContext && !ctx) { appendMsg('assistant', 'Page data is still loading — please wait.'); return; }

        sending = true;
        input.value = '';
        sendBtn.disabled = true;
        appendMsg('user', escapeHtml(text));

        // ── Enhanced loading indicator ──
        var loadingMsgs = opts.loadingMessages || ['Thinking...'];
        var expectedTime = getExpectedTime();
        var loadingHtml = '<div class="cw-loading-indicator">' +
            '<div class="cw-loading-top">' +
                '<span class="cw-loading-spinner"></span>' +
                '<span class="cw-loading-msg">' + loadingMsgs[0] + '</span>' +
            '</div>' +
            '<div class="cw-loading-bottom">' +
                '<span class="cw-loading-timer">0s</span>' +
                (expectedTime ? '<span class="cw-loading-expected">~' + expectedTime + 's expected</span>' : '') +
            '</div>' +
        '</div>';
        var wrap = appendMsg('assistant', loadingHtml);
        var bubble = wrap.querySelector('.cw-bubble');
        var timerEl = bubble.querySelector('.cw-loading-timer');
        var msgEl = bubble.querySelector('.cw-loading-msg');
        var loadingStart = Date.now();
        var msgIdx = 0;
        var loadingTimer = setInterval(function() {
            var elapsed = Math.floor((Date.now() - loadingStart) / 1000);
            if (timerEl) timerEl.textContent = elapsed + 's';
        }, 1000);
        var loadingRotator = loadingMsgs.length > 1 ? setInterval(function() {
            msgIdx = (msgIdx + 1) % loadingMsgs.length;
            if (msgEl) msgEl.textContent = loadingMsgs[msgIdx];
        }, 20000) : null;
        function clearLoadingTimers() {
            clearInterval(loadingTimer);
            if (loadingRotator) clearInterval(loadingRotator);
        }

        fetch(streamUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(Object.assign({message: text, session_id: sessionId}, ctx ? {report_md: ctx} : {}))
        }).then(function(resp) {
            if (!resp.ok) throw new Error('Server error ' + resp.status);
            var reader = resp.body.getReader();
            var decoder = new TextDecoder();
            var fullText = '';
            clearLoadingTimers();
            bubble.innerHTML = '';

            function pump() {
                return reader.read().then(function(result) {
                    if (result.done) { finish(); return; }
                    var chunk = decoder.decode(result.value, {stream: true});
                    var lines = chunk.split('\n');
                    for (var i = 0; i < lines.length; i++) {
                        var line = lines[i];
                        if (!line.startsWith('data: ')) continue;
                        try {
                            var data = JSON.parse(line.slice(6));
                            if (data.token) {
                                fullText += data.token;
                                bubble.innerHTML = marked.parse(fullText) + '<span class="cw-cursor">\u258B</span>';
                            }
                            if (data.error) {
                                bubble.innerHTML += '<br><em class="cw-error">' + data.error + '</em>';
                            }
                            if (data.done) {
                                bubble.innerHTML = marked.parse(fullText);
                                saveMessage('user', text);
                                saveMessage('assistant', fullText);
                                var m = data.metrics || {};
                                var actualTime = m.time != null ? m.time : Math.round((Date.now() - loadingStart) / 1000);
                                recordResponseTime(actualTime);
                                var parts = [];
                                if (m.time != null) {
                                    var timeStr = m.time + 's';
                                    if (m.eval_time != null && m.gen_time != null) {
                                        timeStr += ' (' + m.eval_time + 's eval + ' + m.gen_time + 's gen)';
                                    }
                                    parts.push(timeStr);
                                }
                                if (m.input_tokens != null && m.output_tokens != null) {
                                    parts.push(m.input_tokens + '\u2192' + m.output_tokens + ' tokens');
                                }
                                if (m.speed != null && m.speed > 0) {
                                    parts.push('TPS: ' + m.speed);
                                }
                                if (m.eval_time != null) {
                                    parts.push('TTFT ' + m.eval_time + 's');
                                }
                                if (m.iterations != null) {
                                    parts.push('Loops: ' + m.iterations);
                                }
                                if (m.route) {
                                    parts.push('Route: ' + m.route);
                                }
                                if (m.model) {
                                    parts.push(m.model);
                                }
                                if (parts.length) {
                                    var metaDiv = document.createElement('div');
                                    metaDiv.className = 'cw-meta';
                                    metaDiv.textContent = '\u26A1 ' + parts.join(' | ');
                                    wrap.appendChild(metaDiv);
                                }
                            }
                        } catch(e) {}
                    }
                    msgBox.scrollTop = msgBox.scrollHeight;
                    return pump();
                });
            }

            function finish() { clearLoadingTimers(); sending = false; sendBtn.disabled = false; input.focus(); playDing(); }
            pump().catch(function(err) { bubble.innerHTML += '<br><em class="cw-error">Stream error</em>'; finish(); });
        }).catch(function(err) {
            clearLoadingTimers();
            bubble.innerHTML = '<em class="cw-error">Failed: ' + err.message + '</em>';
            sending = false; sendBtn.disabled = false;
        });
    }

    sendBtn.addEventListener('click', function() { sendQuestion(input.value.trim()); });
    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendQuestion(input.value.trim()); }
    });

    // Restore previous messages on load
    loadChatHistory();
}
