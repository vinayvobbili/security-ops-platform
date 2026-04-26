/**
 * StoryEffects — Visual effects for stepper story modes
 * Confetti, typewriter, spotlight, PNG export, trend badges, sparklines, keyboard shortcuts.
 * Loaded as a global script; exposes window.StoryEffects.
 */
(function () {
    'use strict';

    // ── Feature 2: Confetti ──────────────────────────────────

    let _confettiLoading = false;

    function confetti() {
        if (typeof window.confetti === 'function') {
            window.confetti({
                particleCount: 120,
                spread: 80,
                origin: {x: 0.5, y: 1},
                colors: ['#8b5cf6', '#3b82f6', '#10b981', '#f59e0b', '#ef4444'],
                disableForReducedMotion: true
            });
            return;
        }
        if (!_confettiLoading) {
            _confettiLoading = true;
            var s = document.createElement('script');
            s.src = 'https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js';
            s.onload = function () { confetti(); };
            document.head.appendChild(s);
        }
    }

    // ── Feature 3: Typewriter ────────────────────────────────

    var _typewriterVisited = {};

    function typewriter(el, text, speed, onDone) {
        if (!el || !text) return function () {};
        speed = speed || 30;

        var uid = el.id || text.substring(0, 40);
        if (_typewriterVisited[uid]) {
            el.textContent = text;
            el.classList.remove('typewriter-active');
            if (onDone) onDone();
            return function () {};
        }
        _typewriterVisited[uid] = true;

        el.textContent = '';
        el.classList.add('typewriter-active');
        var i = 0;
        var cancelled = false;

        function tick() {
            if (cancelled) return;
            if (i < text.length) {
                el.textContent += text[i];
                i++;
                setTimeout(tick, speed);
            } else {
                el.classList.remove('typewriter-active');
                if (onDone) onDone();
            }
        }
        tick();

        return function cancel() {
            cancelled = true;
            el.textContent = text;
            el.classList.remove('typewriter-active');
        };
    }

    function resetTypewriterVisited() {
        _typewriterVisited = {};
    }

    // ── Feature 4: Spotlight ─────────────────────────────────

    var _overlayEl = null;
    var _spotlightActive = false;

    function spotlightOn(sectionEl) {
        if (_spotlightActive || !sectionEl) return;
        _spotlightActive = true;

        if (!_overlayEl) {
            _overlayEl = document.createElement('div');
            _overlayEl.className = 'story-spotlight-overlay';
            _overlayEl.addEventListener('click', spotlightOff);
            document.body.appendChild(_overlayEl);
        }
        _overlayEl.classList.add('active');
        sectionEl.classList.add('story-spotlight-focus');
    }

    function spotlightOff() {
        if (!_spotlightActive) return;
        _spotlightActive = false;
        if (_overlayEl) _overlayEl.classList.remove('active');
        var focused = document.querySelectorAll('.story-spotlight-focus');
        for (var i = 0; i < focused.length; i++) {
            focused[i].classList.remove('story-spotlight-focus');
        }
    }

    function isSpotlightActive() { return _spotlightActive; }

    // ── Feature 5: Export Slide as PNG ───────────────────────

    var _html2canvasLoading = false;

    function exportSlide(slideEl, filename) {
        if (!slideEl) return;

        function doCapture() {
            slideEl.classList.add('story-export-flash');
            setTimeout(function () { slideEl.classList.remove('story-export-flash'); }, 300);

            html2canvas(slideEl, {
                backgroundColor: null,
                useCORS: true,
                scale: 2
            }).then(function (canvas) {
                var link = document.createElement('a');
                link.download = filename || 'story-slide.png';
                link.href = canvas.toDataURL('image/png');
                link.click();
            }).catch(function (err) {
                console.error('Export failed:', err);
            });
        }

        if (typeof window.html2canvas === 'function') {
            doCapture();
        } else if (!_html2canvasLoading) {
            _html2canvasLoading = true;
            var s = document.createElement('script');
            s.src = 'https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js';
            s.onload = doCapture;
            document.head.appendChild(s);
        }
    }

    // ── Feature 6: Period Comparison Badges ──────────────────

    function trendBadge(delta, invertedGood) {
        if (delta == null || isNaN(delta) || delta === 0) return '';
        var isUp = delta > 0;
        var isGood = invertedGood ? !isUp : isUp;
        var arrow = isUp ? '\u2191' : '\u2193';
        var cls = isGood ? 'story-trend-badge up' : 'story-trend-badge down';
        return '<span class="' + cls + '">' + arrow + ' ' +
               Math.abs(delta).toFixed(1) + '%</span>';
    }

    // ── Feature 7: Mini Sparklines ──────────────────────────

    function sparklineSVG(values, opts) {
        opts = opts || {};
        var w = opts.width || 60;
        var h = opts.height || 16;
        var color = opts.color || '#8b5cf6';
        var filled = opts.filled !== false;

        if (!values || values.length < 2) return '';

        var max = -Infinity, min = Infinity;
        for (var k = 0; k < values.length; k++) {
            if (values[k] > max) max = values[k];
            if (values[k] < min) min = values[k];
        }
        var range = max - min || 1;
        var step = w / (values.length - 1);

        var points = [];
        for (var i = 0; i < values.length; i++) {
            var x = (i * step).toFixed(1);
            var y = (h - 2 - ((values[i] - min) / range) * (h - 4)).toFixed(1);
            points.push(x + ',' + y);
        }
        var polyline = points.join(' ');

        var fillPath = '';
        if (filled) {
            fillPath = '<polygon points="0,' + h + ' ' + polyline + ' ' +
                       w + ',' + h + '" fill="' + color + '" fill-opacity="0.15" />';
        }

        return '<svg class="story-sparkline" viewBox="0 0 ' + w + ' ' + h +
               '" width="' + w + '" height="' + h +
               '" xmlns="http://www.w3.org/2000/svg">' +
               fillPath +
               '<polyline points="' + polyline +
               '" fill="none" stroke="' + color +
               '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />' +
               '</svg>';
    }

    // ── Feature 8: Keyboard Shortcuts Overlay ────────────────

    var _shortcutsEl = null;

    function showShortcuts(shortcuts) {
        if (_shortcutsEl) { hideShortcuts(); return; }
        shortcuts = shortcuts || [
            {key: '\u2190 \u2192', desc: 'Navigate steps'},
            {key: 'S', desc: 'Toggle spotlight'},
            {key: 'P', desc: 'Export slide as PNG'},
            {key: 'N', desc: 'Toggle narration'},
            {key: 'A', desc: 'Toggle audio'},
            {key: '?', desc: 'Show this overlay'},
            {key: 'Esc', desc: 'Close / exit spotlight'}
        ];
        _shortcutsEl = document.createElement('div');
        _shortcutsEl.className = 'story-shortcuts-overlay';
        var html = '<div class="story-shortcuts-modal">' +
                   '<h3>\u2328\uFE0F Keyboard Shortcuts</h3><div class="story-shortcuts-list">';
        for (var i = 0; i < shortcuts.length; i++) {
            html += '<div class="story-shortcut-row">' +
                    '<kbd>' + shortcuts[i].key + '</kbd><span>' + shortcuts[i].desc + '</span></div>';
        }
        html += '</div><div class="story-shortcuts-close">Press <kbd>?</kbd> or <kbd>Esc</kbd> to close</div></div>';
        _shortcutsEl.innerHTML = html;
        document.body.appendChild(_shortcutsEl);
        requestAnimationFrame(function () { _shortcutsEl.classList.add('active'); });
    }

    function hideShortcuts() {
        if (!_shortcutsEl) return;
        _shortcutsEl.classList.remove('active');
        var el = _shortcutsEl;
        _shortcutsEl = null;
        setTimeout(function () { if (el.parentNode) el.remove(); }, 200);
    }

    function isShortcutsVisible() { return !!_shortcutsEl; }

    // ── Expose ───────────────────────────────────────────────

    window.StoryEffects = {
        confetti: confetti,
        typewriter: typewriter,
        resetTypewriterVisited: resetTypewriterVisited,
        spotlightOn: spotlightOn,
        spotlightOff: spotlightOff,
        isSpotlightActive: isSpotlightActive,
        exportSlide: exportSlide,
        trendBadge: trendBadge,
        sparklineSVG: sparklineSVG,
        showShortcuts: showShortcuts,
        hideShortcuts: hideShortcuts,
        isShortcutsVisible: isShortcutsVisible
    };
})();
