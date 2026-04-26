/**
 * ComparisonMode — Dashboard period comparison overlay utility
 * Provides UI config bar, date presets, trace overlay helpers, and KPI comparison rendering.
 * Loaded as a global script; exposes window.ComparisonMode.
 */
(function () {
    'use strict';

    var _active = false;
    var _cfg = null;          // {btnId, barContainerId, onActivate, onDeactivate, storageKey}
    var _barEl = null;
    var _periodBStart = null;
    var _periodBEnd = null;

    // ── Init ──────────────────────────────────────────────────

    function init(cfg) {
        _cfg = cfg;
        var storageKey = cfg.storageKey || 'comparison-mode';

        var btn = document.getElementById(cfg.btnId);
        if (btn) {
            btn.addEventListener('click', function () {
                if (_active) deactivate();
                else activate();
            });
        }
    }

    // ── Activate / Deactivate ─────────────────────────────────

    function activate() {
        if (_active) return;
        _active = true;

        var btn = document.getElementById(_cfg.btnId);
        if (btn) { btn.classList.add('active'); btn.title = 'Disable comparison mode'; }

        renderConfigBar();
        if (_cfg.onActivate) _cfg.onActivate();
    }

    function deactivate() {
        if (!_active) return;
        _active = false;
        _periodBStart = null;
        _periodBEnd = null;

        var btn = document.getElementById(_cfg.btnId);
        if (btn) { btn.classList.remove('active'); btn.title = 'Compare periods'; }

        var container = document.getElementById(_cfg.barContainerId);
        if (container) container.innerHTML = '';
        if (container) container.style.display = 'none';

        if (_cfg.onDeactivate) _cfg.onDeactivate();
    }

    function isActive() { return _active; }

    function getPeriodB() {
        return { start: _periodBStart, end: _periodBEnd };
    }

    // ── Config Bar ────────────────────────────────────────────

    function renderConfigBar() {
        var container = document.getElementById(_cfg.barContainerId);
        if (!container) return;

        // Compute Period A label from current filters
        var periodALabel = _getPeriodALabel();

        // Compute smart presets
        var presets = computePresets();

        // Default Period B to "Previous Period" preset
        if (!_periodBStart && presets.length > 0) {
            _periodBStart = presets[0].start;
            _periodBEnd = presets[0].end;
        }

        var html = '<div class="comparison-config-bar">' +
            '<div class="comparison-config-left">' +
                '<span class="comparison-label">⚖️ Comparing</span>' +
                '<div class="comparison-periods">' +
                    '<span class="comparison-period-tag period-a">A: ' + periodALabel + '</span>' +
                    '<span class="comparison-vs">vs</span>' +
                    '<span class="comparison-period-tag period-b">B: ' +
                        '<input type="date" class="comparison-date" id="compBStart" value="' + (_periodBStart || '') + '">' +
                        '<span class="comparison-date-sep">→</span>' +
                        '<input type="date" class="comparison-date" id="compBEnd" value="' + (_periodBEnd || '') + '">' +
                    '</span>' +
                '</div>' +
            '</div>' +
            '<div class="comparison-config-right">' +
                '<div class="comparison-presets">';

        for (var i = 0; i < presets.length; i++) {
            var sel = (presets[i].start === _periodBStart && presets[i].end === _periodBEnd) ? ' active' : '';
            html += '<button class="comparison-preset-btn' + sel + '" data-idx="' + i + '">' + presets[i].label + '</button>';
        }

        html += '</div>' +
                '<button class="comparison-close-btn" title="Close comparison">✕</button>' +
            '</div></div>';

        container.innerHTML = html;
        container.style.display = '';

        // Wire events
        var startInput = document.getElementById('compBStart');
        var endInput = document.getElementById('compBEnd');

        function onDateChange() {
            _periodBStart = startInput.value;
            _periodBEnd = endInput.value;
            // Clear active preset styling
            container.querySelectorAll('.comparison-preset-btn').forEach(function (b) { b.classList.remove('active'); });
            if (_periodBStart && _periodBEnd && _cfg.onActivate) _cfg.onActivate();
        }

        if (startInput) startInput.addEventListener('change', onDateChange);
        if (endInput) endInput.addEventListener('change', onDateChange);

        container.querySelectorAll('.comparison-preset-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var idx = parseInt(btn.dataset.idx);
                var p = presets[idx];
                if (!p) return;
                _periodBStart = p.start;
                _periodBEnd = p.end;
                if (startInput) startInput.value = _periodBStart;
                if (endInput) endInput.value = _periodBEnd;
                container.querySelectorAll('.comparison-preset-btn').forEach(function (b) { b.classList.remove('active'); });
                btn.classList.add('active');
                if (_cfg.onActivate) _cfg.onActivate();
            });
        });

        container.querySelector('.comparison-close-btn').addEventListener('click', deactivate);
    }

    // ── Period A Label ────────────────────────────────────────

    function _getPeriodALabel() {
        // Try custom date inputs first
        var customStart = document.getElementById('customDateStart');
        var customEnd = document.getElementById('customDateEnd');
        var customMode = document.getElementById('dateCustomMode');
        if (customStart && customEnd && customMode && customMode.style.display !== 'none' && customStart.value && customEnd.value) {
            return _fmtDate(customStart.value) + ' – ' + _fmtDate(customEnd.value);
        }

        // Try date range slider
        var slider = document.getElementById('dateRangeSlider');
        if (slider) {
            var days = parseInt(slider.value) || 30;
            return 'Last ' + days + ' days';
        }

        // EPP-style date inputs
        var sDate = document.getElementById('startDate');
        var eDate = document.getElementById('endDate');
        if (sDate && eDate && sDate.value && eDate.value) {
            return _fmtDate(sDate.value) + ' – ' + _fmtDate(eDate.value);
        }

        return 'Current filters';
    }

    function _fmtDate(dateStr) {
        if (!dateStr) return '';
        var parts = dateStr.split('-');
        if (parts.length !== 3) return dateStr;
        return parts[1] + '/' + parts[2];
    }

    // ── Presets ───────────────────────────────────────────────

    function computePresets() {
        var periodA = _getCurrentPeriodADates();
        if (!periodA) return [];

        var aStart = new Date(periodA.start + 'T00:00:00');
        var aEnd = new Date(periodA.end + 'T23:59:59');
        var durationMs = aEnd - aStart;
        var durationDays = Math.round(durationMs / 86400000);

        var presets = [];

        // Previous Period (same duration, immediately before)
        var prevEnd = new Date(aStart);
        prevEnd.setDate(prevEnd.getDate() - 1);
        var prevStart = new Date(prevEnd);
        prevStart.setDate(prevStart.getDate() - durationDays + 1);
        presets.push({
            label: 'Previous ' + durationDays + 'd',
            start: _toISO(prevStart),
            end: _toISO(prevEnd)
        });

        // Same period last month
        var lmStart = new Date(aStart);
        lmStart.setMonth(lmStart.getMonth() - 1);
        var lmEnd = new Date(aEnd);
        lmEnd.setMonth(lmEnd.getMonth() - 1);
        presets.push({
            label: 'Month ago',
            start: _toISO(lmStart),
            end: _toISO(lmEnd)
        });

        // Same period last quarter (3 months ago)
        var lqStart = new Date(aStart);
        lqStart.setMonth(lqStart.getMonth() - 3);
        var lqEnd = new Date(aEnd);
        lqEnd.setMonth(lqEnd.getMonth() - 3);
        presets.push({
            label: 'Quarter ago',
            start: _toISO(lqStart),
            end: _toISO(lqEnd)
        });

        return presets;
    }

    function _getCurrentPeriodADates() {
        // Custom date inputs
        var customStart = document.getElementById('customDateStart');
        var customEnd = document.getElementById('customDateEnd');
        var customMode = document.getElementById('dateCustomMode');
        if (customStart && customEnd && customMode && customMode.style.display !== 'none' && customStart.value && customEnd.value) {
            return { start: customStart.value, end: customEnd.value };
        }

        // Slider
        var slider = document.getElementById('dateRangeSlider');
        if (slider) {
            var days = parseInt(slider.value) || 30;
            var end = new Date();
            var start = new Date();
            start.setDate(start.getDate() - days);
            return { start: _toISO(start), end: _toISO(end) };
        }

        // EPP date inputs
        var sDate = document.getElementById('startDate');
        var eDate = document.getElementById('endDate');
        if (sDate && eDate && sDate.value && eDate.value) {
            return { start: sDate.value, end: eDate.value };
        }

        return null;
    }

    function _toISO(d) {
        return d.getFullYear() + '-' +
            String(d.getMonth() + 1).padStart(2, '0') + '-' +
            String(d.getDate()).padStart(2, '0');
    }

    // ── Chart Overlay Helpers ─────────────────────────────────

    /**
     * Merge Period B bar traces alongside Period A traces for grouped comparison.
     * Returns combined array. Period B traces get muted opacity and "(B)" suffix.
     */
    function overlayBarTraces(aTraces, bTraces, opacity) {
        opacity = opacity || 0.45;
        var combined = [];

        for (var i = 0; i < aTraces.length; i++) {
            combined.push(aTraces[i]);
        }

        for (var j = 0; j < bTraces.length; j++) {
            var bt = Object.assign({}, bTraces[j]);
            bt.name = (bt.name || 'Period B') + ' (B)';
            bt.opacity = opacity;
            // Dashed outline pattern for bars
            if (bt.marker) {
                bt.marker = Object.assign({}, bt.marker);
                bt.marker.line = { width: 1.5, color: bt.marker.color || '#888', dash: 'dash' };
            }
            combined.push(bt);
        }

        return combined;
    }

    /**
     * Add Period B line traces alongside Period A. Period B lines are dashed.
     */
    function overlayLineTraces(aTraces, bTraces) {
        var combined = [];

        for (var i = 0; i < aTraces.length; i++) {
            combined.push(aTraces[i]);
        }

        for (var j = 0; j < bTraces.length; j++) {
            var bt = Object.assign({}, bTraces[j]);
            bt.name = (bt.name || 'Period B') + ' (B)';
            bt.line = Object.assign({}, bt.line || {});
            bt.line.dash = 'dash';
            bt.opacity = 0.6;
            combined.push(bt);
        }

        return combined;
    }

    // ── KPI Comparison HTML ───────────────────────────────────

    /**
     * Returns HTML snippet for a comparison line under a KPI value.
     * @param {number|string} aVal - Period A raw value
     * @param {number|string} bVal - Period B raw value
     * @param {object} opts - {suffix, invertedGood, label}
     */
    function kpiComparisonHtml(aVal, bVal, opts) {
        opts = opts || {};
        var aNum = parseFloat(String(aVal).replace(/[^0-9.\-]/g, '')) || 0;
        var bNum = parseFloat(String(bVal).replace(/[^0-9.\-]/g, '')) || 0;

        var delta = aNum !== 0 ? ((aNum - bNum) / Math.abs(bNum)) * 100 : 0;
        if (!isFinite(delta)) delta = 0;

        var isUp = delta > 0;
        var isGood = opts.invertedGood ? !isUp : isUp;
        var arrow = delta === 0 ? '→' : (isUp ? '↑' : '↓');
        var badgeCls = delta === 0 ? 'neutral' : (isGood ? 'up' : 'down');
        var absD = Math.abs(delta).toFixed(1);

        var suffix = opts.suffix || '';
        var bDisplay = typeof bVal === 'string' ? bVal : bNum.toLocaleString() + suffix;

        return '<div class="kpi-comparison-line">' +
            '<span class="kpi-comp-label">vs</span> ' +
            '<span class="kpi-comp-value">' + bDisplay + '</span> ' +
            '<span class="kpi-comp-badge ' + badgeCls + '">' + arrow + ' ' + absD + '%</span>' +
            '</div>';
    }

    // ── Expose ────────────────────────────────────────────────

    window.ComparisonMode = {
        init: init,
        activate: activate,
        deactivate: deactivate,
        isActive: isActive,
        getPeriodB: getPeriodB,
        renderConfigBar: renderConfigBar,
        computePresets: computePresets,
        overlayBarTraces: overlayBarTraces,
        overlayLineTraces: overlayLineTraces,
        kpiComparisonHtml: kpiComparisonHtml
    };

})();
