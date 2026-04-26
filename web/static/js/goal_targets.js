/**
 * Goal Lines / SLA Targets — shared utility
 * Stores targets in localStorage, renders Plotly reference shapes, KPI badges, settings popover.
 * IIFE → window.GoalTargets
 */
(function () {
    'use strict';

    var _storageKey = null;
    var _defaults = {};
    var _popoverEl = null;

    function init(storageKey, defaults) {
        _storageKey = storageKey;
        _defaults = defaults || {};
    }

    function getTargets() {
        if (!_storageKey) return Object.assign({}, _defaults);
        try {
            var saved = JSON.parse(localStorage.getItem(_storageKey));
            return saved ? Object.assign({}, _defaults, saved) : Object.assign({}, _defaults);
        } catch (e) { return Object.assign({}, _defaults); }
    }

    function saveTargets(targets) {
        if (_storageKey) localStorage.setItem(_storageKey, JSON.stringify(targets));
    }

    /**
     * Returns Plotly shapes array for a horizontal or vertical reference line.
     * @param {number} targetValue
     * @param {object} opts - {axis: 'y'|'x', color, dash}
     */
    function plotlyShapes(targetValue, opts) {
        if (targetValue == null || targetValue === 0) return [];
        opts = opts || {};
        var color = opts.color || 'rgba(239, 68, 68, 0.6)';
        var dash = opts.dash || 'dash';

        if (opts.axis === 'x') {
            return [{
                type: 'line', xref: 'x', yref: 'paper',
                x0: targetValue, x1: targetValue, y0: 0, y1: 1,
                line: { color: color, width: 1.5, dash: dash }
            }];
        }
        return [{
            type: 'line', xref: 'paper', yref: 'y',
            x0: 0, x1: 1, y0: targetValue, y1: targetValue,
            line: { color: color, width: 1.5, dash: dash }
        }];
    }

    /**
     * Returns HTML for a target indicator badge.
     * @param {number} value - current metric value
     * @param {number} target - target value
     * @param {object} opts - {lowerIsBetter, unit}
     */
    function kpiTargetBadge(value, target, opts) {
        if (target == null) return '';
        opts = opts || {};
        var met = opts.lowerIsBetter ? (value <= target) : (value >= target);
        var icon = met ? '\uD83C\uDFAF' : '\u26A0\uFE0F';
        var cls = met ? 'goal-met' : 'goal-missed';
        var op = opts.lowerIsBetter ? '\u2264' : '\u2265';
        var label = 'Target: ' + op + target + (opts.unit || '');
        return '<span class="goal-target-badge ' + cls + '" title="' + label + '">' + icon + '</span>';
    }

    function _outsideClickHandler(e) {
        if (_popoverEl && !_popoverEl.contains(e.target)) closePopover();
    }

    /**
     * Render settings popover anchored to an element.
     */
    function renderSettingsPopover(anchorEl, onSave) {
        if (_popoverEl) { closePopover(); return; }

        var targets = getTargets();
        var keys = Object.keys(targets);

        _popoverEl = document.createElement('div');
        _popoverEl.className = 'goal-settings-popover';

        var html = '<div class="goal-settings-header">\uD83C\uDFAF SLA Targets<button class="goal-settings-close">\u00D7</button></div>';
        html += '<div class="goal-settings-body">';
        keys.forEach(function (key) {
            var label = key.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
            html += '<div class="goal-setting-row"><label>' + label + '</label>' +
                '<input type="number" data-key="' + key + '" value="' + targets[key] + '" step="any"></div>';
        });
        html += '</div><div class="goal-settings-footer"><button class="goal-settings-save">Save</button></div>';

        _popoverEl.innerHTML = html;
        document.body.appendChild(_popoverEl);

        var rect = anchorEl.getBoundingClientRect();
        _popoverEl.style.position = 'fixed';
        _popoverEl.style.top = (rect.bottom + 8) + 'px';
        _popoverEl.style.right = (window.innerWidth - rect.right) + 'px';
        _popoverEl.style.zIndex = '5000';

        _popoverEl.querySelector('.goal-settings-close').addEventListener('click', closePopover);
        _popoverEl.querySelector('.goal-settings-save').addEventListener('click', function () {
            var newTargets = {};
            _popoverEl.querySelectorAll('input[data-key]').forEach(function (inp) {
                newTargets[inp.dataset.key] = parseFloat(inp.value) || 0;
            });
            saveTargets(newTargets);
            closePopover();
            if (onSave) onSave(newTargets);
        });

        setTimeout(function () {
            document.addEventListener('click', _outsideClickHandler);
        }, 0);
    }

    function closePopover() {
        if (_popoverEl) { _popoverEl.remove(); _popoverEl = null; }
        document.removeEventListener('click', _outsideClickHandler);
    }

    window.GoalTargets = {
        init: init,
        getTargets: getTargets,
        saveTargets: saveTargets,
        plotlyShapes: plotlyShapes,
        kpiTargetBadge: kpiTargetBadge,
        renderSettingsPopover: renderSettingsPopover,
        closePopover: closePopover
    };
})();
