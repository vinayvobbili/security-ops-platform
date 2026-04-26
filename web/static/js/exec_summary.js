/**
 * Executive Summary — shared utility
 * Renders a collapsible NL summary card with fade transitions.
 * IIFE → window.ExecSummary
 */
(function () {
    'use strict';

    var COLLAPSED_KEY_PREFIX = 'exec-summary-collapsed-';

    /**
     * Render executive summary.
     * @param {string} containerId
     * @param {function} templateFn - function(data) returning HTML string
     * @param {*} data - passed to templateFn
     * @param {object} [opts] - {dashboardKey}
     */
    function render(containerId, templateFn, data, opts) {
        opts = opts || {};
        var el = document.getElementById(containerId);
        if (!el) return;

        var key = opts.dashboardKey || containerId;
        var collapsed = localStorage.getItem(COLLAPSED_KEY_PREFIX + key) === 'true';
        var text = templateFn(data);

        var html = '<div class="exec-summary-card' + (collapsed ? ' collapsed' : '') + '">' +
            '<div class="exec-summary-header">' +
                '<span class="exec-summary-icon">\uD83D\uDCA1</span>' +
                '<span class="exec-summary-title">Executive Summary</span>' +
                '<button class="exec-summary-toggle" title="Toggle summary">' +
                    (collapsed ? '\u25B6' : '\u25BC') + '</button>' +
            '</div>' +
            '<div class="exec-summary-body" style="' + (collapsed ? 'display:none;' : '') + '">' +
                '<p class="exec-summary-text">' + text + '</p>' +
            '</div>' +
        '</div>';

        el.style.opacity = '0';
        el.innerHTML = html;
        requestAnimationFrame(function () {
            el.style.transition = 'opacity 0.3s ease';
            el.style.opacity = '1';
        });

        var toggleBtn = el.querySelector('.exec-summary-toggle');
        var body = el.querySelector('.exec-summary-body');
        var card = el.querySelector('.exec-summary-card');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', function () {
                var isCollapsed = body.style.display === 'none';
                body.style.display = isCollapsed ? '' : 'none';
                toggleBtn.textContent = isCollapsed ? '\u25BC' : '\u25B6';
                card.classList.toggle('collapsed', !isCollapsed);
                localStorage.setItem(COLLAPSED_KEY_PREFIX + key, String(!isCollapsed));
            });
        }
    }

    window.ExecSummary = { render: render };
})();
