/**
 * Drill-Down Drawer — shared utility
 * Slide-out panel from right showing underlying data rows on chart click.
 * IIFE → window.DrilldownDrawer
 */
(function () {
    'use strict';

    var _drawerEl = null;
    var _overlayEl = null;
    var _isOpen = false;

    function _ensureDOM() {
        if (_drawerEl) return;

        _overlayEl = document.createElement('div');
        _overlayEl.className = 'dd-drawer-overlay';
        _overlayEl.addEventListener('click', close);

        _drawerEl = document.createElement('div');
        _drawerEl.className = 'dd-drawer';
        _drawerEl.innerHTML =
            '<div class="dd-drawer-header">' +
                '<span class="dd-drawer-title"></span>' +
                '<div class="dd-drawer-actions">' +
                    '<button class="dd-drawer-filter-btn" title="Apply as filter" style="display:none;">\uD83D\uDD0D Apply Filter</button>' +
                    '<button class="dd-drawer-close">\u00D7</button>' +
                '</div>' +
            '</div>' +
            '<div class="dd-drawer-count"></div>' +
            '<div class="dd-drawer-body"></div>';

        document.body.appendChild(_overlayEl);
        document.body.appendChild(_drawerEl);

        _drawerEl.querySelector('.dd-drawer-close').addEventListener('click', close);

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && _isOpen) close();
        });
    }

    /**
     * Open the drawer with data rows.
     * @param {string} title - header text
     * @param {Array} rows - array of objects
     * @param {Array} columns - [{key, label, width?, render?}]
     * @param {object} [opts] - {onFilter, maxRows}
     */
    function open(title, rows, columns, opts) {
        _ensureDOM();
        opts = opts || {};
        var maxRows = opts.maxRows || 50;
        var displayRows = rows.slice(0, maxRows);

        _drawerEl.querySelector('.dd-drawer-title').textContent = title;
        _drawerEl.querySelector('.dd-drawer-count').textContent =
            'Showing ' + displayRows.length + ' of ' + rows.length + ' records';

        var html = '<table class="dd-drawer-table"><thead><tr>';
        columns.forEach(function (col) {
            html += '<th' + (col.width ? ' style="width:' + col.width + '"' : '') + '>' + col.label + '</th>';
        });
        html += '</tr></thead><tbody>';
        displayRows.forEach(function (row) {
            html += '<tr>';
            columns.forEach(function (col) {
                var val = col.render ? col.render(row[col.key], row) : row[col.key];
                if (val == null) val = '-';
                html += '<td>' + val + '</td>';
            });
            html += '</tr>';
        });
        if (displayRows.length === 0) {
            html += '<tr><td colspan="' + columns.length + '" style="text-align:center;padding:20px;">No matching records</td></tr>';
        }
        html += '</tbody></table>';

        _drawerEl.querySelector('.dd-drawer-body').innerHTML = html;

        var filterBtn = _drawerEl.querySelector('.dd-drawer-filter-btn');
        if (opts.onFilter) {
            filterBtn.style.display = '';
            filterBtn.onclick = function () { opts.onFilter(); close(); };
        } else {
            filterBtn.style.display = 'none';
        }

        _overlayEl.classList.add('active');
        _drawerEl.classList.add('open');
        _isOpen = true;
        document.body.style.overflow = 'hidden';
    }

    function close() {
        if (!_drawerEl) return;
        _overlayEl.classList.remove('active');
        _drawerEl.classList.remove('open');
        _isOpen = false;
        document.body.style.overflow = '';
    }

    function isOpen() { return _isOpen; }

    window.DrilldownDrawer = { open: open, close: close, isOpen: isOpen };
})();
