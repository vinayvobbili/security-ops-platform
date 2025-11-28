/**
 * Table rendering and management
 * This module handles table display, sorting, column management, and drag-drop
 */

import {state, getNestedValue, saveSortPreferences, loadSortPreferences, saveColumnPreferences, loadColumnPreferences} from './state.js';
import {AVAILABLE_COLUMNS, STATUS_MAP, SEVERITY_MAP} from './config.js';
import {attachNotesModalListeners, announceTableStatus} from './ui.js';

export function updateTable() {
    const tbody = document.querySelector('#dataTable tbody');
    if (!tbody) return;

    const sortedData = sortData(state.filteredData);
    const displayData = state.showAllRows ? sortedData : sortedData.slice(0, 100);

    tbody.innerHTML = displayData.map(item => {
        const row = document.createElement('tr');
        state.columnOrder.filter(col => state.visibleColumns.includes(col)).forEach(columnId => {
            const column = AVAILABLE_COLUMNS[columnId];
            if (!column) return;

            const td = document.createElement('td');
            const value = getNestedValue(item, column.path);

            switch (column.type) {
                case 'date':
                    if (value) {
                        const date = new Date(value);
                        const month = (date.getMonth() + 1).toString().padStart(2, '0');
                        const day = date.getDate().toString().padStart(2, '0');
                        const year = date.getFullYear();
                        td.textContent = `${month}/${day}/${year}`;
                    }
                    break;
                case 'duration':
                    td.classList.add('duration-column');
                    if (value && value > 0) {
                        const minutes = Math.floor(value / 60);
                        const seconds = Math.round(value % 60);
                        td.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                    } else {
                        td.textContent = '--';
                    }
                    break;
                case 'array':
                    if (columnId === 'notes' && Array.isArray(value) && value.length > 0) {
                        const notesData = JSON.stringify(value.map(note => ({
                            text: note.note_text || note.contents || '',
                            author: note.author || note.user || 'Unknown',
                            timestamp: note.created_at || (note.created ? new Date(note.created).toLocaleString() : '')
                        })));
                        td.innerHTML = `<span class="notes-icon" data-notes='${notesData.replace(/'/g, '&#39;')}'>📝 ${value.length}</span>`;
                    } else if (Array.isArray(value) && value.length > 0) {
                        td.textContent = `${value.length} items`;
                    } else {
                        td.textContent = '';
                    }
                    break;
                case 'number':
                    if (columnId === 'id') {
                        td.innerHTML = `<a href="https://msoar.crtx.us.paloaltonetworks.com/Custom/caseinfoid/${value}" target="_blank" style="color: #0046ad; text-decoration: underline;">${value}</a>`;
                    } else if (columnId === 'severity') {
                        const severity = SEVERITY_MAP[value] || 'Unknown';
                        td.innerHTML = `<span class="severity-${severity.toLowerCase()}">${severity}</span>`;
                    } else if (columnId === 'status') {
                        const status = STATUS_MAP[value] || 'Unknown';
                        td.innerHTML = `<span class="status-${status.toLowerCase()}">${status}</span>`;
                    } else if (columnId === 'currently_aging_days') {
                        // Fixed: simplified null check
                        if (value == null) {
                            td.textContent = '--';
                            td.style.color = '#6c757d';
                        } else {
                            td.textContent = value;
                        }
                    } else {
                        td.textContent = value;
                    }
                    break;
                default:
                    td.textContent = value || '';
            }
            row.appendChild(td);
        });
        return row.outerHTML;
    }).join('');

    attachNotesModalListeners();

    const emptyHint = document.getElementById('dataTableEmptyHint');
    if (emptyHint) {
        emptyHint.style.display = displayData.length === 0 ? 'block' : 'none';
    }

    updateTableInfo(sortedData.length, displayData.length);
    updateSortIndicators();
}

function updateTableInfo(totalRows, displayedRows) {
    const tableHeader = document.getElementById('tableHeader');
    const tableInfoBar = document.getElementById('tableInfoBar');

    if (tableHeader) {
        tableHeader.textContent = `📋 Case Details (showing first ${displayedRows} of ${totalRows} results)`;
    }

    if (tableInfoBar) {
        if (totalRows > 100 && !state.showAllRows) {
            tableInfoBar.innerHTML = `Showing first 100 of ${totalRows} results. <button id="showAllRowsBtn" class="show-all-btn">Show All ${totalRows} Rows</button>`;
            const btn = document.getElementById('showAllRowsBtn');
            if (btn) {
                btn.addEventListener('click', () => {
                    state.showAllRows = true;
                    updateTable();
                });
            }
        } else {
            tableInfoBar.textContent = `Showing all ${totalRows} results`;
        }
    }

    if (state.lastTableRowCount !== totalRows) {
        announceTableStatus(`Table updated. Showing ${displayedRows} of ${totalRows} results.`);
        state.lastTableRowCount = totalRows;
    }
}

export function sortTable(column) {
    if (state.currentSort.column === column) {
        state.currentSort.direction = state.currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        state.currentSort.column = column;
        state.currentSort.direction = 'asc';
    }
    saveSortPreferences();
    updateSortIndicators();
    updateTable();
}

export function updateSortIndicators() {
    document.querySelectorAll('.sort-indicator').forEach(indicator => {
        indicator.textContent = '';
        indicator.parentElement.classList.remove('sort-asc', 'sort-desc');
    });

    if (state.currentSort.column) {
        const header = document.querySelector(`[data-column="${state.currentSort.column}"]`);
        if (header) {
            const indicator = header.querySelector('.sort-indicator');
            indicator.textContent = state.currentSort.direction === 'asc' ? ' ▲' : ' ▼';
            header.classList.add(state.currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
        }
    }
}

function sortData(data) {
    if (!state.currentSort.column) return data;

    const column = AVAILABLE_COLUMNS[state.currentSort.column];
    if (!column) return data;

    return [...data].sort((a, b) => {
        let aVal = getNestedValue(a, column.path);
        let bVal = getNestedValue(b, column.path);

        if (column.type === 'date') {
            aVal = aVal ? new Date(aVal) : new Date(0);
            bVal = bVal ? new Date(bVal) : new Date(0);
        } else if (column.type === 'number' || column.type === 'duration') {
            aVal = parseInt(aVal) || 0;
            bVal = parseInt(bVal) || 0;
        } else {
            aVal = (aVal || '').toString().toLowerCase();
            bVal = (bVal || '').toString().toLowerCase();
        }

        let comparison = 0;
        if (aVal > bVal) comparison = 1;
        else if (aVal < bVal) comparison = -1;

        return state.currentSort.direction === 'asc' ? comparison : -comparison;
    });
}

export function rebuildTable() {
    buildTableHeaders();
    updateTable();
}

export function buildTableHeaders() {
    const thead = document.querySelector('#dataTable thead tr');
    if (!thead) return;

    thead.innerHTML = '';

    state.columnOrder.filter(col => state.visibleColumns.includes(col)).forEach(columnId => {
        const column = AVAILABLE_COLUMNS[columnId];
        if (column) {
            const th = document.createElement('th');
            th.className = 'sortable';
            th.setAttribute('data-column', columnId);
            th.innerHTML = `${column.label} <span class="sort-indicator"></span>`;
            th.style.cursor = 'pointer';
            if (column.type === 'duration') {
                th.classList.add('duration-column');
                th.title = 'mins:secs';
                th.innerHTML = `${column.label} ℹ️ <span class="sort-indicator"></span>`;
            }
            th.addEventListener('click', () => sortTable(columnId));
            thead.appendChild(th);
        }
    });

    updateSortIndicators();
}

// Column selector
export function setupColumnSelector() {
    const btn = document.getElementById('columnSelectorBtn');
    const dropdown = document.getElementById('columnSelectorDropdown');
    if (!btn || !dropdown) return;

    loadColumnPreferences();

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
        if (dropdown.style.display === 'block') populateColumnSelector();
    });

    document.addEventListener('click', (e) => {
        if (!dropdown.contains(e.target) && !btn.contains(e.target)) {
            dropdown.style.display = 'none';
        }
    });

    document.getElementById('selectAllColumnsBtn')?.addEventListener('click', selectAllColumns);
    document.getElementById('deselectAllColumnsBtn')?.addEventListener('click', deselectAllColumns);
    document.getElementById('resetFiltersBtn')?.addEventListener('click', () => {
        const {resetFilters} = require('./filters.js');
        resetFilters();
    });
}

function populateColumnSelector() {
    const container = document.getElementById('columnCheckboxes');
    if (!container) return;

    container.innerHTML = '';

    const categories = {};
    Object.keys(AVAILABLE_COLUMNS).forEach(columnId => {
        const column = AVAILABLE_COLUMNS[columnId];
        if (!categories[column.category]) categories[column.category] = [];
        categories[column.category].push({id: columnId, ...column});
    });

    Object.keys(categories).sort().forEach(categoryName => {
        const categoryHeader = document.createElement('div');
        categoryHeader.className = 'column-category-header';
        categoryHeader.innerHTML = `<strong>${categoryName}</strong>`;
        categoryHeader.style.gridColumn = '1 / -1';
        container.appendChild(categoryHeader);

        categories[categoryName].forEach(column => {
            const item = document.createElement('div');
            item.className = 'column-checkbox-item';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = `col-${column.id}`;
            checkbox.checked = state.visibleColumns.includes(column.id);

            const isRequired = column.id === 'id' || column.id === 'name';
            if (isRequired) {
                checkbox.disabled = true;
                checkbox.checked = true;
            }

            checkbox.addEventListener('change', function () {
                if (!isRequired) toggleColumn(column.id, this.checked);
            });

            const label = document.createElement('label');
            label.htmlFor = `col-${column.id}`;
            label.textContent = column.label + (isRequired ? ' (Required)' : '');

            item.appendChild(checkbox);
            item.appendChild(label);
            container.appendChild(item);
        });
    });
}

function toggleColumn(columnId, isVisible) {
    if (isVisible && !state.visibleColumns.includes(columnId)) {
        state.visibleColumns.push(columnId);
        if (!state.columnOrder.includes(columnId)) state.columnOrder.push(columnId);
    } else if (!isVisible) {
        state.visibleColumns = state.visibleColumns.filter(id => id !== columnId);
    }
    saveColumnPreferences();
    rebuildTable();
}

function selectAllColumns() {
    state.visibleColumns = Object.keys(AVAILABLE_COLUMNS);
    state.columnOrder = [...state.visibleColumns];
    populateColumnSelector();
    saveColumnPreferences();
    rebuildTable();
}

function deselectAllColumns() {
    state.visibleColumns = ['id', 'name'];
    state.columnOrder = ['id', 'name'];
    populateColumnSelector();
    saveColumnPreferences();
    rebuildTable();
}
