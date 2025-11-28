/**
 * Main entry point for meaningful metrics dashboard
 * Orchestrates all modules and initializes the application
 */

import {state, updateDataTimestamp, loadSortPreferences, loadColumnPreferences} from './state.js';
import {initThemeListener} from './theme.js';
import {populateFilterOptions, applyFilters, resetFilters, removeFilter, initLocationTabs} from './filters.js';
import {updateCharts} from './charts.js';
import {updateTable, setupColumnSelector, sortTable, rebuildTable} from './table.js';
import {setupSliderTooltip, formatMttrValue, formatMttcValue, formatAgeValue, hideLoading, showError, showDashboard} from './ui.js';
import {exportToExcel} from './export.js';

/**
 * Load data from API
 */
async function loadData() {
    try {
        const response = await fetch('/api/meaningful-metrics/data');
        const result = await response.json();

        if (result.success) {
            state.allData = result.data;
            updateDataTimestamp(result.data_generated_at);
            populateFilterOptions();
            applyFilters(updateDashboard);
            hideLoading();
        } else {
            showError('Failed to load data: ' + result.error);
        }
    } catch (error) {
        showError('Error loading data: ' + error.message);
    }
}

/**
 * Update dashboard (charts and table)
 */
function updateDashboard() {
    updateCharts();
    updateTable();
    showDashboard();
}

/**
 * Setup event listeners for filters and controls
 */
function setupEventListeners() {
    // Setup slider tooltips
    setupSliderTooltip('dateRangeSlider', 'dateRangeTooltip', () => applyFilters(updateDashboard));
    setupSliderTooltip('mttrRangeSlider', 'mttrRangeTooltip', () => applyFilters(updateDashboard), formatMttrValue);
    setupSliderTooltip('mttcRangeSlider', 'mttcRangeTooltip', () => applyFilters(updateDashboard), formatMttcValue);
    setupSliderTooltip('ageRangeSlider', 'ageRangeTooltip', () => applyFilters(updateDashboard), formatAgeValue);

    // Add listeners for filter checkboxes
    document.querySelectorAll('#severityFilter input, #statusFilter input, #automationFilter input').forEach(checkbox => {
        checkbox.addEventListener('change', () => applyFilters(updateDashboard));
    });

    // Location tabs
    initLocationTabs();

    // Reset filters button
    const resetBtn = document.getElementById('resetFiltersBtn');
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            resetFilters();
            applyFilters(updateDashboard);
        });
    }

    // Export button
    const exportBtn = document.getElementById('exportExcelBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportToExcel);
    }

    // Column selector
    setupColumnSelector();

    // Load preferences
    loadSortPreferences();
    loadColumnPreferences();
}

/**
 * Initialize the application
 */
function init() {
    initThemeListener();
    loadData();
    setupEventListeners();
}

// Start the application when DOM is ready
document.addEventListener('DOMContentLoaded', init);

// Expose functions to global scope for onclick handlers
window.metricsApp = {
    removeFilter: (type, value) => {
        removeFilter(type, value);
        applyFilters(updateDashboard);
    },
    sortTable,
    rebuildTable
};
