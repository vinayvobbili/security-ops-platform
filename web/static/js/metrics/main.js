/**
 * Main entry point for meaningful metrics dashboard
 * Orchestrates all modules and initializes the application
 */

import {state, updateDataTimestamp, loadSortPreferences, loadColumnPreferences} from './state.js';
import {initThemeListener} from './theme.js';
import {populateFilterOptions, applyFilters, resetFilters, removeFilter, initLocationTabs} from './filters.js';
import {updateCharts} from './charts.js';
import {updateMetrics} from './metrics.js';
import {updateTable, setupColumnSelector, sortTable, rebuildTable, buildTableHeaders} from './table.js';
import {setupSliderTooltip, formatMttrValue, formatMttcValue, formatAgeValue, hideLoading, showError, showDashboard, updateDateSliderLabels, updateMttrSliderLabels, updateMttcSliderLabels, updateAgeSliderLabels, updateSliderTooltip, showSliderTooltip, hideSliderTooltip} from './ui.js';
import {exportToExcel} from './export.js';
import {loadAppConfig} from './config.js';

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
 * Update dashboard (metrics, charts and table)
 */
function updateDashboard() {
    updateMetrics();
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

    // Setup date range slider label clicks
    const dateContainer = document.getElementById('dateRangeSlider')?.parentElement;
    const dateSlider = document.getElementById('dateRangeSlider');
    if (dateContainer && dateSlider) {
        dateContainer.querySelectorAll('.range-preset').forEach(preset => {
            preset.addEventListener('click', function () {
                const value = this.getAttribute('data-value');
                dateSlider.value = value;
                showSliderTooltip('dateRangeTooltip');
                updateDateSliderLabels(value);
                applyFilters(updateDashboard);
                setTimeout(() => hideSliderTooltip('dateRangeTooltip'), 1000);
            });
        });
        // Update labels when slider changes
        dateSlider.addEventListener('input', function () {
            updateDateSliderLabels(this.value);
        });
        // Initialize date slider display
        updateDateSliderLabels(dateSlider.value);
    }

    // Setup MTTR slider label clicks
    const mttrContainer = document.getElementById('mttrRangeSlider')?.parentElement;
    const mttrSlider = document.getElementById('mttrRangeSlider');
    if (mttrContainer && mttrSlider) {
        mttrContainer.querySelectorAll('.slider-labels span').forEach(label => {
            label.addEventListener('click', function () {
                const value = this.getAttribute('data-value');
                mttrSlider.value = value;
                showSliderTooltip('mttrRangeTooltip');
                updateSliderTooltip('mttrRangeSlider', 'mttrRangeTooltip', value, formatMttrValue);
                updateMttrSliderLabels(value);
                applyFilters(updateDashboard);
                setTimeout(() => hideSliderTooltip('mttrRangeTooltip'), 1000);
            });
            label.style.cursor = 'pointer';
        });
        // Update labels when slider changes
        mttrSlider.addEventListener('input', function () {
            updateMttrSliderLabels(this.value);
        });
        // Initialize
        updateMttrSliderLabels(mttrSlider.value);
    }

    // Setup MTTC slider label clicks
    const mttcContainer = document.getElementById('mttcRangeSlider')?.parentElement;
    const mttcSlider = document.getElementById('mttcRangeSlider');
    if (mttcContainer && mttcSlider) {
        mttcContainer.querySelectorAll('.slider-labels span').forEach(label => {
            label.addEventListener('click', function () {
                const value = this.getAttribute('data-value');
                mttcSlider.value = value;
                showSliderTooltip('mttcRangeTooltip');
                updateSliderTooltip('mttcRangeSlider', 'mttcRangeTooltip', value, formatMttcValue);
                updateMttcSliderLabels(value);
                applyFilters(updateDashboard);
                setTimeout(() => hideSliderTooltip('mttcRangeTooltip'), 1000);
            });
            label.style.cursor = 'pointer';
        });
        // Update labels when slider changes
        mttcSlider.addEventListener('input', function () {
            updateMttcSliderLabels(this.value);
        });
        // Initialize
        updateMttcSliderLabels(mttcSlider.value);
    }

    // Setup Age slider label clicks
    const ageContainer = document.getElementById('ageRangeSlider')?.parentElement;
    const ageSlider = document.getElementById('ageRangeSlider');
    if (ageContainer && ageSlider) {
        ageContainer.querySelectorAll('.range-preset').forEach(preset => {
            preset.addEventListener('click', function () {
                const value = this.getAttribute('data-value');
                ageSlider.value = value;
                showSliderTooltip('ageRangeTooltip');
                updateSliderTooltip('ageRangeSlider', 'ageRangeTooltip', value, formatAgeValue);
                updateAgeSliderLabels(value);
                applyFilters(updateDashboard);
                setTimeout(() => hideSliderTooltip('ageRangeTooltip'), 1000);
            });
        });
        // Update labels when slider changes
        ageSlider.addEventListener('input', function () {
            updateAgeSliderLabels(this.value);
        });
        // Initialize
        updateAgeSliderLabels(ageSlider.value);
    }

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

    // Rebuild table headers to match loaded column preferences
    buildTableHeaders();
}

/**
 * Initialize the application
 */
async function init() {
    initThemeListener();
    await loadAppConfig(); // Load app config first (team name, email domain, etc.)
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
