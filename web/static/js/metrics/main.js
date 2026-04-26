/**
 * Main entry point for meaningful metrics dashboard
 * Orchestrates all modules and initializes the application
 */

import {state, updateDataTimestamp, loadSortPreferences, loadColumnPreferences} from './state.js';
import {initThemeListener} from './theme.js';
import {populateFilterOptions, applyFilters, resetFilters, removeFilter, initLocationTabs, applyUrlFilters, addProgrammaticFilter, getCurrentFilters, restoreFilters} from './filters.js';
import {updateCharts, setDrilldownCallback} from './charts.js';
import {createSankeyChart, toggleSankeyAnimation} from './sankey.js';
import {updateMetrics} from './metrics.js';
import {updateTable, setupColumnSelector, sortTable, rebuildTable, buildTableHeaders} from './table.js';
import {setupSliderTooltip, formatMttrValue, formatMttcValue, formatAgeValue, hideLoading, showError, showDashboard, updateDateSliderLabels, updateMttrSliderLabels, updateMttcSliderLabels, updateAgeSliderLabels, updateSliderTooltip, showSliderTooltip, hideSliderTooltip} from './ui.js';
import {exportToExcel} from './export.js';
import {loadAppConfig} from './config.js';
import {initTimeline, adaptTimelineTheme} from './timeline.js';
import {initStory, updateStory, adaptStoryTheme} from './story.js';

/**
 * Load data from API
 */
async function loadData() {
    try {
        const response = await fetch('/api/meaningful-metrics/data');
        const result = await response.json();

        if (result.success) {
            state.allData = result.data;
            state.cachedData = result.data;
            updateDataTimestamp(result.data_generated_at);
            populateFilterOptions();
            applyUrlFilters();
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
    updateComparisonData();
    updateMetrics();
    updateCharts();
    updateTable();
    showDashboard();
    createSankeyChart();
    updateStory();
    updateExecSummary();
}

/**
 * Render executive summary from filtered data
 */
function updateExecSummary() {
    if (!window.ExecSummary) return;
    var el = document.getElementById('executiveSummary');
    if (!el) return;
    el.style.display = '';

    window.ExecSummary.render('executiveSummary', function (data) {
        var total = data.length;
        var countries = new Set(data.map(function (d) { return d.affected_country; })).size;
        var mttrCases = data.filter(function (d) { return d.time_to_respond_secs > 0; });
        var avgMttr = mttrCases.length > 0
            ? mttrCases.reduce(function (s, d) { return s + d.time_to_respond_secs; }, 0) / mttrCases.length
            : 0;
        var mttrMin = Math.floor(avgMttr / 60);
        var mttrSec = Math.round(avgMttr % 60);
        var breaches = data.filter(function (d) { return d.has_breached_response_sla; }).length;
        var openCount = data.filter(function (d) { return d.is_open; }).length;
        var countryMap = {};
        data.forEach(function (d) {
            var c = d.affected_country || 'Unknown';
            countryMap[c] = (countryMap[c] || 0) + 1;
        });
        var sorted = Object.entries(countryMap).sort(function (a, b) { return b[1] - a[1]; });
        var topCountry = sorted.length > 0 ? sorted[0][0] : '';

        // Detect custom date mode vs slider mode
        var customStart = document.getElementById('customDateStart');
        var customEnd = document.getElementById('customDateEnd');
        var customMode = document.getElementById('dateCustomMode');
        var useCustom = customStart && customEnd && customStart.value && customEnd.value &&
            customMode && customMode.style.display !== 'none';

        var periodLabel;
        if (useCustom) {
            periodLabel = 'From <strong>' + customStart.value + '</strong> to <strong>' + customEnd.value + '</strong>';
        } else {
            var slider = document.getElementById('dateRangeSlider');
            var days = parseInt(slider ? slider.value : 30);
            periodLabel = 'In the last <strong>' + days + ' days</strong>';
        }

        var parts = [];
        parts.push(periodLabel + ', there were <strong>' + total.toLocaleString() +
            '</strong> cases across <strong>' + countries + '</strong> countries.');
        parts.push('MTTR averaged <strong>' + mttrMin + ':' + String(mttrSec).padStart(2, '0') + '</strong>.');
        if (breaches > 0) {
            parts.push('<strong>' + breaches + '</strong> SLA breach' + (breaches > 1 ? 'es' : '') +
                ' occurred' + (topCountry ? ', with <strong>' + topCountry + '</strong> leading in volume' : '') + '.');
        } else {
            parts.push('Zero SLA breaches — excellent compliance.');
        }
        if (openCount > 0) {
            parts.push('<strong>' + openCount + '</strong> case' + (openCount > 1 ? 's remain' : ' remains') + ' open.');
        }
        return parts.join(' ');
    }, state.filteredData, { dashboardKey: 'mm' });
}

/**
 * Compute comparison data if comparison mode is active.
 * Filters state.allData with Period B dates → state.comparisonData.
 */
function updateComparisonData() {
    if (!window.ComparisonMode || !window.ComparisonMode.isActive()) {
        state.comparisonData = null;
        return;
    }
    var pb = window.ComparisonMode.getPeriodB();
    if (!pb.start || !pb.end) { state.comparisonData = null; return; }

    var bStart = new Date(pb.start + 'T00:00:00');
    var bEnd = new Date(pb.end + 'T23:59:59');

    state.comparisonData = state.allData.filter(function (item) {
        var created = new Date(item.created);
        if (isNaN(created.getTime())) return false;
        return created >= bStart && created <= bEnd;
    });
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
    document.querySelectorAll('#severityFilter input, #statusFilter input, #automationFilter input, #assignmentFilter input').forEach(checkbox => {
        checkbox.addEventListener('change', () => applyFilters(updateDashboard));
    });

    // Location tabs
    initLocationTabs();

    // Reset filters button
    const resetBtn = document.getElementById('resetFiltersBtn');
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            resetFilters();
            // Restore original cached data if custom range had replaced it
            if (state.cachedData && state.allData !== state.cachedData) {
                state.allData = state.cachedData;
                populateFilterOptions();
            }
            applyFilters(updateDashboard);
        });
    }

    // Export button
    const exportBtn = document.getElementById('exportExcelBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportToExcel);
    }

    // Custom date range toggle
    const toggleDateMode = document.getElementById('toggleDateMode');
    if (toggleDateMode) {
        toggleDateMode.addEventListener('click', (e) => {
            e.preventDefault();
            const sliderMode = document.getElementById('dateSliderMode');
            const customMode = document.getElementById('dateCustomMode');
            if (customMode.style.display === 'none') {
                sliderMode.style.display = 'none';
                customMode.style.display = 'block';
                toggleDateMode.textContent = 'Use slider';
            } else {
                sliderMode.style.display = 'block';
                customMode.style.display = 'none';
                toggleDateMode.textContent = 'Custom range';
                // Restore original cached data if custom range had replaced it
                if (state.cachedData && state.allData !== state.cachedData) {
                    state.allData = state.cachedData;
                    populateFilterOptions();
                }
                // Reset slider to 30 days
                const slider = document.getElementById('dateRangeSlider');
                if (slider) {
                    slider.value = 30;
                    updateDateSliderLabels(30);
                }
                applyFilters(updateDashboard);
            }
        });
    }

    // Custom date Apply button — streams live data from XSOAR via SSE
    const customDateApplyBtn = document.getElementById('customDateApplyBtn');
    if (customDateApplyBtn) {
        customDateApplyBtn.addEventListener('click', () => {
            const startVal = document.getElementById('customDateStart')?.value;
            const endVal = document.getElementById('customDateEnd')?.value;
            if (!startVal || !endVal) {
                const toast = document.getElementById('toast');
                if (toast) {
                    toast.textContent = 'Please select both a start and end date';
                    toast.classList.add('show');
                    setTimeout(() => toast.classList.remove('show'), 2500);
                }
                return;
            }

            // Warn for wide date ranges (live XSOAR query)
            const spanDays = Math.round((new Date(endVal) - new Date(startVal)) / 86400000);
            const estMins = spanDays <= 90 ? 2 : spanDays <= 180 ? 5 : spanDays <= 365 ? 15 : 30;
            if (!confirm(
                `This will query XSOAR live for ${startVal} to ${endVal} (${spanDays} days).\n\n` +
                `Estimated time: up to ${estMins} minutes.\n\n` +
                `Proceed?`
            )) return;

            // Show loading state with progress overlay
            customDateApplyBtn.disabled = true;
            customDateApplyBtn.textContent = 'Loading…';
            const loading = document.getElementById('loading');
            if (loading) loading.style.display = '';
            const progressBox = document.getElementById('loadingProgress');
            const progressText = document.getElementById('loadingProgressText');
            const progressSub = document.getElementById('loadingProgressSub');
            const progressFill = document.getElementById('loadingProgressFill');
            if (progressBox) { progressBox.style.display = ''; progressText.textContent = 'Connecting to XSOAR…'; progressSub.textContent = 'Elapsed: 0s'; }
            if (progressFill) progressFill.style.width = '0%';
            ['metricsGridHeader', 'metricsGrid', 'chartsGrid', 'sankeySection', 'dataTableSection', 'executiveSummary'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            });

            const fetchStart = Date.now();
            const elapsedTimer = setInterval(() => {
                const s = Math.round((Date.now() - fetchStart) / 1000);
                const str = s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
                if (progressSub) progressSub.textContent = `Elapsed: ${str}`;
            }, 1000);
            const es = new EventSource(`/api/meaningful-metrics/data/range/stream?start_date=${startVal}&end_date=${endVal}`);

            es.onmessage = (event) => {
                const msg = JSON.parse(event.data);

                if (msg.status === 'started') {
                    if (progressText) progressText.textContent = 'Fetching tickets from XSOAR…';
                    if (progressFill) progressFill.style.width = '5%';
                } else if (msg.status === 'fetching') {
                    if (progressText) progressText.textContent = `Fetched ${msg.total.toLocaleString()} tickets (page ${msg.page})…`;
                    if (progressFill) progressFill.style.width = `${Math.min(5 + msg.page * 12, 85)}%`;
                } else if (msg.status === 'processing') {
                    if (progressText) progressText.textContent = `Processing ${msg.total.toLocaleString()} tickets…`;
                    if (progressFill) progressFill.style.width = '90%';
                } else if (msg.status === 'complete') {
                    es.close();
                    clearInterval(elapsedTimer);
                    if (progressBox) progressBox.style.display = 'none';
                    state.allData = msg.data;
                    updateDataTimestamp(msg.data_generated_at);
                    populateFilterOptions();
                    applyFilters(updateDashboard);
                    const container = document.getElementById('activeFiltersContainer');
                    if (container) {
                        const dateTag = container.querySelector('.filter-tag:not(.non-removable)');
                        if (dateTag) dateTag.textContent = `${startVal} to ${endVal}`;
                    }
                    hideLoading();
                    customDateApplyBtn.disabled = false;
                    customDateApplyBtn.textContent = 'Apply';
                    const finalSecs = Math.round((Date.now() - fetchStart) / 1000);
                    const finalStr = finalSecs < 60 ? `${finalSecs}s` : `${Math.floor(finalSecs / 60)}m ${finalSecs % 60}s`;
                    const count = state.filteredData ? state.filteredData.length : 0;
                    const toast = document.getElementById('toast');
                    if (toast) {
                        toast.textContent = count > 0
                            ? `Loaded ${count.toLocaleString()} ticket${count === 1 ? '' : 's'} for ${startVal} to ${endVal} in ${finalStr}`
                            : `No tickets found for ${startVal} to ${endVal}`;
                        toast.classList.add('show');
                        setTimeout(() => toast.classList.remove('show'), 3000);
                    }
                } else if (msg.status === 'error') {
                    es.close();
                    clearInterval(elapsedTimer);
                    if (progressBox) progressBox.style.display = 'none';
                    hideLoading();
                    showError('Failed to load data: ' + msg.error);
                    customDateApplyBtn.disabled = false;
                    customDateApplyBtn.textContent = 'Apply';
                }
            };

            es.onerror = () => {
                es.close();
                clearInterval(elapsedTimer);
                if (progressBox) progressBox.style.display = 'none';
                hideLoading();
                showError('Connection lost while fetching data. Please try again.');
                customDateApplyBtn.disabled = false;
                customDateApplyBtn.textContent = 'Apply';
            };
        });
    }

    // Sankey pause button
    const sankeyPauseBtn = document.getElementById('sankeyPauseBtn');
    if (sankeyPauseBtn) {
        sankeyPauseBtn.addEventListener('click', toggleSankeyAnimation);
    }

    // Column selector
    setupColumnSelector();

    // Load preferences
    loadSortPreferences();
    loadColumnPreferences();

    // Rebuild table headers to match loaded column preferences
    buildTableHeaders();

    // PDF export button
    const pdfBtn = document.getElementById('exportPdfBtn');
    if (pdfBtn) {
        pdfBtn.addEventListener('click', () => {
            if (!window.DashboardExport) return;
            const toast = document.getElementById('toast');
            if (toast) { toast.textContent = 'Generating PDF...'; toast.classList.add('show'); }
            window.DashboardExport.exportPdf(null, {
                title: 'Meaningful Metrics Dashboard',
                subtitle: document.getElementById('activeFiltersContainer')?.textContent?.trim() || '',
                sections: ['#metricsGrid', '#chartsGrid', '#sankeySection']
            }, (step, total) => {
                if (toast) toast.textContent = 'Capturing section ' + step + ' of ' + total + '...';
                if (step === total) setTimeout(() => toast.classList.remove('show'), 2000);
            });
        });
    }

    // Share link button
    const shareBtn = document.getElementById('shareLinkBtn');
    if (shareBtn) {
        shareBtn.addEventListener('click', () => {
            const filters = getCurrentFilters();
            const encoded = btoa(JSON.stringify(filters));
            const url = window.location.origin + window.location.pathname + '#' + encoded;
            navigator.clipboard.writeText(url).then(() => {
                const toast = document.getElementById('toast');
                if (toast) {
                    toast.textContent = 'Link copied to clipboard!';
                    toast.classList.add('show');
                    setTimeout(() => toast.classList.remove('show'), 2000);
                }
            });
        });
    }

    // Goal settings button
    const goalBtn = document.getElementById('goalSettingsBtn');
    if (goalBtn && window.GoalTargets) {
        goalBtn.addEventListener('click', () => {
            window.GoalTargets.renderSettingsPopover(goalBtn, () => {
                applyFilters(updateDashboard);
            });
        });
    }

    // Saved filter views
    initSavedViews();
}

const SAVED_VIEWS_KEY = 'metricsSavedViews';

function getSavedViews() {
    try {
        return JSON.parse(localStorage.getItem(SAVED_VIEWS_KEY)) || {};
    } catch { return {}; }
}

function saveSavedViews(views) {
    localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(views));
}

function populateSavedViewsDropdown() {
    const select = document.getElementById('savedViewsSelect');
    if (!select) return;
    const views = getSavedViews();
    const names = Object.keys(views).sort();
    select.innerHTML = '<option value="">Saved Views...</option>' +
        names.map(n => `<option value="${n}">${n}</option>`).join('');
}

function initSavedViews() {
    populateSavedViewsDropdown();

    const saveBtn = document.getElementById('saveViewBtn');
    const select = document.getElementById('savedViewsSelect');
    const deleteBtn = document.getElementById('deleteViewBtn');

    if (saveBtn) {
        saveBtn.addEventListener('click', () => {
            const name = prompt('Name for this view:');
            if (!name || !name.trim()) return;
            const views = getSavedViews();
            views[name.trim()] = getCurrentFilters();
            saveSavedViews(views);
            populateSavedViewsDropdown();
            select.value = name.trim();
            deleteBtn.style.display = 'flex';
            const toast = document.getElementById('toast');
            if (toast) {
                toast.textContent = `View "${name.trim()}" saved`;
                toast.classList.add('show');
                setTimeout(() => toast.classList.remove('show'), 2000);
            }
        });
    }

    if (select) {
        select.addEventListener('change', () => {
            const name = select.value;
            if (!name) {
                deleteBtn.style.display = 'none';
                return;
            }
            const views = getSavedViews();
            const saved = views[name];
            if (saved) {
                restoreFilters(saved);
                applyFilters(updateDashboard);
                deleteBtn.style.display = 'flex';
            }
        });
    }

    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            const name = select.value;
            if (!name) return;
            if (!confirm(`Delete view "${name}"?`)) return;
            const views = getSavedViews();
            delete views[name];
            saveSavedViews(views);
            populateSavedViewsDropdown();
            deleteBtn.style.display = 'none';
            const toast = document.getElementById('toast');
            if (toast) {
                toast.textContent = `View "${name}" deleted`;
                toast.classList.add('show');
                setTimeout(() => toast.classList.remove('show'), 2000);
            }
        });
    }
}

/**
 * Initialize the application
 */
async function init() {
    initThemeListener();
    // Adapt timeline and story charts on theme change
    window.addEventListener('themechange', () => {
        adaptTimelineTheme();
        adaptStoryTheme();
    });
    await loadAppConfig(); // Load app config first (team name, email domain, etc.)

    // Wire chart click-to-filter drill-down
    setDrilldownCallback((filterType, value) => {
        if (addProgrammaticFilter(filterType, value)) {
            applyFilters(updateDashboard);
            // Brief toast notification
            const toast = document.getElementById('toast');
            if (toast) {
                toast.textContent = `Filtered by ${filterType}: ${value}`;
                toast.classList.add('show');
                setTimeout(() => toast.classList.remove('show'), 2000);
            }
        }
    });

    // Initialize goal targets
    if (window.GoalTargets) {
        window.GoalTargets.init('mm-sla-targets', {
            mttr_secs: 900,
            mttc_secs: 1800,
            response_sla_breaches: 0
        });
    }

    loadData();
    setupEventListeners();
    initTimeline();
    initStory();

    // Restore from shareable link hash
    if (window.location.hash && window.location.hash.length > 1) {
        try {
            const decoded = JSON.parse(atob(window.location.hash.substring(1)));
            restoreFilters(decoded);
        } catch (e) { /* invalid hash, ignore */ }
    }

    // Comparison mode
    if (window.ComparisonMode) {
        window.ComparisonMode.init({
            btnId: 'mmCompareBtn',
            barContainerId: 'mmComparisonBar',
            onActivate: function () { applyFilters(updateDashboard); },
            onDeactivate: function () {
                state.comparisonData = null;
                applyFilters(updateDashboard);
            }
        });
    }
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
