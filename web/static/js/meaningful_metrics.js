let allData = [];
let filteredData = [];
let currentSort = {column: null, direction: 'asc'};
let showAllRows = false; // pagination state: false = first 100, true = all

// Feature flags
const should_show_card_tooltips = false;
const should_show_delta_values = false;

// Column configuration with all available fields
const availableColumns = {
    // Primary fields (commonly used)
    'id': {label: 'ID', category: 'Primary', path: 'id', type: 'number'},
    'name': {label: 'Name', category: 'Primary', path: 'name', type: 'string'},
    'severity': {label: 'Severity', category: 'Primary', path: 'severity', type: 'number'},
    'status': {label: 'Status', category: 'Primary', path: 'status', type: 'number'},
    'type': {label: 'Type', category: 'Primary', path: 'type', type: 'string'},
    'created': {label: 'Created', category: 'Primary', path: 'created', type: 'date'},
    'closed': {label: 'Closed', category: 'Primary', path: 'closed', type: 'date'},
    'owner': {label: 'Owner', category: 'Primary', path: 'owner', type: 'string'},

    // Custom Fields (extracted to top-level by ticket_cache.py)
    'affected_country': {label: 'Country', category: 'Location', path: 'affected_country', type: 'string'},
    'affected_region': {label: 'Region', category: 'Location', path: 'affected_region', type: 'string'},
    'impact': {label: 'Impact', category: 'Assessment', path: 'impact', type: 'string'},
    'automation_level': {label: 'Automation Level', category: 'Process', path: 'automation_level', type: 'string'},

    // Calculated Fields (computed by ticket_cache.py)
    'is_open': {label: 'Is Open', category: 'Status', path: 'is_open', type: 'boolean'},
    'currently_aging_days': {label: 'Currently Aging (Days)', category: 'Timing', path: 'currently_aging_days', type: 'number'},
    'days_since_creation': {label: 'Days Since Creation', category: 'Timing', path: 'days_since_creation', type: 'number'},
    'resolution_time_days': {label: 'Resolution Time (Days)', category: 'Timing', path: 'resolution_time_days', type: 'number'},
    'resolution_bucket': {label: 'Resolution Bucket', category: 'Status', path: 'resolution_bucket', type: 'string'},
    'has_resolution_time': {label: 'Has Resolution Time', category: 'Status', path: 'has_resolution_time', type: 'boolean'},
    'age_category': {label: 'Age Category', category: 'Status', path: 'age_category', type: 'string'},
    'status_display': {label: 'Status Name', category: 'Display', path: 'status_display', type: 'string'},
    'severity_display': {label: 'Severity Name', category: 'Display', path: 'severity_display', type: 'string'},
    'created_display': {label: 'Created (MM/DD)', category: 'Display', path: 'created_display', type: 'string'},
    'closed_display': {label: 'Closed (MM/DD)', category: 'Display', path: 'closed_display', type: 'string'},

    // Additional useful fields
    'occurred': {label: 'Occurred', category: 'Timing', path: 'occurred', type: 'date'},
    'dueDate': {label: 'Due Date', category: 'Timing', path: 'dueDate', type: 'date'},
    'phase': {label: 'Phase', category: 'Process', path: 'phase', type: 'string'},
    'category': {label: 'Category', category: 'Classification', path: 'category', type: 'string'},
    'sourceInstance': {label: 'Source Instance', category: 'Technical', path: 'sourceInstance', type: 'string'},
    'openDuration': {label: 'Open Duration', category: 'Metrics', path: 'openDuration', type: 'number'},
    'timetorespond': {label: 'TTR', category: 'Metrics', path: 'time_to_respond_secs', type: 'duration'},
    'timetocontain': {label: 'TTC', category: 'Metrics', path: 'time_to_contain_secs', type: 'duration'},
    'notes': {label: 'User Notes', category: 'Investigation', path: 'notes', type: 'array'}
};

// Default visible columns and their order
let visibleColumns = ['id', 'name', 'severity', 'status', 'affected_country', 'impact', 'type', 'owner', 'created'];
let columnOrder = [...visibleColumns]; // Maintains the order of columns

// Ensure colorSchemes exists (was removed during refactor) before any chart functions use it
if (typeof window !== 'undefined' && !window.colorSchemes) {
    window.colorSchemes = {
        severity: ['#6c757d', '#28a745', '#ffc107', '#fd7e14', '#dc3545'],
        status: ['#ffc107', '#007bff', '#28a745', '#6c757d'],
        countries: ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'],
        sources: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FECA57', '#FF9FF3', '#54A0FF', '#5F27CD']
    };
}
const colorSchemes = window.colorSchemes; // local alias

// THEME / CHART LAYOUT HELPERS (added)
function isDarkMode() {
    return document.body.classList.contains('dark-mode');
}

function getChartColors() {
    if (!isDarkMode()) {
        // Light theme - dark text on light background
        return {
            font: '#1f2937', grid: 'rgba(148,163,184,0.3)', legendBg: 'rgba(255,255,255,0.95)', axisLine: '#6b7280'
        };
    }
    // Dark theme - light text on dark background
    return {
        font: '#e2e8f0', grid: 'rgba(148,163,184,0.18)', legendBg: 'rgba(30,41,59,0.85)', axisLine: '#475569'
    };
}

    function commonLayout(extra = {}) {
        const c = getChartColors();
        return Object.assign({
            font: {family: 'Segoe UI, sans-serif', size: 12, color: c.font},
            showlegend: true,
            legend: {bgcolor: c.legendBg, bordercolor: 'rgba(0,0,0,0)', borderwidth: 0},
            plot_bgcolor: 'rgba(0,0,0,0)',
            paper_bgcolor: 'rgba(0,0,0,0)',
            xaxis: {gridcolor: c.grid, linecolor: c.axisLine, zerolinecolor: c.grid},
            yaxis: {gridcolor: c.grid, linecolor: c.axisLine, zerolinecolor: c.grid},
            margin: {l: 60, r: 40, t: 40, b: 60}
        }, extra);
    }

// Replace previous themechange listener with smoother chart theme adaptation
// Remove any existing themechange listeners added earlier by guarding with a new handler
    window.addEventListener('themechange', () => {
        adaptAllChartsTheme();
    });

// Keep a shared config reference
    const sharedPlotlyConfig = {responsive: true, displayModeBar: true, displaylogo: false};

    function adaptAllChartsTheme() {
        const chartIds = ['geoChart', 'severityChart', 'timelineChart', 'ticketTypeChart', 'heatmapChart', 'funnelChart', 'topHostsChart', 'topUsersChart', 'resolutionTimeChart'];
        chartIds.forEach(id => adaptChartTheme(id));
    }

    function adaptChartTheme(chartId) {
        const el = document.getElementById(chartId);
        if (!el || !el.data || !el.layout) return; // Chart not rendered yet
        const c = getChartColors();

        // Clone layout shallowly to avoid mutating Plotly internal references unexpectedly
        const newLayout = JSON.parse(JSON.stringify(el.layout));
        newLayout.font = newLayout.font || {};
        newLayout.font.color = c.font;
        if (newLayout.legend) {
            newLayout.legend.bgcolor = c.legendBg;
        }
        // Axes (some charts like pie/funnel may not have axes)
        ['xaxis', 'yaxis'].forEach(axis => {
            if (newLayout[axis]) {
                newLayout[axis].gridcolor = c.grid;
                newLayout[axis].linecolor = c.axisLine;
                newLayout[axis].zerolinecolor = c.grid;
            }
        });

        // Clone data to update trace-level text colors (important for pie charts)
        const newData = JSON.parse(JSON.stringify(el.data));
        newData.forEach(trace => {
            // Update textfont color for pie charts and other charts with text labels
            if (trace.textfont && trace.textfont.color !== 'white') {
                trace.textfont.color = c.font;
            }
        });

        // Use Plotly.react for smoother transition; provide same data & config
        try {
            Plotly.react(el, newData, newLayout, sharedPlotlyConfig);
        } catch (e) {
            // Fallback: relayout if react fails
            try {
                Plotly.relayout(el, newLayout);
            } catch (_) {
            }
        }
    }

// Initialize dashboard
// Data freshness functions
    function updateDataTimestamp(dataGeneratedAt) {
        const timestampElement = document.getElementById('dataTimestamp');
        if (timestampElement) {
            if (dataGeneratedAt) {
                // Use the actual timestamp from the API
                const timestamp = new Date(dataGeneratedAt);
                const options = {
                    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true, timeZone: 'America/New_York', timeZoneName: 'short'
                };
                timestampElement.textContent = timestamp.toLocaleString('en-US', options);
            } else {
                // Fallback to previous behavior if timestamp not provided
                const today = new Date();
                const options = {
                    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true, timeZone: 'America/New_York', timeZoneName: 'short'
                };
                const todayAt1201 = new Date(today);
                todayAt1201.setHours(0, 1, 0, 0);
                timestampElement.textContent = todayAt1201.toLocaleString('en-US', options);
            }
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        loadData();
        setupEventListeners();
    });

    function setupEventListeners() {
        // Setup date range slider with tooltip
        setupSliderTooltip('dateRangeSlider', 'dateRangeTooltip', applyFilters);

        // Setup MTTR range slider with tooltip
        setupSliderTooltip('mttrRangeSlider', 'mttrRangeTooltip', applyFilters, formatMttrValue);

        // Setup MTTC range slider with tooltip
        setupSliderTooltip('mttcRangeSlider', 'mttcRangeTooltip', applyFilters, formatMttcValue);

        // Setup age range slider with tooltip
        setupSliderTooltip('ageRangeSlider', 'ageRangeTooltip', applyFilters, formatAgeValue);

        // Add listeners for existing severity, status, and automation checkboxes
        document.querySelectorAll('#severityFilter input, #statusFilter input, #automationFilter input').forEach(checkbox => {
            checkbox.addEventListener('change', applyFilters);
        });

        // Add listeners to date slider preset values for click functionality
        const dateContainer = document.getElementById('dateRangeSlider').parentElement;
        const dateSlider = document.getElementById('dateRangeSlider');
        if (dateContainer && dateSlider) {
            dateContainer.querySelectorAll('.range-preset').forEach(preset => {
                preset.addEventListener('click', function () {
                    const value = this.getAttribute('data-value');
                    dateSlider.value = value;
                    showSliderTooltip('dateRangeTooltip');
                    updateSliderLabels(value);
                    applyFilters();
                    // Hide tooltip after a brief delay when using presets
                    setTimeout(() => hideSliderTooltip('dateRangeTooltip'), 1000);
                });
            });
        }

        // Initialize date slider display
        const dateSliderInit = document.getElementById('dateRangeSlider');
        if (dateSliderInit) {
            updateSliderLabels(dateSliderInit.value);
        }

        // Add listeners to MTTR slider labels for click functionality
        const mttrContainer = document.getElementById('mttrRangeSlider').parentElement;
        const mttrSlider = document.getElementById('mttrRangeSlider');
        if (mttrContainer && mttrSlider) {
            mttrContainer.querySelectorAll('.slider-labels span').forEach(label => {
                label.addEventListener('click', function () {
                    const value = this.getAttribute('data-value');
                    mttrSlider.value = value;
                    showSliderTooltip('mttrRangeTooltip');
                    updateSliderTooltip('mttrRangeSlider', 'mttrRangeTooltip', value, formatMttrValue);
                    updateMttrSliderLabels(value);
                    applyFilters();
                    setTimeout(() => hideSliderTooltip('mttrRangeTooltip'), 1000);
                });
                label.style.cursor = 'pointer';
            });
        }

        // Add listeners to MTTC slider labels for click functionality
        const mttcContainer = document.getElementById('mttcRangeSlider').parentElement;
        const mttcSlider = document.getElementById('mttcRangeSlider');
        if (mttcContainer && mttcSlider) {
            mttcContainer.querySelectorAll('.slider-labels span').forEach(label => {
                label.addEventListener('click', function () {
                    const value = this.getAttribute('data-value');
                    mttcSlider.value = value;
                    showSliderTooltip('mttcRangeTooltip');
                    updateSliderTooltip('mttcRangeSlider', 'mttcRangeTooltip', value, formatMttcValue);
                    updateMttcSliderLabels(value);
                    applyFilters();
                    setTimeout(() => hideSliderTooltip('mttcRangeTooltip'), 1000);
                });
                label.style.cursor = 'pointer';
            });
        }

        // Add listeners to age slider preset values for click functionality
        const ageContainer = document.getElementById('ageRangeSlider').parentElement;
        const ageSlider = document.getElementById('ageRangeSlider');
        if (ageContainer && ageSlider) {
            ageContainer.querySelectorAll('.range-preset').forEach(preset => {
                preset.addEventListener('click', function () {
                    const value = this.getAttribute('data-value');
                    ageSlider.value = value;
                    showSliderTooltip('ageRangeTooltip');
                    updateSliderTooltip('ageRangeSlider', 'ageRangeTooltip', value, formatAgeValue);
                    updateAgeSliderLabels(value);
                    applyFilters();
                    setTimeout(() => hideSliderTooltip('ageRangeTooltip'), 1000);
                });
            });
        }

        // Update age slider labels when dragging the slider
        if (ageSlider) {
            ageSlider.addEventListener('input', function () {
                updateAgeSliderLabels(this.value);
            });
            // Initialize on page load
            updateAgeSliderLabels(ageSlider.value);
        }

        // Add listeners for sortable table headers
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', function () {
                const column = this.getAttribute('data-column');
                sortTable(column);
            });
            header.style.cursor = 'pointer';
        });

        // Load sort preferences from cookies
        loadSortPreferences();

        // Setup column selector
        setupColumnSelector();

        // Reset filters
        const resetBtn = document.getElementById('resetFiltersBtn');
        if (resetBtn && !resetBtn.dataset.bound) {
            resetBtn.addEventListener('click', resetFilters);
            resetBtn.dataset.bound = 'true';
        }
        // Export to Excel
        const exportExcelBtn = document.getElementById('exportExcelBtn');
        if (exportExcelBtn && !exportExcelBtn.dataset.bound) {
            exportExcelBtn.addEventListener('click', exportToExcel);
            exportExcelBtn.dataset.bound = 'true';
        }
        // Column selector open state persistence (applied after original setup)
        const dropdown = document.getElementById('columnSelectorDropdown');
        const btn = document.getElementById('columnSelectorBtn');
        if (btn && !btn.dataset.openStateBound) {
            btn.addEventListener('click', () => {
                const isOpen = dropdown.style.display === 'block';
                localStorage.setItem('mmColumnSelectorOpen', (!isOpen).toString());
            });
            btn.dataset.openStateBound = 'true';
        }
        document.addEventListener('click', (e) => {
            if (dropdown && btn && dropdown.style.display === 'block' && !dropdown.contains(e.target) && !btn.contains(e.target)) {
                localStorage.setItem('mmColumnSelectorOpen', 'false');
            }
        });
        // Select / Deselect all buttons (now without inline handlers)
        const selectAllBtn = document.getElementById('selectAllColumnsBtn');
        if (selectAllBtn && !selectAllBtn.dataset.bound) {
            selectAllBtn.addEventListener('click', selectAllColumns);
            selectAllBtn.dataset.bound = 'true';
        }
        const deselectAllBtn = document.getElementById('deselectAllColumnsBtn');
        if (deselectAllBtn && !deselectAllBtn.dataset.bound) {
            deselectAllBtn.addEventListener('click', deselectAllColumns);
            deselectAllBtn.dataset.bound = 'true';
        }

        // Restore column selector open state if previously open
        const savedOpen = localStorage.getItem('mmColumnSelectorOpen');
        if (savedOpen === 'true' && dropdown && btn) {
            dropdown.style.display = 'block';
            populateColumnSelector();
        }
    }

// Generic slider tooltip functions
    function updateSliderTooltip(sliderId, tooltipId, value, formatFunction = null) {
        const tooltip = document.getElementById(tooltipId);
        const slider = document.getElementById(sliderId);
        if (tooltip && slider) {
            // Use custom format function if provided, otherwise just show the value
            tooltip.textContent = formatFunction ? formatFunction(value) : value;

            // Calculate position based on slider value
            const min = parseInt(slider.min);
            const max = parseInt(slider.max);
            const val = parseInt(value);
            const percentage = ((val - min) / (max - min)) * 100;

            // Position tooltip above the thumb (accounting for thumb width)
            tooltip.style.left = `calc(${percentage}% + ${8 - percentage * 0.16}px)`;
        }
    }

    function showSliderTooltip(tooltipId) {
        const tooltip = document.getElementById(tooltipId);
        if (tooltip) {
            tooltip.style.display = 'block';
        }
    }

    function hideSliderTooltip(tooltipId) {
        const tooltip = document.getElementById(tooltipId);
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    }

    function setupSliderTooltip(sliderId, tooltipId, updateCallback, formatFunction = null) {
        const slider = document.getElementById(sliderId);
        if (!slider) return;

        // Show tooltip when user starts interacting
        slider.addEventListener('mousedown', () => showSliderTooltip(tooltipId));
        slider.addEventListener('touchstart', () => showSliderTooltip(tooltipId));

        // Hide tooltip when user stops interacting
        slider.addEventListener('mouseup', () => hideSliderTooltip(tooltipId));
        slider.addEventListener('touchend', () => hideSliderTooltip(tooltipId));
        slider.addEventListener('mouseleave', () => hideSliderTooltip(tooltipId));

        // Update tooltip during sliding
        slider.addEventListener('input', function () {
            showSliderTooltip(tooltipId);
            updateSliderTooltip(sliderId, tooltipId, this.value, formatFunction);
            if (updateCallback) updateCallback();
        });

        // Initialize the slider position (but keep tooltip hidden)
        updateSliderTooltip(sliderId, tooltipId, slider.value, formatFunction);
    }

// Format functions for different slider types
    function formatMttrValue(value) {
        const labels = ['All', '≤3', '>3', '>5'];
        return labels[value] || 'All';
    }

    function formatMttcValue(value) {
        const labels = ['All', '≤5', '≤15', '>15'];
        return labels[value] || 'All';
    }

    function formatAgeValue(value) {
        if (value == 0) return 'All';
        return value;
    }

// Legacy functions for date slider compatibility
    function updateSliderLabels(value) {
        updateSliderTooltip('dateRangeSlider', 'dateRangeTooltip', value);
    }

    function showDateSliderTooltip() {
        showSliderTooltip('dateRangeTooltip');
    }

    function hideDateSliderTooltip() {
        hideSliderTooltip('dateRangeTooltip');
    }

    function updateMttrSliderLabels(value) {
        const mttrContainer = document.getElementById('mttrRangeSlider').parentElement;
        mttrContainer.querySelectorAll('.slider-labels span').forEach(span => {
            span.classList.remove('active');
        });
        mttrContainer.querySelector(`.slider-labels span[data-value="${value}"]`).classList.add('active');
    }

    function updateMttcSliderLabels(value) {
        const mttcContainer = document.getElementById('mttcRangeSlider').parentElement;
        mttcContainer.querySelectorAll('.slider-labels span').forEach(span => {
            span.classList.remove('active');
        });
        mttcContainer.querySelector(`.slider-labels span[data-value="${value}"]`).classList.add('active');
    }

    function updateAgeSliderLabels(value) {
        const ageContainer = document.getElementById('ageRangeSlider').parentElement;
        if (!ageContainer) return;

        // Remove active class from all labels
        ageContainer.querySelectorAll('.slider-labels .range-preset').forEach(span => {
            span.classList.remove('active');
        });

        // Find the matching preset or closest one
        let matchingPreset = null;
        if (value == 0) {
            matchingPreset = ageContainer.querySelector('.slider-labels .range-preset[data-value="0"]');
        } else if (value >= 7 && value < 30) {
            matchingPreset = ageContainer.querySelector('.slider-labels .range-preset[data-value="7"]');
        } else if (value >= 30) {
            matchingPreset = ageContainer.querySelector('.slider-labels .range-preset[data-value="30"]');
        }

        // Add active class to matching preset
        if (matchingPreset) {
            matchingPreset.classList.add('active');
        }
    }

    async function loadData() {
        try {
            const response = await fetch('/api/meaningful-metrics/data');
            const result = await response.json();

            if (result.success) {
                allData = result.data;
                updateDataTimestamp(result.data_generated_at);
                populateFilterOptions();
                applyFilters();
                hideLoading();
            } else {
                showError('Failed to load data: ' + result.error);
            }
        } catch (error) {
            showError('Error loading data: ' + error.message);
        }
    }

    function populateFilterOptions() {
        // Populate filters with checkboxes
        const countries = [...new Set(allData.map(item => item.affected_country))].filter(c => c && c !== 'Unknown').sort();
        const regions = [...new Set(allData.map(item => item.affected_region))].filter(r => r && r !== 'Unknown').sort();
        const impacts = [...new Set(allData.map(item => item.impact))].filter(i => i && i !== 'Unknown').sort();
        const ticketTypes = [...new Set(allData.map(item => item.type))].filter(t => t && t !== 'Unknown').sort();
        const automationLevels = [...new Set(allData.map(item => item.automation_level))].filter(a => a && a !== 'Unknown').sort();

        // Add "No Country" option to countries list
        countries.unshift('No Country');

        // Add "No Region" option to regions list
        regions.unshift('No Region');

        // Add "No Impact" option to impacts list
        impacts.unshift('No Impact');

        // Add "No Level" option to automation levels list
        automationLevels.unshift('No Level');

        populateCheckboxFilter('countryFilter', countries);
        populateCheckboxFilter('regionFilter', regions);
        populateCheckboxFilter('impactFilter', impacts);
        populateCheckboxFilter('ticketTypeFilter', ticketTypes);
        populateCheckboxFilter('automationFilter', automationLevels);
    }

    function populateCheckboxFilter(filterId, options) {
        const container = document.getElementById(filterId);
        options.forEach(option => {
            const label = document.createElement('label');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.value = option;
            checkbox.addEventListener('change', applyFilters);

            // For ticket types, remove METCIRT prefix for display
            let displayText = option;
            if (filterId === 'ticketTypeFilter' && option.startsWith('METCIRT')) {
                displayText = option.replace(/^METCIRT[_\-\s]*/i, '');
            }

            label.appendChild(checkbox);
            label.appendChild(document.createTextNode(' ' + displayText));
            container.appendChild(label);
        });
    }

    function applyFilters() {
        const dateSlider = document.getElementById('dateRangeSlider');
        const dateRange = parseInt(dateSlider ? dateSlider.value : 30);

        const mttrSlider = document.getElementById('mttrRangeSlider');
        // Map slider positions to MTTR ranges: 0=All, 1=≤3mins, 2=>3mins, 3=>5mins
        const mttrFilter = parseInt(mttrSlider ? mttrSlider.value : 0);

        const mttcSlider = document.getElementById('mttcRangeSlider');
        // Map slider positions to MTTC ranges: 0=All, 1=≤5mins, 2=≤15mins, 3=>15mins
        const mttcFilter = parseInt(mttcSlider ? mttcSlider.value : 0);

        const ageSlider = document.getElementById('ageRangeSlider');
        // Age filter now uses continuous values: 0=All, 1-60=specific days
        const ageFilter = parseInt(ageSlider ? ageSlider.value : 0);

        const countries = Array.from(document.querySelectorAll('#countryFilter input:checked')).map(cb => cb.value);
        const regions = Array.from(document.querySelectorAll('#regionFilter input:checked')).map(cb => cb.value);
        const impacts = Array.from(document.querySelectorAll('#impactFilter input:checked')).map(cb => cb.value);
        const severities = Array.from(document.querySelectorAll('#severityFilter input:checked')).map(cb => cb.value);
        const ticketTypes = Array.from(document.querySelectorAll('#ticketTypeFilter input:checked')).map(cb => cb.value);
        const statuses = Array.from(document.querySelectorAll('#statusFilter input:checked')).map(cb => cb.value);
        const automationLevels = Array.from(document.querySelectorAll('#automationFilter input:checked')).map(cb => cb.value);

        // Update filter summary
        updateFilterSummary(dateRange, mttrFilter, mttcFilter, ageFilter, countries, regions, impacts, severities, ticketTypes, statuses, automationLevels);

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - dateRange);

        filteredData = allData.filter(item => {
            // Date filter - use pre-calculated days ago
            if (item.created_days_ago !== null && item.created_days_ago > dateRange) return false;

            // Location filters (countries and regions are mutually exclusive)
            if (countries.length > 0 || regions.length > 0) {
                let locationMatch = false;

                // Check countries if selected
                if (countries.length > 0) {
                    const hasNoCountry = !item.affected_country || item.affected_country === 'Unknown' || item.affected_country.trim() === '';
                    const shouldShowNoCountry = countries.includes('No Country') && hasNoCountry;
                    const shouldShowWithCountry = countries.some(c => c !== 'No Country' && c === item.affected_country);
                    locationMatch = shouldShowNoCountry || shouldShowWithCountry;
                }

                // Check regions if selected
                if (regions.length > 0) {
                    const hasNoRegion = !item.affected_region || item.affected_region === 'Unknown' || item.affected_region.trim() === '';
                    const shouldShowNoRegion = regions.includes('No Region') && hasNoRegion;
                    const shouldShowWithRegion = regions.some(r => r !== 'No Region' && r === item.affected_region);
                    locationMatch = shouldShowNoRegion || shouldShowWithRegion;
                }

                if (!locationMatch) return false;
            }
            if (impacts.length > 0) {
                const hasNoImpact = !item.impact || item.impact === 'Unknown' || item.impact.trim() === '';
                const shouldShowNoImpact = impacts.includes('No Impact') && hasNoImpact;
                const shouldShowWithImpact = impacts.some(i => i !== 'No Impact' && i === item.impact);

                if (!shouldShowNoImpact && !shouldShowWithImpact) return false;
            }
            if (severities.length > 0 && !severities.includes(item.severity.toString())) return false;
            if (ticketTypes.length > 0 && !ticketTypes.includes(item.type)) return false;
            if (statuses.length > 0 && !statuses.includes(item.status.toString())) return false;
            if (automationLevels.length > 0) {
                const hasNoLevel = !item.automation_level || item.automation_level === 'Unknown' || item.automation_level.trim() === '';
                const shouldShowNoLevel = automationLevels.includes('No Level') && hasNoLevel;
                const shouldShowWithLevel = automationLevels.some(l => l !== 'No Level' && l === item.automation_level);

                if (!shouldShowNoLevel && !shouldShowWithLevel) return false;
            }

            // MTTR filter
            if (mttrFilter > 0) {
                const mttrSeconds = item.time_to_respond_secs ? item.time_to_respond_secs : null;
                if (mttrSeconds === null || mttrSeconds === 0) return false; // Skip items without MTTR data

                if (mttrFilter === 1 && mttrSeconds > 180) return false; // ≤3 mins (180 seconds)
                if (mttrFilter === 2 && mttrSeconds <= 180) return false; // >3 mins
                if (mttrFilter === 3 && mttrSeconds <= 300) return false; // >5 mins (300 seconds)
            }

            // MTTC filter - only consider cases with host populated
            if (mttcFilter > 0) {
                if (!item.has_hostname) return false; // Skip items without host

                const mttcSeconds = item.time_to_contain_secs ? item.time_to_contain_secs : null;
                if (mttcSeconds === null || mttcSeconds === 0) return false; // Skip items without MTTC data

                if (mttcFilter === 1 && mttcSeconds > 300) return false; // ≤5 mins (300 seconds)
                if (mttcFilter === 2 && mttcSeconds > 900) return false; // ≤15 mins (900 seconds)
                if (mttcFilter === 3 && mttcSeconds <= 900) return false; // >15 mins (900 seconds)
            }

            // Age filter - when set (>0), include ONLY tickets whose currently_aging_days exists and is strictly greater
            if (ageFilter > 0) {
                if (item.currently_aging_days === null || item.currently_aging_days === undefined) return false; // exclude items without age
                if (Number(item.currently_aging_days) <= ageFilter) return false; // must be strictly greater than selected age
            }

            return true;
        });

        updateDashboard();
    }

    function updateFilterSummary(dateRange, mttrFilter, mttcFilter, ageFilter, countries, regions, impacts, severities, ticketTypes, statuses, automationLevels) {
        const container = document.getElementById('activeFiltersContainer');

        // Preserve non-removable filters
        const nonRemovableFilters = container.querySelectorAll('.filter-tag.non-removable');
        container.innerHTML = Array.from(nonRemovableFilters).map(filter => filter.outerHTML).join('');

        // Date range - no X button, use slider to change
        const dateText = `Created in Last ${dateRange} day${dateRange === 1 ? '' : 's'}`;

        container.innerHTML += `<span class="filter-tag">${dateText}</span>`;

        // MTTR filter
        if (mttrFilter > 0) {
            const mttrText = mttrFilter === 1 ? 'MTTR ≤3 mins' : mttrFilter === 2 ? 'MTTR >3 mins' : mttrFilter === 3 ? 'MTTR >5 mins' : 'All MTTR';
            container.innerHTML += `<span class="filter-tag">${mttrText} <button class="remove-filter-btn" onclick="removeFilter('mttr', '${mttrFilter}')">×</button></span>`;
        }

        // MTTC filter
        if (mttcFilter > 0) {
            const mttcText = mttcFilter === 1 ? 'MTTC ≤5 mins' : mttcFilter === 2 ? 'MTTC ≤15 mins' : mttcFilter === 3 ? 'MTTC >15 mins' : 'All MTTC';
            container.innerHTML += `<span class="filter-tag">${mttcText} <button class="remove-filter-btn" onclick="removeFilter('mttc', '${mttcFilter}')">×</button></span>`;
        }

        // Age filter
        if (ageFilter > 0) {
            const ageText = ageFilter === 1 ? 'Age >1 day' : `Age >${ageFilter} days`;
            container.innerHTML += `<span class="filter-tag">${ageText} <button class="remove-filter-btn" onclick="removeFilter('age', '${ageFilter}')">×</button></span>`;
        }

        // Add other filters if selected
        if (countries.length > 0) {
            countries.forEach(country => {
                container.innerHTML += `<span class="filter-tag">Country: ${country} <button class="remove-filter-btn" onclick="removeFilter('country', '${country}')">×</button></span>`;
            });
        }
        if (regions.length > 0) {
            regions.forEach(region => {
                container.innerHTML += `<span class="filter-tag">Region: ${region} <button class="remove-filter-btn" onclick="removeFilter('region', '${region}')">×</button></span>`;
            });
        }
        if (impacts.length > 0) {
            impacts.forEach(impact => {
                container.innerHTML += `<span class="filter-tag">Impact: ${impact} <button class="remove-filter-btn" onclick="removeFilter('impact', '${impact}')">×</button></span>`;
            });
        }
        if (severities.length > 0) {
            severities.forEach(severity => {
                const severityName = severity === '4' ? 'Critical' : severity === '3' ? 'High' : severity === '2' ? 'Medium' : severity === '1' ? 'Low' : 'Unknown';
                container.innerHTML += `<span class="filter-tag">Severity: ${severityName} <button class="remove-filter-btn" onclick="removeFilter('severity', '${severity}')">×</button></span>`;
            });
        }
        if (ticketTypes.length > 0) {
            ticketTypes.forEach(type => {
                const displayType = type.startsWith('METCIRT') ? type.replace(/^METCIRT[_\-\s]*/i, '') : type;
                container.innerHTML += `<span class="filter-tag">Type: ${displayType} <button class="remove-filter-btn" onclick="removeFilter('ticketType', '${type}')">×</button></span>`;
            });
        }
        if (statuses.length > 0) {
            statuses.forEach(status => {
                const statusName = status === '0' ? 'Pending' : status === '1' ? 'Active' : status === '2' ? 'Closed' : 'Unknown';
                container.innerHTML += `<span class="filter-tag">Status: ${statusName} <button class="remove-filter-btn" onclick="removeFilter('status', '${status}')">×</button></span>`;
            });
        }
        if (automationLevels.length > 0) {
            automationLevels.forEach(automation => {
                const displayAutomation = automation === 'Semi-Automated' ? 'Semi-Auto' : automation;
                container.innerHTML += `<span class="filter-tag">Automation: ${displayAutomation} <button class="remove-filter-btn" onclick="removeFilter('automation', '${automation}')">×</button></span>`;
            });
        }
    }

    function removeFilter(filterType, value) {
        if (filterType === 'country') {
            const checkbox = document.querySelector(`#countryFilter input[value="${value}"]`);
            if (checkbox) checkbox.checked = false;
        } else if (filterType === 'region') {
            const checkbox = document.querySelector(`#regionFilter input[value="${value}"]`);
            if (checkbox) checkbox.checked = false;
        } else if (filterType === 'impact') {
            const checkbox = document.querySelector(`#impactFilter input[value="${value}"]`);
            if (checkbox) checkbox.checked = false;
        } else if (filterType === 'severity') {
            const checkbox = document.querySelector(`#severityFilter input[value="${value}"]`);
            if (checkbox) checkbox.checked = false;
        } else if (filterType === 'ticketType') {
            const checkbox = document.querySelector(`#ticketTypeFilter input[value="${value}"]`);
            if (checkbox) checkbox.checked = false;
        } else if (filterType === 'status') {
            const checkbox = document.querySelector(`#statusFilter input[value="${value}"]`);
            if (checkbox) checkbox.checked = false;
        } else if (filterType === 'automation') {
            const checkbox = document.querySelector(`#automationFilter input[value="${value}"]`);
            if (checkbox) checkbox.checked = false;
        } else if (filterType === 'mttr') {
            const mttrSlider = document.getElementById('mttrRangeSlider');
            if (mttrSlider) {
                mttrSlider.value = 0;
                updateMttrSliderLabels(0);
            }
        } else if (filterType === 'mttc') {
            const mttcSlider = document.getElementById('mttcRangeSlider');
            if (mttcSlider) {
                mttcSlider.value = 0;
                updateMttcSliderLabels(0);
            }
        } else if (filterType === 'age') {
            const ageSlider = document.getElementById('ageRangeSlider');
            if (ageSlider) {
                ageSlider.value = 0;
                updateAgeSliderLabels(0);
            }
        }

        // Re-apply filters
        applyFilters();
    }

    function resetFilters() {
        // Reset date range slider to default (30 days)
        const dateSlider = document.getElementById('dateRangeSlider');
        if (dateSlider) {
            dateSlider.value = 30;
            updateSliderLabels(30);
        }

        // Reset MTTR range slider to default (All, position 0)
        const mttrSlider = document.getElementById('mttrRangeSlider');
        if (mttrSlider) {
            mttrSlider.value = 0;
            updateMttrSliderLabels(0);
        }

        // Reset MTTC range slider to default (All, position 0)
        const mttcSlider = document.getElementById('mttcRangeSlider');
        if (mttcSlider) {
            mttcSlider.value = 0;
            updateMttcSliderLabels(0);
        }

        // Reset age range slider to default (All, value 0)
        const ageSlider = document.getElementById('ageRangeSlider');
        if (ageSlider) {
            ageSlider.value = 0;
            updateSliderTooltip('ageRangeSlider', 'ageRangeTooltip', 0, formatAgeValue);
        }

        // Uncheck all checkboxes
        document.querySelectorAll('#countryFilter input, #impactFilter input, #severityFilter input, #ticketTypeFilter input, #statusFilter input, #automationFilter input').forEach(checkbox => {
            checkbox.checked = false;
        });

        // Re-apply filters
        applyFilters();
    }

    function updateDashboard() {
        updateMetrics();
        updateCharts();
        updateTable();
        showDashboard();
    }

    function calculatePeriodMetrics(data) {
        const totalIncidents = data.length;

        const responseSlaBreaches = data.filter(item => {
            return item.has_breached_response_sla === true;
        }).length;

        const containmentSlaBreaches = data.filter(item => {
            const hasHost = item.hostname && item.hostname.trim() !== '' && item.hostname !== 'Unknown';
            return hasHost && item.has_breached_containment_sla === true;
        }).length;

        const openIncidents = data.filter(item => item.is_open).length;

        // Calculate MTTR
        const casesWithOwnerAndTimeToRespond = data.filter(item => item.owner && item.owner.trim() !== '' && item.time_to_respond_secs && item.time_to_respond_secs > 0);
        const mttr = casesWithOwnerAndTimeToRespond.length > 0 ? casesWithOwnerAndTimeToRespond.reduce((sum, item) => sum + item.time_to_respond_secs, 0) / casesWithOwnerAndTimeToRespond.length : 0;

        // Calculate MTTC
        const casesWithOwnerAndTimeToContain = data.filter(item => item.has_hostname && item.time_to_contain_secs && item.time_to_contain_secs > 0);
        const mttc = casesWithOwnerAndTimeToContain.length > 0 ? casesWithOwnerAndTimeToContain.reduce((sum, item) => sum + item.time_to_contain_secs, 0) / casesWithOwnerAndTimeToContain.length : 0;

        const uniqueCountries = new Set(data.map(item => item.affected_country)).size;

        return {
            totalIncidents,
            responseSlaBreaches,
            containmentSlaBreaches,
            openIncidents,
            mttr,
            mttc,
            uniqueCountries,
            casesWithOwnerAndTimeToRespond: casesWithOwnerAndTimeToRespond.length,
            casesWithOwnerAndTimeToContain: casesWithOwnerAndTimeToContain.length
        };
    }

    function calculatePreviousPeriodMetrics() {
        // Get current date range setting
        const dateSlider = document.getElementById('dateRangeSlider');
        const dateRange = parseInt(dateSlider.value) || 30;

        // For longer periods (60, 90 days), we likely don't have enough historical data
        // Only show deltas for 7 and 30 day periods
        if (dateRange > 30) {
            return null; // No previous period comparison available
        }

        // Calculate previous period dates
        const now = new Date();
        const currentPeriodStart = new Date(now);
        currentPeriodStart.setDate(currentPeriodStart.getDate() - dateRange);

        const previousPeriodStart = new Date(currentPeriodStart);
        previousPeriodStart.setDate(previousPeriodStart.getDate() - dateRange);
        const previousPeriodEnd = currentPeriodStart;

        // Filter data for previous period
        const previousPeriodData = allData.filter(item => {
            const createdDate = new Date(item.created);
            return createdDate >= previousPeriodStart && createdDate < previousPeriodEnd;
        });

        // Only return metrics if we have reasonable data in the previous period
        if (previousPeriodData.length < 5) {
            return null; // Not enough data for meaningful comparison
        }

        return calculatePeriodMetrics(previousPeriodData);
    }

    function createDeltaBadge(currentValue, previousValue, isPercentage = false, reverse = false, isTime = false) {
        // Check feature flag
        if (!should_show_delta_values) {
            return '';
        }

        // No badge if no previous data available
        if (previousValue === null || previousValue === undefined) {
            return '';
        }

        // Handle zero values separately
        if (previousValue === 0) {
            return '';
        }

        const delta = currentValue - previousValue;
        const percentChange = (delta / previousValue) * 100;

        if (delta === 0) {
            const tooltipAttr = should_show_card_tooltips ? 'title="No change vs previous period"' : '';
            return `<span class="delta-badge neutral" ${tooltipAttr}>±0 vs prev</span>`;
        }

        const isImprovement = reverse ? delta < 0 : delta > 0;
        const badgeClass = isImprovement ? 'improvement' : 'regression';
        const sign = delta > 0 ? '+' : '';
        const direction = delta > 0 ? '↑' : '↓';

        // Format time values in min:sec format
        const formatTime = (seconds) => {
            if (seconds === 0) return '0:00';
            const mins = Math.floor(Math.abs(seconds) / 60);
            const secs = Math.round(Math.abs(seconds) % 60);
            return `${mins}:${secs.toString().padStart(2, '0')}`;
        };

        let displayValue, tooltipValue, previousDisplayValue;

        if (isTime) {
            displayValue = formatTime(delta);
            tooltipValue = `${sign}${formatTime(delta)}`;
            previousDisplayValue = formatTime(previousValue);
        } else {
            displayValue = Math.abs(delta).toLocaleString();
            tooltipValue = `${sign}${delta.toLocaleString()}`;
            previousDisplayValue = previousValue.toLocaleString();
        }

        const tooltipText = `Change vs previous period: ${tooltipValue} (${sign}${percentChange.toFixed(1)}%, was: ${previousDisplayValue})`;
        const tooltipAttr = should_show_card_tooltips ? `title="${tooltipText}"` : '';

        return `<span class="delta-badge ${badgeClass}" ${tooltipAttr}>${direction}${displayValue} vs prev</span>`;
    }

    function updateMetrics() {
        // Calculate current period metrics
        const currentMetrics = calculatePeriodMetrics(filteredData);

        // Calculate previous period metrics for comparison
        const previousMetrics = calculatePreviousPeriodMetrics();

        // Convert seconds to mins:secs format for display
        const formatTime = (seconds) => {
            if (seconds === 0) return '0:00';
            const mins = Math.floor(seconds / 60);
            const secs = Math.round(seconds % 60);
            return `${mins}:${secs.toString().padStart(2, '0')}`;
        };

        const mttrFormatted = formatTime(currentMetrics.mttr);
        const mttcFormatted = formatTime(currentMetrics.mttc);

        document.getElementById('metricsGrid').innerHTML = `
        <div class="metric-card">
            <div class="metric-title">🎫 Total Cases</div>
            <div class="metric-value">
                ${currentMetrics.totalIncidents.toLocaleString()}<br>
                ${createDeltaBadge(currentMetrics.totalIncidents, previousMetrics?.totalIncidents, false, true)}
            </div>
        </div>
        <div class="metric-card">
            <div class="metric-title">⏱️ MTTR (mins:secs)</div>
            <div class="metric-value">
                ${mttrFormatted}<br>
                ${createDeltaBadge(currentMetrics.mttr, previousMetrics?.mttr, false, true, true)}
            </div>
            <div class="metric-subtitle">${currentMetrics.casesWithOwnerAndTimeToRespond} cases acknowledged</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🔒 MTTC (mins:secs)</div>
            <div class="metric-value">
                ${mttcFormatted}<br>
                ${createDeltaBadge(currentMetrics.mttc, previousMetrics?.mttc, false, true, true)}
            </div>
            <div class="metric-subtitle">${currentMetrics.casesWithOwnerAndTimeToContain} cases with hostnames</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🚨 Response SLA Breaches</div>
            <div class="metric-value">
                ${currentMetrics.responseSlaBreaches.toLocaleString()}<br>
                ${createDeltaBadge(currentMetrics.responseSlaBreaches, previousMetrics?.responseSlaBreaches, false, true)}
            </div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🔒 Containment SLA Breaches</div>
            <div class="metric-value">
                ${currentMetrics.containmentSlaBreaches.toLocaleString()}<br>
                ${createDeltaBadge(currentMetrics.containmentSlaBreaches, previousMetrics?.containmentSlaBreaches, false, true)}
            </div>
        </div>
        <div class="metric-card">
            <div class="metric-title">📈 Open</div>
            <div class="metric-value">
                ${currentMetrics.openIncidents.toLocaleString()}<br>
                ${createDeltaBadge(currentMetrics.openIncidents, previousMetrics?.openIncidents, false, true)}
            </div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🌍 Total Countries</div>
            <div class="metric-value">
                ${currentMetrics.uniqueCountries}<br>
                ${createDeltaBadge(currentMetrics.uniqueCountries, previousMetrics?.uniqueCountries, false, true)}
            </div>
        </div>
    `;
    }


// Reusable Plotly helper to minimize flicker and reuse DOM
    function safePlot(chartId, data, layout, config = sharedPlotlyConfig) {
        const el = document.getElementById(chartId);
        if (!el) return;
        try {
            if (el.data && el.layout) {
                Plotly.react(el, data, layout, config);
            } else {
                Plotly.newPlot(el, data, layout, config);
            }
        } catch (e) {
            try {
                Plotly.newPlot(el, data, layout, config);
            } catch (_) {
            }
        }
    }

    function updateCharts() {
        const chartIds = ['geoChart', 'severityChart', 'timelineChart', 'ticketTypeChart', 'heatmapChart', 'funnelChart', 'topHostsChart', 'topUsersChart', 'resolutionTimeChart'];
        if (filteredData.length === 0) {
            // Mark all chart containers as empty with skeleton + watermark
            chartIds.forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    try {
                        if (el.data) Plotly.purge(el);
                    } catch (e) {
                    }
                    el.innerHTML = '';
                    const container = el.closest('.chart-container');
                    if (container) container.classList.add('empty');
                }
            });
            return;
        }
        // Remove empty state before drawing
        chartIds.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                const container = el.closest('.chart-container');
                if (container) container.classList.remove('empty');
            }
        });
        createGeoChart();
        createTicketTypeChart();
        createTimelineChart();
        createImpactChart();
        createOwnerChart();
        createFunnelChart();
        createTopHostsChart();
        createTopUsersChart();
        createResolutionTimeChart();
    }

// Re-implement createGeoChart with shared config
    createGeoChart = function () {
        const counts = {};
        filteredData.forEach(item => {
            const country = item.affected_country || 'Unknown';
            counts[country] = (counts[country] || 0) + 1;
        });
        const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
        const trace = {
            x: sortedEntries.map(e => e[1]),
            y: sortedEntries.map(e => e[0]),
            type: 'bar',
            orientation: 'h',
            marker: {color: colorSchemes.countries, line: {color: 'rgba(255,255,255,0.8)', width: 1}},
            hovertemplate: '<b>%{y}</b><br>Incidents: %{x}<extra></extra>'
        };
        const layout = commonLayout({margin: {l: 120, r: 40, t: 40, b: 40}, showlegend: false});
        safePlot('geoChart', [trace], layout);
    }

    function createTimelineChart() {
        const dailyInflow = {};
        const dailyOutflow = {};
        filteredData.forEach(item => {
            if (item.owner && item.owner.trim() !== '') {
                if (item.created && item.created.trim() !== '') {
                    const createdDate = new Date(item.created);
                    if (!isNaN(createdDate.getTime()) && createdDate.getFullYear() >= 2020) {
                        const date = createdDate.toISOString().split('T')[0];
                        dailyInflow[date] = (dailyInflow[date] || 0) + 1;
                    }
                }
                if (item.closed && item.closed.trim() !== '') {
                    const closedDate = new Date(item.closed);
                    if (!isNaN(closedDate.getTime()) && closedDate.getFullYear() >= 2020) {
                        const date = closedDate.toISOString().split('T')[0];
                        dailyOutflow[date] = (dailyOutflow[date] || 0) + 1;
                    }
                }
            }
        });
        const allDates = [...new Set([...Object.keys(dailyInflow), ...Object.keys(dailyOutflow)])].sort();
        const traces = [{
            x: allDates,
            y: allDates.map(d => dailyInflow[d] || 0),
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Inflow (Acknowledged by Analyst)',
            line: {color: '#007bff', width: 3},
            marker: {color: '#007bff', size: 6},
            hovertemplate: '<b>%{x}</b><br>Created: %{y}<extra></extra>'
        }, {
            x: allDates,
            y: allDates.map(d => dailyOutflow[d] || 0),
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Outflow (Closed by Analyst)',
            line: {color: '#28a745', width: 3},
            marker: {color: '#28a745', size: 6},
            hovertemplate: '<b>%{x}</b><br>Closed: %{y}<extra></extra>'
        }];
        const layout = commonLayout({
            legend: {x: 0.5, y: -0.2, xanchor: 'center', orientation: 'h'},
            margin: {l: 50, r: 10, t: 30, b: 40},
            yaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid},
            xaxis: {gridcolor: getChartColors().grid, tickangle: 90, tickformat: '%m/%d', dtick: 86400000 * 2}
        });
        safePlot('timelineChart', traces, layout, {responsive: true, displayModeBar: true, displaylogo: false});
    }

    function createImpactChart() {
        const counts = {};
        filteredData.forEach(item => {
            const impact = item.impact || 'Unknown';
            counts[impact] = (counts[impact] || 0) + 1;
        });
        const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
        const trace = {
            labels: sortedEntries.map(([impact]) => impact),
            values: sortedEntries.map(([, count]) => count),
            type: 'pie',
            hole: 0.3,
            marker: {colors: colorSchemes.countries, line: {color: 'white', width: 2}},
            textinfo: 'label+value',
            textfont: {size: 12, color: getChartColors().font},
            hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        };
        const layout = commonLayout({showlegend: false, margin: {l: 10, r: 10, t: 20, b: 20}});
        safePlot('ticketTypeChart', [trace], layout, {responsive: true, displayModeBar: true, displaylogo: false});
    }

    function createTicketTypeChart() {
        const counts = {};
        filteredData.forEach(item => {
            const ticketType = item.type || 'Unknown';
            counts[ticketType] = (counts[ticketType] || 0) + 1;
        });
        const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
        const trace = {
            labels: sortedEntries.map(([ticketType]) => ticketType.startsWith('METCIRT') ? ticketType.replace(/^METCIRT[_\-\s]*/i, '') : ticketType),
            values: sortedEntries.map(([, c]) => c),
            type: 'pie',
            hole: 0.6,
            marker: {colors: colorSchemes.sources, line: {color: 'white', width: 2}},
            textinfo: 'label+value',
            textfont: {size: 11, color: getChartColors().font},
            hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        };
        const layout = commonLayout({showlegend: false, margin: {l: 20, r: 20, t: 40, b: 40}});
        safePlot('severityChart', [trace], layout, {responsive: true, displayModeBar: true, displaylogo: false});
    }

    function createOwnerChart() {
        const counts = {};
        filteredData.forEach(item => {
            if (item.owner && item.owner.trim() !== '') {
                let owner = item.owner;
                if (owner.endsWith('@company.com')) owner = owner.replace('@company.com', '');
                counts[owner] = (counts[owner] || 0) + 1;
            }
        });
        const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
        const trace = {
            x: sortedEntries.map(([, count]) => count).reverse(),
            y: sortedEntries.map(([owner]) => owner).reverse(),
            type: 'bar',
            orientation: 'h',
            text: sortedEntries.map(([, count]) => count).reverse(),
            textposition: 'inside',
            textfont: {color: 'white', size: 12},
            marker: {
                color: sortedEntries.map((_, i) => colorSchemes.sources[i % colorSchemes.sources.length]).reverse(), line: {color: 'rgba(255,255,255,0.8)', width: 1}
            },
            hovertemplate: '<b>%{y}</b><br>Cases: %{x}<extra></extra>'
        };
        const layout = commonLayout({showlegend: false, margin: {l: 120, r: 40, t: 20, b: 40}, xaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid}, yaxis: {gridcolor: getChartColors().grid}});
        safePlot('heatmapChart', [trace], layout, {responsive: true, displayModeBar: true, displaylogo: false});
    }

    function createFunnelChart() {
        const totalCases = filteredData.length;
        const assignedCases = filteredData.filter(i => i.owner && i.owner.trim() !== '').length;
        const maliciousTruePositives = filteredData.filter(i => i.impact === 'Malicious True Positive').length;
        const trace = {
            type: 'funnel',
            y: ['All Cases', 'Assigned Cases', 'Malicious True Positive'],
            x: [totalCases, assignedCases, maliciousTruePositives],
            textinfo: 'value+percent initial',
            marker: {color: ['#4472C4', '#70AD47', '#C5504B'], line: {color: 'white', width: 2}},
            hovertemplate: '<b>%{y}</b><br>Count: %{x}<br>Percentage: %{percentInitial}<extra></extra>'
        };
        const layout = commonLayout({showlegend: false, margin: {l: 150, r: 40, t: 20, b: 40}});
        safePlot('funnelChart', [trace], layout, {responsive: true, displayModeBar: true, displaylogo: false});
    }

    let lastTableRowCount = null; // Tracks last announced row count for accessibility
    function updateTable() {
        const tbody = document.querySelector('#dataTable tbody');
        const tableSection = document.getElementById('dataTableSection');
        if (!tbody || !tableSection) return;

        // Empty state handling: show shimmer + NO DATA watermark (CSS already defined)
        if (filteredData.length === 0) {
            tbody.innerHTML = '';
            if (!tableSection.classList.contains('empty')) {
                tableSection.classList.add('empty');
            }
            if (lastTableRowCount !== 0) {
                announceTableStatus('No cases match the current filters. Adjust filters to see results.');
                lastTableRowCount = 0;
            }
            return; // Nothing else to render
        } else {
            tableSection.classList.remove('empty');
        }

        tbody.innerHTML = '';

        // Sort the filtered data before displaying
        const sortedData = sortData(filteredData);
        const total = filteredData.length;
        if (total <= 100 && showAllRows) {
            // Auto-reset if filters reduced total
            showAllRows = false;
        }
        const limit = showAllRows ? total : 100;
        const displayData = sortedData.slice(0, limit); // Limit to 100 rows for performance

        // Update table header with accurate counts
        const tableHeader = document.getElementById('tableHeader');
        if (tableHeader) {
            if (total === 0) {
                tableHeader.textContent = '📋 Case Details';
            } else if (displayData.length === total) {
                tableHeader.textContent = `📋 Case Details (showing all ${total} results)`;
            } else {
                tableHeader.textContent = `📋 Case Details (showing first ${displayData.length} of ${total} results)`;
            }
        }

        displayData.forEach(item => {
            const row = document.createElement('tr');

            // Use column order, but only show visible columns
            const orderedVisibleColumns = columnOrder.filter(col => visibleColumns.includes(col));

            orderedVisibleColumns.forEach(columnId => {
                const column = availableColumns[columnId];
                if (column) {
                    const td = document.createElement('td');
                    let value = getNestedValue(item, column.path);

                    // Format the value based on type
                    if (value !== null && value !== undefined) {
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
                                td.style.textAlign = 'right';
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
                                // Format array values (e.g., notes)
                                if (columnId === 'notes' && Array.isArray(value) && value.length > 0) {
                                    // Store notes data for modal
                                    const notesData = JSON.stringify(value.map(note => ({
                                        text: note.note_text || note.contents || '',
                                        author: note.author || note.user || 'Unknown',
                                        timestamp: note.created_at || (note.created ? new Date(note.created).toLocaleString() : '')
                                    })));

                                    // Show compact icon with count
                                    td.innerHTML = `<span class="notes-icon" data-notes='${notesData.replace(/'/g, '&#39;')}'>
                                                        📝 ${value.length}
                                                    </span>`;
                                    td.style.textAlign = 'center';
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
                                    const severityMap = {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'};
                                    const severity = severityMap[value] || 'Unknown';
                                    td.innerHTML = `<span class="severity-${severity.toLowerCase()}">${severity}</span>`;
                                } else if (columnId === 'status') {
                                    const statusMap = {0: 'Pending', 1: 'Active', 2: 'Closed'};
                                    const status = statusMap[value] || 'Unknown';
                                    td.innerHTML = `<span class="status-${status.toLowerCase()}">${status}</span>`;
                                } else if (columnId === 'currently_aging_days') {
                                    td.style.textAlign = 'center';
                                    if (value === null || value === undefined) {
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
                                if (columnId === 'name' && value.length > 50) {
                                    td.innerHTML = `<span title="${value}">${value.substring(0, 50)}...</span>`;
                                } else {
                                    td.textContent = value || '';
                                }
                        }
                    } else {
                        td.textContent = '';
                    }

                    row.appendChild(td);
                }
            });

            tbody.appendChild(row);
        });

        // Accessibility announcement only if count changed materially
        if (lastTableRowCount !== filteredData.length) {
            const total = filteredData.length;
            const shown = displayData.length;
            const msg = total > shown ? `Showing first ${shown} of ${total} cases.` : `Showing ${shown} case${shown === 1 ? '' : 's'}.`;
            announceTableStatus(msg);
            lastTableRowCount = filteredData.length;
        }

        // Attach event listeners to notes icons
        attachNotesModalListeners();
    }

    // Custom notes modal functionality
    let notesModal = null;

    function createNotesModal() {
        if (!notesModal) {
            notesModal = document.createElement('div');
            notesModal.className = 'notes-modal-overlay';
            notesModal.innerHTML = `
                <div class="notes-modal">
                    <div class="notes-modal-header">
                        <div class="notes-modal-title">📝 User Notes</div>
                        <button class="notes-modal-close" aria-label="Close">×</button>
                    </div>
                    <div class="notes-modal-body">
                        <table class="notes-table">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Note</th>
                                    <th>Author</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody id="notesTableBody"></tbody>
                        </table>
                    </div>
                </div>
            `;
            document.body.appendChild(notesModal);

            // Close button handler
            const closeBtn = notesModal.querySelector('.notes-modal-close');
            closeBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                hideNotesModal();
            });

            // Close on overlay click
            notesModal.addEventListener('click', function(e) {
                if (e.target === notesModal) {
                    hideNotesModal();
                }
            });

            // Close on Escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && notesModal.classList.contains('show')) {
                    hideNotesModal();
                }
            });
        }
        return notesModal;
    }

    function showNotesModal(notesData) {
        const modal = createNotesModal();
        const notes = JSON.parse(notesData);
        const tbody = modal.querySelector('#notesTableBody');

        // Build table rows
        tbody.innerHTML = notes.map((note, index) => `
            <tr>
                <td class="notes-table-number">${index + 1}</td>
                <td class="notes-table-text">${note.text}</td>
                <td class="notes-table-author">${note.author}</td>
                <td class="notes-table-timestamp">${note.timestamp}</td>
            </tr>
        `).join('');

        // Force positioning via inline styles
        modal.style.cssText = `
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            right: 0 !important;
            bottom: 0 !important;
            width: 100vw !important;
            height: 100vh !important;
            z-index: 10000 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            margin: 0 !important;
            padding: 20px !important;
            transform: none !important;
        `;

        // Show modal
        modal.classList.add('show');

        // Scroll to top of page so modal is visible
        window.scrollTo({
            top: 0,
            left: 0,
            behavior: 'smooth'
        });

        // Prevent body scroll when modal is open
        document.body.style.overflow = 'hidden';
    }

    function hideNotesModal() {
        if (notesModal) {
            notesModal.classList.remove('show');
            notesModal.style.display = 'none';
            document.body.style.overflow = '';
        }
    }

    function attachNotesModalListeners() {
        document.querySelectorAll('.notes-icon').forEach(icon => {
            icon.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                const notesData = this.getAttribute('data-notes');
                if (notesData) {
                    showNotesModal(notesData);
                }
            });
        });
    }

    // Export notes confirmation modal
    let exportNotesModal = null;
    let exportNotesResolve = null;

    function createExportNotesModal() {
        if (!exportNotesModal) {
            exportNotesModal = document.createElement('div');
            exportNotesModal.className = 'notes-modal-overlay export-notes-modal';
            exportNotesModal.innerHTML = `
                <div class="notes-modal export-confirmation-modal">
                    <div class="notes-modal-header">
                        <div class="notes-modal-title">📝 Include User Notes in Export?</div>
                        <button class="notes-modal-close" aria-label="Close">×</button>
                    </div>
                    <div class="notes-modal-body export-confirmation-body">
                        <div class="export-options-grid">
                            <div class="export-option-card export-with-notes">
                                <div class="export-card-icon">📝</div>
                                <div class="export-card-title">With Notes</div>
                                <div class="export-card-description">
                                    Fetch enriched notes from XSOAR API
                                </div>
                                <div class="export-card-timing">
                                    <span class="timing-icon">⏱️</span>
                                    <span class="timing-text">30-60 seconds</span>
                                </div>
                            </div>
                            <div class="export-option-card export-without-notes">
                                <div class="export-card-icon">⚡</div>
                                <div class="export-card-title">Without Notes</div>
                                <div class="export-card-description">
                                    Quick export with basic ticket data
                                </div>
                                <div class="export-card-timing">
                                    <span class="timing-icon">🚀</span>
                                    <span class="timing-text">Instant</span>
                                </div>
                            </div>
                        </div>
                        <div class="export-info-banner">
                            <span class="info-icon">ℹ️</span>
                            <span>Only filtered tickets will be enriched with notes</span>
                        </div>
                    </div>
                    <div class="export-modal-footer">
                        <button class="export-btn export-btn-cancel">
                            <span class="btn-icon">✕</span>
                            <span>Cancel</span>
                        </button>
                        <button class="export-btn export-btn-without">
                            <span class="btn-icon">⚡</span>
                            <span>Export Without Notes</span>
                        </button>
                        <button class="export-btn export-btn-with">
                            <span class="btn-icon">📝</span>
                            <span>Export With Notes</span>
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(exportNotesModal);

            // Close button handler
            const closeBtn = exportNotesModal.querySelector('.notes-modal-close');
            closeBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                hideExportNotesModal(null);
            });

            // Close on overlay click
            exportNotesModal.addEventListener('click', function(e) {
                if (e.target === exportNotesModal) {
                    hideExportNotesModal(null);
                }
            });

            // Close on Escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && exportNotesModal.classList.contains('show')) {
                    hideExportNotesModal(null);
                }
            });

            // Button handlers
            exportNotesModal.querySelector('.export-btn-cancel').addEventListener('click', function() {
                hideExportNotesModal(null);
            });

            exportNotesModal.querySelector('.export-btn-without').addEventListener('click', function() {
                hideExportNotesModal(false);
            });

            exportNotesModal.querySelector('.export-btn-with').addEventListener('click', function() {
                hideExportNotesModal(true);
            });

            // Card click handlers (make cards clickable)
            exportNotesModal.querySelector('.export-with-notes').addEventListener('click', function() {
                hideExportNotesModal(true);
            });

            exportNotesModal.querySelector('.export-without-notes').addEventListener('click', function() {
                hideExportNotesModal(false);
            });
        }
        return exportNotesModal;
    }

    function showExportNotesModal() {
        return new Promise((resolve) => {
            exportNotesResolve = resolve;
            const modal = createExportNotesModal();

            // Apply override styling for proper display
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                right: 0 !important;
                bottom: 0 !important;
                z-index: 10000 !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                margin: 0 !important;
                padding: 20px !important;
                transform: none !important;
            `;

            // Show modal
            modal.classList.add('show');

            // Scroll to top of page so modal is visible
            window.scrollTo({
                top: 0,
                left: 0,
                behavior: 'smooth'
            });

            // Prevent body scroll when modal is open
            document.body.style.overflow = 'hidden';
        });
    }

    function hideExportNotesModal(result) {
        if (exportNotesModal) {
            exportNotesModal.classList.remove('show');
            exportNotesModal.style.display = 'none';
            document.body.style.overflow = '';
            if (exportNotesResolve) {
                exportNotesResolve(result);
                exportNotesResolve = null;
            }
        }
    }

    function getCurrentFilters() {
        // Gather all current filter values
        const dateSlider = document.getElementById('dateRangeSlider');
        const mttrSlider = document.getElementById('mttrRangeSlider');
        const mttcSlider = document.getElementById('mttcRangeSlider');
        const ageSlider = document.getElementById('ageRangeSlider');

        return {
            dateRange: parseInt(dateSlider ? dateSlider.value : 30),
            mttrFilter: parseInt(mttrSlider ? mttrSlider.value : 0),
            mttcFilter: parseInt(mttcSlider ? mttcSlider.value : 0),
            ageFilter: parseInt(ageSlider ? ageSlider.value : 0),
            countries: Array.from(document.querySelectorAll('#countryFilter input:checked')).map(cb => cb.value),
            regions: Array.from(document.querySelectorAll('#regionFilter input:checked')).map(cb => cb.value),
            impacts: Array.from(document.querySelectorAll('#impactFilter input:checked')).map(cb => cb.value),
            severities: Array.from(document.querySelectorAll('#severityFilter input:checked')).map(cb => cb.value),
            ticketTypes: Array.from(document.querySelectorAll('#ticketTypeFilter input:checked')).map(cb => cb.value),
            statuses: Array.from(document.querySelectorAll('#statusFilter input:checked')).map(cb => cb.value),
            automationLevels: Array.from(document.querySelectorAll('#automationFilter input:checked')).map(cb => cb.value)
        };
    }

    async function exportToExcel() {
        // Use server-side export with filter parameters instead of sending full data
        try {
            // Ask user if they want to include notes (requires fetching from XSOAR API)
            const includeNotes = await showExportNotesModal();

            // If user clicked Cancel or closed the modal, abort export
            if (includeNotes === null) {
                return;
            }

            const exportBtn = document.getElementById('exportExcelBtn');
            const originalText = exportBtn.textContent;
            if (includeNotes) {
                exportBtn.textContent = '⏳ Exporting with notes (please wait)...';
            } else {
                exportBtn.textContent = '⏳ Exporting...';
            }
            exportBtn.disabled = true;

            // Build column labels mapping
            const columnLabels = {};
            visibleColumns.forEach(colId => {
                columnLabels[colId] = availableColumns[colId]?.label || colId;
            });

            // Get current filter parameters instead of sending all filtered data
            const filters = getCurrentFilters();

            const response = await fetch('/api/meaningful-metrics/export', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    filters: filters,
                    visible_columns: visibleColumns,
                    column_labels: columnLabels,
                    include_notes: includeNotes
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Export failed');
            }

            // Download the file
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_incidents.xlsx';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            exportBtn.textContent = originalText;
            exportBtn.disabled = false;
        } catch (error) {
            console.error('Export error:', error);
            alert('Failed to export: ' + error.message);
            const exportBtn = document.getElementById('exportExcelBtn');
            exportBtn.textContent = '📥 Export to Excel';
            exportBtn.disabled = false;
        }
    }

    function hideLoading() {
        document.getElementById('loading').style.display = 'none';
    }

    function showError(message) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('error').textContent = message;
        document.getElementById('error').style.display = 'block';
    }

    function showDashboard() {
        document.getElementById('metricsGrid').style.display = 'grid';
        document.getElementById('chartsGrid').style.display = 'grid';
        document.getElementById('dataTableSection').style.display = 'block';

        // Initialize table headers on first load
        buildTableHeaders();
    }

// Navigation functions


// Table sorting functions
    function sortTable(column) {
        if (currentSort.column === column) {
            currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
            currentSort.column = column;
            currentSort.direction = 'asc';
        }

        // Save sort preferences to cookies
        saveSortPreferences();

        // Update sort indicators
        updateSortIndicators();

        // Re-render table with sorted data
        updateTable();
    }

    function updateSortIndicators() {
        // Clear all sort indicators
        document.querySelectorAll('.sort-indicator').forEach(indicator => {
            indicator.textContent = '';
            indicator.parentElement.classList.remove('sort-asc', 'sort-desc');
        });

        // Set current sort indicator
        if (currentSort.column) {
            const header = document.querySelector(`[data-column="${currentSort.column}"]`);
            if (header) {
                const indicator = header.querySelector('.sort-indicator');
                indicator.textContent = currentSort.direction === 'asc' ? ' ▲' : ' ▼';
                header.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
            }
        }
    }

    function sortData(data) {
        if (!currentSort.column) return data;

        const column = availableColumns[currentSort.column];
        if (!column) return data;

        return [...data].sort((a, b) => {
            let aVal = getNestedValue(a, column.path);
            let bVal = getNestedValue(b, column.path);

            // Handle different data types
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
            if (aVal > bVal) comparison = 1; else if (aVal < bVal) comparison = -1;

            return currentSort.direction === 'asc' ? comparison : -comparison;
        });
    }

    function saveSortPreferences() {
        const preferences = {
            column: currentSort.column, direction: currentSort.direction
        };
        document.cookie = `tableSort=${JSON.stringify(preferences)}; path=/; max-age=${60 * 60 * 24 * 30}`; // 30 days
    }

    function loadSortPreferences() {
        const cookies = document.cookie.split(';');
        const sortCookie = cookies.find(cookie => cookie.trim().startsWith('tableSort='));

        if (sortCookie) {
            try {
                const preferences = JSON.parse(sortCookie.split('=')[1]);
                currentSort.column = preferences.column;
                currentSort.direction = preferences.direction;
                updateSortIndicators();
            } catch (e) {
                // Invalid cookie, ignore
            }
        }
    }

// Column selector functions
    function setupColumnSelector() {
        const btn = document.getElementById('columnSelectorBtn');
        const dropdown = document.getElementById('columnSelectorDropdown');

        // Load column preferences
        loadColumnPreferences();

        // Toggle dropdown
        btn.addEventListener('click', function (e) {
            e.stopPropagation();
            dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
            if (dropdown.style.display === 'block') {
                populateColumnSelector();
            }
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', function (e) {
            if (!dropdown.contains(e.target) && !btn.contains(e.target)) {
                dropdown.style.display = 'none';
            }
        });
    }

    function populateColumnSelector() {
        const container = document.getElementById('columnCheckboxes');
        container.innerHTML = '';

        // Group columns by category
        const categories = {};
        Object.keys(availableColumns).forEach(columnId => {
            const column = availableColumns[columnId];
            if (!categories[column.category]) {
                categories[column.category] = [];
            }
            categories[column.category].push({id: columnId, ...column});
        });

        // Create checkboxes grouped by category
        Object.keys(categories).sort().forEach(categoryName => {
            // Category header
            const categoryHeader = document.createElement('div');
            categoryHeader.className = 'column-category-header';
            categoryHeader.innerHTML = `<strong>${categoryName}</strong>`;
            categoryHeader.style.gridColumn = '1 / -1';
            categoryHeader.style.marginTop = '10px';
            categoryHeader.style.marginBottom = '5px';
            categoryHeader.style.fontSize = '13px';
            categoryHeader.style.color = '#666';
            container.appendChild(categoryHeader);

            categories[categoryName].forEach(column => {
                const item = document.createElement('div');
                item.className = 'column-checkbox-item';

                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.id = `col-${column.id}`;
                checkbox.checked = visibleColumns.includes(column.id);

                // Disable ID and Name checkboxes - they cannot be unchecked
                const isRequired = column.id === 'id' || column.id === 'name';
                if (isRequired) {
                    checkbox.disabled = true;
                    checkbox.checked = true;
                    if (!visibleColumns.includes(column.id)) {
                        visibleColumns.push(column.id);
                    }
                }

                checkbox.addEventListener('change', function () {
                    if (!isRequired) {
                        toggleColumn(column.id, this.checked);
                    }
                });

                const label = document.createElement('label');
                label.htmlFor = `col-${column.id}`;
                label.textContent = column.label + (isRequired ? ' (Required)' : '');
                if (isRequired) {
                    label.style.color = '#6c757d';
                    label.style.fontStyle = 'italic';
                }

                item.appendChild(checkbox);
                item.appendChild(label);
                container.appendChild(item);
            });
        });

        // Populate column order list
        populateColumnOrder();
    }

    function populateColumnOrder() {
        const container = document.getElementById('columnOrderList');
        container.innerHTML = '';

        // Show only visible columns in order
        const orderedVisibleColumns = columnOrder.filter(col => visibleColumns.includes(col));

        orderedVisibleColumns.forEach((columnId, index) => {
            const column = availableColumns[columnId];
            if (column) {
                const item = document.createElement('div');
                item.className = 'column-order-item';
                item.draggable = true;
                item.dataset.columnId = columnId;
                item.dataset.index = index;

                item.innerHTML = `
                <span class="drag-handle">⋮⋮</span>
                <span class="column-order-label">${column.label}</span>
            `;

                // Add drag event listeners
                item.addEventListener('dragstart', handleDragStart);
                item.addEventListener('dragover', handleDragOver);
                item.addEventListener('drop', handleDrop);
                item.addEventListener('dragend', handleDragEnd);

                container.appendChild(item);
            }
        });
    }

    function toggleColumn(columnId, isVisible) {
        if (isVisible && !visibleColumns.includes(columnId)) {
            visibleColumns.push(columnId);
            // Add to column order if not present
            if (!columnOrder.includes(columnId)) {
                columnOrder.push(columnId);
            }
        } else if (!isVisible && visibleColumns.includes(columnId)) {
            visibleColumns = visibleColumns.filter(id => id !== columnId);
        }

        // Save preferences and rebuild table
        saveColumnPreferences();
        rebuildTable();
        populateColumnOrder();
    }

    function selectAllColumns() {
        visibleColumns = Object.keys(availableColumns);
        columnOrder = [...visibleColumns];
        populateColumnSelector();
        saveColumnPreferences();
        rebuildTable();
    }

    function deselectAllColumns() {
        // Keep required columns (id and name)
        visibleColumns = ['id', 'name'];
        populateColumnSelector();
        saveColumnPreferences();
        rebuildTable();
    }

// Drag and drop handlers
    let draggedElement = null;

    function handleDragStart(e) {
        draggedElement = this;
        this.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/html', this.outerHTML);
    }

    function handleDragOver(e) {
        if (e.preventDefault) {
            e.preventDefault();
        }
        e.dataTransfer.dropEffect = 'move';

        // Add visual feedback
        this.classList.add('drag-over');
        return false;
    }

    function handleDrop(e) {
        if (e.stopPropagation) {
            e.stopPropagation();
        }

        if (draggedElement !== this) {
            const draggedIndex = parseInt(draggedElement.dataset.index);
            const targetIndex = parseInt(this.dataset.index);
            const draggedColumnId = draggedElement.dataset.columnId;

            // Remove dragged column from its current position in order
            const currentOrderIndex = columnOrder.indexOf(draggedColumnId);
            if (currentOrderIndex !== -1) {
                columnOrder.splice(currentOrderIndex, 1);
            }

            // Insert at new position
            const visibleOrderedColumns = columnOrder.filter(col => visibleColumns.includes(col));
            const targetColumnId = this.dataset.columnId;
            const newTargetIndex = columnOrder.indexOf(targetColumnId);

            if (draggedIndex < targetIndex) {
                columnOrder.splice(newTargetIndex + 1, 0, draggedColumnId);
            } else {
                columnOrder.splice(newTargetIndex, 0, draggedColumnId);
            }

            // Update UI and save
            populateColumnOrder();
            saveColumnPreferences();
            rebuildTable();
        }

        // Clean up drag over styles
        document.querySelectorAll('.drag-over').forEach(el => {
            el.classList.remove('drag-over');
        });

        return false;
    }

    function handleDragEnd(e) {
        this.classList.remove('dragging');
        document.querySelectorAll('.drag-over').forEach(el => {
            el.classList.remove('drag-over');
        });
        draggedElement = null;
    }

    function saveColumnPreferences() {
        const preferences = {
            visibleColumns: visibleColumns, columnOrder: columnOrder
        };
        document.cookie = `tableColumns=${JSON.stringify(preferences)}; path=/; max-age=${60 * 60 * 24 * 30}`; // 30 days
    }

    function loadColumnPreferences() {
        const cookies = document.cookie.split(';');
        const columnCookie = cookies.find(cookie => cookie.trim().startsWith('tableColumns='));

        if (columnCookie) {
            try {
                const preferences = JSON.parse(columnCookie.split('=')[1]);
                if (preferences.visibleColumns) {
                    visibleColumns = preferences.visibleColumns;
                }
                if (preferences.columnOrder) {
                    columnOrder = preferences.columnOrder;
                }
            } catch (e) {
                // Invalid cookie, ignore
            }
        }
    }

    function getNestedValue(obj, path) {
        return path.split('.').reduce((current, key) => {
            return current && current[key] !== undefined ? current[key] : null;
        }, obj);
    }

    function rebuildTable() {
        buildTableHeaders();
        updateTable();
    }

    function buildTableHeaders() {
        const thead = document.querySelector('#dataTable thead tr');
        thead.innerHTML = '';

        // Use column order, but only show visible columns
        const orderedVisibleColumns = columnOrder.filter(col => visibleColumns.includes(col));

        orderedVisibleColumns.forEach(columnId => {
            const column = availableColumns[columnId];
            if (column) {
                const th = document.createElement('th');
                th.className = 'sortable';
                th.setAttribute('data-column', columnId);
                th.innerHTML = `${column.label} <span class="sort-indicator"></span>`;
                th.style.cursor = 'pointer';
                if (column.type === 'duration') {
                    th.style.textAlign = 'right';
                    th.classList.add('duration-column');
                    th.title = 'mins:secs';
                    th.innerHTML = `${column.label} ℹ️ <span class="sort-indicator"></span>`;
                }
                th.addEventListener('click', function () {
                    sortTable(columnId);
                });
                thead.appendChild(th);
            }
        });

        // Update sort indicators after rebuilding headers
        updateSortIndicators();
    }

// Location Filter Tab Functionality
    function initLocationTabs() {
        const tabButtons = document.querySelectorAll('.tab-button');

        tabButtons.forEach(button => {
            button.addEventListener('click', function () {
                const targetTab = this.getAttribute('data-tab');

                // Remove active class from all buttons and panes
                tabButtons.forEach(btn => btn.classList.remove('active'));
                document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

                // Add active class to clicked button and corresponding pane
                this.classList.add('active');
                document.getElementById(targetTab + 'Tab').classList.add('active');

                // Clear selections in the other tab (mutual exclusion)
                if (targetTab === 'country') {
                    // Clear region selections
                    document.querySelectorAll('#regionFilter input[type="checkbox"]').forEach(checkbox => {
                        checkbox.checked = false;
                    });
                } else if (targetTab === 'region') {
                    // Clear country selections
                    document.querySelectorAll('#countryFilter input[type="checkbox"]').forEach(checkbox => {
                        checkbox.checked = false;
                    });
                }

                // Update filters
                applyFilters();
            });
        });
    }

// Initialize location tabs when DOM is loaded
    document.addEventListener('DOMContentLoaded', function () {
        initLocationTabs();
    });

    function announceTableStatus(message) {
        const live = document.getElementById('tableStatusLive');
        if (!live) return;
        // Clear then set so screen readers announce updates reliably
        live.textContent = '';
        // Slight delay to ensure DOM mutation is recognized
        setTimeout(() => {
            live.textContent = message;
        }, 40);
    }

    function createTopHostsChart() {
        const counts = {};
        filteredData.forEach(item => {
            const hostname = item.hostname || 'Unknown';
            if (hostname && hostname.trim() !== '' && hostname !== 'Unknown') {
                counts[hostname] = (counts[hostname] || 0) + 1;
            }
        });
        const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);

        if (sortedEntries.length === 0) {
            const el = document.getElementById('topHostsChart');
            if (el) {
                try {
                    if (el.data) Plotly.purge(el);
                } catch (e) {}
                el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No hostname data available</div>';
            }
            return;
        }

        const trace = {
            x: sortedEntries.map(e => e[1]).reverse(),
            y: sortedEntries.map(e => e[0]).reverse(),
            type: 'bar',
            orientation: 'h',
            text: sortedEntries.map(e => e[1]).reverse(),
            textposition: 'inside',
            textfont: {color: 'white', size: 12},
            marker: {
                color: sortedEntries.map((_, i) => colorSchemes.countries[i % colorSchemes.countries.length]).reverse(),
                line: {color: 'rgba(255,255,255,0.8)', width: 1}
            },
            hovertemplate: '<b>%{y}</b><br>Tickets: %{x}<extra></extra>'
        };
        const layout = commonLayout({margin: {l: 200, r: 40, t: 40, b: 40}, showlegend: false});
        safePlot('topHostsChart', [trace], layout);
    }

    function createTopUsersChart() {
        const counts = {};
        filteredData.forEach(item => {
            const username = item.username || 'Unknown';
            if (username && username.trim() !== '' && username !== 'Unknown') {
                counts[username] = (counts[username] || 0) + 1;
            }
        });
        const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);

        if (sortedEntries.length === 0) {
            const el = document.getElementById('topUsersChart');
            if (el) {
                try {
                    if (el.data) Plotly.purge(el);
                } catch (e) {}
                el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No username data available</div>';
            }
            return;
        }

        const trace = {
            x: sortedEntries.map(e => e[1]).reverse(),
            y: sortedEntries.map(e => e[0]).reverse(),
            type: 'bar',
            orientation: 'h',
            text: sortedEntries.map(e => e[1]).reverse(),
            textposition: 'inside',
            textfont: {color: 'white', size: 12},
            marker: {
                color: sortedEntries.map((_, i) => colorSchemes.severity[i % colorSchemes.severity.length]).reverse(),
                line: {color: 'rgba(255,255,255,0.8)', width: 1}
            },
            hovertemplate: '<b>%{y}</b><br>Tickets: %{x}<extra></extra>'
        };
        const layout = commonLayout({margin: {l: 120, r: 40, t: 40, b: 40}, showlegend: false});
        safePlot('topUsersChart', [trace], layout);
    }

    function createResolutionTimeChart() {
        const typeResolutionData = {};

        filteredData.forEach(item => {
            const ticketType = item.type || 'Unknown';
            if (item.resolution_time_days !== null && item.resolution_time_days !== undefined && item.resolution_time_days > 0) {
                if (!typeResolutionData[ticketType]) {
                    typeResolutionData[ticketType] = [];
                }
                typeResolutionData[ticketType].push(item.resolution_time_days);
            }
        });

        const typeAverages = {};
        Object.keys(typeResolutionData).forEach(type => {
            const times = typeResolutionData[type];
            if (times.length > 0) {
                const average = times.reduce((sum, time) => sum + time, 0) / times.length;
                typeAverages[type] = average;
            }
        });

        const sortedEntries = Object.entries(typeAverages).sort((a, b) => b[1] - a[1]).slice(0, 10);

        if (sortedEntries.length === 0) {
            const el = document.getElementById('resolutionTimeChart');
            if (el) {
                try {
                    if (el.data) Plotly.purge(el);
                } catch (e) {}
                el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No resolution time data available</div>';
            }
            return;
        }

        const trace = {
            x: sortedEntries.map(e => e[1].toFixed(1)).reverse(),
            y: sortedEntries.map(([type]) => type.startsWith('METCIRT') ? type.replace(/^METCIRT[_\-\s]*/i, '') : type).reverse(),
            type: 'bar',
            orientation: 'h',
            text: sortedEntries.map(e => e[1].toFixed(1)).reverse(),
            textposition: 'inside',
            textfont: {color: 'white', size: 12},
            marker: {
                color: sortedEntries.map((_, i) => colorSchemes.sources[i % colorSchemes.sources.length]).reverse(),
                line: {color: 'rgba(255,255,255,0.8)', width: 1}
            },
            hovertemplate: '<b>%{y}</b><br>Avg Resolution: %{x} days<extra></extra>'
        };
        const layout = commonLayout({
            margin: {l: 150, r: 40, t: 40, b: 40},
            showlegend: false,
            xaxis: {title: 'Average Resolution Time (Days)', gridcolor: getChartColors().grid}
        });
        safePlot('resolutionTimeChart', [trace], layout);
    }

