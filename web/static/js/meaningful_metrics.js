let allData = [];
let filteredData = [];
let currentSort = {column: null, direction: 'asc'};

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

    // Custom Fields (from data analysis)
    'affected_country': {label: 'Country', category: 'Location', path: 'affected_country', type: 'string'},
    'affected_region': {label: 'Region', category: 'Location', path: 'CustomFields.affectedregion', type: 'string'},
    'impact': {label: 'Impact', category: 'Assessment', path: 'impact', type: 'string'},
    'contained': {label: 'Contained', category: 'Status', path: 'CustomFields.contained', type: 'string'},
    'automation': {label: 'Automation Level', category: 'Process', path: 'CustomFields.automation', type: 'string'},
    'escalation_state': {label: 'Escalation State', category: 'Process', path: 'CustomFields.escalationstate', type: 'string'},
    'source': {label: 'Source', category: 'Detection', path: 'CustomFields.source', type: 'string'},
    'threat_type': {label: 'Threat Type', category: 'Assessment', path: 'CustomFields.threattype', type: 'string'},
    'root_cause': {label: 'Root Cause', category: 'Assessment', path: 'CustomFields.rootcause', type: 'string'},
    'breach_confirmation': {label: 'Breach Confirmation', category: 'Assessment', path: 'CustomFields.breachconfirmation', type: 'string'},

    // Additional useful fields
    'occurred': {label: 'Occurred', category: 'Timing', path: 'occurred', type: 'date'},
    'dueDate': {label: 'Due Date', category: 'Timing', path: 'dueDate', type: 'date'},
    'phase': {label: 'Phase', category: 'Process', path: 'phase', type: 'string'},
    'category': {label: 'Category', category: 'Classification', path: 'category', type: 'string'},
    'sourceInstance': {label: 'Source Instance', category: 'Technical', path: 'sourceInstance', type: 'string'},
    'openDuration': {label: 'Open Duration', category: 'Metrics', path: 'openDuration', type: 'number'},
    'timetorespond': {label: 'TTR (mins)', category: 'Metrics', path: 'timetorespond.totalDuration', type: 'duration'},
    'timetocontain': {label: 'TTC (mins)', category: 'Metrics', path: 'timetocontain.totalDuration', type: 'duration'}
};

// Default visible columns and their order
let visibleColumns = ['id', 'name', 'severity', 'status', 'affected_country', 'impact', 'type', 'owner', 'created'];
let columnOrder = [...visibleColumns]; // Maintains the order of columns

// Color schemes for consistent theming
const colorSchemes = {
    severity: ['#6c757d', '#28a745', '#ffc107', '#fd7e14', '#dc3545'],
    status: ['#ffc107', '#007bff', '#28a745', '#6c757d'],
    countries: ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'],
    sources: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FECA57', '#FF9FF3', '#54A0FF', '#5F27CD']
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function () {
    loadData();
    setupEventListeners();
});

function setupEventListeners() {
    // Add listener for date range slider
    const dateSlider = document.getElementById('dateRangeSlider');
    if (dateSlider) {
        dateSlider.addEventListener('input', function () {
            updateSliderLabels(this.value);
            applyFilters();
        });
    }

    // Add listener for MTTR range slider
    const mttrSlider = document.getElementById('mttrRangeSlider');
    if (mttrSlider) {
        mttrSlider.addEventListener('input', function () {
            updateMttrSliderLabels(this.value);
            applyFilters();
        });
    }

    // Add listener for MTTC range slider
    const mttcSlider = document.getElementById('mttcRangeSlider');
    if (mttcSlider) {
        mttcSlider.addEventListener('input', function () {
            updateMttcSliderLabels(this.value);
            applyFilters();
        });
    }

    // Add listener for age range slider
    const ageSlider = document.getElementById('ageRangeSlider');
    if (ageSlider) {
        ageSlider.addEventListener('input', function () {
            updateAgeSliderLabels(this.value);
            applyFilters();
        });
    }

    // Add listeners for existing severity, status, and automation checkboxes
    document.querySelectorAll('#severityFilter input, #statusFilter input, #automationFilter input').forEach(checkbox => {
        checkbox.addEventListener('change', applyFilters);
    });

    // Add listeners to date slider labels for click functionality
    const dateContainer = document.getElementById('dateRangeSlider').parentElement;
    dateContainer.querySelectorAll('.slider-labels span').forEach(label => {
        label.addEventListener('click', function () {
            const value = this.getAttribute('data-value');
            dateSlider.value = value;
            updateSliderLabels(value);
            applyFilters();
        });
        label.style.cursor = 'pointer';
    });

    // Add listeners to MTTR slider labels for click functionality
    const mttrContainer = document.getElementById('mttrRangeSlider').parentElement;
    mttrContainer.querySelectorAll('.slider-labels span').forEach(label => {
        label.addEventListener('click', function () {
            const value = this.getAttribute('data-value');
            mttrSlider.value = value;
            updateMttrSliderLabels(value);
            applyFilters();
        });
        label.style.cursor = 'pointer';
    });

    // Add listeners to MTTC slider labels for click functionality
    const mttcContainer = document.getElementById('mttcRangeSlider').parentElement;
    mttcContainer.querySelectorAll('.slider-labels span').forEach(label => {
        label.addEventListener('click', function () {
            const value = this.getAttribute('data-value');
            mttcSlider.value = value;
            updateMttcSliderLabels(value);
            applyFilters();
        });
        label.style.cursor = 'pointer';
    });

    // Add listeners to age slider labels for click functionality
    const ageContainer = document.getElementById('ageRangeSlider').parentElement;
    ageContainer.querySelectorAll('.slider-labels span').forEach(label => {
        label.addEventListener('click', function () {
            const value = this.getAttribute('data-value');
            ageSlider.value = value;
            updateAgeSliderLabels(value);
            applyFilters();
        });
        label.style.cursor = 'pointer';
    });

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
}

function updateSliderLabels(value) {
    const dateContainer = document.getElementById('dateRangeSlider').parentElement;
    dateContainer.querySelectorAll('.slider-labels span').forEach(span => {
        span.classList.remove('active');
    });
    dateContainer.querySelector(`.slider-labels span[data-value="${value}"]`).classList.add('active');
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
    ageContainer.querySelectorAll('.slider-labels span').forEach(span => {
        span.classList.remove('active');
    });
    ageContainer.querySelector(`.slider-labels span[data-value="${value}"]`).classList.add('active');
}

async function loadData() {
    try {
        const response = await fetch('/api/meaningful-metrics/data');
        const result = await response.json();

        if (result.success) {
            allData = result.data;
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
    const impacts = [...new Set(allData.map(item => item.impact))].filter(i => i && i !== 'Unknown').sort();
    const ticketTypes = [...new Set(allData.map(item => item.type))].filter(t => t && t !== 'Unknown').sort();
    const automationLevels = [...new Set(allData.map(item => item.automation_level))].filter(a => a && a !== 'Unknown').sort();

    // Add "No Country" option to countries list
    countries.unshift('No Country');

    // Add "No Impact" option to impacts list
    impacts.unshift('No Impact');

    // Add "No Level" option to automation levels list
    automationLevels.unshift('No Level');

    populateCheckboxFilter('countryFilter', countries);
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
    const sliderValue = parseInt(dateSlider ? dateSlider.value : 1);
    // Map slider positions to days: 0=7, 1=30, 2=60, 3=90
    const dateRange = [7, 30, 60, 90][sliderValue] || 30;

    const mttrSlider = document.getElementById('mttrRangeSlider');
    const mttrValue = parseInt(mttrSlider ? mttrSlider.value : 0);
    // Map slider positions to MTTR ranges: 0=All, 1=≤3mins, 2=>3mins, 3=>5mins
    const mttrFilter = mttrValue;

    const mttcSlider = document.getElementById('mttcRangeSlider');
    const mttcValue = parseInt(mttcSlider ? mttcSlider.value : 0);
    // Map slider positions to MTTC ranges: 0=All, 1=≤5mins, 2=≤15mins, 3=>15mins
    const mttcFilter = mttcValue;

    const ageSlider = document.getElementById('ageRangeSlider');
    const ageValue = parseInt(ageSlider ? ageSlider.value : 0);
    // Map slider positions to age ranges: 0=All, 1=≤7days, 2=≤30days, 3=≤90days
    const ageFilter = ageValue;

    const countries = Array.from(document.querySelectorAll('#countryFilter input:checked')).map(cb => cb.value);
    const impacts = Array.from(document.querySelectorAll('#impactFilter input:checked')).map(cb => cb.value);
    const severities = Array.from(document.querySelectorAll('#severityFilter input:checked')).map(cb => cb.value);
    const ticketTypes = Array.from(document.querySelectorAll('#ticketTypeFilter input:checked')).map(cb => cb.value);
    const statuses = Array.from(document.querySelectorAll('#statusFilter input:checked')).map(cb => cb.value);
    const automationLevels = Array.from(document.querySelectorAll('#automationFilter input:checked')).map(cb => cb.value);

    // Update filter summary
    updateFilterSummary(dateRange, mttrFilter, mttcFilter, ageFilter, countries, impacts, severities, ticketTypes, statuses, automationLevels);

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - dateRange);

    filteredData = allData.filter(item => {
        // Date filter
        const createdDate = new Date(item.created);
        if (createdDate < cutoffDate) return false;

        // Other filters
        if (countries.length > 0) {
            const hasNoCountry = !item.affected_country || item.affected_country === 'Unknown' || item.affected_country.trim() === '';
            const shouldShowNoCountry = countries.includes('No Country') && hasNoCountry;
            const shouldShowWithCountry = countries.some(c => c !== 'No Country' && c === item.affected_country);

            if (!shouldShowNoCountry && !shouldShowWithCountry) return false;
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
            const mttrSeconds = item.timetorespond && item.timetorespond.totalDuration ? item.timetorespond.totalDuration : null;
            if (mttrSeconds === null || mttrSeconds === 0) return false; // Skip items without MTTR data

            if (mttrFilter === 1 && mttrSeconds > 180) return false; // ≤3 mins (180 seconds)
            if (mttrFilter === 2 && mttrSeconds <= 180) return false; // >3 mins
            if (mttrFilter === 3 && mttrSeconds <= 300) return false; // >5 mins (300 seconds)
        }

        // MTTC filter - only consider cases with host populated
        if (mttcFilter > 0) {
            const hasHost = item.hostname && item.hostname.trim() !== '' && item.hostname !== 'Unknown';
            if (!hasHost) return false; // Skip items without host

            const mttcSeconds = item.timetocontain && item.timetocontain.totalDuration ? item.timetocontain.totalDuration : null;
            if (mttcSeconds === null || mttcSeconds === 0) return false; // Skip items without MTTC data

            if (mttcFilter === 1 && mttcSeconds > 300) return false; // ≤5 mins (300 seconds)
            if (mttcFilter === 2 && mttcSeconds > 900) return false; // ≤15 mins (900 seconds)
            if (mttcFilter === 3 && mttcSeconds <= 900) return false; // >15 mins (900 seconds)
        }

        // Age filter - calculate days since creation
        if (ageFilter > 0) {
            const createdDate = new Date(item.created);
            const currentDate = new Date();
            const daysDiff = Math.floor((currentDate - createdDate) / (1000 * 60 * 60 * 24));

            if (ageFilter === 1 && daysDiff > 7) return false; // ≤7 days
            if (ageFilter === 2 && daysDiff > 30) return false; // ≤30 days
            if (ageFilter === 3 && daysDiff > 90) return false; // ≤90 days
        }

        return true;
    });

    updateDashboard();
}

function updateFilterSummary(dateRange, mttrFilter, mttcFilter, ageFilter, countries, impacts, severities, ticketTypes, statuses, automationLevels) {
    const container = document.getElementById('activeFiltersContainer');

    // Preserve non-removable filters
    const nonRemovableFilters = container.querySelectorAll('.filter-tag.non-removable');
    const nonRemovableHTML = Array.from(nonRemovableFilters).map(filter => filter.outerHTML).join('');

    container.innerHTML = nonRemovableHTML;

    // Date range - no X button, use radio buttons to change
    const dateText = dateRange === 7 ? 'Last 7 days' :
        dateRange === 30 ? 'Last 30 days' :
            dateRange === 60 ? 'Last 60 days' :
                dateRange === 90 ? 'Last 90 days' :
                    dateRange === 365 ? 'Last year' : `Last ${dateRange} days`;

    container.innerHTML += `<span class="filter-tag">${dateText}</span>`;

    // MTTR filter
    if (mttrFilter > 0) {
        const mttrText = mttrFilter === 1 ? 'MTTR ≤3 mins' :
            mttrFilter === 2 ? 'MTTR >3 mins' :
                mttrFilter === 3 ? 'MTTR >5 mins' : 'All MTTR';
        container.innerHTML += `<span class="filter-tag">${mttrText} <button class="remove-filter-btn" onclick="removeFilter('mttr', '${mttrFilter}')">×</button></span>`;
    }

    // MTTC filter
    if (mttcFilter > 0) {
        const mttcText = mttcFilter === 1 ? 'MTTC ≤5 mins' :
            mttcFilter === 2 ? 'MTTC ≤15 mins' :
                mttcFilter === 3 ? 'MTTC >15 mins' : 'All MTTC';
        container.innerHTML += `<span class="filter-tag">${mttcText} <button class="remove-filter-btn" onclick="removeFilter('mttc', '${mttcFilter}')">×</button></span>`;
    }

    // Age filter
    if (ageFilter > 0) {
        const ageText = ageFilter === 1 ? 'Age ≤7 days' :
            ageFilter === 2 ? 'Age ≤30 days' :
                ageFilter === 3 ? 'Age ≤90 days' : 'All Ages';
        container.innerHTML += `<span class="filter-tag">${ageText} <button class="remove-filter-btn" onclick="removeFilter('age', '${ageFilter}')">×</button></span>`;
    }

    // Add other filters if selected
    if (countries.length > 0) {
        countries.forEach(country => {
            container.innerHTML += `<span class="filter-tag">Country: ${country} <button class="remove-filter-btn" onclick="removeFilter('country', '${country}')">×</button></span>`;
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
    // Reset date range slider to default (30 days, position 1)
    const dateSlider = document.getElementById('dateRangeSlider');
    if (dateSlider) {
        dateSlider.value = 1;
        updateSliderLabels(1);
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

    // Reset age range slider to default (All, position 0)
    const ageSlider = document.getElementById('ageRangeSlider');
    if (ageSlider) {
        ageSlider.value = 0;
        updateAgeSliderLabels(0);
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

function updateMetrics() {
    const totalIncidents = filteredData.length;
    const responseSlaBreaches = filteredData.filter(item => {
        const timeToRespond = item.timetorespond;
        return timeToRespond && (timeToRespond.breachTriggered === true || timeToRespond.breachTriggered === 'true');
    }).length;

    const containmentSlaBreaches = filteredData.filter(item => {
        // Only consider cases with host populated
        const hasHost = item.hostname && item.hostname.trim() !== '' && item.hostname !== 'Unknown';
        const timeToContain = item.timetocontain;
        return hasHost && timeToContain && (timeToContain.breachTriggered === true || timeToContain.breachTriggered === 'true');
    }).length;

    const openIncidents = filteredData.filter(item => item.status !== 2).length;

    // Calculate MTTR (Mean Time to Respond) - only for cases with an owner
    const casesWithOwnerAndTimeToRespond = filteredData.filter(item =>
        item.owner &&
        item.owner.trim() !== '' &&
        item.timetorespond &&
        item.timetorespond.totalDuration > 0
    );
    const mttr = casesWithOwnerAndTimeToRespond.length > 0
        ? casesWithOwnerAndTimeToRespond.reduce((sum, item) => sum + item.timetorespond.totalDuration, 0) / casesWithOwnerAndTimeToRespond.length
        : 0;

    // Calculate MTTC (Mean Time to Contain) - only for cases with hostname populated
    const casesWithOwnerAndTimeToContain = filteredData.filter(item =>
        item.hostname &&
        item.hostname.trim() !== '' &&
        item.hostname !== 'Unknown' &&
        item.timetocontain &&
        item.timetocontain.totalDuration > 0
    );
    const mttc = casesWithOwnerAndTimeToContain.length > 0
        ? casesWithOwnerAndTimeToContain.reduce((sum, item) => sum + item.timetocontain.totalDuration, 0) / casesWithOwnerAndTimeToContain.length
        : 0;

    // Convert seconds to mins:secs format for display
    const formatTime = (seconds) => {
        if (seconds === 0) return '0:00';
        const mins = Math.floor(seconds / 60);
        const secs = Math.round(seconds % 60);
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    };

    const mttrFormatted = formatTime(mttr);
    const mttcFormatted = formatTime(mttc);

    const metricsHTML = `
        <div class="metric-card">
            <div class="metric-title">🎫 Total Cases</div>
            <div class="metric-value">${totalIncidents.toLocaleString()}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">⏱️ MTTR (mins:secs)</div>
            <div class="metric-value">${mttrFormatted}</div>
            <div class="metric-subtitle">${casesWithOwnerAndTimeToRespond.length} cases acknowledged</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🔒 MTTC (mins:secs)</div>
            <div class="metric-value">${mttcFormatted}</div>
            <div class="metric-subtitle">${casesWithOwnerAndTimeToContain.length} cases with hostnames</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🚨 Response SLA Breaches</div>
            <div class="metric-value">${responseSlaBreaches.toLocaleString()}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🔒 Containment SLA Breaches</div>
            <div class="metric-value">${containmentSlaBreaches.toLocaleString()}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">📈 Open</div>
            <div class="metric-value">${openIncidents.toLocaleString()}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🌍 Countries</div>
            <div class="metric-value">${new Set(filteredData.map(item => item.affected_country)).size}</div>
        </div>
    `;

    document.getElementById('metricsGrid').innerHTML = metricsHTML;
}

function updateCharts() {
    createGeoChart();
    createTicketTypeChart();
    createTimelineChart();
    createImpactChart();
    createOwnerChart();
    createFunnelChart();
}

function createGeoChart() {
    const counts = {};
    filteredData.forEach(item => {
        const country = item.affected_country || 'Unknown';
        counts[country] = (counts[country] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);

    const trace = {
        x: sortedEntries.map(([country, count]) => count),
        y: sortedEntries.map(([country, count]) => country),
        type: 'bar',
        orientation: 'h',
        marker: {
            color: colorSchemes.countries,
            line: {color: 'rgba(255,255,255,0.8)', width: 1}
        },
        hovertemplate: '<b>%{y}</b><br>Incidents: %{x}<extra></extra>'
    };

    const layout = {
        margin: {l: 120, r: 20, t: 40, b: 40},
        font: {family: 'Segoe UI, sans-serif', size: 12},
        showlegend: false,
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        xaxis: {gridcolor: 'rgba(128,128,128,0.2)'},
        yaxis: {gridcolor: 'rgba(128,128,128,0.2)'}
    };

    const config = {responsive: true, displayModeBar: true, displaylogo: false};
    Plotly.newPlot('geoChart', [trace], layout, config);
}


function createTimelineChart() {
    const dailyInflow = {};
    const dailyOutflow = {};

    filteredData.forEach(item => {
        // Only include cases with owners
        if (item.owner && item.owner.trim() !== '') {
            // Calculate inflow (created cases)
            if (item.created && item.created.trim() !== '') {
                const createdDate = new Date(item.created);
                if (!isNaN(createdDate.getTime()) && createdDate.getFullYear() >= 2020) {
                    const date = createdDate.toISOString().split('T')[0];
                    dailyInflow[date] = (dailyInflow[date] || 0) + 1;
                }
            }

            // Calculate outflow (closed cases)
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

    const traces = [
        {
            x: allDates,
            y: allDates.map(date => dailyInflow[date] || 0),
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Inflow (Acknowledged by Analyst)',
            line: {color: '#007bff', width: 3},
            marker: {color: '#007bff', size: 6},
            hovertemplate: '<b>%{x}</b><br>Created: %{y}<extra></extra>'
        },
        {
            x: allDates,
            y: allDates.map(date => dailyOutflow[date] || 0),
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Outflow (Closed by Analyst)',
            line: {color: '#28a745', width: 3},
            marker: {color: '#28a745', size: 6},
            hovertemplate: '<b>%{x}</b><br>Closed: %{y}<extra></extra>'
        }
    ];

    const layout = {
        margin: {l: 60, r: 20, t: 20, b: 60},
        font: {family: 'Segoe UI, sans-serif', size: 12},
        showlegend: true,
        legend: {x: 0, y: 1, bgcolor: 'rgba(255,255,255,0.8)'},
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        xaxis: {
            gridcolor: 'rgba(128,128,128,0.2)',
            tickangle: 90,
            tickformat: '%m/%d',
            dtick: 86400000 * 2
        },
        yaxis: {
            gridcolor: 'rgba(128,128,128,0.2)',
            title: 'Number of Cases'
        }
    };

    const config = {responsive: true, displayModeBar: true, displaylogo: false};
    Plotly.newPlot('timelineChart', traces, layout, config);
}

function createImpactChart() {
    const counts = {};
    filteredData.forEach(item => {
        const impact = item.impact || 'Unknown';
        counts[impact] = (counts[impact] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]);

    const trace = {
        labels: sortedEntries.map(([impact, count]) => impact),
        values: sortedEntries.map(([impact, count]) => count),
        type: 'pie',
        hole: 0.3,
        marker: {
            colors: colorSchemes.countries,
            line: {color: 'white', width: 2}
        },
        textinfo: 'label+value',
        textfont: {size: 12},
        hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    };

    const layout = {
        margin: {l: 10, r: 10, t: 20, b: 20},
        font: {family: 'Segoe UI, sans-serif', size: 12},
        showlegend: false,
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)'
    };

    const config = {responsive: true, displayModeBar: true, displaylogo: false};
    Plotly.newPlot('ticketTypeChart', [trace], layout, config);
}

function createTicketTypeChart() {
    const counts = {};
    filteredData.forEach(item => {
        const ticketType = item.type || 'Unknown';
        counts[ticketType] = (counts[ticketType] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);

    const trace = {
        labels: sortedEntries.map(([ticketType, count]) => {
            // Remove METCIRT prefix for display
            return ticketType.startsWith('METCIRT') ? ticketType.replace(/^METCIRT[_\-\s]*/i, '') : ticketType;
        }),
        values: sortedEntries.map(([ticketType, count]) => count),
        type: 'pie',
        hole: 0.6,
        marker: {
            colors: colorSchemes.sources,
            line: {color: 'white', width: 2}
        },
        textinfo: 'label+value',
        textfont: {size: 11},
        hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    };

    const layout = {
        margin: {l: 20, r: 20, t: 40, b: 40},
        font: {family: 'Segoe UI, sans-serif', size: 12},
        showlegend: false,
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)'
    };

    const config = {responsive: true, displayModeBar: true, displaylogo: false};
    Plotly.newPlot('severityChart', [trace], layout, config);
}

function createOwnerChart() {
    const counts = {};
    filteredData.forEach(item => {
        // Only include cases with actual owners (skip unassigned)
        if (item.owner && item.owner.trim() !== '') {
            let owner = item.owner;
            // Remove @company.com suffix
            if (owner.endsWith('@company.com')) {
                owner = owner.replace('@company.com', '');
            }
            counts[owner] = (counts[owner] || 0) + 1;
        }
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);

    const trace = {
        x: sortedEntries.map(([owner, count]) => count),
        y: sortedEntries.map(([owner, count]) => owner),
        type: 'bar',
        orientation: 'h',
        marker: {
            color: colorSchemes.sources,
            line: {color: 'rgba(255,255,255,0.8)', width: 1}
        },
        hovertemplate: '<b>%{y}</b><br>Cases: %{x}<extra></extra>'
    };

    const layout = {
        margin: {l: 120, r: 20, t: 20, b: 40},
        font: {family: 'Segoe UI, sans-serif', size: 12},
        showlegend: false,
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        xaxis: {gridcolor: 'rgba(128,128,128,0.2)', title: 'Number of Cases'},
        yaxis: {gridcolor: 'rgba(128,128,128,0.2)'}
    };

    const config = {responsive: true, displayModeBar: true, displaylogo: false};
    Plotly.newPlot('heatmapChart', [trace], layout, config);
}

function createFunnelChart() {
    // Calculate the funnel stages
    const totalCases = filteredData.length;

    const assignedCases = filteredData.filter(item =>
        item.owner && item.owner.trim() !== ''
    ).length;

    const maliciousTruePositives = filteredData.filter(item => {
        return item.impact === 'Malicious True Positive';
    }).length;

    const trace = {
        type: 'funnel',
        y: ['All Cases', 'Assigned Cases', 'Malicious True Positive'],
        x: [totalCases, assignedCases, maliciousTruePositives],
        textinfo: 'value+percent initial',
        marker: {
            color: ['#4472C4', '#70AD47', '#C5504B'],
            line: {color: 'white', width: 2}
        },
        hovertemplate: '<b>%{y}</b><br>Count: %{x}<br>Percentage: %{percentInitial}<extra></extra>'
    };

    const layout = {
        margin: {l: 150, r: 20, t: 20, b: 40},
        font: {family: 'Segoe UI, sans-serif', size: 12},
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)'
    };

    const config = {responsive: true, displayModeBar: true, displaylogo: false};
    Plotly.newPlot('funnelChart', [trace], layout, config);
}

function updateTable() {
    const tbody = document.querySelector('#dataTable tbody');
    tbody.innerHTML = '';

    // Sort the filtered data before displaying
    const sortedData = sortData(filteredData);
    const displayData = sortedData.slice(0, 100); // Limit to 100 rows for performance

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
                                td.textContent = new Date(value).toLocaleDateString();
                            }
                            break;
                        case 'duration':
                            if (value && value > 0) {
                                const minutes = Math.floor(value / 60);
                                const seconds = Math.round(value % 60);
                                td.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                            } else {
                                td.textContent = '--';
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
}

function exportToCSV() {
    const headers = ['ID', 'Name', 'Severity', 'Status', 'Country', 'Impact', 'Type', 'Created'];
    const severityMap = {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'};
    const statusMap = {0: 'Pending', 1: 'Active', 2: 'Closed'};

    const csvContent = [
        headers.join(','),
        ...filteredData.map(item => [
            item.id,
            `"${item.name.replace(/"/g, '""')}"`,
            severityMap[item.severity] || 'Unknown',
            statusMap[item.status] || 'Unknown',
            item.affected_country,
            item.impact,
            item.type,
            new Date(item.created).toISOString()
        ].join(','))
    ].join('\n');

    downloadCSV(csvContent, 'security_incidents.csv');
}

function exportSummary() {
    const totalIncidents = filteredData.length;
    const criticalIncidents = filteredData.filter(item => item.severity === 4).length;
    const openIncidents = filteredData.filter(item => item.status !== 2).length;

    const summaryData = [
        ['Metric', 'Value'],
        ['Total Incidents', totalIncidents],
        ['Critical Incidents', criticalIncidents],
        ['Open Incidents', openIncidents],
        ['Countries Affected', new Set(filteredData.map(item => item.affected_country)).size],
        ['Top Country', getMostCommon('affected_country')],
        ['Top Ticket Type', getMostCommon('type')]
    ];

    const csvContent = summaryData.map(row => row.join(',')).join('\n');
    downloadCSV(csvContent, 'incident_summary.csv');
}

function getMostCommon(field) {
    const counts = {};
    filteredData.forEach(item => {
        const value = item[field] || 'Unknown';
        counts[value] = (counts[value] || 0) + 1;
    });

    return Object.keys(counts).reduce((a, b) => counts[a] > counts[b] ? a : b, 'N/A');
}

function downloadCSV(content, filename) {
    const blob = new Blob([content], {type: 'text/csv'});
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
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
        if (aVal > bVal) comparison = 1;
        else if (aVal < bVal) comparison = -1;

        return currentSort.direction === 'asc' ? comparison : -comparison;
    });
}

function saveSortPreferences() {
    const preferences = {
        column: currentSort.column,
        direction: currentSort.direction
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
        visibleColumns: visibleColumns,
        columnOrder: columnOrder
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
            th.addEventListener('click', function () {
                sortTable(columnId);
            });
            thead.appendChild(th);
        }
    });

    // Update sort indicators after rebuilding headers
    updateSortIndicators();
}