let allData = [];
let filteredData = [];
let currentSort = { column: null, direction: 'asc' };

// Column configuration with all available fields
const availableColumns = {
    // Primary fields (commonly used)
    'id': { label: 'ID', category: 'Primary', path: 'id', type: 'number' },
    'name': { label: 'Name', category: 'Primary', path: 'name', type: 'string' },
    'severity': { label: 'Severity', category: 'Primary', path: 'severity', type: 'number' },
    'status': { label: 'Status', category: 'Primary', path: 'status', type: 'number' },
    'type': { label: 'Type', category: 'Primary', path: 'type', type: 'string' },
    'created': { label: 'Created', category: 'Primary', path: 'created', type: 'date' },
    'closed': { label: 'Closed', category: 'Primary', path: 'closed', type: 'date' },
    'owner': { label: 'Owner', category: 'Primary', path: 'owner', type: 'string' },

    // Custom Fields (from data analysis)
    'affected_country': { label: 'Country', category: 'Location', path: 'CustomFields.affectedcountry', type: 'string' },
    'affected_region': { label: 'Region', category: 'Location', path: 'CustomFields.affectedregion', type: 'string' },
    'impact': { label: 'Impact', category: 'Assessment', path: 'CustomFields.impact', type: 'string' },
    'contained': { label: 'Contained', category: 'Status', path: 'CustomFields.contained', type: 'string' },
    'automation': { label: 'Automation Level', category: 'Process', path: 'CustomFields.automation', type: 'string' },
    'escalation_state': { label: 'Escalation State', category: 'Process', path: 'CustomFields.escalationstate', type: 'string' },
    'source': { label: 'Source', category: 'Detection', path: 'CustomFields.source', type: 'string' },
    'threat_type': { label: 'Threat Type', category: 'Assessment', path: 'CustomFields.threattype', type: 'string' },
    'root_cause': { label: 'Root Cause', category: 'Assessment', path: 'CustomFields.rootcause', type: 'string' },
    'breach_confirmation': { label: 'Breach Confirmation', category: 'Assessment', path: 'CustomFields.breachconfirmation', type: 'string' },

    // Additional useful fields
    'occurred': { label: 'Occurred', category: 'Timing', path: 'occurred', type: 'date' },
    'dueDate': { label: 'Due Date', category: 'Timing', path: 'dueDate', type: 'date' },
    'phase': { label: 'Phase', category: 'Process', path: 'phase', type: 'string' },
    'category': { label: 'Category', category: 'Classification', path: 'category', type: 'string' },
    'sourceInstance': { label: 'Source Instance', category: 'Technical', path: 'sourceInstance', type: 'string' },
    'openDuration': { label: 'Open Duration', category: 'Metrics', path: 'openDuration', type: 'number' }
};

// Default visible columns and their order
let visibleColumns = ['id', 'name', 'severity', 'status', 'affected_country', 'impact', 'type', 'created'];
let columnOrder = [...visibleColumns]; // Maintains the order of columns

// Color schemes for consistent theming
const colorSchemes = {
    severity: ['#6c757d', '#28a745', '#ffc107', '#fd7e14', '#dc3545'],
    status: ['#ffc107', '#007bff', '#28a745', '#6c757d'],
    countries: ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'],
    sources: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FECA57', '#FF9FF3', '#54A0FF', '#5F27CD']
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    loadData();
    setupEventListeners();
});

function setupEventListeners() {
    // Add listener for date range slider
    const dateSlider = document.getElementById('dateRangeSlider');
    if (dateSlider) {
        dateSlider.addEventListener('input', function() {
            updateSliderLabels(this.value);
            applyFilters();
        });
    }

    // Add listeners for existing severity, status, and automation checkboxes
    document.querySelectorAll('#severityFilter input, #statusFilter input, #automationFilter input').forEach(checkbox => {
        checkbox.addEventListener('change', applyFilters);
    });

    // Add listeners to slider labels for click functionality
    document.querySelectorAll('.slider-labels span').forEach(label => {
        label.addEventListener('click', function() {
            const value = this.getAttribute('data-value');
            dateSlider.value = value;
            updateSliderLabels(value);
            applyFilters();
        });
    });

    // Add listeners for sortable table headers
    document.querySelectorAll('.sortable').forEach(header => {
        header.addEventListener('click', function() {
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
    document.querySelectorAll('.slider-labels span').forEach(span => {
        span.classList.remove('active');
    });
    document.querySelector(`.slider-labels span[data-value="${value}"]`).classList.add('active');
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
    const automationLevels = [...new Set(allData.map(item => item.automation_level || 'Unknown'))].sort();

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
    const countries = Array.from(document.querySelectorAll('#countryFilter input:checked')).map(cb => cb.value);
    const impacts = Array.from(document.querySelectorAll('#impactFilter input:checked')).map(cb => cb.value);
    const severities = Array.from(document.querySelectorAll('#severityFilter input:checked')).map(cb => cb.value);
    const ticketTypes = Array.from(document.querySelectorAll('#ticketTypeFilter input:checked')).map(cb => cb.value);
    const statuses = Array.from(document.querySelectorAll('#statusFilter input:checked')).map(cb => cb.value);
    const automationLevels = Array.from(document.querySelectorAll('#automationFilter input:checked')).map(cb => cb.value);

    // Update filter summary
    updateFilterSummary(dateRange, countries, impacts, severities, ticketTypes, statuses, automationLevels);

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - dateRange);

    filteredData = allData.filter(item => {
        // Date filter
        const createdDate = new Date(item.created);
        if (createdDate < cutoffDate) return false;

        // Other filters
        if (countries.length > 0 && !countries.includes(item.affected_country)) return false;
        if (impacts.length > 0 && !impacts.includes(item.impact)) return false;
        if (severities.length > 0 && !severities.includes(item.severity.toString())) return false;
        if (ticketTypes.length > 0 && !ticketTypes.includes(item.type)) return false;
        if (statuses.length > 0 && !statuses.includes(item.status.toString())) return false;
        if (automationLevels.length > 0 && !automationLevels.includes(item.automation_level || 'Unknown')) return false;

        return true;
    });

    updateDashboard();
}

function updateFilterSummary(dateRange, countries, impacts, severities, ticketTypes, statuses, automationLevels) {
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
    }

    // Re-apply filters
    applyFilters();
}

function clearAllFilters() {
    // Reset date range slider to default (30 days, position 1)
    const dateSlider = document.getElementById('dateRangeSlider');
    if (dateSlider) {
        dateSlider.value = 1;
        updateSliderLabels(1);
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
    const criticalIncidents = filteredData.filter(item => item.severity === 4).length;
    const openIncidents = filteredData.filter(item => item.status !== 2).length;
    const containedIncidents = filteredData.filter(item => item.contained === true).length;

    const metricsHTML = `
        <div class="metric-card">
            <div class="metric-title">🎫 Total Incidents</div>
            <div class="metric-value">${totalIncidents.toLocaleString()}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🚨 Critical</div>
            <div class="metric-value">${criticalIncidents.toLocaleString()}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">📈 Open</div>
            <div class="metric-value">${openIncidents.toLocaleString()}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🔒 Contained</div>
            <div class="metric-value">${containedIncidents.toLocaleString()}</div>
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
    createSeverityChart();
    createTimelineChart();
    createTicketTypeChart();
    createHeatmapChart();
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
            line: { color: 'rgba(255,255,255,0.8)', width: 1 }
        },
        hovertemplate: '<b>%{y}</b><br>Incidents: %{x}<extra></extra>'
    };

    const layout = {
        margin: { l: 120, r: 20, t: 40, b: 40 },
        font: { family: 'Segoe UI, sans-serif', size: 12 },
        showlegend: false,
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        xaxis: { gridcolor: 'rgba(128,128,128,0.2)' },
        yaxis: { gridcolor: 'rgba(128,128,128,0.2)' }
    };

    const config = { responsive: true, displayModeBar: true, displaylogo: false };
    Plotly.newPlot('geoChart', [trace], layout, config);
}

function createSeverityChart() {
    const severityMap = { 0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
    const counts = { 'Unknown': 0, 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0 };

    filteredData.forEach(item => {
        const severity = severityMap[item.severity] || 'Unknown';
        counts[severity]++;
    });

    const trace = {
        labels: Object.keys(counts),
        values: Object.values(counts),
        type: 'pie',
        hole: 0.4,
        marker: {
            colors: colorSchemes.severity,
            line: { color: 'white', width: 2 }
        },
        textinfo: 'label+percent+value',
        textfont: { size: 12 },
        hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    };

    const layout = {
        margin: { l: 20, r: 20, t: 40, b: 40 },
        font: { family: 'Segoe UI, sans-serif', size: 12 },
        showlegend: true,
        legend: { orientation: 'h', y: -0.1 },
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)'
    };

    const config = { responsive: true, displayModeBar: true, displaylogo: false };
    Plotly.newPlot('severityChart', [trace], layout, config);
}

function createTimelineChart() {
    const dailyCounts = {};
    filteredData.forEach(item => {
        const date = new Date(item.created).toISOString().split('T')[0];
        dailyCounts[date] = (dailyCounts[date] || 0) + 1;
    });

    const sortedDates = Object.keys(dailyCounts).sort();

    const trace = {
        x: sortedDates,
        y: sortedDates.map(date => dailyCounts[date]),
        type: 'scatter',
        mode: 'lines+markers',
        line: { color: '#007bff', width: 3 },
        marker: { color: '#007bff', size: 6 },
        fill: 'tonexty',
        fillcolor: 'rgba(0, 123, 255, 0.1)',
        hovertemplate: '<b>%{x}</b><br>Incidents: %{y}<extra></extra>'
    };

    const layout = {
        margin: { l: 60, r: 20, t: 40, b: 60 },
        font: { family: 'Segoe UI, sans-serif', size: 12 },
        showlegend: false,
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        xaxis: {
            gridcolor: 'rgba(128,128,128,0.2)',
            tickangle: -45
        },
        yaxis: {
            gridcolor: 'rgba(128,128,128,0.2)',
            title: 'Number of Incidents'
        }
    };

    const config = { responsive: true, displayModeBar: true, displaylogo: false };
    Plotly.newPlot('timelineChart', [trace], layout, config);
}

function createTicketTypeChart() {
    const counts = {};
    filteredData.forEach(item => {
        const ticketType = item.type || 'Unknown';
        counts[ticketType] = (counts[ticketType] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);

    const trace = {
        labels: sortedEntries.map(([ticketType, count]) => ticketType),
        values: sortedEntries.map(([ticketType, count]) => count),
        type: 'pie',
        hole: 0.6,
        marker: {
            colors: colorSchemes.sources,
            line: { color: 'white', width: 2 }
        },
        textinfo: 'label+percent',
        textfont: { size: 11 },
        hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    };

    const layout = {
        margin: { l: 20, r: 20, t: 40, b: 40 },
        font: { family: 'Segoe UI, sans-serif', size: 12 },
        showlegend: true,
        legend: { orientation: 'h', y: -0.1 },
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)'
    };

    const config = { responsive: true, displayModeBar: true, displaylogo: false };
    Plotly.newPlot('ticketTypeChart', [trace], layout, config);
}

function createHeatmapChart() {
    const statusMap = { 0: 'Pending', 1: 'Active', 2: 'Closed', 3: 'Archive' };
    const impacts = [...new Set(filteredData.map(item => item.impact))].filter(i => i && i !== 'Unknown').sort();
    const statuses = [...new Set(filteredData.map(item => statusMap[item.status]))].filter(s => s).sort();

    const matrix = [];
    const hoverText = [];

    statuses.forEach(status => {
        const row = [];
        const hoverRow = [];
        impacts.forEach(impact => {
            const count = filteredData.filter(item =>
                item.impact === impact && statusMap[item.status] === status
            ).length;
            row.push(count);
            hoverRow.push(`Impact: ${impact}<br>Status: ${status}<br>Count: ${count}`);
        });
        matrix.push(row);
        hoverText.push(hoverRow);
    });

    const trace = {
        z: matrix,
        x: impacts,
        y: statuses,
        type: 'heatmap',
        colorscale: 'Viridis',
        hovertemplate: '%{text}<extra></extra>',
        text: hoverText,
        showscale: true
    };

    const layout = {
        margin: { l: 80, r: 40, t: 40, b: 80 },
        font: { family: 'Segoe UI, sans-serif', size: 12 },
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        xaxis: { tickangle: -45 },
        yaxis: { autorange: 'reversed' }
    };

    const config = { responsive: true, displayModeBar: true, displaylogo: false };
    Plotly.newPlot('heatmapChart', [trace], layout, config);
}

function createFunnelChart() {
    const statusMap = { 0: 'Pending', 1: 'Active', 2: 'Closed', 3: 'Archive' };
    const escalationCounts = {};

    filteredData.forEach(item => {
        const escalation = item.escalation_state || 'Unknown';
        escalationCounts[escalation] = (escalationCounts[escalation] || 0) + 1;
    });

    const sortedEntries = Object.entries(escalationCounts).sort((a, b) => b[1] - a[1]);

    const trace = {
        type: 'funnel',
        y: sortedEntries.map(([escalation, count]) => escalation),
        x: sortedEntries.map(([escalation, count]) => count),
        textinfo: 'value+percent initial',
        marker: {
            color: colorSchemes.status,
            line: { color: 'white', width: 2 }
        },
        hovertemplate: '<b>%{y}</b><br>Count: %{x}<br>Percentage: %{percentInitial}<extra></extra>'
    };

    const layout = {
        margin: { l: 120, r: 20, t: 40, b: 40 },
        font: { family: 'Segoe UI, sans-serif', size: 12 },
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)'
    };

    const config = { responsive: true, displayModeBar: true, displaylogo: false };
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
                        case 'number':
                            if (columnId === 'id') {
                                td.innerHTML = `<a href="https://msoar.crtx.us.paloaltonetworks.com/Custom/caseinfoid/${value}" target="_blank" style="color: #0046ad; text-decoration: underline;">${value}</a>`;
                            } else if (columnId === 'severity') {
                                const severityMap = { 0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
                                const severity = severityMap[value] || 'Unknown';
                                td.innerHTML = `<span class="severity-${severity.toLowerCase()}">${severity}</span>`;
                            } else if (columnId === 'status') {
                                const statusMap = { 0: 'Pending', 1: 'Active', 2: 'Closed' };
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
    const severityMap = { 0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
    const statusMap = { 0: 'Pending', 1: 'Active', 2: 'Closed' };

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
    const blob = new Blob([content], { type: 'text/csv' });
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

function toggleAudio() {
    // Placeholder for audio functionality
    const icon = document.getElementById('music-icon');
    icon.style.opacity = icon.style.opacity === '0.5' ? '1' : '0.5';
}




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
        } else if (column.type === 'number') {
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
    btn.addEventListener('click', function(e) {
        e.stopPropagation();
        dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
        if (dropdown.style.display === 'block') {
            populateColumnSelector();
        }
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
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
        categories[column.category].push({ id: columnId, ...column });
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

            checkbox.addEventListener('change', function() {
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
            th.addEventListener('click', function() {
                sortTable(columnId);
            });
            thead.appendChild(th);
        }
    });

    // Update sort indicators after rebuilding headers
    updateSortIndicators();
}