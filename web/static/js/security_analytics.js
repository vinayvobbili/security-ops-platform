let allData = [];
let filteredData = [];

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
}

function updateSliderLabels(value) {
    document.querySelectorAll('.slider-labels span').forEach(span => {
        span.classList.remove('active');
    });
    document.querySelector(`.slider-labels span[data-value="${value}"]`).classList.add('active');
}

async function loadData() {
    try {
        const response = await fetch('/api/security-analytics/data');
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
    container.innerHTML = '';

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

    const displayData = filteredData.slice(0, 100); // Limit to 100 rows for performance

    displayData.forEach(item => {
        const row = document.createElement('tr');

        const severityMap = { 0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
        const statusMap = { 0: 'Pending', 1: 'Active', 2: 'Closed' };

        const severity = severityMap[item.severity] || 'Unknown';
        const status = statusMap[item.status] || 'Unknown';

        row.innerHTML = `
            <td><a href="https://msoar.crtx.us.paloaltonetworks.com/Custom/caseinfoid/${item.id}" target="_blank" style="color: #0046ad; text-decoration: underline;">${item.id}</a></td>
            <td title="${item.name}">${item.name.substring(0, 50)}${item.name.length > 50 ? '...' : ''}</td>
            <td><span class="severity-${severity.toLowerCase()}">${severity}</span></td>
            <td><span class="status-${status.toLowerCase()}">${status}</span></td>
            <td>${item.affected_country}</td>
            <td>${item.impact}</td>
            <td>${item.type}</td>
            <td>${new Date(item.created).toLocaleDateString()}</td>
        `;

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
}

// Navigation functions
function toggleMenu() {
    const menu = document.getElementById('burgerMenu');
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
}

function toggleAudio() {
    // Placeholder for audio functionality
    const icon = document.getElementById('music-icon');
    icon.style.opacity = icon.style.opacity === '0.5' ? '1' : '0.5';
}

// Close menu when clicking outside
document.addEventListener('click', function(event) {
    const menu = document.getElementById('burgerMenu');
    const burger = document.querySelector('.nav-burger');
    if (!burger.contains(event.target) && !menu.contains(event.target)) {
        menu.style.display = 'none';
    }
});

// Theme toggle functionality
function toggleTheme() {
    const body = document.body;
    const themeToggle = document.querySelector('.theme-toggle');

    if (body.getAttribute('data-theme') === 'dark') {
        body.removeAttribute('data-theme');
        themeToggle.textContent = '🌙';
        themeToggle.title = 'Toggle Dark Mode';
        localStorage.setItem('theme', 'light');
    } else {
        body.setAttribute('data-theme', 'dark');
        themeToggle.textContent = '☀️';
        themeToggle.title = 'Toggle Light Mode';
        localStorage.setItem('theme', 'dark');
    }
}

// Load saved theme on page load
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('theme');
    const themeToggle = document.querySelector('.theme-toggle');

    if (savedTheme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        themeToggle.textContent = '☀️';
        themeToggle.title = 'Toggle Light Mode';
    }
});

// Burger menu functions
function toggleMenu() {
    var menu = document.getElementById('burgerMenu');
    menu.style.display = (menu.style.display === 'none' || menu.style.display === '') ? 'block' : 'none';
}

// Close menu when a link is clicked
document.addEventListener('DOMContentLoaded', function () {
    var burgerMenu = document.getElementById('burgerMenu');
    if (burgerMenu) {
        burgerMenu.querySelectorAll('a').forEach(function (link) {
            link.addEventListener('click', function () {
                burgerMenu.style.display = 'none';
            });
        });
    }
});

// Close burger menu when clicking outside
document.addEventListener('click', function (e) {
    var burgerMenu = document.getElementById('burgerMenu');
    var navBurger = document.querySelector('.nav-burger');

    if (burgerMenu && !burgerMenu.contains(e.target) && !navBurger.contains(e.target)) {
        burgerMenu.style.display = 'none';
    }
});