/**
 * Chart creation and rendering using Plotly
 */

import {state} from './state.js';
import {COLOR_SCHEMES, PLOTLY_CONFIG} from './config.js';
import {commonLayout, getChartColors} from './theme.js';

// Plotly is loaded from CDN
/* global Plotly */

/**
 * Safe plot wrapper with error handling
 */
function safePlot(chartId, data, layout, config = PLOTLY_CONFIG) {
    const el = document.getElementById(chartId);
    if (!el) {
        console.warn(`Chart element ${chartId} not found`);
        return;
    }

    try {
        Plotly.newPlot(el, data, layout, config);
    } catch (error) {
        console.error(`Failed to create chart ${chartId}:`, error);
        el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">Chart rendering failed</div>';
    }
}

export function createGeoChart() {
    const counts = {};
    state.filteredData.forEach(item => {
        const country = item.affected_country || 'Unknown';
        counts[country] = (counts[country] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const trace = {
        x: sortedEntries.map(([, count]) => count).reverse(),
        y: sortedEntries.map(([country]) => country).reverse(),
        type: 'bar',
        orientation: 'h',
        text: sortedEntries.map(([, count]) => count).reverse(),
        textposition: 'inside',
        textfont: {color: 'white', size: 12},
        marker: {
            color: sortedEntries.map((_, i) => COLOR_SCHEMES.countries[i % COLOR_SCHEMES.countries.length]).reverse(),
            line: {color: 'rgba(255,255,255,0.8)', width: 1}
        },
        hovertemplate: '<b>%{y}</b><br>Cases: %{x}<extra></extra>'
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 100, r: 40, t: 20, b: 40},
        xaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid},
        yaxis: {gridcolor: getChartColors().grid}
    });

    safePlot('geoChart', [trace], layout);
}

export function createTimelineChart() {
    const dailyInflow = {};
    const dailyOutflow = {};

    state.filteredData.forEach(item => {
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
    const traces = [
        {
            x: allDates,
            y: allDates.map(d => dailyInflow[d] || 0),
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Inflow (Acknowledged by Analyst)',
            line: {color: '#007bff', width: 3},
            marker: {color: '#007bff', size: 6},
            hovertemplate: '<b>%{x}</b><br>Created: %{y}<extra></extra>'
        },
        {
            x: allDates,
            y: allDates.map(d => dailyOutflow[d] || 0),
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Outflow (Closed by Analyst)',
            line: {color: '#28a745', width: 3},
            marker: {color: '#28a745', size: 6},
            hovertemplate: '<b>%{x}</b><br>Closed: %{y}<extra></extra>'
        }
    ];

    const layout = commonLayout({
        legend: {x: 0.5, y: -0.2, xanchor: 'center', orientation: 'h'},
        margin: {l: 50, r: 10, t: 30, b: 40},
        yaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid},
        xaxis: {gridcolor: getChartColors().grid, tickangle: 90, tickformat: '%m/%d', dtick: 86400000 * 2}
    });

    safePlot('timelineChart', traces, layout);
}

export function createImpactChart() {
    const counts = {};
    state.filteredData.forEach(item => {
        const impact = item.impact || 'Unknown';
        counts[impact] = (counts[impact] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const trace = {
        labels: sortedEntries.map(([impact]) => impact),
        values: sortedEntries.map(([, count]) => count),
        type: 'pie',
        hole: 0.3,
        marker: {colors: COLOR_SCHEMES.countries, line: {color: 'white', width: 2}},
        textinfo: 'label+value',
        textfont: {size: 12, color: getChartColors().font},
        hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    };

    const layout = commonLayout({showlegend: false, margin: {l: 10, r: 10, t: 20, b: 20}});
    safePlot('ticketTypeChart', [trace], layout);
}

export function createTicketTypeChart() {
    const counts = {};
    state.filteredData.forEach(item => {
        const ticketType = item.type || 'Unknown';
        counts[ticketType] = (counts[ticketType] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const trace = {
        labels: sortedEntries.map(([ticketType]) =>
            ticketType.startsWith('METCIRT') ? ticketType.replace(/^METCIRT[_\-\s]*/i, '') : ticketType
        ),
        values: sortedEntries.map(([, c]) => c),
        type: 'pie',
        hole: 0.6,
        marker: {colors: COLOR_SCHEMES.sources, line: {color: 'white', width: 2}},
        textinfo: 'label+value',
        textfont: {size: 11, color: getChartColors().font},
        hovertemplate: '<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    };

    const layout = commonLayout({showlegend: false, margin: {l: 20, r: 20, t: 40, b: 40}});
    safePlot('severityChart', [trace], layout);
}

export function createOwnerChart() {
    const counts = {};
    state.filteredData.forEach(item => {
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
            color: sortedEntries.map((_, i) => COLOR_SCHEMES.sources[i % COLOR_SCHEMES.sources.length]).reverse(),
            line: {color: 'rgba(255,255,255,0.8)', width: 1}
        },
        hovertemplate: '<b>%{y}</b><br>Cases: %{x}<extra></extra>'
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 120, r: 40, t: 20, b: 40},
        xaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid},
        yaxis: {gridcolor: getChartColors().grid}
    });

    safePlot('heatmapChart', [trace], layout);
}

export function createFunnelChart() {
    const totalCases = state.filteredData.length;
    const assignedCases = state.filteredData.filter(i => i.owner && i.owner.trim() !== '').length;
    const maliciousTruePositives = state.filteredData.filter(i => i.impact === 'Malicious True Positive').length;

    const trace = {
        type: 'funnel',
        y: ['All Cases', 'Assigned Cases', 'Malicious True Positive'],
        x: [totalCases, assignedCases, maliciousTruePositives],
        textinfo: 'value+percent initial',
        marker: {color: ['#4472C4', '#70AD47', '#C5504B'], line: {color: 'white', width: 2}},
        hovertemplate: '<b>%{y}</b><br>Count: %{x}<br>Percentage: %{percentInitial}<extra></extra>'
    };

    const layout = commonLayout({showlegend: false, margin: {l: 150, r: 40, t: 20, b: 40}});
    safePlot('funnelChart', [trace], layout);
}

export function createTopHostsChart() {
    const counts = {};
    state.filteredData.forEach(item => {
        const hostname = item.hostname || 'Unknown';
        if (hostname && hostname !== 'Unknown') {
            counts[hostname] = (counts[hostname] || 0) + 1;
        }
    });

    if (Object.keys(counts).length === 0) {
        const el = document.getElementById('topHostsChart');
        if (el) {
            el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No hostname data available</div>';
        }
        return;
    }

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const trace = {
        x: sortedEntries.map(([, count]) => count).reverse(),
        y: sortedEntries.map(([hostname]) => hostname).reverse(),
        type: 'bar',
        orientation: 'h',
        text: sortedEntries.map(([, count]) => count).reverse(),
        textposition: 'inside',
        textfont: {color: 'white', size: 12},
        marker: {
            color: sortedEntries.map((_, i) => COLOR_SCHEMES.countries[i % COLOR_SCHEMES.countries.length]).reverse(),
            line: {color: 'rgba(255,255,255,0.8)', width: 1}
        },
        hovertemplate: '<b>%{y}</b><br>Cases: %{x}<extra></extra>'
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 150, r: 40, t: 20, b: 40},
        xaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid},
        yaxis: {gridcolor: getChartColors().grid}
    });

    safePlot('topHostsChart', [trace], layout);
}

export function createTopUsersChart() {
    const counts = {};
    state.filteredData.forEach(item => {
        const username = item.username || 'Unknown';
        if (username && username !== 'Unknown') {
            counts[username] = (counts[username] || 0) + 1;
        }
    });

    if (Object.keys(counts).length === 0) {
        const el = document.getElementById('topUsersChart');
        if (el) {
            el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No username data available</div>';
        }
        return;
    }

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const trace = {
        x: sortedEntries.map(([, count]) => count).reverse(),
        y: sortedEntries.map(([username]) => username).reverse(),
        type: 'bar',
        orientation: 'h',
        text: sortedEntries.map(([, count]) => count).reverse(),
        textposition: 'inside',
        textfont: {color: 'white', size: 12},
        marker: {
            color: sortedEntries.map((_, i) => COLOR_SCHEMES.sources[i % COLOR_SCHEMES.sources.length]).reverse(),
            line: {color: 'rgba(255,255,255,0.8)', width: 1}
        },
        hovertemplate: '<b>%{y}</b><br>Cases: %{x}<extra></extra>'
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 150, r: 40, t: 20, b: 40},
        xaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid},
        yaxis: {gridcolor: getChartColors().grid}
    });

    safePlot('topUsersChart', [trace], layout);
}

export function createResolutionTimeChart() {
    const avgByType = {};
    const countsByType = {};

    state.filteredData.forEach(item => {
        if (item.type && item.resolution_time_days != null && item.resolution_time_days > 0) {
            if (!avgByType[item.type]) avgByType[item.type] = 0;
            if (!countsByType[item.type]) countsByType[item.type] = 0;
            avgByType[item.type] += item.resolution_time_days;
            countsByType[item.type]++;
        }
    });

    Object.keys(avgByType).forEach(type => {
        avgByType[type] = avgByType[type] / countsByType[type];
    });

    if (Object.keys(avgByType).length === 0) {
        const el = document.getElementById('resolutionTimeChart');
        if (el) {
            el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No resolution time data available</div>';
        }
        return;
    }

    const sortedEntries = Object.entries(avgByType).sort((a, b) => b[1] - a[1]);
    const trace = {
        x: sortedEntries.map(([, avg]) => avg.toFixed(1)).reverse(),
        y: sortedEntries.map(([type]) => type.startsWith('METCIRT') ? type.replace(/^METCIRT[_\-\s]*/i, '') : type).reverse(),
        type: 'bar',
        orientation: 'h',
        text: sortedEntries.map(([, avg]) => avg.toFixed(1) + ' days').reverse(),
        textposition: 'inside',
        textfont: {color: 'white', size: 11},
        marker: {
            color: sortedEntries.map((_, i) => COLOR_SCHEMES.countries[i % COLOR_SCHEMES.countries.length]).reverse(),
            line: {color: 'rgba(255,255,255,0.8)', width: 1}
        },
        hovertemplate: '<b>%{y}</b><br>Avg Resolution Time: %{x} days<extra></extra>'
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 180, r: 40, t: 20, b: 40},
        xaxis: {title: 'Average Days to Resolution', gridcolor: getChartColors().grid},
        yaxis: {gridcolor: getChartColors().grid}
    });

    safePlot('resolutionTimeChart', [trace], layout);
}

/**
 * Update all charts with filtered data
 */
export function updateCharts() {
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
