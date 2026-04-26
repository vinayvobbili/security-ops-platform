/**
 * Chart creation and rendering using Plotly
 */

import {state} from './state.js';
import {COLOR_SCHEMES, PLOTLY_CONFIG, appConfig} from './config.js';
import {commonLayout, getChartColors} from './theme.js';

// Drill-down callback — set by main.js to wire chart clicks to filters
let _drilldownCallback = null;

export function setDrilldownCallback(fn) {
    _drilldownCallback = fn;
}

function attachClickHandler(chartId, filterType, labelExtractor) {
    const el = document.getElementById(chartId);
    if (!el || !_drilldownCallback) return;
    el.removeAllListeners?.('plotly_click');
    el.on('plotly_click', (data) => {
        if (!data.points || !data.points.length) return;
        const pt = data.points[0];
        const label = labelExtractor(pt);
        if (label) _drilldownCallback(filterType, label);
    });
}

// Drawer columns for MM drill-down
const MM_DRAWER_COLS = [
    {key: 'id', label: 'ID', width: '70px'},
    {key: 'name', label: 'Name', width: '40%'},
    {key: 'affected_country', label: 'Country'},
    {key: 'severity', label: 'Severity'},
    {key: 'created_display', label: 'Created'}
];

function attachDrawerHandler(chartId, filterType, labelExtractor, matchFn) {
    const el = document.getElementById(chartId);
    if (!el || !window.DrilldownDrawer) return;
    el.on('plotly_click', (data) => {
        if (!data.points || !data.points.length) return;
        const pt = data.points[0];
        const label = labelExtractor(pt);
        if (!label) return;
        const rows = state.filteredData.filter(item => matchFn(item, label)).map(item => ({
            ...item,
            created_display: item.created ? new Date(item.created).toLocaleDateString() : '-'
        }));
        window.DrilldownDrawer.open(
            filterType + ': ' + label + ' (' + rows.length + ')',
            rows,
            MM_DRAWER_COLS,
            { onFilter: () => { if (_drilldownCallback) _drilldownCallback(filterType, label); } }
        );
    });
}

// Stop words filtered out of incident names for the word cloud
const WORD_CLOUD_STOP_WORDS = new Set([
    // Common English
    'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
    'should', 'may', 'might', 'shall', 'can', 'need', 'not', 'no',
    'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as',
    'into', 'through', 'during', 'before', 'after', 'between', 'out',
    'off', 'over', 'under', 'and', 'but', 'or', 'nor', 'so', 'very',
    'just', 'that', 'this', 'these', 'those', 'it', 'its', 'they',
    'them', 'their', 'we', 'our', 'you', 'your', 'all', 'each',
    'every', 'both', 'few', 'more', 'most', 'other', 'some', 'such',
    'only', 'own', 'same', 'than', 'too', 'also', 'new', 'one', 'two',
    // SOC noise — common in ticket titles but not analytically meaningful
    'alert', 'alerts', 'detected', 'detection', 'detections', 'event',
    'events', 'notification', 'incident', 'ticket', 'case', 'rule',
    'triggered', 'found', 'observed', 'reported', 'see', 'via', 'using',
    'within', 'unknown', 'none', 'null', 'undefined', 'test', 'true',
    'false', 'high', 'medium', 'low', 'critical', 'severity', 'status',
]);

// Helper function to strip team name prefix from ticket types
function stripTeamPrefix(ticketType) {
    const teamName = appConfig.team_name || 'TEAM';
    const regex = new RegExp(`^${teamName}[_\\-\\s]*`, 'i');
    return ticketType.startsWith(teamName) ? ticketType.replace(regex, '') : ticketType;
}

// Helper function to strip email domain from owner
function stripEmailDomain(owner) {
    const emailDomain = appConfig.email_domain || 'example.com';
    return owner.endsWith('@' + emailDomain) ? owner.replace('@' + emailDomain, '') : owner;
}

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

    // Period B overlay
    const geoTraces = [trace];
    if (state.comparisonData) {
        const bCounts = {};
        state.comparisonData.forEach(item => { const c = item.affected_country || 'Unknown'; bCounts[c] = (bCounts[c] || 0) + 1; });
        const bTrace = {
            x: sortedEntries.map(([country]) => bCounts[country] || 0).reverse(),
            y: sortedEntries.map(([country]) => country).reverse(),
            type: 'bar', orientation: 'h', name: 'Period B',
            opacity: 0.45,
            text: sortedEntries.map(([country]) => bCounts[country] || 0).reverse(),
            textposition: 'inside', textfont: {color: 'white', size: 11},
            marker: { color: '#a78bfa', line: {color: 'rgba(255,255,255,0.8)', width: 1} },
            hovertemplate: '<b>%{y}</b><br>Period B: %{x}<extra></extra>'
        };
        geoTraces.push(bTrace);
        layout.barmode = 'group';
    }

    safePlot('geoChart', geoTraces, layout);
    attachClickHandler('geoChart', 'country', pt => pt.y);
    attachDrawerHandler('geoChart', 'Country', pt => pt.y, (item, label) => item.affected_country === label);
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

    // Adapt tick interval and format to the date span
    const spanMs = allDates.length > 1
        ? new Date(allDates[allDates.length - 1]) - new Date(allDates[0])
        : 0;
    const spanDays = spanMs / 86400000;
    let dtick, tickformat;
    if (spanDays <= 14) {
        dtick = 86400000;          // every day
        tickformat = '%m/%d';
    } else if (spanDays <= 60) {
        dtick = 86400000 * 2;      // every 2 days
        tickformat = '%m/%d';
    } else if (spanDays <= 180) {
        dtick = 86400000 * 7;      // weekly
        tickformat = '%b %d';
    } else {
        dtick = 'M1';              // monthly
        tickformat = '%b %Y';
    }

    const layout = commonLayout({
        legend: {x: 0.5, y: -0.2, xanchor: 'center', orientation: 'h'},
        margin: {l: 50, r: 10, t: 30, b: 40},
        yaxis: {title: 'Number of Cases', gridcolor: getChartColors().grid},
        xaxis: {
            type: 'date',
            gridcolor: getChartColors().grid,
            tickangle: spanDays > 60 ? 45 : 90,
            tickformat: tickformat,
            dtick: dtick
        }
    });

    // Period B overlay — dashed lines
    if (state.comparisonData) {
        const bInflow = {}, bOutflow = {};
        state.comparisonData.forEach(item => {
            if (item.owner && item.owner.trim() !== '') {
                if (item.created && item.created.trim() !== '') {
                    const d = new Date(item.created);
                    if (!isNaN(d.getTime()) && d.getFullYear() >= 2020) {
                        const dt = d.toISOString().split('T')[0];
                        bInflow[dt] = (bInflow[dt] || 0) + 1;
                    }
                }
                if (item.closed && item.closed.trim() !== '') {
                    const d = new Date(item.closed);
                    if (!isNaN(d.getTime()) && d.getFullYear() >= 2020) {
                        const dt = d.toISOString().split('T')[0];
                        bOutflow[dt] = (bOutflow[dt] || 0) + 1;
                    }
                }
            }
        });
        const bDates = [...new Set([...Object.keys(bInflow), ...Object.keys(bOutflow)])].sort();
        traces.push({
            x: bDates, y: bDates.map(d => bInflow[d] || 0),
            type: 'scatter', mode: 'lines', name: 'Inflow (B)',
            line: {color: '#007bff', width: 2, dash: 'dash'}, opacity: 0.5,
            hovertemplate: '<b>%{x}</b><br>Period B Created: %{y}<extra></extra>'
        });
        traces.push({
            x: bDates, y: bDates.map(d => bOutflow[d] || 0),
            type: 'scatter', mode: 'lines', name: 'Outflow (B)',
            line: {color: '#28a745', width: 2, dash: 'dash'}, opacity: 0.5,
            hovertemplate: '<b>%{x}</b><br>Period B Closed: %{y}<extra></extra>'
        });
    }

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
    attachClickHandler('ticketTypeChart', 'impact', pt => pt.label);
}

export function createTicketTypeChart() {
    const counts = {};
    state.filteredData.forEach(item => {
        const ticketType = item.type || 'Unknown';
        counts[ticketType] = (counts[ticketType] || 0) + 1;
    });

    const sortedEntries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const trace = {
        labels: sortedEntries.map(([ticketType]) => stripTeamPrefix(ticketType)),
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
    // Map stripped label back to raw type for filter
    const labelToRaw = Object.fromEntries(sortedEntries.map(([t]) => [stripTeamPrefix(t), t]));
    attachClickHandler('severityChart', 'ticketType', pt => labelToRaw[pt.label] || pt.label);
}

export function createOwnerChart() {
    const counts = {};
    state.filteredData.forEach(item => {
        if (item.owner && item.owner.trim() !== '') {
            let owner = stripEmailDomain(item.owner);
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

    // Period B overlay
    const ownerTraces = [trace];
    if (state.comparisonData) {
        const bCounts = {};
        state.comparisonData.forEach(item => { if (item.owner && item.owner.trim() !== '') { let o = stripEmailDomain(item.owner); bCounts[o] = (bCounts[o] || 0) + 1; } });
        ownerTraces.push({
            x: sortedEntries.map(([owner]) => bCounts[owner] || 0).reverse(),
            y: sortedEntries.map(([owner]) => owner).reverse(),
            type: 'bar', orientation: 'h', name: 'Period B', opacity: 0.45,
            text: sortedEntries.map(([owner]) => bCounts[owner] || 0).reverse(),
            textposition: 'inside', textfont: {color: 'white', size: 11},
            marker: { color: '#a78bfa', line: {color: 'rgba(255,255,255,0.8)', width: 1} },
            hovertemplate: '<b>%{y}</b><br>Period B: %{x}<extra></extra>'
        });
        layout.barmode = 'group';
    }

    safePlot('heatmapChart', ownerTraces, layout);
    attachDrawerHandler('heatmapChart', 'Owner', pt => pt.y, (item, label) => item.owner === label);
}

export function createFunnelChart() {
    const totalCases = state.filteredData.length;
    const assignedCases = state.filteredData.filter(i => i.owner && i.owner.trim() !== '').length;
    const maliciousTruePositives = state.filteredData.filter(i => i.impact === 'Malicious True Positive').length;

    let textValues;
    if (state.comparisonData) {
        const bTotal = state.comparisonData.length;
        const bAssigned = state.comparisonData.filter(i => i.owner && i.owner.trim() !== '').length;
        const bMTP = state.comparisonData.filter(i => i.impact === 'Malicious True Positive').length;
        textValues = [
            `${totalCases} vs ${bTotal}`,
            `${assignedCases} vs ${bAssigned}`,
            `${maliciousTruePositives} vs ${bMTP}`
        ];
    }

    const trace = {
        type: 'funnel',
        y: ['All Cases', 'Assigned Cases', 'Malicious True Positive'],
        x: [totalCases, assignedCases, maliciousTruePositives],
        textinfo: state.comparisonData ? 'text' : 'value+percent initial',
        text: textValues,
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

    // Period B overlay
    const hostTraces = [trace];
    if (state.comparisonData) {
        const bCounts = {};
        state.comparisonData.forEach(item => { const h = item.hostname || 'Unknown'; if (h !== 'Unknown') bCounts[h] = (bCounts[h] || 0) + 1; });
        hostTraces.push({
            x: sortedEntries.map(([h]) => bCounts[h] || 0).reverse(),
            y: sortedEntries.map(([h]) => h).reverse(),
            type: 'bar', orientation: 'h', name: 'Period B', opacity: 0.45,
            text: sortedEntries.map(([h]) => bCounts[h] || 0).reverse(),
            textposition: 'inside', textfont: {color: 'white', size: 11},
            marker: { color: '#a78bfa', line: {color: 'rgba(255,255,255,0.8)', width: 1} },
            hovertemplate: '<b>%{y}</b><br>Period B: %{x}<extra></extra>'
        });
        layout.barmode = 'group';
    }

    safePlot('topHostsChart', hostTraces, layout);
    attachDrawerHandler('topHostsChart', 'Host', pt => pt.y, (item, label) => item.hostname === label);
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

    // Period B overlay
    const userTraces = [trace];
    if (state.comparisonData) {
        const bCounts = {};
        state.comparisonData.forEach(item => { const u = item.username || 'Unknown'; if (u !== 'Unknown') bCounts[u] = (bCounts[u] || 0) + 1; });
        userTraces.push({
            x: sortedEntries.map(([u]) => bCounts[u] || 0).reverse(),
            y: sortedEntries.map(([u]) => u).reverse(),
            type: 'bar', orientation: 'h', name: 'Period B', opacity: 0.45,
            text: sortedEntries.map(([u]) => bCounts[u] || 0).reverse(),
            textposition: 'inside', textfont: {color: 'white', size: 11},
            marker: { color: '#a78bfa', line: {color: 'rgba(255,255,255,0.8)', width: 1} },
            hovertemplate: '<b>%{y}</b><br>Period B: %{x}<extra></extra>'
        });
        layout.barmode = 'group';
    }

    safePlot('topUsersChart', userTraces, layout);
    attachDrawerHandler('topUsersChart', 'User', pt => pt.y, (item, label) => item.username === label);
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
        y: sortedEntries.map(([type]) => stripTeamPrefix(type)).reverse(),
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

    // Period B overlay
    const resTraces = [trace];
    if (state.comparisonData) {
        const bAvg = {}, bCnt = {};
        state.comparisonData.forEach(item => {
            if (item.type && item.resolution_time_days != null && item.resolution_time_days > 0) {
                if (!bAvg[item.type]) bAvg[item.type] = 0;
                if (!bCnt[item.type]) bCnt[item.type] = 0;
                bAvg[item.type] += item.resolution_time_days;
                bCnt[item.type]++;
            }
        });
        Object.keys(bAvg).forEach(t => { bAvg[t] = bAvg[t] / bCnt[t]; });
        resTraces.push({
            x: sortedEntries.map(([type]) => (bAvg[type] || 0).toFixed(1)).reverse(),
            y: sortedEntries.map(([type]) => stripTeamPrefix(type)).reverse(),
            type: 'bar', orientation: 'h', name: 'Period B', opacity: 0.45,
            text: sortedEntries.map(([type]) => (bAvg[type] || 0).toFixed(1) + 'd').reverse(),
            textposition: 'inside', textfont: {color: 'white', size: 11},
            marker: { color: '#a78bfa', line: {color: 'rgba(255,255,255,0.8)', width: 1} },
            hovertemplate: '<b>%{y}</b><br>Period B Avg: %{x} days<extra></extra>'
        });
        layout.barmode = 'group';
    }

    safePlot('resolutionTimeChart', resTraces, layout);
}

export function createWordCloudChart() {
    const wordCounts = {};
    const teamName = (appConfig.team_name || '').toLowerCase();

    state.filteredData.forEach(item => {
        const name = item.name || '';
        const words = name.toLowerCase().match(/[a-z]{3,}/g) || [];
        words.forEach(word => {
            if (!WORD_CLOUD_STOP_WORDS.has(word) && word !== teamName) {
                wordCounts[word] = (wordCounts[word] || 0) + 1;
            }
        });
    });

    const el = document.getElementById('wordCloudChart');
    if (!el) return;

    const entries = Object.entries(wordCounts).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
        el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No keyword data available</div>';
        return;
    }

    const topWords = entries.slice(0, 60);
    const maxCount = topWords[0][1];
    const minCount = topWords[topWords.length - 1][1];
    const range = maxCount - minCount || 1;

    // Position words in a golden-angle spiral
    const goldenAngle = 137.508 * (Math.PI / 180);
    const xPos = [];
    const yPos = [];
    const textLabels = [];
    const sizes = [];
    const colors = [];
    const hoverTexts = [];
    const allColors = [...COLOR_SCHEMES.countries, ...COLOR_SCHEMES.sources];

    topWords.forEach(([word, count], i) => {
        const angle = i * goldenAngle;
        const radius = Math.sqrt(i + 1) * 0.8;
        xPos.push(radius * Math.cos(angle));
        yPos.push(radius * Math.sin(angle));
        textLabels.push(word);
        const normalized = (count - minCount) / range;
        sizes.push(10 + normalized * 22);
        colors.push(allColors[i % allColors.length]);
        hoverTexts.push(`<b>${word}</b><br>Occurrences: ${count}`);
    });

    const trace = {
        x: xPos,
        y: yPos,
        text: textLabels,
        mode: 'text',
        type: 'scatter',
        textfont: {
            size: sizes,
            color: colors,
            family: 'Segoe UI, sans-serif'
        },
        hovertext: hoverTexts,
        hoverinfo: 'text',
        hoverlabel: {bgcolor: 'white', font: {size: 13}}
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 10, r: 10, t: 10, b: 10},
        xaxis: {
            showgrid: false, showticklabels: false, zeroline: false,
            showline: false, visible: false
        },
        yaxis: {
            showgrid: false, showticklabels: false, zeroline: false,
            showline: false, visible: false, scaleanchor: 'x'
        },
        hovermode: 'closest'
    });

    safePlot('wordCloudChart', [trace], layout);
}

export function createNotesWordCloudChart() {
    const wordCounts = {};
    const teamName = (appConfig.team_name || '').toLowerCase();

    state.filteredData.forEach(item => {
        // Collect text from close notes
        const closeNotes = item.closeNotes || '';
        // Collect text from user notes (if enriched)
        const userNotes = (item.notes || [])
            .filter(n => n && typeof n === 'object' && n.note_text)
            .map(n => n.note_text)
            .join(' ');

        const allText = (closeNotes + ' ' + userNotes).toLowerCase();
        const words = allText.match(/[a-z]{3,}/g) || [];
        words.forEach(word => {
            if (!WORD_CLOUD_STOP_WORDS.has(word) && word !== teamName) {
                wordCounts[word] = (wordCounts[word] || 0) + 1;
            }
        });
    });

    const el = document.getElementById('notesWordCloudChart');
    if (!el) return;

    const entries = Object.entries(wordCounts).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
        el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No notes data available</div>';
        return;
    }

    const topWords = entries.slice(0, 60);
    const maxCount = topWords[0][1];
    const minCount = topWords[topWords.length - 1][1];
    const range = maxCount - minCount || 1;

    const goldenAngle = 137.508 * (Math.PI / 180);
    const xPos = [];
    const yPos = [];
    const textLabels = [];
    const sizes = [];
    const colors = [];
    const hoverTexts = [];
    const allColors = [...COLOR_SCHEMES.sources, ...COLOR_SCHEMES.countries];

    topWords.forEach(([word, count], i) => {
        const angle = i * goldenAngle;
        const radius = Math.sqrt(i + 1) * 0.8;
        xPos.push(radius * Math.cos(angle));
        yPos.push(radius * Math.sin(angle));
        textLabels.push(word);
        const normalized = (count - minCount) / range;
        sizes.push(10 + normalized * 22);
        colors.push(allColors[i % allColors.length]);
        hoverTexts.push(`<b>${word}</b><br>Occurrences: ${count}`);
    });

    const trace = {
        x: xPos,
        y: yPos,
        text: textLabels,
        mode: 'text',
        type: 'scatter',
        textfont: {
            size: sizes,
            color: colors,
            family: 'Segoe UI, sans-serif'
        },
        hovertext: hoverTexts,
        hoverinfo: 'text',
        hoverlabel: {bgcolor: 'white', font: {size: 13}}
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 10, r: 10, t: 10, b: 10},
        xaxis: {
            showgrid: false, showticklabels: false, zeroline: false,
            showline: false, visible: false
        },
        yaxis: {
            showgrid: false, showticklabels: false, zeroline: false,
            showline: false, visible: false, scaleanchor: 'x'
        },
        hovermode: 'closest'
    });

    safePlot('notesWordCloudChart', [trace], layout);
}

export function createDayHourHeatmap() {
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    // Initialize 7x24 grid
    const grid = Array.from({length: 7}, () => new Array(24).fill(0));

    state.filteredData.forEach(item => {
        if (!item.created) return;
        const d = new Date(item.created);
        if (isNaN(d.getTime())) return;
        grid[d.getDay()][d.getHours()]++;
    });

    const zData = grid; // rows = days (0=Sun..6=Sat), cols = hours (0-23)
    const hours = Array.from({length: 24}, (_, i) => `${i.toString().padStart(2, '0')}:00`);

    const trace = {
        z: zData,
        x: hours,
        y: days,
        type: 'heatmap',
        colorscale: [
            [0, '#f0f4ff'],
            [0.25, '#93c5fd'],
            [0.5, '#3b82f6'],
            [0.75, '#1d4ed8'],
            [1, '#1e3a8a']
        ],
        hovertemplate: '<b>%{y} %{x}</b><br>Incidents: %{z}<extra></extra>',
        showscale: true,
        colorbar: {
            title: {text: 'Count', font: {size: 11, color: getChartColors().font}},
            tickfont: {color: getChartColors().font}
        }
    };

    const layout = commonLayout({
        showlegend: false,
        margin: {l: 50, r: 80, t: 20, b: 50},
        xaxis: {
            title: 'Hour of Day',
            dtick: 1,
            gridcolor: getChartColors().grid,
            side: 'bottom'
        },
        yaxis: {
            gridcolor: getChartColors().grid,
            autorange: 'reversed'
        }
    });

    safePlot('dayHourHeatmap', [trace], layout);
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
    createWordCloudChart();
    createNotesWordCloudChart();
    createDayHourHeatmap();
}
