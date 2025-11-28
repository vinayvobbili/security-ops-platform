/**
 * Theme management and chart styling
 */

import {PLOTLY_CONFIG} from './config.js';

// Plotly is loaded from CDN
/* global Plotly */

/**
 * Check if dark mode is active
 */
export function isDarkMode() {
    return document.body.classList.contains('dark-mode');
}

/**
 * Get chart colors based on current theme
 */
export function getChartColors() {
    if (!isDarkMode()) {
        return {
            font: '#1f2937',
            grid: 'rgba(148,163,184,0.3)',
            legendBg: 'rgba(255,255,255,0.95)',
            axisLine: '#6b7280'
        };
    }
    return {
        font: '#e2e8f0',
        grid: 'rgba(148,163,184,0.18)',
        legendBg: 'rgba(30,41,59,0.85)',
        axisLine: '#475569'
    };
}

/**
 * Create common layout for charts with theme support
 */
export function commonLayout(extra = {}) {
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

/**
 * Adapt single chart to current theme
 */
export function adaptChartTheme(chartId) {
    const el = document.getElementById(chartId);
    if (!el || !el.data || !el.layout) return;

    const c = getChartColors();
    const newLayout = JSON.parse(JSON.stringify(el.layout));

    newLayout.font = newLayout.font || {};
    newLayout.font.color = c.font;

    if (newLayout.legend) {
        newLayout.legend.bgcolor = c.legendBg;
    }

    ['xaxis', 'yaxis'].forEach(axis => {
        if (newLayout[axis]) {
            newLayout[axis].gridcolor = c.grid;
            newLayout[axis].linecolor = c.axisLine;
            newLayout[axis].zerolinecolor = c.grid;
        }
    });

    const newData = JSON.parse(JSON.stringify(el.data));
    newData.forEach(trace => {
        if (trace.textfont && trace.textfont.color !== 'white') {
            trace.textfont.color = c.font;
        }
    });

    try {
        Plotly.react(el, newData, newLayout, PLOTLY_CONFIG);
    } catch (e) {
        try {
            Plotly.relayout(el, newLayout);
        } catch (_) {
            // Fallback failed, ignore
        }
    }
}

/**
 * Adapt all charts to current theme
 */
export function adaptAllChartsTheme() {
    const chartIds = [
        'geoChart',
        'severityChart',
        'timelineChart',
        'ticketTypeChart',
        'heatmapChart',
        'funnelChart',
        'topHostsChart',
        'topUsersChart',
        'resolutionTimeChart'
    ];
    chartIds.forEach(id => adaptChartTheme(id));
}

/**
 * Initialize theme change listener
 */
export function initThemeListener() {
    window.addEventListener('themechange', () => {
        adaptAllChartsTheme();
    });
}
