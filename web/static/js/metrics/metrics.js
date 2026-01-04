/**
 * Metrics calculation and display
 * Handles metric cards with KPIs like MTTR, MTTC, SLA breaches, etc.
 */

import {state} from './state.js';

// Feature flags for delta values and tooltips
const should_show_delta_values = false;
const should_show_card_tooltips = false;

/**
 * Calculate metrics for a given data set
 */
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

/**
 * Calculate metrics for the previous period for comparison
 */
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
    const previousPeriodData = state.allData.filter(item => {
        const createdDate = new Date(item.created);
        return createdDate >= previousPeriodStart && createdDate < previousPeriodEnd;
    });

    // Only return metrics if we have reasonable data in the previous period
    if (previousPeriodData.length < 5) {
        return null; // Not enough data for meaningful comparison
    }

    return calculatePeriodMetrics(previousPeriodData);
}

/**
 * Create a delta badge showing change from previous period
 */
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

/**
 * Update metric cards display
 */
export function updateMetrics() {
    // Calculate current period metrics
    const currentMetrics = calculatePeriodMetrics(state.filteredData);

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
