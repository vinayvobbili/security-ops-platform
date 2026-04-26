/**
 * Metrics calculation and display
 * Handles metric cards with KPIs like MTTR, MTTC, SLA breaches, etc.
 */

import {state} from './state.js';

// Feature flags for delta values and tooltips
const should_show_delta_values = true;
const should_show_card_tooltips = true;

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
    // Detect custom date mode
    const customStartEl = document.getElementById('customDateStart');
    const customEndEl = document.getElementById('customDateEnd');
    const customMode = document.getElementById('dateCustomMode');
    const useCustom = customStartEl && customEndEl && customStartEl.value && customEndEl.value &&
        customMode && customMode.style.display !== 'none';

    let dateRange;
    let currentPeriodStart, previousPeriodStart, previousPeriodEnd;

    if (useCustom) {
        const cStart = new Date(customStartEl.value + 'T00:00:00');
        const cEnd = new Date(customEndEl.value + 'T23:59:59');
        dateRange = Math.round((cEnd - cStart) / 86400000);
        currentPeriodStart = cStart;
        previousPeriodEnd = new Date(cStart);
        previousPeriodStart = new Date(cStart);
        previousPeriodStart.setDate(previousPeriodStart.getDate() - dateRange);
    } else {
        const dateSlider = document.getElementById('dateRangeSlider');
        dateRange = parseInt(dateSlider.value) || 30;
        const now = new Date();
        currentPeriodStart = new Date(now);
        currentPeriodStart.setDate(currentPeriodStart.getDate() - dateRange);
        previousPeriodEnd = new Date(currentPeriodStart);
        previousPeriodStart = new Date(currentPeriodStart);
        previousPeriodStart.setDate(previousPeriodStart.getDate() - dateRange);
    }

    // For very long periods, skip comparison — not enough prior data
    if (dateRange > 180) {
        return null;
    }

    // Filter data for previous period
    const previousPeriodData = state.allData.filter(item => {
        const createdDate = new Date(item.created);
        return createdDate >= previousPeriodStart && createdDate < previousPeriodEnd;
    });

    // Only return metrics if we have reasonable data in the previous period
    if (previousPeriodData.length < 2) {
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
 * Generate an inline SVG sparkline from an array of daily values.
 * Returns an HTML string for an SVG element, or '' if insufficient data.
 */
function createSparkline(dailyValues, color = 'var(--text-primary)') {
    if (!dailyValues || dailyValues.length < 2) return '';

    const width = 120;
    const height = 36;
    const padding = 2;

    const max = Math.max(...dailyValues);
    const min = Math.min(...dailyValues);
    const range = max - min || 1;

    const points = dailyValues.map((v, i) => {
        const x = padding + (i / (dailyValues.length - 1)) * (width - 2 * padding);
        const y = height - padding - ((v - min) / range) * (height - 2 * padding);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');

    return `<svg class="sparkline" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
        <polyline points="${points}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
}

/**
 * Build daily time series from filtered data for sparklines.
 * Returns an object with arrays keyed by metric name.
 */
function buildDailyTimeSeries() {
    const byDate = {};

    state.filteredData.forEach(item => {
        if (!item.created) return;
        const d = new Date(item.created);
        if (isNaN(d.getTime())) return;
        const key = d.toISOString().split('T')[0];
        if (!byDate[key]) byDate[key] = {total: 0, mttrSum: 0, mttrCount: 0, mttcSum: 0, mttcCount: 0, breaches: 0, open: 0};
        byDate[key].total++;
        if (item.time_to_respond_secs > 0) {
            byDate[key].mttrSum += item.time_to_respond_secs;
            byDate[key].mttrCount++;
        }
        if (item.has_hostname && item.time_to_contain_secs > 0) {
            byDate[key].mttcSum += item.time_to_contain_secs;
            byDate[key].mttcCount++;
        }
        if (item.has_breached_response_sla) byDate[key].breaches++;
        if (item.is_open) byDate[key].open++;
    });

    const sortedDates = Object.keys(byDate).sort();
    return {
        total: sortedDates.map(d => byDate[d].total),
        mttr: sortedDates.map(d => byDate[d].mttrCount > 0 ? byDate[d].mttrSum / byDate[d].mttrCount / 60 : 0),
        mttc: sortedDates.map(d => byDate[d].mttcCount > 0 ? byDate[d].mttcSum / byDate[d].mttcCount / 60 : 0),
        breaches: sortedDates.map(d => byDate[d].breaches),
        open: sortedDates.map(d => byDate[d].open)
    };
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

    // Build sparkline data
    const spark = buildDailyTimeSeries();

    document.getElementById('metricsGrid').innerHTML = `
        <div class="metric-card">
            <div class="metric-title">🎫 Total Cases</div>
            <div class="metric-value">
                ${currentMetrics.totalIncidents.toLocaleString()}<br>
                ${createDeltaBadge(currentMetrics.totalIncidents, previousMetrics?.totalIncidents, false, true)}
            </div>
            ${createSparkline(spark.total, '#3b82f6')}
        </div>
        <div class="metric-card">
            <div class="metric-title">⏱️ MTTR (mins:secs)</div>
            <div class="metric-value">
                ${mttrFormatted}<br>
                ${createDeltaBadge(currentMetrics.mttr, previousMetrics?.mttr, false, true, true)}
            </div>
            ${createSparkline(spark.mttr, '#f59e0b')}
            <div class="metric-subtitle">${currentMetrics.casesWithOwnerAndTimeToRespond} cases acknowledged</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🔒 MTTC (mins:secs)</div>
            <div class="metric-value">
                ${mttcFormatted}<br>
                ${createDeltaBadge(currentMetrics.mttc, previousMetrics?.mttc, false, true, true)}
            </div>
            ${createSparkline(spark.mttc, '#8b5cf6')}
            <div class="metric-subtitle">${currentMetrics.casesWithOwnerAndTimeToContain} cases with hostnames</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">🚨 Response SLA Breaches</div>
            <div class="metric-value">
                ${currentMetrics.responseSlaBreaches.toLocaleString()}<br>
                ${createDeltaBadge(currentMetrics.responseSlaBreaches, previousMetrics?.responseSlaBreaches, false, true)}
            </div>
            ${createSparkline(spark.breaches, '#ef4444')}
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
            ${createSparkline(spark.open, '#10b981')}
        </div>
        <div class="metric-card">
            <div class="metric-title">🌍 Total Countries</div>
            <div class="metric-value">
                ${currentMetrics.uniqueCountries}<br>
                ${createDeltaBadge(currentMetrics.uniqueCountries, previousMetrics?.uniqueCountries, false, true)}
            </div>
        </div>
    `;

    // Period B comparison overlay
    if (state.comparisonData && window.ComparisonMode) {
        const compMetrics = calculatePeriodMetrics(state.comparisonData);
        const compMttr = formatTime(compMetrics.mttr);
        const compMttc = formatTime(compMetrics.mttc);
        const CM = window.ComparisonMode;

        const cards = document.querySelectorAll('#metricsGrid .metric-card');
        const compData = [
            CM.kpiComparisonHtml(currentMetrics.totalIncidents, compMetrics.totalIncidents, {invertedGood: true}),
            CM.kpiComparisonHtml(mttrFormatted, compMttr, {invertedGood: true}),
            CM.kpiComparisonHtml(mttcFormatted, compMttc, {invertedGood: true}),
            CM.kpiComparisonHtml(currentMetrics.responseSlaBreaches, compMetrics.responseSlaBreaches, {invertedGood: true}),
            CM.kpiComparisonHtml(currentMetrics.containmentSlaBreaches, compMetrics.containmentSlaBreaches, {invertedGood: true}),
            CM.kpiComparisonHtml(currentMetrics.openIncidents, compMetrics.openIncidents, {invertedGood: true}),
            CM.kpiComparisonHtml(currentMetrics.uniqueCountries, compMetrics.uniqueCountries, {})
        ];
        cards.forEach(function (card, i) {
            if (compData[i]) {
                var valueEl = card.querySelector('.metric-value');
                if (valueEl) valueEl.insertAdjacentHTML('beforeend', compData[i]);
            }
        });
    }

    // Goal target badges
    if (window.GoalTargets) {
        const targets = window.GoalTargets.getTargets();
        const cards = document.querySelectorAll('#metricsGrid .metric-card');
        // MTTR card (index 1)
        if (cards[1] && targets.mttr_secs != null) {
            const badge = window.GoalTargets.kpiTargetBadge(currentMetrics.mttr, targets.mttr_secs, {lowerIsBetter: true, unit: 's'});
            if (badge) cards[1].querySelector('.metric-title').insertAdjacentHTML('beforeend', ' ' + badge);
        }
        // MTTC card (index 2)
        if (cards[2] && targets.mttc_secs != null) {
            const badge = window.GoalTargets.kpiTargetBadge(currentMetrics.mttc, targets.mttc_secs, {lowerIsBetter: true, unit: 's'});
            if (badge) cards[2].querySelector('.metric-title').insertAdjacentHTML('beforeend', ' ' + badge);
        }
        // Response SLA Breaches (index 3) - target 0
        if (cards[3] && targets.response_sla_breaches != null) {
            const badge = window.GoalTargets.kpiTargetBadge(currentMetrics.responseSlaBreaches, targets.response_sla_breaches, {lowerIsBetter: true});
            if (badge) cards[3].querySelector('.metric-title').insertAdjacentHTML('beforeend', ' ' + badge);
        }
    }

    // Show metrics grid header
    const hdr = document.getElementById('metricsGridHeader');
    if (hdr) hdr.style.display = 'flex';
}
