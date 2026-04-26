/**
 * XSOAR Ticket Timeline — Animated Bar Chart Race (D3)
 *
 * D3-powered horizontal bar chart race that animates week-by-week across
 * 3+ years of XSOAR ticket data. Bars smoothly glide up/down as ranks
 * change, with simultaneous width transitions. Cumulative trend uses Plotly.
 *
 * Dimensions: Severity, Security Categories, Affected Regions, Ticket Types, Impact
 */

import { isDarkMode, getChartColors, commonLayout } from './theme.js';
import { PLOTLY_CONFIG } from './config.js';

/* global d3, Plotly */

// ---- State ----
let timelineData = null;
let currentDimension = 'type';
let currentMonthIndex = 0;
let animationTimer = null;
let isPlaying = false;
let speed = 1000;
let isLoaded = false;
let granularity = 'monthly';

const MAX_CUMULATIVE_LINES = 15;
const ALL_DIMENSIONS = ['type', 'impact', 'severity', 'category', 'region'];

// ---- D3 Race Chart State ----
let raceSvg = null;
let raceX = null;
let raceY = null;
let raceBarsG = null;
let raceAxisG = null;
let racePeriodLabel = null;

const BAR_HEIGHT = 38;
const RACE_MARGIN = { top: 10, right: 60, bottom: 30, left: 220 };

// ---- Stable color maps per dimension ----
const dimensionColorMaps = {};
const dimensionStableNames = {};

function buildColorMaps() {
    if (!timelineData) return;
    for (const dim of ALL_DIMENSIONS) {
        const data = timelineData[dim];
        if (!data) continue;
        const totals = {};
        for (const period of (data.periods || data.months || [])) {
            for (const item of (data.series[period] || [])) {
                totals[item.name] = (totals[item.name] || 0) + item.count;
            }
        }
        const ranked = Object.entries(totals).sort((a, b) => b[1] - a[1]);
        const colorMap = {};
        ranked.forEach(([name], i) => {
            colorMap[name] = getBaseColor(name, dim, i);
        });
        colorMap['Other'] = '#94a3b8';
        dimensionColorMaps[dim] = colorMap;
        dimensionStableNames[dim] = ranked.map(d => d[0]);
    }
}

// ---- Color Palettes ----

const SEVERITY_COLORS = {
    'Unknown': '#94a3b8',
    'Low':      '#3b82f6',
    'Medium':   '#f59e0b',
    'High':     '#f97316',
    'Critical': '#ef4444',
};

const PALETTE = [
    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
    '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
    '#14b8a6', '#e11d48', '#a855f7', '#0ea5e9', '#d946ef',
];

const IMPACT_COLORS = {
    'Benign True Positive':  '#10b981',
    'True Positive':         '#3b82f6',
    'False Positive':        '#94a3b8',
    'Malicious True Positive': '#ef4444',
    'Unknown':               '#6b7280',
};

function getBaseColor(name, dimension, index) {
    if (dimension === 'severity') return SEVERITY_COLORS[name] || '#94a3b8';
    if (dimension === 'impact') return IMPACT_COLORS[name] || PALETTE[index % PALETTE.length];
    return PALETTE[index % PALETTE.length];
}

function getColor(name, dimension) {
    const map = dimensionColorMaps[dimension];
    if (map && map[name]) return map[name];
    return '#94a3b8';
}

// ---- Logo mapping (ticket type → logo file in /static/logos/) ----
const TYPE_LOGOS = {
    'crowdstrike falcon detection': 'crowdstrike.png',
    'crowdstrike falcon incident':  'crowdstrike.png',
    'third party compromise':       'third_party.png',
    'qradar alert':                 'qradar.png',
    'prisma cloud compute runtime alert': 'prisma_cloud.png',
    'prisma cloud runtime alert':   'prisma_cloud.png',
    'ueba prisma cloud':            'prisma_cloud.png',
    'ioc hunt':                     'ioc_hunt.png',
    'case':                         'case.png',
    'akamai alert':                 'akamai.png',
    'vectra detection':             'vectra.png',
    'splunk alert':                 'splunk.png',
    'lost or stolen computer':      'lost_stolen_device.png',
    'employee reported incident':   'employee_report.png',
    'leaked credentials':           'leaked_credentials.png',
    'area1 alert':                  'area1.png',
    'varonis alert':                'varonis.png',
    'sdm escalation':               'unknown.png',
};

// Width multiplier for wide/landscape logos (default is 1 = square)
const LOGO_SCALE = {
    'varonis alert':                2.5,
    'akamai alert':                 2,
    'area1 alert':                  2,
    'splunk alert':                 1.5,
    'prisma cloud compute runtime alert': 1.8,
    'prisma cloud runtime alert':   1.8,
    'ueba prisma cloud':            1.8,
    'qradar alert':                 1.2,
    'leaked credentials':           1.4,
};

function getLogoUrl(name) {
    const file = TYPE_LOGOS[name.toLowerCase()] || 'unknown.png';
    return `/static/logos/${file}`;
}

function getLogoWidth(name, baseSize) {
    const scale = LOGO_SCALE[name.toLowerCase()] || 1;
    return Math.round(baseSize * scale);
}

// ---- Helpers ----

function getPeriods() {
    if (!timelineData || !timelineData[currentDimension]) return [];
    const d = timelineData[currentDimension];
    return d.periods || d.months || [];
}

const getMonths = getPeriods;

function getFrameData(monthIndex) {
    const months = getPeriods();
    if (monthIndex < 0 || monthIndex >= months.length) return [];
    const period = months[monthIndex];
    const series = timelineData[currentDimension].series || {};
    const items = series[period] || [];

    const countMap = {};
    for (const item of items) {
        countMap[item.name] = (countMap[item.name] || 0) + item.count;
    }

    const stableNames = dimensionStableNames[currentDimension] || [];
    return stableNames.map(name => ({ name, count: countMap[name] || 0 }));
}

function formatPeriod(periodStr) {
    if (!periodStr) return '—';
    if (periodStr.includes('W')) {
        const [y, w] = periodStr.split('-W');
        return `W${parseInt(w, 10)} ${y}`;
    }
    const [y, m] = periodStr.split('-');
    const names = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return `${names[parseInt(m, 10) - 1]} ${y}`;
}

const formatMonth = formatPeriod;

// ---- Data Fetching ----

async function fetchTimelineData() {
    try {
        const resp = await fetch(`/api/xsoar/timeline?granularity=${granularity}`);
        const result = await resp.json();
        if (!result.success) {
            console.error('Timeline API error:', result.error);
            return false;
        }
        if (!result.has_data) {
            showNoData();
            return false;
        }
        timelineData = result.data;
        buildColorMaps();
        populateSummary(result.meta);
        return true;
    } catch (err) {
        console.error('Failed to fetch timeline data:', err);
        return false;
    }
}

function showNoData() {
    const content = document.getElementById('xtContent');
    if (content) {
        content.innerHTML = '<div class="xt-no-data">No timeline data available. Run the backfill script on lab-vm to populate historical data.</div>';
        content.style.display = 'block';
    }
}

function populateSummary(meta) {
    if (!meta) return;
    const totalEl = document.getElementById('xtTotalTickets');
    const rangeEl = document.getElementById('xtDateRange');
    const syncEl = document.getElementById('xtLastSync');

    if (totalEl) totalEl.textContent = (meta.ticket_count || 0).toLocaleString();
    if (rangeEl && meta.date_range) {
        const earliest = meta.date_range.earliest ? meta.date_range.earliest.substring(0, 10) : '?';
        const latest = meta.date_range.latest ? meta.date_range.latest.substring(0, 10) : '?';
        rangeEl.textContent = `${earliest} — ${latest}`;
    }
    if (syncEl && meta.last_synced_at) {
        syncEl.textContent = meta.last_synced_at.substring(0, 16).replace('T', ' ');
    }
}

// ---- D3 Bar Chart Race ----

function getBarCount() {
    const names = dimensionStableNames[currentDimension];
    return names ? names.length : 12;
}

function initRaceChart() {
    const el = document.getElementById('xtBarChart');
    if (!el) return;
    el.innerHTML = '';

    const barCount = getBarCount();
    const width = el.clientWidth || 900;
    const height = RACE_MARGIN.top + BAR_HEIGHT * barCount + RACE_MARGIN.bottom;

    raceSvg = d3.select(el).append('svg')
        .attr('width', '100%')
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('preserveAspectRatio', 'xMidYMid meet')
        .style('overflow', 'visible');

    raceX = d3.scaleLinear()
        .range([RACE_MARGIN.left, width - RACE_MARGIN.right]);

    raceY = d3.scaleBand()
        .domain(d3.range(barCount))
        .range([RACE_MARGIN.top, RACE_MARGIN.top + BAR_HEIGHT * barCount])
        .padding(0.12);

    // X axis
    raceAxisG = raceSvg.append('g')
        .attr('class', 'xt-race-axis')
        .attr('transform', `translate(0,${height - RACE_MARGIN.bottom})`);

    // Bars container
    raceBarsG = raceSvg.append('g').attr('class', 'xt-race-bars');

    // Large period watermark
    racePeriodLabel = raceSvg.append('text')
        .attr('class', 'xt-race-period')
        .attr('x', width - RACE_MARGIN.right - 10)
        .attr('y', height - RACE_MARGIN.bottom - 30)
        .attr('text-anchor', 'end')
        .attr('font-size', '52px')
        .attr('font-weight', '800')
        .attr('fill-opacity', 0.08)
        .attr('pointer-events', 'none');
}

function renderFrame(monthIndex) {
    const months = getPeriods();
    if (!months.length) return;
    if (!raceSvg) initRaceChart();

    currentMonthIndex = Math.max(0, Math.min(monthIndex, months.length - 1));
    const period = months[currentMonthIndex];

    // Update UI controls
    const monthDisplay = document.getElementById('xtMonthDisplay');
    const slider = document.getElementById('xtTimeSlider');
    const counter = document.getElementById('xtMonthCounter');
    if (monthDisplay) monthDisplay.textContent = formatPeriod(period);
    if (slider) slider.value = currentMonthIndex;
    if (counter) counter.textContent = `${currentMonthIndex + 1} / ${months.length}`;

    // Sort by count desc → assign rank
    const frameData = getFrameData(currentMonthIndex);
    const sorted = [...frameData].sort((a, b) => b.count - a.count);
    sorted.forEach((d, i) => { d.rank = i; });

    const maxVal = Math.max(...sorted.map(d => d.count), 1);
    raceX.domain([0, maxVal * 1.15]);

    const dur = Math.min(speed * 0.7, 800);
    const t = raceSvg.transition().duration(dur).ease(d3.easeCubicInOut);

    // Theme colors
    const dark = isDarkMode();
    const textColor = dark ? '#e2e8f0' : '#1e293b';
    const dimColor = dark ? '#94a3b8' : '#64748b';
    const axisColor = dark ? '#475569' : '#cbd5e1';

    // Update x axis
    raceAxisG.transition(t)
        .call(d3.axisBottom(raceX).ticks(6).tickFormat(d3.format(',d')))
        .call(g => g.select('.domain').attr('stroke', axisColor))
        .call(g => g.selectAll('.tick line').attr('stroke', axisColor))
        .call(g => g.selectAll('.tick text').attr('fill', dimColor).attr('font-size', '11px'));

    // Period watermark
    racePeriodLabel
        .text(formatPeriod(period))
        .attr('fill', textColor);

    // ---- D3 data join (keyed by name) ----
    const bars = raceBarsG.selectAll('.xt-race-bar')
        .data(sorted, d => d.name);

    // ENTER — new bars
    const barEnter = bars.enter().append('g')
        .attr('class', 'xt-race-bar')
        .attr('transform', d => `translate(0,${raceY(d.rank)})`);

    barEnter.append('rect')
        .attr('x', RACE_MARGIN.left)
        .attr('height', raceY.bandwidth())
        .attr('width', 0)
        .attr('fill', d => getColor(d.name, currentDimension))
        .attr('rx', 4)
        .attr('opacity', 0.85);

    // Name label (left of bar)
    barEnter.append('text')
        .attr('class', 'xt-bar-name')
        .attr('x', RACE_MARGIN.left - 8)
        .attr('y', raceY.bandwidth() / 2)
        .attr('dy', '0.35em')
        .attr('text-anchor', 'end')
        .attr('fill', textColor)
        .attr('font-size', '12px')
        .attr('font-weight', '500')
        .text(d => d.name);

    // Value label (right of bar)
    barEnter.append('text')
        .attr('class', 'xt-bar-val')
        .attr('y', raceY.bandwidth() / 2)
        .attr('dy', '0.35em')
        .attr('fill', textColor)
        .attr('font-size', '13px')
        .attr('font-weight', '700')
        .attr('font-variant-numeric', 'tabular-nums');

    // Logo icon (right of value label) — only for 'type' dimension
    const logoSize = Math.round(raceY.bandwidth() * 0.7);
    if (currentDimension === 'type') {
        barEnter.append('image')
            .attr('class', 'xt-bar-logo')
            .attr('href', d => getLogoUrl(d.name))
            .attr('width', d => getLogoWidth(d.name, logoSize))
            .attr('height', logoSize)
            .attr('preserveAspectRatio', 'xMidYMid meet')
            .attr('y', (raceY.bandwidth() - logoSize) / 2)
            .attr('opacity', 0.9)
            .on('error', function() { this.setAttribute('opacity', '0'); });
    }

    // ENTER + UPDATE
    const barMerge = barEnter.merge(bars);

    // Transition y position (rank change — the racing effect)
    barMerge.transition(t)
        .attr('transform', d => `translate(0,${raceY(d.rank)})`);

    // Transition bar width
    barMerge.select('rect')
        .transition(t)
        .attr('width', d => Math.max(0, raceX(d.count) - RACE_MARGIN.left))
        .attr('fill', d => getColor(d.name, currentDimension));

    // Update name label color (for theme switches)
    barMerge.select('.xt-bar-name')
        .attr('fill', textColor);

    // Transition value label position + animated counter
    barMerge.select('.xt-bar-val')
        .attr('fill', textColor)
        .transition(t)
        .attr('x', d => raceX(d.count) + 6)
        .tween('text', function(d) {
            const node = this;
            const prev = +(node.textContent.replace(/,/g, '')) || 0;
            const interp = d3.interpolateRound(prev, d.count);
            return (tick) => {
                const val = interp(tick);
                node.textContent = val > 0 ? val.toLocaleString() : '';
            };
        });

    // Transition logo position (follows the value label)
    if (currentDimension === 'type') {
        barMerge.select('.xt-bar-logo')
            .transition(t)
            .attr('x', d => raceX(d.count) + 42);
    }

    // EXIT
    bars.exit()
        .transition(t)
        .attr('opacity', 0)
        .remove();
}

function destroyRaceChart() {
    raceSvg = null;
    raceBarsG = null;
    raceAxisG = null;
    racePeriodLabel = null;
    const el = document.getElementById('xtBarChart');
    if (el) el.innerHTML = '';
}

// ---- Cumulative Trend (Plotly) ----

function renderCumulativeChart() {
    const months = getPeriods();
    if (!months.length) return;

    const series = timelineData[currentDimension].series || {};

    const allNames = new Set();
    for (const month of months) {
        for (const item of (series[month] || [])) {
            allNames.add(item.name);
        }
    }

    const nameList = [...allNames];
    const cumulatives = {};
    nameList.forEach(n => { cumulatives[n] = []; });

    const running = {};
    nameList.forEach(n => { running[n] = 0; });

    for (const month of months) {
        const monthMap = {};
        (series[month] || []).forEach(item => { monthMap[item.name] = item.count; });
        nameList.forEach(n => {
            running[n] += (monthMap[n] || 0);
            cumulatives[n].push(running[n]);
        });
    }

    const sortedNames = nameList
        .map(n => ({ name: n, total: running[n] }))
        .sort((a, b) => b.total - a.total);
    const topNames = sortedNames.slice(0, MAX_CUMULATIVE_LINES).map(d => d.name);

    const c = getChartColors();
    const traces = topNames.map((name) => ({
        type: 'scatter',
        mode: 'lines',
        name: name,
        x: months.map(formatMonth),
        y: cumulatives[name],
        line: { width: 2.5, color: getColor(name, currentDimension) },
        hovertemplate: `${name}: %{y:,}<extra></extra>`,
    }));

    const layout = commonLayout({
        showlegend: true,
        legend: {
            bgcolor: c.legendBg,
            bordercolor: 'rgba(0,0,0,0)',
            orientation: 'h',
            y: -0.25,
            x: 0.5,
            xanchor: 'center',
        },
        margin: { l: 70, r: 20, t: 10, b: 80 },
        xaxis: {
            gridcolor: c.grid,
            linecolor: c.axisLine,
            zerolinecolor: c.grid,
            tickangle: -45,
            dtick: Math.max(1, Math.floor(months.length / 12)),
        },
        yaxis: {
            gridcolor: c.grid,
            linecolor: c.axisLine,
            zerolinecolor: c.grid,
            title: { text: 'Cumulative Count', font: { size: 12, color: c.font } },
        },
    });

    const el = document.getElementById('xtCumulativeChart');
    if (!el) return;

    try {
        Plotly.react(el, traces, layout, PLOTLY_CONFIG);
    } catch (err) {
        console.error('Cumulative chart render failed:', err);
    }
}

// ---- Playback Controls ----

function play() {
    if (isPlaying) return;
    const months = getPeriods();
    if (!months.length) return;

    isPlaying = true;
    updatePlayButton();

    animationTimer = setInterval(() => {
        if (currentMonthIndex >= months.length - 1) {
            pause();
            return;
        }
        renderFrame(currentMonthIndex + 1);
    }, speed);
}

function pause() {
    isPlaying = false;
    if (animationTimer) {
        clearInterval(animationTimer);
        animationTimer = null;
    }
    updatePlayButton();
}

function togglePlayPause() {
    if (isPlaying) {
        pause();
    } else {
        const months = getPeriods();
        if (currentMonthIndex >= months.length - 1) {
            currentMonthIndex = 0;
            renderFrame(0);
        }
        play();
    }
}

function updatePlayButton() {
    const btn = document.getElementById('xtPlayBtn');
    if (btn) {
        btn.innerHTML = isPlaying ? '&#9646;&#9646;' : '&#9654;';
        btn.title = isPlaying ? 'Pause' : 'Play';
    }
}

function setSpeed(newSpeed) {
    speed = newSpeed;
    if (isPlaying) {
        pause();
        play();
    }
}

// ---- Event Setup ----

function setupControls() {
    const playBtn = document.getElementById('xtPlayBtn');
    if (playBtn) playBtn.addEventListener('click', togglePlayPause);

    document.querySelectorAll('.xt-speed-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.xt-speed-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            setSpeed(parseInt(btn.dataset.speed, 10));
        });
    });

    const slider = document.getElementById('xtTimeSlider');
    if (slider) {
        slider.addEventListener('input', () => {
            pause();
            renderFrame(parseInt(slider.value, 10));
        });
    }

    document.querySelectorAll('.xt-granularity-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const newGranularity = btn.dataset.granularity;
            if (newGranularity === granularity) return;
            pause();
            granularity = newGranularity;
            document.querySelectorAll('.xt-granularity-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const ok = await fetchTimelineData();
            if (ok) resetForDimension();
        });
    });

    document.querySelectorAll('.xt-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            if (tab.dataset.dimension === currentDimension) return;
            pause();
            document.querySelectorAll('.xt-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentDimension = tab.dataset.dimension;
            resetForDimension();
        });
    });

    // Lazy-render cumulative chart when details is expanded
    document.addEventListener('toggle', (e) => {
        if (e.target.classList.contains('xt-cumulative-details') && e.target.open) {
            renderCumulativeChart();
        }
    }, true);
}

function rebuildContentHTML(container) {
    const tabs = [
        { key: 'type',      label: 'Ticket Types' },
        { key: 'impact',    label: 'Impact' },
        { key: 'severity',  label: 'Severity' },
        { key: 'category',  label: 'Security Categories' },
        { key: 'region',    label: 'Affected Regions' },
    ];
    const tabsHTML = tabs.map(t =>
        `<button class="xt-tab${currentDimension === t.key ? ' active' : ''}" data-dimension="${t.key}">${t.label}</button>`
    ).join('');

    const speedBtns = [
        { ms: 2000, label: 'Slow' },
        { ms: 1000, label: 'Normal' },
        { ms: 500,  label: 'Fast' },
        { ms: 200,  label: 'Very Fast' },
    ].map(s =>
        `<button class="xt-speed-btn${speed === s.ms ? ' active' : ''}" data-speed="${s.ms}">${s.label}</button>`
    ).join('');

    container.innerHTML = `
        <div class="xt-summary" id="xtSummary">
            <div class="xt-summary-item"><span>Total Tickets:</span> <span class="xt-summary-value" id="xtTotalTickets">—</span></div>
            <div class="xt-summary-item"><span>Date Range:</span> <span class="xt-summary-value" id="xtDateRange">—</span></div>
            <div class="xt-summary-item"><span>Last Synced:</span> <span class="xt-summary-value" id="xtLastSync">—</span></div>
        </div>
        <div class="xt-tabs">${tabsHTML}</div>
        <div class="xt-controls">
            <button class="xt-play-btn" id="xtPlayBtn" title="Play">&#9654;</button>
            <div class="xt-granularity-group">
                <button class="xt-granularity-btn${granularity === 'monthly' ? ' active' : ''}" data-granularity="monthly">Monthly</button>
                <button class="xt-granularity-btn${granularity === 'weekly' ? ' active' : ''}" data-granularity="weekly">Weekly</button>
            </div>
            <div class="xt-speed-group">${speedBtns}</div>
            <div class="xt-month-display" id="xtMonthDisplay">—</div>
            <div class="xt-slider-group">
                <input type="range" class="xt-time-slider" id="xtTimeSlider" min="0" max="0" value="0">
                <span class="xt-month-counter" id="xtMonthCounter">0 / 0</span>
            </div>
        </div>
        <div class="xt-chart-title" id="xtBarChartTitle">${granularity === 'weekly' ? 'Weekly' : 'Monthly'} Ticket Distribution</div>
        <div class="xt-chart-container" id="xtBarChart"></div>
        <details class="xt-cumulative-details">
            <summary class="xt-cumulative-toggle">Cumulative Trend</summary>
            <div class="xt-cumulative-container" id="xtCumulativeChart"></div>
        </details>
    `;
}

function resetForDimension() {
    currentMonthIndex = 0;

    const months = getPeriods();
    const slider = document.getElementById('xtTimeSlider');
    if (slider) {
        slider.max = Math.max(0, months.length - 1);
        slider.value = 0;
    }

    const titleEl = document.getElementById('xtBarChartTitle');
    if (titleEl) titleEl.textContent = `${granularity === 'weekly' ? 'Weekly' : 'Monthly'} Ticket Distribution`;

    // Destroy & rebuild SVG for clean dimension switch
    destroyRaceChart();

    if (timelineData) fetchMetaSummary();

    renderFrame(0);

    // Re-render cumulative if it's already open
    const details = document.querySelector('.xt-cumulative-details');
    if (details && details.open) renderCumulativeChart();
}

function fetchMetaSummary() {
    fetch('/api/xsoar/timeline/status')
        .then(r => r.json())
        .then(result => {
            if (result.success) {
                const totalEl = document.getElementById('xtTotalTickets');
                const syncEl = document.getElementById('xtLastSync');
                if (totalEl) totalEl.textContent = (result.ticket_count || 0).toLocaleString();
                if (syncEl && result.last_synced_at) syncEl.textContent = result.last_synced_at.substring(0, 16).replace('T', ' ');
            }
        })
        .catch(() => {});

    if (timelineData) {
        const allMonths = new Set();
        for (const dim of ALL_DIMENSIONS) {
            if (timelineData[dim] && (timelineData[dim].periods || timelineData[dim].months)) {
                (timelineData[dim].periods || timelineData[dim].months).forEach(m => allMonths.add(m));
            }
        }
        const sorted = [...allMonths].sort();
        const rangeEl = document.getElementById('xtDateRange');
        if (rangeEl && sorted.length) {
            rangeEl.textContent = `${formatMonth(sorted[0])} — ${formatMonth(sorted[sorted.length - 1])}`;
        }
    }
}

// ---- Public API ----

export function initTimeline() {
    const section = document.getElementById('timelineSection');
    if (!section) return;
    section.style.display = 'block';

    const header = document.getElementById('xtHeaderToggle');
    if (header) {
        header.addEventListener('click', async () => {
            const content = document.getElementById('xtContent');
            const chevron = document.getElementById('xtChevron');
            if (!content) return;

            const isExpanding = content.style.display === 'none';
            content.style.display = isExpanding ? 'block' : 'none';
            if (chevron) chevron.classList.toggle('expanded', isExpanding);

            if (isExpanding && !isLoaded) {
                content.innerHTML = '<div class="xt-loading"><div class="xt-loading-spinner"></div><span>Loading timeline data...</span></div>';
                content.style.display = 'block';

                const ok = await fetchTimelineData();
                if (ok) {
                    isLoaded = true;
                    rebuildContentHTML(content);
                    setupControls();
                    resetForDimension();
                }
            }

            if (!isExpanding) pause();
        });
    }
}

export function adaptTimelineTheme() {
    if (!isLoaded || !timelineData) return;
    if (raceSvg) {
        destroyRaceChart();
        renderFrame(currentMonthIndex);
    }
    const details = document.querySelector('.xt-cumulative-details');
    if (details && details.open) renderCumulativeChart();
}
