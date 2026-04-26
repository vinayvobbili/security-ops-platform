/**
 * Sankey diagram for incident resolution flow
 * Shows: Severity → Ticket Type → Impact → Status
 */

import {state} from './state.js';
import {COLOR_SCHEMES, PLOTLY_CONFIG, appConfig} from './config.js';
import {commonLayout, getChartColors, isDarkMode} from './theme.js';

// Plotly is loaded from CDN
/* global Plotly */

const SEVERITY_LABELS = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Unknown'};
const STATUS_LABELS = {0: 'Pending', 1: 'Active', 2: 'Closed'};

const SEVERITY_COLORS = {
    'Critical': '#dc3545',
    'High': '#fd7e14',
    'Medium': '#ffc107',
    'Low': '#28a745',
    'Unknown': '#6c757d'
};

const STATUS_COLORS = {
    'Pending': '#ffc107',
    'Active': '#007bff',
    'Closed': '#28a745'
};

const MAX_TYPES = 8;
const MAX_IMPACTS = 6;

function stripTeamPrefix(ticketType) {
    const teamName = appConfig.team_name || 'TEAM';
    const regex = new RegExp(`^${teamName}[_\\-\\s]*`, 'i');
    return ticketType.startsWith(teamName) ? ticketType.replace(regex, '') : ticketType;
}

/**
 * Build nodes and links from filtered data for the Sankey diagram
 */
function buildSankeyData() {
    const data = state.filteredData;
    if (!data || data.length === 0) return null;

    // Count ticket types and impacts to find top N
    const typeCounts = {};
    const impactCounts = {};
    data.forEach(item => {
        const type = stripTeamPrefix(item.type || 'Unknown');
        typeCounts[type] = (typeCounts[type] || 0) + 1;
        const impact = item.impact || 'Unknown';
        impactCounts[impact] = (impactCounts[impact] || 0) + 1;
    });

    const topTypes = Object.entries(typeCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, MAX_TYPES)
        .map(([t]) => t);
    const topTypeSet = new Set(topTypes);

    const topImpacts = Object.entries(impactCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, MAX_IMPACTS)
        .map(([i]) => i);
    const topImpactSet = new Set(topImpacts);

    // Count flows between each stage
    const sevToType = {};   // "severity|type" → count
    const typeToImpact = {}; // "type|impact" → count
    const impactToStatus = {}; // "impact|status" → count

    data.forEach(item => {
        const severity = SEVERITY_LABELS[item.severity] || 'Unknown';
        let type = stripTeamPrefix(item.type || 'Unknown');
        if (!topTypeSet.has(type)) type = 'Other Types';
        let impact = item.impact || 'Unknown';
        if (!topImpactSet.has(impact)) impact = 'Other Impacts';
        const status = STATUS_LABELS[item.status] || 'Unknown';

        const stKey = `${severity}|${type}`;
        sevToType[stKey] = (sevToType[stKey] || 0) + 1;

        const tiKey = `${type}|${impact}`;
        typeToImpact[tiKey] = (typeToImpact[tiKey] || 0) + 1;

        const isKey = `${impact}|${status}`;
        impactToStatus[isKey] = (impactToStatus[isKey] || 0) + 1;
    });

    // Build node list — each stage gets its own set of labels
    // Stage 0: Severities, Stage 1: Types, Stage 2: Impacts, Stage 3: Statuses
    const severities = Object.values(SEVERITY_LABELS).filter(s =>
        Object.keys(sevToType).some(k => k.startsWith(s + '|'))
    );
    const types = [...topTypes];
    if (Object.keys(sevToType).some(k => k.endsWith('|Other Types'))) {
        types.push('Other Types');
    }
    const impacts = [...topImpacts];
    if (Object.keys(typeToImpact).some(k => k.endsWith('|Other Impacts'))) {
        impacts.push('Other Impacts');
    }
    const statuses = Object.values(STATUS_LABELS).filter(s =>
        Object.keys(impactToStatus).some(k => k.endsWith('|' + s))
    );

    const nodeLabels = [];
    const nodeColors = [];

    // Stage 0: Severity nodes
    const sevOffset = 0;
    severities.forEach(s => {
        nodeLabels.push(s);
        nodeColors.push(SEVERITY_COLORS[s] || '#6c757d');
    });

    // Stage 1: Type nodes
    const typeOffset = nodeLabels.length;
    types.forEach(t => {
        nodeLabels.push(t);
        nodeColors.push(COLOR_SCHEMES.sources[types.indexOf(t) % COLOR_SCHEMES.sources.length]);
    });

    // Stage 2: Impact nodes
    const impactOffset = nodeLabels.length;
    impacts.forEach(im => {
        nodeLabels.push(im);
        nodeColors.push(COLOR_SCHEMES.countries[impacts.indexOf(im) % COLOR_SCHEMES.countries.length]);
    });

    // Stage 3: Status nodes
    const statusOffset = nodeLabels.length;
    statuses.forEach(s => {
        nodeLabels.push(s);
        nodeColors.push(STATUS_COLORS[s] || '#6c757d');
    });

    // Build link arrays
    const linkSource = [];
    const linkTarget = [];
    const linkValue = [];
    const linkColor = [];

    // Severity → Type links
    Object.entries(sevToType).forEach(([key, value]) => {
        const [sev, type] = key.split('|');
        const sourceIdx = sevOffset + severities.indexOf(sev);
        const targetIdx = typeOffset + types.indexOf(type);
        if (sourceIdx >= 0 && targetIdx >= 0) {
            linkSource.push(sourceIdx);
            linkTarget.push(targetIdx);
            linkValue.push(value);
            const baseColor = SEVERITY_COLORS[sev] || '#6c757d';
            linkColor.push(hexToRgba(baseColor, 0.35));
        }
    });

    // Type → Impact links
    Object.entries(typeToImpact).forEach(([key, value]) => {
        const [type, impact] = key.split('|');
        const sourceIdx = typeOffset + types.indexOf(type);
        const targetIdx = impactOffset + impacts.indexOf(impact);
        if (sourceIdx >= 0 && targetIdx >= 0) {
            linkSource.push(sourceIdx);
            linkTarget.push(targetIdx);
            linkValue.push(value);
            const baseColor = COLOR_SCHEMES.sources[types.indexOf(type) % COLOR_SCHEMES.sources.length];
            linkColor.push(hexToRgba(baseColor, 0.3));
        }
    });

    // Impact → Status links
    Object.entries(impactToStatus).forEach(([key, value]) => {
        const [impact, status] = key.split('|');
        const sourceIdx = impactOffset + impacts.indexOf(impact);
        const targetIdx = statusOffset + statuses.indexOf(status);
        if (sourceIdx >= 0 && targetIdx >= 0) {
            linkSource.push(sourceIdx);
            linkTarget.push(targetIdx);
            linkValue.push(value);
            const baseColor = STATUS_COLORS[status] || '#6c757d';
            linkColor.push(hexToRgba(baseColor, 0.35));
        }
    });

    return {nodeLabels, nodeColors, linkSource, linkTarget, linkValue, linkColor};
}

function hexToRgba(hex, alpha) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${alpha})`;
}

// ── Flowing-dot animation overlay ──────────────────────────────────
// Each link gets its own dots that flow left → right along the
// forward edge of the filled path shape (top curve only).

let _animFrame = 0;
let _paused = false;
let _lastTickFn = null;    // stash tick so we can resume
let _lastTime = 0;
const DOT_SPEED = 0.35;       // px per ms
const DOT_RADIUS = 2.8;
const DOT_OPACITY = 0.8;
const MAX_DOTS_PER_LINK = 14;

function stopSankeyAnimation() {
    if (_animFrame) {
        cancelAnimationFrame(_animFrame);
        _animFrame = 0;
    }
    _paused = false;
    _lastTickFn = null;
}

/**
 * Toggle pause/resume of the Sankey dot animation
 */
export function toggleSankeyAnimation() {
    const btn = document.getElementById('sankeyPauseBtn');
    if (_paused) {
        // Resume
        _paused = false;
        if (btn) btn.innerHTML = '&#9646;&#9646;';
        if (btn) btn.title = 'Pause animation';
        if (_lastTickFn) {
            _lastTime = performance.now();
            _animFrame = requestAnimationFrame(_lastTickFn);
        }
    } else {
        // Pause
        _paused = true;
        if (btn) btn.innerHTML = '&#9654;';
        if (btn) btn.title = 'Resume animation';
        if (_animFrame) {
            cancelAnimationFrame(_animFrame);
            _animFrame = 0;
        }
    }
}

function startSankeyAnimation(container, sankeyData) {
    stopSankeyAnimation();

    // Respect prefers-reduced-motion accessibility setting
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const linkPaths = container.querySelectorAll('path.sankey-link');
    if (!linkPaths.length) return;

    const plotSvg = container.querySelector('.main-svg');
    if (!plotSvg) return;

    const old = container.querySelector('.sankey-dot-overlay');
    if (old) old.remove();

    const overlay = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    overlay.classList.add('sankey-dot-overlay');
    overlay.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:5;';
    overlay.setAttribute('viewBox', plotSvg.getAttribute('viewBox') || `0 0 ${plotSvg.clientWidth} ${plotSvg.clientHeight}`);
    overlay.setAttribute('preserveAspectRatio', plotSvg.getAttribute('preserveAspectRatio') || 'xMidYMid meet');
    container.style.position = 'relative';
    container.appendChild(overlay);

    const {linkValue, linkColor} = sankeyData;
    const maxVal = Math.max(...linkValue);

    // Plotly link paths are CLOSED SHAPES tracing the band outline:
    //   top edge (source→target) → vertical → bottom edge (target→source) → close.
    // We only animate along the top edge (the "forward run") where x increases
    // from the source node to the target node.
    const FWD_SAMPLES = 50;
    const dots = [];

    linkPaths.forEach((pathEl, i) => {
        const totalLen = pathEl.getTotalLength();
        if (totalLen < 10) return;

        // 1) Find the global max-x along the path
        let maxX = -Infinity;
        for (let s = 0; s <= FWD_SAMPLES; s++) {
            const x = pathEl.getPointAtLength((s / FWD_SAMPLES) * totalLen).x;
            if (x > maxX) maxX = x;
        }
        // 2) Find the FIRST offset that reaches within 1px of max-x.
        //    This is where the forward edge ends (before the vertical drop
        //    and return edge begin).
        let fwdLen = totalLen / 2;
        for (let s = 0; s <= FWD_SAMPLES; s++) {
            const t = (s / FWD_SAMPLES) * totalLen;
            if (pathEl.getPointAtLength(t).x >= maxX - 1) {
                fwdLen = t;
                break;
            }
        }
        if (fwdLen < 10) return;

        // The path outline is: top-curve → V (right edge down) → bottom-curve → Z (close).
        // We need to locate the bottom curve's start and end offsets so we can
        // correctly map top-edge positions to bottom-edge positions.
        const minX = pathEl.getPointAtLength(0).x;

        // botStart: first offset past fwdLen where x drops below maxX (past the V)
        let botStart = fwdLen;
        for (let s = 1; s <= 20; s++) {
            const t = fwdLen + (s / 20) * (totalLen - fwdLen);
            if (pathEl.getPointAtLength(t).x < maxX - 2) {
                botStart = t;
                break;
            }
        }
        // botEnd: last offset before totalLen where x is still above minX (before the Z)
        let botEnd = totalLen;
        for (let s = 20; s >= 0; s--) {
            const t = fwdLen + (s / 20) * (totalLen - fwdLen);
            if (pathEl.getPointAtLength(t).x > minX + 2) {
                botEnd = t;
                break;
            }
        }

        // Dot count and size proportional to link value (every link gets at least 1)
        const ratio = linkValue[i] / maxVal;
        const count = Math.max(1, Math.min(MAX_DOTS_PER_LINK, Math.round(ratio * MAX_DOTS_PER_LINK)));
        const radius = DOT_RADIUS * (0.6 + 0.6 * ratio);

        // Measure band width at midpoint to decide how many horizontal lanes
        const midF = 0.5;
        const midTopPt = pathEl.getPointAtLength(midF * fwdLen);
        const midBotOff = botStart + (1 - midF) * (botEnd - botStart);
        const midBotPt = pathEl.getPointAtLength(midBotOff);
        const bandWidth = Math.abs(midBotPt.y - midTopPt.y);

        let lanes = 1;
        if (bandWidth > 12 && count >= 3) lanes = 2;
        if (bandWidth > 25 && count >= 6) lanes = 3;

        let color = linkColor[i] || 'rgba(100,100,100,0.6)';
        color = color.replace(/[\d.]+\)$/, `${DOT_OPACITY})`);

        const dotsPerLane = Math.ceil(count / lanes);
        let placed = 0;
        for (let lane = 0; lane < lanes && placed < count; lane++) {
            const laneFrac = (lane + 1) / (lanes + 1);
            const n = Math.min(dotsPerLane, count - placed);
            for (let d = 0; d < n; d++) {
                const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                circle.setAttribute('r', radius);
                circle.setAttribute('fill', color);
                overlay.appendChild(circle);
                dots.push({
                    circle,
                    path: pathEl,
                    fwdLen,
                    botStart,
                    botEnd,
                    laneFrac,
                    offset: (d / n) * fwdLen,
                    speed: DOT_SPEED * (0.85 + Math.random() * 0.3)
                });
                placed++;
            }
        }
    });

    console.log(`[sankey-dots v12] ${linkPaths.length} links, ${dots.length} dots`);
    if (!dots.length) return;

    const FADE_ZONE = 0.12; // fade in/out over first/last 12% of each link
    const MAX_DT = 50;      // cap frame delta at 50ms to prevent teleporting on tab switch
    _lastTime = performance.now();

    function tick(now) {
        const dt = Math.min(now - _lastTime, MAX_DT);
        _lastTime = now;

        for (const dot of dots) {
            dot.offset = (dot.offset + dot.speed * dt) % dot.fwdLen;
            try {
                const top = dot.path.getPointAtLength(dot.offset);
                const f = dot.offset / dot.fwdLen;
                const botOff = dot.botStart + (1 - f) * (dot.botEnd - dot.botStart);
                const bot = dot.path.getPointAtLength(botOff);
                dot.circle.setAttribute('cx', top.x);
                dot.circle.setAttribute('cy', top.y + (bot.y - top.y) * dot.laneFrac);

                // Fade in at left edge, fade out at right edge
                let opacity = DOT_OPACITY;
                if (f < FADE_ZONE) opacity = DOT_OPACITY * (f / FADE_ZONE);
                else if (f > 1 - FADE_ZONE) opacity = DOT_OPACITY * ((1 - f) / FADE_ZONE);
                dot.circle.setAttribute('opacity', opacity);
            } catch { /* path may be invalid on resize */ }
        }
        _animFrame = requestAnimationFrame(tick);
    }

    _lastTickFn = tick;
    _paused = false;
    const btn = document.getElementById('sankeyPauseBtn');
    if (btn) btn.innerHTML = '&#9646;&#9646;';
    _animFrame = requestAnimationFrame(tick);
}

/**
 * Create or update the Sankey diagram
 */
export function createSankeyChart() {
    stopSankeyAnimation();
    const el = document.getElementById('sankeyChart');
    if (!el) return;

    const sankeyData = buildSankeyData();

    if (!sankeyData || sankeyData.linkSource.length === 0) {
        el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">No data available for Sankey diagram</div>';
        return;
    }

    const c = getChartColors();

    const trace = {
        type: 'sankey',
        orientation: 'h',
        arrangement: 'snap',
        node: {
            pad: 20,
            thickness: 24,
            line: {color: isDarkMode() ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.1)', width: 1},
            label: sankeyData.nodeLabels,
            color: sankeyData.nodeColors,
            hovertemplate: '<b>%{label}</b><br>Total: %{value} cases<extra></extra>'
        },
        link: {
            source: sankeyData.linkSource,
            target: sankeyData.linkTarget,
            value: sankeyData.linkValue,
            color: sankeyData.linkColor,
            hovertemplate: '%{source.label} → %{target.label}<br>Cases: %{value}<extra></extra>'
        }
    };

    const layout = commonLayout({
        margin: {l: 20, r: 20, t: 10, b: 10},
        showlegend: false
    });

    try {
        Plotly.newPlot(el, [trace], layout, PLOTLY_CONFIG);
        // Kick off flowing-dot animation after Plotly finishes rendering
        requestAnimationFrame(() => startSankeyAnimation(el, sankeyData));
    } catch (error) {
        console.error('Failed to create Sankey chart:', error);
        el.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">Chart rendering failed</div>';
    }
}
