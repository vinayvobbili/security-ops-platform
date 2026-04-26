/**
 * Stepper Story Mode for Meaningful Metrics dashboard
 * A 5-step narrative walkthrough of incident data
 */

import {state} from './state.js';
import {COLOR_SCHEMES, PLOTLY_CONFIG, appConfig} from './config.js';
import {commonLayout, getChartColors} from './theme.js';

const TOTAL_STEPS = 5;
const STORAGE_KEY = 'mm-story-collapsed';
const ENABLED_KEY = 'mm-story-enabled';
let currentStep = 0;
let storyEnabled = false;
let confettiFired = false;
let typewriterCancel = null;
const descIds = ['mmDescVolume', 'mmDescResponse', 'mmDescLandscape', 'mmDescGeography', 'mmDescOutcome'];

// ── helpers ──────────────────────────────────────────────────

function safePlot(chartId, data, layout, config = PLOTLY_CONFIG) {
    const el = document.getElementById(chartId);
    if (!el) { console.warn(`Story chart element ${chartId} not found`); return; }
    try { Plotly.newPlot(el, data, layout, config); }
    catch (err) { console.error(`Story chart ${chartId} failed:`, err); el.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-secondary)">Chart rendering failed</div>'; }
}

function stripTeamPrefix(type) {
    if (!type || !appConfig.team_name) return type;
    const re = new RegExp('^' + appConfig.team_name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[_\\-\\s]+', 'i');
    return type.replace(re, '');
}

function formatTime(seconds) {
    if (!seconds || seconds === 0) return '0:00';
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
}

function calcMetrics(data) {
    const responseSlaBreaches = data.filter(d => d.has_breached_response_sla === true).length;
    const containmentSlaBreaches = data.filter(d => {
        const hasHost = d.hostname && d.hostname.trim() !== '' && d.hostname !== 'Unknown';
        return hasHost && d.has_breached_containment_sla === true;
    }).length;
    const mttrCases = data.filter(d => d.owner && d.owner.trim() !== '' && d.time_to_respond_secs > 0);
    const mttr = mttrCases.length > 0 ? mttrCases.reduce((s, d) => s + d.time_to_respond_secs, 0) / mttrCases.length : 0;
    const mttcCases = data.filter(d => d.has_hostname && d.time_to_contain_secs > 0);
    const mttc = mttcCases.length > 0 ? mttcCases.reduce((s, d) => s + d.time_to_contain_secs, 0) / mttcCases.length : 0;
    return {responseSlaBreaches, containmentSlaBreaches, mttr, mttc, mttrCount: mttrCases.length, mttcCount: mttcCases.length};
}

// ── animation helpers ────────────────────────────────────────

function animateKpis(container) {
    if (!window.StoryAudio) return;
    container.querySelectorAll('[data-countup]').forEach(el => {
        window.StoryAudio.countUp(el, el.dataset.countup, 1200);
    });
}

function replayEntrance(slideEl) {
    if (!slideEl) return;
    // Force animation replay by resetting animation property
    slideEl.style.animation = 'none';
    void slideEl.offsetWidth; // reflow
    slideEl.style.animation = '';
}

function addAnnotation(chartId, text) {
    const chart = document.getElementById(chartId);
    if (!chart) return;
    // Remove existing annotations from the chart element itself
    chart.querySelectorAll('.story-annotation').forEach(a => a.remove());
    const ann = document.createElement('div');
    ann.className = 'story-annotation';
    ann.textContent = text;
    chart.style.position = 'relative';
    ann.style.top = '8px';
    ann.style.right = '12px';
    chart.appendChild(ann);
}

function narrateStep(n, text) {
    if (!window.StoryAudio) return;
    if (!text) {
        const el = document.getElementById(descIds[n]);
        text = el ? el.textContent : '';
    }
    if (text) window.StoryAudio.speak(text);
}

function computePeriodDeltas() {
    const data = state.filteredData;
    if (!data || data.length < 4) return {};
    const sorted = data.filter(d => d.created).sort((a, b) => new Date(a.created) - new Date(b.created));
    if (sorted.length < 4) return {};
    const mid = Math.floor(sorted.length / 2);
    const m1 = calcMetrics(sorted.slice(0, mid));
    const m2 = calcMetrics(sorted.slice(mid));
    const pct = (o, n) => o === 0 ? (n > 0 ? 100 : 0) : ((n - o) / o) * 100;
    return {
        volume: pct(mid, sorted.length - mid),
        mttr: pct(m1.mttr, m2.mttr),
        mttc: pct(m1.mttc, m2.mttc),
        sla: pct(m1.responseSlaBreaches, m2.responseSlaBreaches)
    };
}

// ── step renderers ───────────────────────────────────────────

function renderVolume() {
    const data = state.filteredData;
    const byCreated = {}, byClosed = {};
    data.forEach(d => {
        if (d.created) {
            const dt = new Date(d.created);
            if (!isNaN(dt) && dt.getFullYear() >= 2020) {
                const key = dt.toISOString().split('T')[0];
                byCreated[key] = (byCreated[key] || 0) + 1;
            }
        }
        if (d.closed) {
            const dt = new Date(d.closed);
            if (!isNaN(dt) && dt.getFullYear() >= 2020) {
                const key = dt.toISOString().split('T')[0];
                byClosed[key] = (byClosed[key] || 0) + 1;
            }
        }
    });
    const allDates = [...new Set([...Object.keys(byCreated), ...Object.keys(byClosed)])].sort();
    const layout = commonLayout({
        xaxis: {title: '', gridcolor: getChartColors().grid, linecolor: getChartColors().axisLine, zerolinecolor: getChartColors().grid},
        yaxis: {title: 'Cases', gridcolor: getChartColors().grid, linecolor: getChartColors().axisLine, zerolinecolor: getChartColors().grid},
        margin: {l: 50, r: 20, t: 30, b: 40},
        legend: {orientation: 'h', y: 1.12, bgcolor: 'rgba(0,0,0,0)'}
    });
    const createdVals = allDates.map(d => byCreated[d] || 0);
    // Add peak annotation directly on the data point
    if (createdVals.length) {
        const maxIdx = createdVals.indexOf(Math.max(...createdVals));
        layout.annotations = [{
            x: allDates[maxIdx],
            y: createdVals[maxIdx],
            text: `Peak: ${createdVals[maxIdx]} cases on ${allDates[maxIdx]}`,
            showarrow: true,
            arrowhead: 2,
            arrowsize: 1,
            arrowcolor: '#3b82f6',
            ax: 0,
            ay: -35,
            bgcolor: 'rgba(59,130,246,0.1)',
            bordercolor: '#3b82f6',
            borderwidth: 1,
            borderpad: 4,
            font: {size: 11, color: getChartColors().font}
        }];
    }
    safePlot('mmChartVolume', [
        {x: allDates, y: createdVals, type: 'scatter', mode: 'lines+markers', name: 'Inflow (Created)', line: {color: '#3b82f6', width: 2}, marker: {size: 4}},
        {x: allDates, y: allDates.map(d => byClosed[d] || 0), type: 'scatter', mode: 'lines+markers', name: 'Outflow (Closed)', line: {color: '#10b981', width: 2}, marker: {size: 4}}
    ], layout);
}

function renderResponse() {
    const m = calcMetrics(state.filteredData);
    const el = document.getElementById('mmKpiRow');
    if (!el) return;
    el.innerHTML = `
        <div class="story-kpi-card">
            <div class="story-kpi-icon">⏱️</div>
            <div class="story-kpi-value" data-countup="${formatTime(m.mttr)}">${formatTime(m.mttr)}</div>
            <div class="story-kpi-label">Avg Response Time (MTTR)<br><small>${m.mttrCount} cases</small></div>
        </div>
        <div class="story-kpi-card">
            <div class="story-kpi-icon">🔒</div>
            <div class="story-kpi-value" data-countup="${formatTime(m.mttc)}">${formatTime(m.mttc)}</div>
            <div class="story-kpi-label">Avg Containment Time (MTTC)<br><small>${m.mttcCount} cases</small></div>
        </div>
        <div class="story-kpi-card">
            <div class="story-kpi-icon">🚨</div>
            <div class="story-kpi-value" data-countup="${m.responseSlaBreaches}">${m.responseSlaBreaches}</div>
            <div class="story-kpi-label">Response SLA Breaches</div>
        </div>`;
    // Count-up animation
    animateKpis(el);
    // Trend badges
    if (window.StoryEffects) {
        const d = computePeriodDeltas();
        const cards = el.querySelectorAll('.story-kpi-value');
        if (cards[0] && d.mttr != null) cards[0].innerHTML += window.StoryEffects.trendBadge(d.mttr, true);
        if (cards[1] && d.mttc != null) cards[1].innerHTML += window.StoryEffects.trendBadge(d.mttc, true);
        if (cards[2] && d.sla != null) cards[2].innerHTML += window.StoryEffects.trendBadge(d.sla, true);
    }
}

function renderLandscape() {
    const counts = {};
    state.filteredData.forEach(d => {
        const t = stripTeamPrefix(d.type || 'Unknown');
        counts[t] = (counts[t] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const labels = sorted.map(e => e[0]);
    const values = sorted.map(e => e[1]);
    const colors = COLOR_SCHEMES.sources.concat(COLOR_SCHEMES.countries);
    const layout = commonLayout({
        margin: {l: 20, r: 20, t: 10, b: 10},
        showlegend: true,
        legend: {orientation: 'h', y: -0.15, bgcolor: 'rgba(0,0,0,0)', font: {size: 11, color: getChartColors().font}}
    });
    safePlot('mmChartLandscape', [{
        labels, values, type: 'pie', hole: 0.45,
        marker: {colors: colors.slice(0, labels.length)},
        textinfo: 'percent+label', textposition: 'inside',
        textfont: {size: 11}, hoverinfo: 'label+value+percent',
        sort: false
    }], layout);
    // Annotation: top ticket type
    if (sorted.length) {
        const topPct = state.filteredData.length > 0 ? ((sorted[0][1] / state.filteredData.length) * 100).toFixed(1) : 0;
        addAnnotation('mmChartLandscape', `#1: ${sorted[0][0]} (${topPct}%)`);
    }
}

function renderGeography() {
    const counts = {};
    state.filteredData.forEach(d => {
        const c = d.affected_country || 'Unknown';
        counts[c] = (counts[c] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const labels = sorted.map(e => e[0]).reverse();
    const values = sorted.map(e => e[1]).reverse();
    const c = getChartColors();
    const layout = commonLayout({
        xaxis: {title: 'Cases', gridcolor: c.grid, linecolor: c.axisLine, zerolinecolor: c.grid},
        yaxis: {gridcolor: c.grid, linecolor: c.axisLine, zerolinecolor: c.grid, automargin: true},
        margin: {l: 110, r: 20, t: 10, b: 40},
        showlegend: false
    });
    safePlot('mmChartGeography', [{
        x: values, y: labels, type: 'bar', orientation: 'h',
        marker: {color: COLOR_SCHEMES.countries.slice(0, values.length).reverse()},
        text: values.map(v => v.toString()), textposition: 'outside',
        textfont: {color: c.font, size: 11},
        hoverinfo: 'x+y'
    }], layout);
    // Annotation: top country
    if (sorted.length) {
        addAnnotation('mmChartGeography', `Top: ${sorted[0][0]} — ${sorted[0][1]} cases`);
    }
}

function renderOutcome() {
    const counts = {};
    state.filteredData.forEach(d => {
        const impact = d.impact || 'Unknown';
        counts[impact] = (counts[impact] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const labels = sorted.map(e => e[0]);
    const values = sorted.map(e => e[1]);
    const impactColors = {
        'Malicious - True Positive': '#dc3545', 'Non-Malicious - Informational': '#28a745',
        'Non-Malicious - True Positive': '#17a2b8', 'Malicious - False Positive': '#ffc107',
        'Non-Malicious - False Positive': '#6c757d', 'Unknown': '#adb5bd'
    };
    const colors = labels.map(l => impactColors[l] || COLOR_SCHEMES.sources[labels.indexOf(l) % COLOR_SCHEMES.sources.length]);
    const layout = commonLayout({
        margin: {l: 20, r: 20, t: 10, b: 10},
        showlegend: true,
        legend: {orientation: 'h', y: -0.15, bgcolor: 'rgba(0,0,0,0)', font: {size: 11, color: getChartColors().font}}
    });
    safePlot('mmChartOutcome', [{
        labels, values, type: 'pie', hole: 0.4,
        marker: {colors},
        textinfo: 'percent+label', textposition: 'inside',
        textfont: {size: 11}, hoverinfo: 'label+value+percent',
        sort: false
    }], layout);
    // Annotation: dominant impact type
    if (sorted.length) {
        const topPct = state.filteredData.length > 0 ? ((sorted[0][1] / state.filteredData.length) * 100).toFixed(1) : 0;
        addAnnotation('mmChartOutcome', `Dominant: ${sorted[0][0].split(' - ')[0]} (${topPct}%)`);
    }
}

// ── navigation ───────────────────────────────────────────────

function goToStep(n) {
    if (n < 0 || n >= TOTAL_STEPS) return;
    // Reset confetti when starting over
    if (n === 0 && currentStep === TOTAL_STEPS - 1) confettiFired = false;
    const slides = document.querySelectorAll('#mmStorySlides .story-slide');
    const dots = document.querySelectorAll('#mmStoryDots .story-dot');
    if (!slides.length) return;

    slides[currentStep]?.classList.remove('active');
    dots[currentStep]?.classList.remove('active');

    currentStep = n;

    slides[currentStep]?.classList.add('active');
    dots[currentStep]?.classList.add('active');

    const fill = document.getElementById('mmProgressFill');
    if (fill) fill.style.width = `${((currentStep + 1) / TOTAL_STEPS) * 100}%`;

    const label = document.getElementById('mmStepLabel');
    if (label) label.textContent = `Step ${currentStep + 1} of ${TOTAL_STEPS}`;

    const back = document.getElementById('mmStoryBack');
    const next = document.getElementById('mmStoryNext');
    if (back) back.disabled = currentStep === 0;
    if (next) {
        next.disabled = false;
        next.textContent = currentStep === TOTAL_STEPS - 1 ? '↻ Start Over' : 'Next →';
    }

    // Sonification
    if (window.StoryAudio) {
        if (currentStep === TOTAL_STEPS - 1) window.StoryAudio.playComplete();
        else window.StoryAudio.playStep(currentStep, TOTAL_STEPS);
    }

    // Cancel any in-progress typewriter
    if (typewriterCancel) { typewriterCancel(); typewriterCancel = null; }

    // Confetti on final step (first time only)
    if (currentStep === TOTAL_STEPS - 1 && !confettiFired && window.StoryEffects) {
        confettiFired = true;
        window.StoryEffects.confetti();
    }

    // Replay entrance animation on the new slide
    replayEntrance(slides[currentStep]);

    // Render after brief delay so Plotly sees the visible container
    setTimeout(() => renderStep(currentStep), 50);

    // Capture full description text before typewriter modifies it
    const descEl = document.getElementById(descIds[currentStep]);
    const fullDesc = descEl ? descEl.textContent : '';

    // Typewriter on description (first visit per step)
    if (descEl && window.StoryEffects) {
        typewriterCancel = window.StoryEffects.typewriter(descEl, fullDesc, 25);
    }

    // Narrate the full description (not the typewriter-in-progress text)
    setTimeout(() => narrateStep(currentStep, fullDesc), 200);
}

function renderStep(n) {
    switch (n) {
        case 0: renderVolume(); break;
        case 1: renderResponse(); break;
        case 2: renderLandscape(); break;
        case 3: renderGeography(); break;
        case 4: renderOutcome(); break;
    }
}

// ── dynamic text ─────────────────────────────────────────────

function updateDescriptions() {
    const data = state.filteredData;
    const total = data.length;

    const dateSlider = document.getElementById('dateRangeSlider');
    const days = dateSlider ? parseInt(dateSlider.value) || 30 : 30;

    const el0 = document.getElementById('mmDescVolume');
    if (el0) {
        const byDay = {};
        data.forEach(d => { if (d.created) { const k = new Date(d.created).toISOString().split('T')[0]; byDay[k] = (byDay[k] || 0) + 1; }});
        const dayVals = Object.keys(byDay).sort().map(k => byDay[k]);
        const spark = window.StoryEffects ? window.StoryEffects.sparklineSVG(dayVals, {color: '#3b82f6', filled: true}) : '';
        el0.innerHTML = `Your team handled ${total.toLocaleString()} cases over the past ${days} days. ${spark} Here's the daily inflow vs outflow.`;
    }

    const m = calcMetrics(data);
    const el1 = document.getElementById('mmDescResponse');
    if (el1) el1.textContent = `Average response time ${formatTime(m.mttr)}, containment ${formatTime(m.mttc)}. ${m.responseSlaBreaches} response SLA breaches.`;

    const types = new Set(data.map(d => d.type)).size;
    const el2 = document.getElementById('mmDescLandscape');
    if (el2) el2.textContent = `Cases span ${types} ticket types — here's the breakdown by category.`;

    const countries = new Set(data.map(d => d.affected_country).filter(Boolean)).size;
    const el3 = document.getElementById('mmDescGeography');
    if (el3) el3.textContent = `Incidents originated from ${countries} countries. Here are the top 10.`;

    const tp = data.filter(d => d.impact && d.impact.toLowerCase().includes('true positive')).length;
    const tpPct = total > 0 ? ((tp / total) * 100).toFixed(1) : 0;
    const assigned = data.filter(d => d.owner && d.owner.trim() !== '').length;
    const closed = data.filter(d => !d.is_open).length;
    const el4 = document.getElementById('mmDescOutcome');
    if (el4) el4.textContent = `${tpPct}% true positives, ${assigned.toLocaleString()} cases assigned, ${closed.toLocaleString()} resolved.`;
}

// ── public API ───────────────────────────────────────────────

function setToggleButtonState(btn, enabled) {
    if (!btn) return;
    btn.classList.toggle('active', enabled);
    btn.title = enabled ? 'Hide Data Story' : 'Show Data Story narrative mode';
}

function toggleStory() {
    const section = document.getElementById('mmStorySection');
    const btn = document.getElementById('storyToggleBtn');
    storyEnabled = !storyEnabled;
    localStorage.setItem(ENABLED_KEY, storyEnabled);
    if (section) section.style.display = storyEnabled ? '' : 'none';
    setToggleButtonState(btn, storyEnabled);
    // Render active step when enabling (Plotly needs visible container)
    if (storyEnabled && state.filteredData && state.filteredData.length) {
        updateDescriptions();
        setTimeout(() => renderStep(currentStep), 80);
    }
}

export function initStory() {
    const section = document.getElementById('mmStorySection');
    const header = document.getElementById('mmStoryHeader');
    const toggleBtn = document.getElementById('storyToggleBtn');

    // Restore enabled state from localStorage
    storyEnabled = localStorage.getItem(ENABLED_KEY) === 'true';
    if (section) section.style.display = storyEnabled ? '' : 'none';
    setToggleButtonState(toggleBtn, storyEnabled);

    // Toggle button in filter bar
    if (toggleBtn) toggleBtn.addEventListener('click', toggleStory);

    if (!section || !header) return;

    // Restore collapse state
    if (localStorage.getItem(STORAGE_KEY) === 'true') {
        section.classList.add('collapsed');
    }

    // Toggle collapse
    header.addEventListener('click', () => {
        section.classList.toggle('collapsed');
        localStorage.setItem(STORAGE_KEY, section.classList.contains('collapsed'));
    });

    // Nav buttons
    const back = document.getElementById('mmStoryBack');
    const next = document.getElementById('mmStoryNext');
    if (back) back.addEventListener('click', (e) => { e.stopPropagation(); goToStep(currentStep - 1); });
    if (next) next.addEventListener('click', (e) => {
        e.stopPropagation();
        goToStep(currentStep === TOTAL_STEPS - 1 ? 0 : currentStep + 1);
    });

    // Dot clicks
    document.querySelectorAll('#mmStoryDots .story-dot').forEach(dot => {
        dot.addEventListener('click', (e) => {
            e.stopPropagation();
            goToStep(parseInt(dot.dataset.dot));
        });
    });

    // Arrow key navigation + extended shortcuts
    section.addEventListener('mouseenter', () => section.dataset.hover = 'true');
    section.addEventListener('mouseleave', () => section.dataset.hover = 'false');
    document.addEventListener('keydown', (e) => {
        // Global: Escape closes overlays
        if (e.key === 'Escape') {
            if (window.StoryEffects) {
                if (window.StoryEffects.isShortcutsVisible()) { window.StoryEffects.hideShortcuts(); return; }
                if (window.StoryEffects.isSpotlightActive()) { window.StoryEffects.spotlightOff(); return; }
            }
        }
        if (section.dataset.hover !== 'true' || section.classList.contains('collapsed')) return;
        if (e.key === 'ArrowLeft') goToStep(currentStep - 1);
        else if (e.key === 'ArrowRight') goToStep(currentStep + 1);
        else if ((e.key === 's' || e.key === 'S') && window.StoryEffects) {
            if (window.StoryEffects.isSpotlightActive()) window.StoryEffects.spotlightOff();
            else window.StoryEffects.spotlightOn(section);
        }
        else if ((e.key === 'p' || e.key === 'P') && window.StoryEffects) {
            const slide = document.querySelector('#mmStorySlides .story-slide.active');
            if (slide) window.StoryEffects.exportSlide(slide, `meaningful-metrics-step-${currentStep + 1}.png`);
        }
        else if (e.key === '?' && window.StoryEffects) {
            window.StoryEffects.showShortcuts();
        }
        else if ((e.key === 'n' || e.key === 'N') && window.StoryAudio) {
            window.StoryAudio.toggleNarration();
            const nb = document.getElementById('mmNarrationToggle');
            if (nb) { nb.textContent = window.StoryAudio.isNarrationEnabled() ? '🗣️' : '🔕'; nb.title = window.StoryAudio.isNarrationEnabled() ? 'Mute narration' : 'Enable narration'; }
        }
        else if ((e.key === 'a' || e.key === 'A') && window.StoryAudio) {
            window.StoryAudio.toggle();
            const ab = document.getElementById('mmAudioToggle');
            if (ab) { ab.textContent = window.StoryAudio.isEnabled() ? '🔊' : '🔇'; ab.title = window.StoryAudio.isEnabled() ? 'Mute story audio' : 'Enable story audio'; }
        }
    });

    // Sonification + narration toggle buttons
    if (window.StoryAudio) {
        window.StoryAudio.wireToggleButton('mmAudioToggle');
        window.StoryAudio.wireNarrationButton('mmNarrationToggle');
    }

    // Effect buttons
    if (window.StoryEffects) {
        const spotBtn = document.getElementById('mmSpotlightToggle');
        if (spotBtn) spotBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (window.StoryEffects.isSpotlightActive()) window.StoryEffects.spotlightOff();
            else window.StoryEffects.spotlightOn(section);
        });

        const expBtn = document.getElementById('mmExportSlide');
        if (expBtn) expBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const slide = document.querySelector('#mmStorySlides .story-slide.active');
            if (slide) window.StoryEffects.exportSlide(slide, `meaningful-metrics-step-${currentStep + 1}.png`);
        });

        const kbdBtn = document.getElementById('mmShortcutsBtn');
        if (kbdBtn) kbdBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            window.StoryEffects.showShortcuts();
        });
    }
}

export function updateStory() {
    if (!storyEnabled || !state.filteredData || !state.filteredData.length) return;
    // Reset per-session state on data refilter
    confettiFired = false;
    if (window.StoryEffects) window.StoryEffects.resetTypewriterVisited();
    updateDescriptions();
    renderStep(currentStep);
}

export function adaptStoryTheme() {
    if (!storyEnabled || !state.filteredData || !state.filteredData.length) return;
    renderStep(currentStep);
}
