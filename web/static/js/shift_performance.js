/**
 * Shift Performance Dashboard JavaScript
 */

// Initialize the page when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    initializeShiftPerformance();
});

function initializeShiftPerformance() {
    setupMenuHandlers();
    setupTableSorting();
    setupModalHandlers();
    updateLastRefreshTime();
    addInteractiveEffects();
    setupConfetti();

    // Log caching info to console
    console.log('%c💾 Shift Performance Caching Enabled', 'color: #00d4ff; font-weight: bold; font-size: 14px;');
    console.log('%cData is cached for 1 hour to speed up subsequent loads.', 'color: #888;');
    console.log('%cTo fetch fresh data:', 'color: #888;');
    console.log('%c  • Hard refresh: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)', 'color: #888;');
    console.log('%c  • Clear cache: clearShiftCache() then reload', 'color: #888;');

    // Show fun loading spinner immediately
    showLoadingSpinner();

    // Load data after a short delay
    setTimeout(() => {
        loadInitialData();
    }, 100);
}

function setupMenuHandlers() {
    // Retain only filter menu + ESC handling; burger menu behavior is centralized in common.js
    document.addEventListener('click', function (e) {
        // Close filter menu when clicking outside
        const filterMenu = document.getElementById('filterMenu');
        const filterDropdown = document.querySelector('.filter-dropdown');
        if (filterMenu && filterDropdown && !filterDropdown.contains(e.target)) {
            closeFilters();
        }
    });

    // Close filter menu on ESC key
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            closeFilters();
        }
    });
}


function setupTableSorting() {
    // Map header cells to their actual column index in tbody
    // Row 1: Date(0), Day(1), Shift(2), Staffing(colspan=2), Tickets(colspan=2), MTPs(7), Mean Time To(colspan=2), SLA Breaches(colspan=2), Score(12), Actions(13)
    // Row 2: Scheduled(3), Actual(4), Acknowledged(5), Closed(6), Respond(8), Contain(9), Response(10), Containment(11)

    const headerMap = {
        0: 0,   // Date
        1: 1,   // Day
        2: 2,   // Shift
        // index 3: "Staffing" (colspan, parent header - NOT sortable)
        // index 4: "Tickets" (colspan, parent header - NOT sortable)
        5: 7,   // MTPs
        // index 6: "Mean Time To" (colspan, parent header - NOT sortable)
        // index 7: "SLA Breaches" (colspan, parent header - NOT sortable)
        8: 12,  // Score
        9: 13,  // Actions
        10: 3,  // Scheduled (row 2)
        11: 4,  // Actual (row 2)
        12: 5,  // Acknowledged (row 2)
        13: 6,  // Closed (row 2)
        14: 8,  // Respond (row 2)
        15: 9,  // Contain (row 2)
        16: 10, // Response (row 2)
        17: 11  // Containment (row 2)
    };

    const headers = document.querySelectorAll('.performance-table th');
    headers.forEach((header, index) => {
        const colIndex = headerMap[index];
        if (colIndex !== undefined && colIndex >= 3 && colIndex <= 12) {
            header.style.cursor = 'pointer';
            header.title = 'Click to sort (ascending → descending → original)';
            header.addEventListener('click', () => sortTable(colIndex, header));
        }
    });
}

function sortTable(columnIndex, headerElement) {
    const table = document.querySelector('.performance-table');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    // Helper to parse numeric or mm:ss
    const parseValue = (cellText) => {
        if (!cellText) return 0;
        const trimmed = cellText.trim();
        // mm:ss pattern
        if (/^\d+:\d{2}$/.test(trimmed)) {
            const [m, s] = trimmed.split(':').map(Number);
            return m + (s / 60);
        }
        // pure number
        const num = parseFloat(trimmed.replace(/[^0-9.]/g, ''));
        return isNaN(num) ? 0 : num;
    };

    // Three-state toggle: none -> asc -> desc -> none
    const currentSort = headerElement.dataset.sortDirection || 'none';
    let newSort;

    if (currentSort === 'none') {
        newSort = 'asc';
    } else if (currentSort === 'asc') {
        newSort = 'desc';
    } else {
        newSort = 'none';
    }

    // Update visual indicators - clear all first
    document.querySelectorAll('.performance-table th').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        delete th.dataset.sortDirection;
    });

    if (newSort === 'none') {
        // Restore original order
        tbody.innerHTML = '';
        originalRowOrder.forEach(row => tbody.appendChild(row));
    } else {
        // Sort rows
        const isAscending = newSort === 'asc';
        rows.sort((a, b) => {
            const aVal = parseValue(a.cells[columnIndex].textContent);
            const bVal = parseValue(b.cells[columnIndex].textContent);
            return isAscending ? aVal - bVal : bVal - aVal;
        });

        // Set indicator on clicked header
        headerElement.dataset.sortDirection = newSort;
        headerElement.classList.add(newSort === 'asc' ? 'sort-asc' : 'sort-desc');

        rows.forEach(row => tbody.appendChild(row));
    }
}

function refreshData() {
    const button = document.querySelector('.refresh-button');
    if (button) {
        button.textContent = 'Refreshing...';
        button.disabled = true;
    }

    // Show loading state
    const container = document.querySelector('.container');
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading';
    loadingDiv.textContent = 'Refreshing shift performance data...';
    container.appendChild(loadingDiv);

    // Reload the page after a short delay
    setTimeout(() => {
        window.location.reload();
    }, 1000);
}

function updateLastRefreshTime() {
    // Remove any existing refresh time display from top of page
    const existingRefreshTime = document.querySelector('.refresh-time');
    if (existingRefreshTime) {
        existingRefreshTime.remove();
    }

    // Note: Last updated time is now shown in bottom status info only
}

function exportToCSV() {
    const table = document.querySelector('.performance-table');
    const rows = table.querySelectorAll('tr');
    let csv = [];

    for (let i = 0; i < rows.length; i++) {
        const row = [];
        const cols = rows[i].querySelectorAll('td, th');

        for (let j = 0; j < cols.length - 1; j++) { // Skip last column (staffing details)
            let text = cols[j].textContent.trim();
            text = text.replace(/"/g, '""'); // Escape quotes
            row.push('"' + text + '"');
        }
        csv.push(row.join(','));
    }

    // Download CSV
    const csvContent = 'data:text/csv;charset=utf-8,' + csv.join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `shift_performance_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Auto-refresh every 30 minutes
setInterval(() => {
    console.log('Auto-refreshing shift performance data...');
    refreshData();
}, 30 * 60 * 1000);

function setupModalHandlers() {
    const modal = document.getElementById('shiftDetailsModal');

    // Close modal on ESC key
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && modal && modal.style.display === 'block') {
            closeShiftDetails();
        }
    });

    // Close modal when clicking outside of modal content
    if (modal) {
        modal.addEventListener('click', function (e) {
            if (e.target === modal) {
                closeShiftDetails();
            }
        });
    }
}

// ============================================================================
// DATA ARCHITECTURE
// ============================================================================
// All shift data comes from a SINGLE API endpoint: /api/shift-list
// - Loads once on page load
// - Cached in globalShiftData for instant access
// - Table and Details modal both use this same data source
// - All ticket counts derived from inflow_tickets/outflow_tickets arrays
// - No additional API calls when opening Details modal
// ============================================================================

// Store shift data globally so Details button can use it
let globalShiftData = [];
// Store original row order for sort reset
let originalRowOrder = [];

function loadShiftDetails(shiftId, button) {
    // Show loading state
    const originalText = button.textContent;
    button.textContent = '⏳ Loading...';
    button.disabled = true;

    // Find the shift in already-loaded data (no API call needed!)
    const shiftData = globalShiftData.find(s => s.id === shiftId);

    if (!shiftData) {
        console.error('Shift data not found for:', shiftId);
        showToast('❌ Shift data not found', 'warning');
        button.textContent = originalText;
        button.disabled = false;
        return;
    }

    // Use cached data - no API calls needed!
    try {
        const data = {
            summary: {
                shift_name: shiftData.shift,
                day_name: shiftData.day,
                date: shiftData.date
            },
            staffing: {
                shift_lead: shiftData.shift_lead || 'N/A',
                basic_staffing: shiftData.basic_staffing || {total_staff: 0, teams: {}},
                detailed_staffing: shiftData.detailed_staffing || {}
            },
            tickets: {
                tickets_acknowledged: shiftData.tickets_acknowledged || 0,
                tickets_closed: shiftData.tickets_closed || 0,
                response_time_minutes: shiftData.response_time_minutes || 0,
                contain_time_minutes: shiftData.contain_time_minutes || 0,
                response_sla_breaches: shiftData.response_sla_breaches || 0,
                containment_sla_breaches: shiftData.containment_sla_breaches || 0
            },
            performance: {
                score: shiftData.score || 1,
                actual_staff: shiftData.actual_staff || 0
            },
            security: shiftData.security_actions || {
                iocs_blocked: 0,
                domains_blocked: 0,
                malicious_true_positives: 0
            },
            inflow: {tickets: shiftData.inflow_tickets || []},
            outflow: {tickets: shiftData.outflow_tickets || []}
        };

        showShiftDetailsFromGranular(data);
        button.textContent = originalText;
        button.disabled = false;
    } catch (error) {
        console.error('Error displaying shift details:', error);
        showToast('❌ Error displaying shift details', 'warning');
        button.textContent = originalText;
        button.disabled = false;
    }
}

function formatTime(minutes) {
    if (minutes == null || isNaN(minutes) || minutes <= 0) return '0:00';
    let mins = Math.floor(minutes);
    let secs = Math.round((minutes - mins) * 60);
    if (secs === 60) {
        mins += 1;
        secs = 0;
    }
    return `${mins}:${secs.toString().padStart(2, '0')}`;
}

function closeShiftDetails() {
    const modal = document.getElementById('shiftDetailsModal');
    modal.style.display = 'none';
    document.body.style.overflow = 'auto'; // Restore scrolling
}

function showLoadingSpinner() {
    const loadingMessages = [
        '🎭 Magic building...', '🧙‍♂️ Summoning data wizards...', '⚡ Charging quantum processors...', '🔮 Consulting crystal ball...',
        '🚀 Launching data rockets...', '🎪 Setting up data circus...', '🌟 Sprinkling fairy dust...', '🎨 Painting performance pixels...',
        '🎯 Targeting shift statistics...', '🔥 Igniting analytics engine...', '🎵 Composing data symphony...', '🎪 Training performance monkeys...',
        '⚗️ Brewing shift potions...', '🎪 Juggling staff schedules...', '🎭 Rehearsing data drama...'
    ];
    let currentMessageIndex = 0;
    let messageInterval;
    window.loadingStartTime = performance.now();
    const EXPECTED_LOAD_TIME_MS = 90000; // 90 seconds average load time

    // Dim skeleton rows
    document.querySelectorAll('.skeleton-row').forEach(r => {
        r.style.opacity = '0.1';
        r.style.pointerEvents = 'none';
    });

    const loadingOverlay = document.createElement('div');
    loadingOverlay.id = 'loadingOverlay';
    loadingOverlay.innerHTML = `
        <div class="loading-spinner-container">
            <div class="loading-progress-bar-container">
                <div class="loading-progress-bar">
                    <div id="loadingProgressFill" class="loading-progress-fill"></div>
                </div>
                <div id="loadingElapsedInside" class="loading-elapsed">0s / ~90s</div>
            </div>
            <div class="loading-message" id="loadingMessage">${loadingMessages[0]}</div>
        </div>
    `;
    const tableContainer = document.querySelector('.table-container');
    if (tableContainer) tableContainer.appendChild(loadingOverlay);

    messageInterval = setInterval(() => {
        currentMessageIndex = (currentMessageIndex + 1) % loadingMessages.length;
        const el = document.getElementById('loadingMessage');
        if (!el) return;
        el.style.opacity = '0';
        setTimeout(() => {
            el.textContent = loadingMessages[currentMessageIndex];
            el.style.opacity = '1';
        }, 300);
    }, 5000);
    window.loadingMessageInterval = messageInterval;

    window.loadingElapsedInterval = setInterval(() => {
        const elapsedEl = document.getElementById('loadingElapsedInside');
        const progressFill = document.getElementById('loadingProgressFill');
        if (!elapsedEl || !progressFill || window.loadingStartTime == null) return;

        const elapsedMs = performance.now() - window.loadingStartTime;
        const secsFloat = elapsedMs / 1000;
        const display = Math.round(secsFloat);

        // Calculate progress percentage based on expected load time
        const progressPercent = Math.min((elapsedMs / EXPECTED_LOAD_TIME_MS) * 100, 100);
        progressFill.style.width = progressPercent + '%';

        // Color coding for both text and progress bar
        let cls = 'load-time-good'; // <60s
        let progressColor = 'linear-gradient(90deg, #667eea 0%, #764ba2 100%)'; // Blue/purple

        if (secsFloat >= 90) {
            cls = 'load-time-slow';
            progressColor = 'linear-gradient(90deg, #e74c3c 0%, #c0392b 100%)'; // Red
        } else if (secsFloat >= 60) {
            cls = 'load-time-warn';
            progressColor = 'linear-gradient(90deg, #f39c12 0%, #e67e22 100%)'; // Orange/yellow
        }

        progressFill.style.background = progressColor;
        elapsedEl.textContent = `${display}s / ~90s`;
        elapsedEl.className = 'loading-elapsed ' + cls;
    }, 1000);
}

function hideLoadingSpinner() {
    if (window.loadingMessageInterval) {
        clearInterval(window.loadingMessageInterval);
        window.loadingMessageInterval = null;
    }
    if (window.loadingElapsedInterval) {
        clearInterval(window.loadingElapsedInterval);
        window.loadingElapsedInterval = null;
    }
    // Compute final load duration for status display
    if (window.loadingStartTime != null) {
        const totalSecs = (performance.now() - window.loadingStartTime) / 1000;
        window.finalLoadDurationSeconds = totalSecs; // store for updateStatusInfo
        const finalDisplay = totalSecs >= 30 ? Math.round(totalSecs) : totalSecs.toFixed(1);
        console.log(`⚡ Shift data loaded in ${finalDisplay}s`); // feature #5 logging
    }
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingOverlay) {
        loadingOverlay.style.opacity = '0';
        setTimeout(() => {
            loadingOverlay.remove();
        }, 300);
    }
    const skeletonRows = document.querySelectorAll('.skeleton-row');
    skeletonRows.forEach(row => {
        row.style.opacity = '1';
        row.style.pointerEvents = 'auto';
        row.style.display = '';
    });
}

function showShiftDetailsFromGranular(data) {
    const {summary, staffing, tickets, security, inflow, outflow, performance} = data;

    // Update modal title
    const modalTitle = document.getElementById('modalTitle');
    modalTitle.textContent = `${summary.shift_name} Shift - ${summary.day_name}, ${summary.date}`;

    // Helper function to convert minutes to mm:ss format
    const formatMinutesToTime = (minutes) => {
        if (minutes === null || minutes === undefined || isNaN(minutes)) return 'N/A';
        const mins = Math.floor(minutes);
        const secs = Math.round((minutes - mins) * 60);
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    };

    // Helper function to generate ticket table
    const generateInflowTable = (tickets) => {
        if (!tickets || tickets.length === 0) {
            return '<div class="empty-state">No inflow tickets for this shift</div>';
        }
        const base = (typeof window !== 'undefined' && window.XSOAR_BASE) ? window.XSOAR_BASE.replace(/\/$/, '') : 'https://msoar.crtx.us.paloaltonetworks.com';
        return `
            <table class="ticket-table">
                <thead>
                    <tr>
                        <th>Ticket #</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Owner</th>
                        <th>TTR (mm:ss)</th>
                        <th>TTC (mm:ss)</th>
                        <th>Created (ET)</th>
                    </tr>
                </thead>
                <tbody>
                    ${tickets.map(ticket => `
                        <tr>
                            <td><a href="${base}/Custom/caseinfoid/${ticket.id}" target="_blank" rel="noopener noreferrer">${ticket.id}</a></td>
                            <td>${ticket.name || 'N/A'}</td>
                            <td><span class="ticket-type-badge">${ticket.type || 'N/A'}</span></td>
                            <td>${ticket.owner || 'Unassigned'}</td>
                            <td>${formatMinutesToTime(ticket.ttr)}</td>
                            <td>${formatMinutesToTime(ticket.ttc)}</td>
                            <td>${ticket.created || 'N/A'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    };

    const generateOutflowTable = (tickets) => {
        if (!tickets || tickets.length === 0) {
            return '<div class="empty-state">No outflow tickets for this shift</div>';
        }
        const base = (typeof window !== 'undefined' && window.XSOAR_BASE) ? window.XSOAR_BASE.replace(/\/$/, '') : 'https://msoar.crtx.us.paloaltonetworks.com';
        return `
            <table class="ticket-table">
                <thead>
                    <tr>
                        <th>Ticket #</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Owner</th>
                        <th>Closed (ET)</th>
                        <th>Impact</th>
                    </tr>
                </thead>
                <tbody>
                    ${tickets.map(ticket => `
                        <tr>
                            <td><a href="${base}/Custom/caseinfoid/${ticket.id}" target="_blank" rel="noopener noreferrer">${ticket.id}</a></td>
                            <td>${ticket.name || 'N/A'}</td>
                            <td><span class="ticket-type-badge">${ticket.type || 'N/A'}</span></td>
                            <td>${ticket.owner || 'Unassigned'}</td>
                            <td>${ticket.closed || 'N/A'}</td>
                            <td>${ticket.impact || 'Unknown'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    };

    // Build modal content using granular data with tabs
    const modalBody = document.getElementById('modalBody');
    modalBody.innerHTML = `
        <div class="modal-tabs">
            <button class="modal-tab active" onclick="switchTab(event, 'inflow-tab')">📥 Inflow (${inflow.tickets.length})</button>
            <button class="modal-tab" onclick="switchTab(event, 'outflow-tab')">📤 Outflow (${outflow.tickets.length})</button>
            <button class="modal-tab" onclick="switchTab(event, 'metrics-tab')">📊 Metrics</button>
            <button class="modal-tab" onclick="switchTab(event, 'staff-tab')">👥 Staff</button>
        </div>

        <div id="inflow-tab" class="tab-content active">
            <h3>📥 Inflow Tickets</h3>
            ${generateInflowTable(inflow.tickets)}
        </div>

        <div id="outflow-tab" class="tab-content">
            <h3>📤 Outflow Tickets (Closed)</h3>
            ${generateOutflowTable(outflow.tickets)}
        </div>

        <div id="metrics-tab" class="tab-content">
        <div class="detail-section">
            <h3>🎯 Key Performance Metrics</h3>
            <div class="key-metrics-grid">
                <div class="key-metric score-highlight">
                    <div class="metric-label">Performance Score</div>
                    <div class="metric-value metric-score ${performance.score >= 9 ? 'metric-good' : performance.score >= 7 ? 'metric-warning' : 'metric-bad'}">${performance.score}/10</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Tickets Acknowledged</div>
                    <div class="metric-value ${tickets.tickets_acknowledged > 15 ? 'metric-bad' : tickets.tickets_acknowledged > 10 ? 'metric-warning' : 'metric-good'}">${tickets.tickets_acknowledged}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Tickets Closed</div>
                    <div class="metric-value ${tickets.tickets_closed >= tickets.tickets_acknowledged ? 'metric-good' : tickets.tickets_closed < tickets.tickets_acknowledged * 0.5 ? 'metric-bad' : 'metric-warning'}">${tickets.tickets_closed}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Respond</div>
                    <div class="metric-value ${tickets.response_time_minutes <= 3 ? 'metric-good' : tickets.response_time_minutes <= 4 ? 'metric-warning' : 'metric-bad'}">${formatTime(tickets.response_time_minutes)}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Contain</div>
                    <div class="metric-value ${tickets.contain_time_minutes <= 15 ? 'metric-good' : tickets.contain_time_minutes <= 30 ? 'metric-warning' : 'metric-bad'}">${formatTime(tickets.contain_time_minutes)}</div>
                </div>
            </div>
            <div class="key-metrics-grid" style="margin-top: 20px;">
                <div class="key-metric">
                    <div class="metric-label">Response SLA Breaches</div>
                    <div class="metric-value ${(tickets.response_sla_breaches || 0) === 0 ? 'metric-good' : 'metric-bad'}">${tickets.response_sla_breaches || 0} ${(tickets.response_sla_breaches || 0) > 0 ? '(-2pts each)' : ''}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Containment SLA Breaches</div>
                    <div class="metric-value ${(tickets.containment_sla_breaches || 0) === 0 ? 'metric-good' : 'metric-bad'}">${tickets.containment_sla_breaches || 0} ${(tickets.containment_sla_breaches || 0) > 0 ? '(-2pts each)' : ''}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">SLA Compliance</div>
                    <div class="metric-value ${(tickets.response_sla_breaches || 0) === 0 && (tickets.containment_sla_breaches || 0) === 0 ? 'metric-good' : 'metric-bad'}">${(tickets.response_sla_breaches || 0) === 0 && (tickets.containment_sla_breaches || 0) === 0 ? '100%' : ((1 - Math.min((tickets.response_sla_breaches || 0) + (tickets.containment_sla_breaches || 0), tickets.tickets_acknowledged) / Math.max(tickets.tickets_acknowledged, 1)) * 100).toFixed(0) + '%'}</div>
                </div>
            </div>
        </div>

        <div class="detail-section score-breakdown">
            <h3>📈 Score Breakdown</h3>
            <div class="score-explanation">
                <p><strong>How the score is calculated (1-10 scale):</strong></p>
                <div class="score-factors">
                    <div class="score-factor">
                        <span class="factor-icon">📊</span>
                        <div class="factor-details">
                            <strong>Productivity (30%)</strong>
                            <ul>
                                <li>Tickets closed per analyst: ${performance.actual_staff > 0 ? (tickets.tickets_closed / performance.actual_staff).toFixed(1) : 'N/A'} tickets/analyst</li>
                                <li>${tickets.tickets_closed >= tickets.tickets_acknowledged ? '✓ Closed ≥ Acknowledged (+10pts bonus)' : '✗ Closed < Acknowledged (-10pts penalty)'}</li>
                            </ul>
                        </div>
                    </div>
                    <div class="score-factor">
                        <span class="factor-icon">⚡</span>
                        <div class="factor-details">
                            <strong>Response Quality (50%)</strong>
                            <ul>
                                <li>Response time: ${formatTime(tickets.response_time_minutes)} ${tickets.response_time_minutes <= 1 ? '(excellent)' : tickets.response_time_minutes <= 3 ? '(good)' : tickets.response_time_minutes <= 4 ? '(acceptable)' : '(needs improvement)'}</li>
                                <li>Containment time: ${formatTime(tickets.contain_time_minutes)} ${tickets.contain_time_minutes <= 8 ? '(excellent)' : tickets.contain_time_minutes <= 15 ? '(good)' : tickets.contain_time_minutes <= 30 ? '(acceptable)' : '(needs improvement)'}</li>
                            </ul>
                        </div>
                    </div>
                    <div class="score-factor">
                        <span class="factor-icon">⚠️</span>
                        <div class="factor-details">
                            <strong>SLA Compliance (20%)</strong>
                            <ul>
                                <li>Response SLA breaches: ${tickets.response_sla_breaches || 0} ${tickets.response_sla_breaches > 0 ? '(-2pts each)' : '(0 breaches ✓)'}</li>
                                <li>Containment SLA breaches: ${tickets.containment_sla_breaches || 0} ${tickets.containment_sla_breaches > 0 ? '(-2pts each)' : '(0 breaches ✓)'}</li>
                            </ul>
                        </div>
                    </div>
                </div>
                <div class="score-legend">
                    <span class="legend-item"><span class="legend-color metric-good"></span> 9-10: Excellent</span>
                    <span class="legend-item"><span class="legend-color metric-warning"></span> 7-8: Average</span>
                    <span class="legend-item"><span class="legend-color metric-bad"></span> 1-6: Needs Improvement</span>
                </div>
            </div>
        </div>

        <div class="detail-section">
            <h3>🔍 Detailed Score Analysis</h3>
            <div class="score-analysis">
                ${(() => {
                    const staff = Math.max(performance.actual_staff, 1);
                    const ticketsPerAnalyst = tickets.tickets_closed / staff;

                    // 1. Productivity (up to 20 pts)
                    const productivityPts = Math.min(ticketsPerAnalyst * 10, 20);

                    // 2. Backlog clearing (+10 or -10)
                    const backlogPts = tickets.tickets_closed >= tickets.tickets_acknowledged ? 10 : -10;

                    // 3. Response time (up to 25 pts)
                    let responsePts = 0;
                    if (tickets.response_time_minutes <= 5) responsePts = 25;
                    else if (tickets.response_time_minutes <= 15) responsePts = 18;
                    else if (tickets.response_time_minutes <= 30) responsePts = 10;

                    // 4. Containment time (up to 25 pts)
                    let containmentPts = 0;
                    if (tickets.contain_time_minutes <= 30) containmentPts = 25;
                    else if (tickets.contain_time_minutes <= 60) containmentPts = 18;
                    else if (tickets.contain_time_minutes <= 120) containmentPts = 10;

                    // 5. Response SLA (up to 10 pts)
                    const responseSLAPts = Math.max(0, 10 - (tickets.response_sla_breaches || 0) * 2);

                    // 6. Containment SLA (up to 10 pts)
                    const containmentSLAPts = Math.max(0, 10 - (tickets.containment_sla_breaches || 0) * 2);

                    const totalPts = productivityPts + backlogPts + responsePts + containmentPts + responseSLAPts + containmentSLAPts;
                    const cappedTotal = Math.max(0, Math.min(100, totalPts));
                    const finalScore = Math.max(1, Math.min(10, Math.round(cappedTotal / 10)));

                    return `
                        <div class="score-calculation">
                            <table class="score-table">
                                <thead>
                                    <tr>
                                        <th>Component</th>
                                        <th>Calculation</th>
                                        <th>Points</th>
                                        <th>Max</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr class="${productivityPts >= 15 ? 'score-good' : productivityPts >= 10 ? 'score-warning' : 'score-bad'}">
                                        <td><strong>1. Productivity</strong></td>
                                        <td>${ticketsPerAnalyst.toFixed(1)} tickets/analyst × 10</td>
                                        <td>${productivityPts.toFixed(1)}</td>
                                        <td>20</td>
                                    </tr>
                                    <tr class="${backlogPts > 0 ? 'score-good' : 'score-bad'}">
                                        <td><strong>2. Backlog Clearing</strong></td>
                                        <td>${tickets.tickets_closed} closed ${tickets.tickets_closed >= tickets.tickets_acknowledged ? '≥' : '<'} ${tickets.tickets_acknowledged} ack</td>
                                        <td>${backlogPts > 0 ? '+' : ''}${backlogPts}</td>
                                        <td>+10/-10</td>
                                    </tr>
                                    <tr class="${responsePts >= 20 ? 'score-good' : responsePts >= 15 ? 'score-warning' : 'score-bad'}">
                                        <td><strong>3. Response Time</strong></td>
                                        <td>${formatTime(tickets.response_time_minutes)} avg</td>
                                        <td>${responsePts}</td>
                                        <td>25</td>
                                    </tr>
                                    <tr class="${containmentPts >= 20 ? 'score-good' : containmentPts >= 15 ? 'score-warning' : 'score-bad'}">
                                        <td><strong>4. Containment Time</strong></td>
                                        <td>${formatTime(tickets.contain_time_minutes)} avg</td>
                                        <td>${containmentPts}</td>
                                        <td>25</td>
                                    </tr>
                                    <tr class="${responseSLAPts >= 8 ? 'score-good' : responseSLAPts >= 5 ? 'score-warning' : 'score-bad'}">
                                        <td><strong>5. Response SLA</strong></td>
                                        <td>10 - (${tickets.response_sla_breaches || 0} × 2)</td>
                                        <td>${responseSLAPts}</td>
                                        <td>10</td>
                                    </tr>
                                    <tr class="${containmentSLAPts >= 8 ? 'score-good' : containmentSLAPts >= 5 ? 'score-warning' : 'score-bad'}">
                                        <td><strong>6. Containment SLA</strong></td>
                                        <td>10 - (${tickets.containment_sla_breaches || 0} × 2)</td>
                                        <td>${containmentSLAPts}</td>
                                        <td>10</td>
                                    </tr>
                                    <tr class="score-total">
                                        <td colspan="2"><strong>TOTAL</strong></td>
                                        <td><strong>${cappedTotal}</strong></td>
                                        <td><strong>100</strong></td>
                                    </tr>
                                    <tr class="score-final">
                                        <td colspan="2"><strong>FINAL SCORE (÷ 10)</strong></td>
                                        <td colspan="2"><strong>${finalScore}/10</strong></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>

                        <div class="score-tips">
                            <h4>💡 Tips to Improve Score</h4>
                            <ul>
                                ${productivityPts < 15 ? '<li><strong>Boost Productivity:</strong> Increase tickets closed per analyst. Target: 2+ tickets/analyst for full 20pts</li>' : ''}
                                ${backlogPts < 0 ? `<li><strong>Clear Backlog:</strong> Close ≥ acknowledged tickets. ${tickets.tickets_acknowledged - tickets.tickets_closed} more needed for +10pts bonus</li>` : ''}
                                ${responsePts < 25 ? `<li><strong>Faster Response:</strong> Reduce avg response time to &lt;5min for full 25pts (currently ${formatTime(tickets.response_time_minutes)})</li>` : ''}
                                ${containmentPts < 25 ? `<li><strong>Faster Containment:</strong> Reduce avg containment to &lt;30min for full 25pts (currently ${formatTime(tickets.contain_time_minutes)})</li>` : ''}
                                ${responseSLAPts < 10 ? `<li><strong>Response SLA:</strong> Avoid breaches. ${tickets.response_sla_breaches} breach${tickets.response_sla_breaches > 1 ? 'es' : ''} cost ${(tickets.response_sla_breaches || 0) * 2}pts</li>` : ''}
                                ${containmentSLAPts < 10 ? `<li><strong>Containment SLA:</strong> Avoid breaches. ${tickets.containment_sla_breaches} breach${tickets.containment_sla_breaches > 1 ? 'es' : ''} cost ${(tickets.containment_sla_breaches || 0) * 2}pts</li>` : ''}
                                ${finalScore >= 9 ? '<li><strong>🎉 Excellent Work!</strong> This shift met all performance targets!</li>' : ''}
                            </ul>
                        </div>
                    `;
                })()}
            </div>
        </div>

        <div class="detail-section">
            <h3>👤 Shift Leadership</h3>
            <div class="leadership-info">
                <div class="shift-lead">
                    <strong>Shift Lead:</strong> ${staffing.shift_lead}
                </div>
                <div class="shift-stats">
                    <span>Total Staff: ${staffing.basic_staffing.total_staff}</span> •
                    <span>Tickets per Staff: ${staffing.basic_staffing.total_staff > 0 ? (tickets.tickets_closed / staffing.basic_staffing.total_staff).toFixed(1) : 'N/A'}</span>
                </div>
            </div>
        </div>

        <div class="detail-section">
            <h3>🛡️ Security Actions & Performance</h3>
            <div class="security-grid">
                <div class="security-item">
                    <strong>IOCs Blocked</strong>
                    <div class="security-value">${security.iocs_blocked || 0}</div>
                </div>
                <div class="security-item">
                    <strong>Domains Blocked</strong>
                    <div class="security-value">${security.domains_blocked || 0}</div>
                </div>
                <div class="security-item">
                    <strong>Malicious True Positives</strong>
                    <div class="security-value">${security.malicious_true_positives}</div>
                </div>
            </div>
        </div>

        <div class="detail-section">
            <h3>📊 Additional Metrics</h3>
            <div class="additional-metrics">
                <div class="metric-row">
                    <span class="metric-label">Tickets per Staff Member:</span>
                    <span class="metric-value">${staffing.basic_staffing.total_staff > 0 ? (tickets.tickets_closed / staffing.basic_staffing.total_staff).toFixed(1) : 'N/A'}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Shift Effectiveness:</span>
                    <span class="metric-value ${tickets.tickets_closed >= tickets.tickets_acknowledged ? 'metric-good' : 'metric-warning'}">${tickets.tickets_acknowledged > 0 ? ((tickets.tickets_closed / tickets.tickets_acknowledged) * 100).toFixed(0) + '%' : 'N/A'}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Team Coverage:</span>
                    <span class="metric-value">${Object.keys(staffing.basic_staffing.teams).length} teams active</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Workload Balance:</span>
                    <span class="metric-value ${staffing.basic_staffing.total_staff >= 6 ? 'metric-good' : staffing.basic_staffing.total_staff >= 4 ? 'metric-warning' : 'metric-bad'}">${staffing.basic_staffing.total_staff >= 6 ? 'Well Staffed' : staffing.basic_staffing.total_staff >= 4 ? 'Adequate' : 'Understaffed'}</span>
                </div>
            </div>
        </div>
        </div>

        <div id="staff-tab" class="tab-content">
            <div class="detail-section">
                <h3>👤 Shift Leadership</h3>
                <div class="leadership-info">
                    <div class="shift-lead">
                        <strong>Shift Lead:</strong> ${staffing.shift_lead}
                    </div>
                    <div class="shift-stats">
                        <span>Total Staff: ${staffing.basic_staffing.total_staff}</span> •
                        <span>Tickets per Staff: ${staffing.basic_staffing.total_staff > 0 ? (tickets.tickets_closed / staffing.basic_staffing.total_staff).toFixed(1) : 'N/A'}</span>
                    </div>
                </div>
            </div>

            <div class="detail-section staffing-section">
                <h3>👥 Full Shift Staff</h3>
                <div class="staff-grid">
                    ${Object.entries(staffing.detailed_staffing).map(([team, members]) => `
                        <div class="staff-team">
                            <h4>${team} (${staffing.basic_staffing.teams[team] || 0})</h4>
                            <div class="staff-list">
                                ${Array.isArray(members) && members.length > 0 && members[0] !== 'N/A (Excel file missing)'
        ? members.map(member => `<span class="staff-member">${member}</span>`).join('')
        : '<span class="no-staff">No staff assigned</span>'}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;

    // Show modal
    const modal = document.getElementById('shiftDetailsModal');
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden'; // Prevent background scrolling

    // Trigger confetti for excellent performance
    if (security.malicious_true_positives === 0 && tickets.tickets_closed >= tickets.tickets_acknowledged) {
        setTimeout(() => {
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                createConfetti(modalContent);
            }
        }, 500);
    }
}

// Tab switching function for modal
function switchTab(event, tabId) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
    });

    // Remove active class from all tabs
    const tabs = document.querySelectorAll('.modal-tab');
    tabs.forEach(tab => {
        tab.classList.remove('active');
    });

    // Show the selected tab content
    const selectedTab = document.getElementById(tabId);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Add active class to the clicked tab
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }
}

function openMtpModal(mtpIds, shiftId) {
    const modal = document.getElementById('mtpModal');
    const body = document.getElementById('mtpModalBody');
    if (!modal || !body) return;
    const base = (typeof window !== 'undefined' && window.XSOAR_BASE) ? window.XSOAR_BASE.replace(/\/$/, '') : 'https://msoar.crtx.us.paloaltonetworks.com';
    if (!mtpIds.length) {
        body.innerHTML = '<p>No Malicious True Positives for this shift.</p>';
    } else {
        const list = mtpIds.map(rawId => {
            const id = (rawId || '').toString().trim();
            const url = `${base}/Custom/caseinfoid/${encodeURIComponent(id)}`;
            return `<li class=\"mtp-id\"><a href=\"${url}\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"mtp-link\">${id}</a></li>`;
        }).join('');
        body.innerHTML = `<p><strong>${mtpIds.length}</strong> MTP ticket(s) in shift <code>${shiftId}</code>:</p><ul class=\"mtp-list\">${list}</ul>`;
    }
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function closeMtpModal() {
    const modal = document.getElementById('mtpModal');
    if (modal) modal.style.display = 'none';
    document.body.style.overflow = 'auto';
}

// Add keyboard shortcuts
document.addEventListener('keydown', function (e) {
    if (e.ctrlKey || e.metaKey) {
        switch (e.key) {
            case 'r':
                e.preventDefault();
                refreshData();
                break;
            case 'e':
                e.preventDefault();
                exportToCSV();
                break;
        }
    }
});

function addInteractiveEffects() {
    // Add click effects to metrics
    document.querySelectorAll('.metric-good, .metric-warning, .metric-bad').forEach(metric => {
        metric.addEventListener('click', function () {
            this.style.animation = 'none';
            setTimeout(() => {
                this.style.animation = '';
            }, 10);

            // Create a ripple effect
            const ripple = document.createElement('span');
            ripple.classList.add('ripple');
            this.appendChild(ripple);

            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });

    // Add hover sound effect (optional)
    document.querySelectorAll('.summary-card').forEach(card => {
        card.addEventListener('mouseenter', function () {
            // Optional: add a subtle hover sound
            // playHoverSound();
        });
    });
}

function setupConfetti() {
    // Trigger confetti for exceptional performance
    const exceptionalMetrics = document.querySelectorAll('.metric-good');
    exceptionalMetrics.forEach(metric => {
        if (parseInt(metric.textContent) > 20) { // Customize threshold
            metric.addEventListener('click', function () {
                createConfetti(this);
            });
        }
    });
}

function createConfetti(element) {
    const rect = element.getBoundingClientRect();
    const colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24', '#f0932b', '#eb4d4b', '#6c5ce7'];

    for (let i = 0; i < 30; i++) {
        const confetti = document.createElement('div');
        confetti.style.cssText = `
            position: fixed;
            width: 10px;
            height: 10px;
            background: ${colors[Math.floor(Math.random() * colors.length)]};
            top: ${rect.top + rect.height / 2}px;
            left: ${rect.left + rect.width / 2}px;
            z-index: 1000;
            border-radius: 50%;
            pointer-events: none;
            animation: confettiFall 2s ease-out forwards;
            transform-origin: center;
        `;

        // Random direction and rotation
        const angle = Math.random() * 360;
        const velocity = Math.random() * 200 + 50;
        confetti.style.setProperty('--angle', angle + 'deg');
        confetti.style.setProperty('--velocity', velocity + 'px');

        document.body.appendChild(confetti);

        setTimeout(() => {
            confetti.remove();
        }, 2000);
    }
}

// Add dynamic CSS for confetti animation
const confettiStyles = document.createElement('style');
confettiStyles.textContent = `
    @keyframes confettiFall {
        0% {
            transform: translateY(0) rotate(0deg) scale(1);
            opacity: 1;
        }
        100% {
            transform: translateY(500px) rotate(720deg) scale(0.5);
            opacity: 0;
        }
    }

    .ripple {
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.6);
        transform: scale(0);
        animation: rippleEffect 0.6s linear;
        pointer-events: none;
    }

    @keyframes rippleEffect {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
`;
document.head.appendChild(confettiStyles);

// Performance monitoring (silent)
if ('performance' in window) {
    window.addEventListener('load', function () {
        setTimeout(function () {
            const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
            console.log('🚀 Shift Performance page loaded in', loadTime, 'ms');
        }, 0);
    });
}

function loadInitialData() {
    const CACHE_KEY = 'shift_performance_data';
    const CACHE_DURATION_MS = 60 * 60 * 1000; // 1 hour

    // Check for cached data
    try {
        const cachedItem = localStorage.getItem(CACHE_KEY);
        if (cachedItem) {
            const {timestamp, data} = JSON.parse(cachedItem);
            const age = Date.now() - timestamp;

            if (age < CACHE_DURATION_MS) {
                // Use cached data
                console.log(`Using cached data (${Math.round(age / 1000)}s old)`);
                hideLoadingSpinner();
                updateStatusInfo();
                populateTable(data.data);
                showToast(`📦 Loaded from cache (${Math.round(age / 60000)}min old) • Use Clear cache button at the bottom right corner for fresh data`, 'info');
                return;
            } else {
                console.log('Cache expired, fetching fresh data');
            }
        }
    } catch (e) {
        console.warn('Cache read error:', e);
    }

    // Make AJAX call to get shift list data
    fetch('/api/shift-list')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Cache the data
                try {
                    const cacheItem = {
                        timestamp: Date.now(),
                        data: data
                    };
                    localStorage.setItem(CACHE_KEY, JSON.stringify(cacheItem));
                    console.log('Data cached successfully');
                } catch (e) {
                    console.warn('Cache write error:', e);
                }

                // Hide loading spinner
                hideLoadingSpinner();

                // Update status info
                updateStatusInfo();

                // Populate table
                populateTable(data.data);

                // Show success message
                showToast('🎉 Shift data loaded!', 'success');
            } else {
                console.error('API Error:', data.error);
                hideLoadingSpinner();
                showToast('❌ Failed to load shift data: ' + data.error, 'warning');
            }
        })
        .catch(error => {
            console.error('Network Error:', error);
            hideLoadingSpinner();
            showToast('❌ Network error loading shift data', 'warning');
        });
}

/**
 * Manually clear the shift performance cache
 * Usage: Call clearShiftCache() from browser console or programmatically
 */
function clearShiftCache() {
    const CACHE_KEY = 'shift_performance_data';
    try {
        localStorage.removeItem(CACHE_KEY);
        console.log('✅ Cache cleared successfully');
        showToast('🗑️ Cache cleared! Reload page to fetch fresh data.', 'success');
        return true;
    } catch (e) {
        console.error('❌ Error clearing cache:', e);
        return false;
    }
}

/**
 * Clear both client-side and server-side cache, then reload
 * Used by the UI button
 */
function clearCacheAndReload() {
    const CACHE_KEY = 'shift_performance_data';

    // Show loading toast
    showToast('🗑️ Clearing cache...', 'info');

    try {
        // 1. Clear client-side localStorage
        localStorage.removeItem(CACHE_KEY);
        console.log('✅ Client cache cleared');

        // 2. Clear server-side cache via API
        fetch('/api/clear-cache', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log('✅ Server cache cleared');
                    showToast('🔄 Fetching fresh data...', 'info');
                    // 3. Force reload from server
                    setTimeout(() => {
                        location.reload(true);
                    }, 500);
                } else {
                    console.error('❌ Server cache clear failed:', data.error);
                    showToast('⚠️ Warning: Server cache may not be cleared', 'warning');
                    // Reload anyway
                    setTimeout(() => {
                        location.reload(true);
                    }, 1000);
                }
            })
            .catch(error => {
                console.error('❌ Error calling clear-cache API:', error);
                showToast('⚠️ Warning: Server cache may not be cleared', 'warning');
                // Reload anyway
                setTimeout(() => {
                    location.reload(true);
                }, 1000);
            });
    } catch (e) {
        console.error('❌ Error clearing cache:', e);
        showToast('❌ Error clearing cache', 'warning');
    }
}

// Make functions globally accessible
window.clearShiftCache = clearShiftCache;
window.clearCacheAndReload = clearCacheAndReload;

function updateStatusInfo() {
    const now = new Date();
    const timeOptions = {year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short', hour12: true};
    const timeString = now.toLocaleString('en-US', timeOptions);
    const el = document.getElementById('last-updated');
    if (!el) return;
    let text = `Last updated: ${timeString}`;
    if (window.finalLoadDurationSeconds != null) {
        const secs = window.finalLoadDurationSeconds;
        const display = secs >= 30 ? Math.round(secs) : secs.toFixed(1);
        let cls = 'load-time-good';
        if (secs >= 60) cls = 'load-time-slow';
        else if (secs >= 30) cls = 'load-time-warn';
        text += ` • Loaded in <span class="load-duration ${cls}">${display}s</span>`;
    }
    el.innerHTML = text;
}

function populateTable(shiftData) {
    // Store shift data globally for use in Details modal
    globalShiftData = shiftData;

    const tbody = document.getElementById('shifts-tbody');
    tbody.innerHTML = '';
    originalRowOrder = []; // Clear previous order

    shiftData.forEach((shift, index) => {
        const row = document.createElement('tr');
        row.className = `shift-${shift.shift.toLowerCase()} shift-status-${shift.status}`;
        row.setAttribute('data-shift', shift.shift.toLowerCase());
        row.setAttribute('data-status', shift.status);
        row.setAttribute('data-date', shift.date);

        const formatTime = (minutes) => {
            if (!minutes || minutes === 0) return '0:00';
            const mins = Math.floor(minutes);
            const secs = Math.round((minutes - mins) * 60);
            return `${mins}:${secs.toString().padStart(2, '0')}`;
        };
        const mtpListRaw = shift.mtp_ticket_ids || '';
        const mtpIds = mtpListRaw.split(/\s*,\s*/).filter(id => id);
        const mtpCount = mtpIds.length;
        const mtpCellContent = `<span class=\"mtp-cell\" data-shift-id=\"${shift.id}\" data-mtp-ids=\"${mtpIds.join(',')}\" title=\"${mtpIds.length ? 'MTP IDs: ' + mtpIds.join(', ') : 'No MTPs'}\">${mtpCount}</span>`;

        // Format score with color coding (1-10 scale)
        const score = shift.score || 1;
        let scoreClass = 'metric-bad';  // Red for < 7
        if (score >= 9) {
            scoreClass = 'metric-good';  // Green for >= 9
        } else if (score >= 7) {
            scoreClass = 'metric-warning';  // Orange for >= 7
        }

        row.innerHTML = `
            <td>${shift.date}</td>
            <td>${shift.day}</td>
            <td><strong>${shift.shift}</strong></td>
            <td>${shift.total_staff}</td>
            <td>${shift.actual_staff || 0}</td>
            <td>${shift.tickets_acknowledged}</td>
            <td class="${shift.tickets_closed >= shift.tickets_acknowledged ? 'metric-good' : ''}">${shift.tickets_closed}</td>
            <td>${mtpCellContent}</td>
            <td>${formatTime(shift.response_time_minutes)}</td>
            <td>${formatTime(shift.contain_time_minutes)}</td>
            <td>${shift.response_sla_breaches}</td>
            <td>${shift.containment_sla_breaches}</td>
            <td><strong class="${scoreClass}">${score}</strong></td>
            <td>
                <button class="load-details-btn" onclick="loadShiftDetails('${shift.id}', this)" data-shift-id="${shift.id}">📊 Details</button>
            </td>`;
        row.style.opacity = '0';
        row.style.transform = 'translateX(-20px)';
        tbody.appendChild(row);
        originalRowOrder.push(row); // Store original order

        // Stagger the animation only, not the DOM insertion
        setTimeout(() => {
            row.style.transition = 'all 0.5s ease';
            row.style.opacity = '1';
            row.style.transform = 'translateX(0)';
        }, index * 50);
    });
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? '#00b894' : type === 'warning' ? '#fdcb6e' : '#74b9ff'};
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        z-index: 10000;
        animation: slideInToast 1s ease-out;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    `;
    toast.textContent = message;

    const toastStyles = document.createElement('style');
    toastStyles.textContent = `
        @keyframes slideInToast {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOutToast {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(toastStyles);

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOutToast 0.3s ease-out';
        setTimeout(() => {
            toast.remove();
            toastStyles.remove();
        }, 300);
    }, 3000);
}

// Filter Functions
function toggleFilters() {
    const menu = document.getElementById('filterMenu');
    const isVisible = menu.style.display !== 'none';
    menu.style.display = isVisible ? 'none' : 'block';

    // Update button text
    const button = document.querySelector('.filter-toggle');
    button.textContent = isVisible ? '🔽 Filters' : '🔼 Filters';
}

function closeFilters() {
    const menu = document.getElementById('filterMenu');
    menu.style.display = 'none';
    const button = document.querySelector('.filter-toggle');
    button.textContent = '🔽 Filters';
}

function applyFilters() {
    // Get selected shift types
    const shiftFilters = [];
    const checkboxes = document.querySelectorAll('.filter-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            shiftFilters.push(cb.value.toLowerCase());
        }
    });

    // Get selected time range
    const checkedTime = document.querySelector('input[name="timeRange"]:checked');
    const timeRangeValue = checkedTime ? checkedTime.value : '7';

    console.log('=== FILTER DEBUG ===');
    console.log('Selected shift types:', shiftFilters);
    console.log('Selected time range:', timeRangeValue);

    // Calculate date range based on time range selection
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let cutoffDate;
    let maxDate;

    if (timeRangeValue === 'today') {
        cutoffDate = new Date(today);
        maxDate = new Date(today);
    } else if (timeRangeValue === 'yesterday') {
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        cutoffDate = new Date(yesterday);
        maxDate = new Date(yesterday);
    } else {
        // Last N days including today
        const days = parseInt(timeRangeValue);
        cutoffDate = new Date(today);
        cutoffDate.setDate(cutoffDate.getDate() - days + 1);
        maxDate = new Date(today);
    }

    console.log('Today:', today.toISOString().split('T')[0]);
    console.log('Cutoff date:', cutoffDate.toISOString().split('T')[0]);
    console.log('Max date:', maxDate.toISOString().split('T')[0]);

    // Apply filters to all rows
    const rows = document.querySelectorAll('#shifts-tbody tr');
    let visibleCount = 0;

    rows.forEach((row, idx) => {
        // Check shift type filter
        const shiftType = row.getAttribute('data-shift');
        const showShift = shiftFilters.length === 0 || shiftFilters.includes(shiftType);

        // Check date filter
        const dateStr = row.getAttribute('data-date');

        if (idx < 3) {
            console.log(`Row ${idx}: data-date="${dateStr}", data-shift="${shiftType}"`);
        }

        let showDate = true;
        if (dateStr) {
            // Parse date - handle both YYYY-MM-DD and MM/DD/YYYY formats
            let rowDate;
            if (dateStr.includes('-')) {
                // YYYY-MM-DD format
                rowDate = new Date(dateStr + 'T00:00:00');
            } else {
                // MM/DD/YYYY format
                const dateParts = dateStr.split('/');
                if (dateParts.length === 3) {
                    rowDate = new Date(parseInt(dateParts[2]), parseInt(dateParts[0]) - 1, parseInt(dateParts[1]));
                }
            }

            if (rowDate) {
                rowDate.setHours(0, 0, 0, 0);
                showDate = rowDate >= cutoffDate && rowDate <= maxDate;

                if (idx < 3) {
                    console.log(`Row ${idx}: parsed=${rowDate.toISOString().split('T')[0]}, showDate=${showDate}`);
                }
            }
        } else {
            if (idx < 3) {
                console.log(`Row ${idx}: NO data-date attribute found!`);
            }
        }

        // Show or hide row
        if (showShift && showDate) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
        }
    });

    console.log(`Filters applied: ${visibleCount} rows visible out of ${rows.length}`);
    console.log('===================');

    // Close filter menu after applying
    closeFilters();
}

function clearFilters() {
    // Reset all checkboxes to default state (all checked)
    const checkboxes = document.querySelectorAll('.filter-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        cb.checked = true;
    });

    // Reset time range to 7 days
    const timeRangeEl = document.querySelector('input[name="timeRange"][value="7"]');
    if (timeRangeEl) timeRangeEl.checked = true;

    // Apply filters to show all rows
    applyFilters();
}


function deepLinkIfRequested(shiftData) {
    const params = new URLSearchParams(window.location.search);
    const shiftId = params.get('shift_id');
    if (!shiftId) return;
    const mtpOpen = params.get('mtp') === '1';

    // Find shift in cached data
    const shift = shiftData.find(s => s.id === shiftId);
    if (!shift) return;

    // Build data from cached shift
    const data = {
        summary: {
            shift_name: shift.shift,
            day_name: shift.day,
            date: shift.date
        },
        staffing: {
            shift_lead: shift.shift_lead || 'N/A',
            basic_staffing: shift.basic_staffing || {total_staff: 0, teams: {}},
            detailed_staffing: shift.detailed_staffing || {}
        },
        tickets: {
            tickets_acknowledged: shift.tickets_acknowledged || 0,
            tickets_closed: shift.tickets_closed || 0,
            response_time_minutes: shift.response_time_minutes || 0,
            contain_time_minutes: shift.contain_time_minutes || 0,
            response_sla_breaches: shift.response_sla_breaches || 0,
            containment_sla_breaches: shift.containment_sla_breaches || 0
        },
        performance: {
            score: shift.score || 1,
            actual_staff: shift.actual_staff || 0
        },
        security: shift.security_actions || {
            iocs_blocked: 0,
            domains_blocked: 0,
            malicious_true_positives: 0
        },
        inflow: {tickets: shift.inflow_tickets || []},
        outflow: {tickets: shift.outflow_tickets || []}
    };

    showShiftDetailsFromGranular(data);

    if (mtpOpen) {
        const mtpIds = shift.mtp_ticket_ids ? shift.mtp_ticket_ids.split(',').map(id => id.trim()).filter(id => id) : [];
        if (mtpIds.length) openMtpModal(mtpIds, shiftId);
    }
}

// Patch populateTable to handle deep linking after cells exist (wrap original)
const _origPopulateTable = populateTable;
populateTable = function (shiftData) {
    _origPopulateTable(shiftData);
    // Deep link after small delay to ensure DOM laid out
    setTimeout(() => {
        deepLinkIfRequested(shiftData);
    }, 50);
};
