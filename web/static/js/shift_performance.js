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


function filterShift(shiftType) {
    const rows = document.querySelectorAll('tbody tr');
    const buttons = document.querySelectorAll('.filter-controls button');

    // Update active button
    buttons.forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.getElementById('btn-' + (shiftType === 'all' ? 'all' : shiftType.toLowerCase()));
    if (activeBtn) {
        activeBtn.classList.add('active');
    }

    // Filter rows with animation
    rows.forEach((row, index) => {
        if (shiftType === 'all' || row.getAttribute('data-shift') === shiftType) {
            row.style.display = '';
            row.style.opacity = '0';
            setTimeout(() => {
                row.style.opacity = '1';
            }, index * 50); // Staggered animation
        } else {
            row.style.opacity = '0';
            setTimeout(() => {
                row.style.display = 'none';
            }, 200);
        }
    });

    updateFilteredSummary(shiftType);
}

function updateFilteredSummary(shiftType) {
    const rows = document.querySelectorAll('tbody tr');
    let totalInflow = 0;
    let totalOutflow = 0;
    let totalMaliciousTp = 0;
    let totalStaff = 0;
    let visibleRows = 0;

    rows.forEach(row => {
        if (shiftType === 'all' || row.getAttribute('data-shift') === shiftType) {
            const cells = row.querySelectorAll('td');
            // Expecting structure: 0 Date,1 Day,2 Shift,3 Staff,4 Tickets In,5 Tickets Out,6 MTPs(count),7 MTTR,8 MTTC,9 Resp SLA,10 Contain SLA,11 Actions
            if (cells.length >= 12 && !row.classList.contains('skeleton-row')) {
                totalStaff += parseInt(cells[3].textContent) || 0;
                totalInflow += parseInt(cells[4].textContent) || 0;
                totalOutflow += parseInt(cells[5].textContent) || 0;
                totalMaliciousTp += parseInt(cells[6].textContent) || 0;
                visibleRows++;
            }
        }
    });

    const summaryCards = document.querySelectorAll('.summary-value');
    if (summaryCards.length >= 4) {
        summaryCards[0].textContent = totalInflow;
        summaryCards[1].textContent = totalOutflow;
        summaryCards[2].textContent = totalMaliciousTp;
        summaryCards[3].textContent = visibleRows > 0 ? (totalStaff / visibleRows).toFixed(1) : '0.0';
    }
}

function setupTableSorting() {
    const headers = document.querySelectorAll('.performance-table th');
    headers.forEach((header, index) => {
        if (index > 2) { // Skip Date, Day, Shift columns
            header.style.cursor = 'pointer';
            header.title = 'Click to sort';
            header.addEventListener('click', () => sortTable(index));
        }
    });
}

function sortTable(columnIndex) {
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

    // Determine sort direction
    const isAscending = !table.dataset.sortAsc || table.dataset.sortAsc === 'false';
    table.dataset.sortAsc = isAscending;

    rows.sort((a, b) => {
        const aVal = parseValue(a.cells[columnIndex].textContent);
        const bVal = parseValue(b.cells[columnIndex].textContent);
        return isAscending ? aVal - bVal : bVal - aVal;
    });

    // Update visual indicators
    document.querySelectorAll('.performance-table th').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
    });
    const header = document.querySelectorAll('.performance-table th')[columnIndex];
    header.classList.add(isAscending ? 'sort-asc' : 'sort-desc');

    rows.forEach(row => tbody.appendChild(row));
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

// Store shift data globally so Details button can use it
let globalShiftData = [];

function loadShiftDetails(shiftId, button) {
    // Show loading state
    const originalText = button.textContent;
    button.textContent = '⏳ Loading...';
    button.disabled = true;

    // Find the shift in already-loaded data
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
                basic_staffing: shiftData.basic_staffing || { total_staff: 0, teams: {} },
                detailed_staffing: shiftData.detailed_staffing || {}
            },
            tickets: {
                tickets_inflow: shiftData.tickets_inflow || 0,
                tickets_closed: shiftData.tickets_closed || 0,
                response_time_minutes: shiftData.response_time_minutes || 0,
                contain_time_minutes: shiftData.contain_time_minutes || 0
            },
            security: shiftData.security_actions || {
                iocs_blocked: 0,
                domains_blocked: 0,
                malicious_true_positives: 0
            },
            inflow: { tickets: shiftData.inflow_tickets || [] },
            outflow: { tickets: shiftData.outflow_tickets || [] }
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
    if (secs === 60) { mins += 1; secs = 0; }
    return `${mins}:${secs.toString().padStart(2,'0')}`;
}

function showShiftDetails(shift) {
    // Update modal title
    const modalTitle = document.getElementById('modalTitle');
    modalTitle.textContent = `${shift.shift} Shift - ${shift.day}, ${shift.date} (${shift.shift_times.start} - ${shift.shift_times.end})`;

    // Build modal content focusing on key metrics
    const modalBody = document.getElementById('modalBody');
    modalBody.innerHTML = `
        <div class="detail-section">
            <h3>🎯 Key Performance Metrics</h3>
            <div class="key-metrics-grid">
                <div class="key-metric">
                    <div class="metric-label">Tickets Inflow</div>
                    <div class="metric-value ${shift.inflow > 15 ? 'metric-bad' : shift.inflow > 10 ? 'metric-warning' : 'metric-good'}">${shift.inflow}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Tickets Closed</div>
                    <div class="metric-value ${shift.outflow >= shift.inflow ? 'metric-good' : shift.outflow < shift.inflow * 0.5 ? 'metric-bad' : 'metric-warning'}">${shift.outflow}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Respond</div>
                    <div class="metric-value ${shift.avg_response_time_min <= 30 ? 'metric-good' : shift.avg_response_time_min <= 60 ? 'metric-warning' : 'metric-bad'}">${formatTime(shift.avg_response_time_min)}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Contain</div>
                    <div class="metric-value ${shift.avg_containment_time_min <= 120 ? 'metric-good' : shift.avg_containment_time_min <= 240 ? 'metric-warning' : 'metric-bad'}">${formatTime(shift.avg_containment_time_min)}</div>
                </div>
            </div>
        </div>

        <div class="detail-section">
            <h3>👤 Shift Leadership</h3>
            <div class="leadership-info">
                <div class="shift-lead">
                    <strong>Shift Lead:</strong> ${shift.shift_lead}
                </div>
                <div class="shift-stats">
                    <span>Total Staff: ${shift.total_staff}</span> •
                    <span>Tickets/Analyst: ${shift.tickets_per_analyst}</span>
                </div>
            </div>
        </div>

        <div class="detail-section">
            <h3>🛡️ Security Actions</h3>
            <div class="security-grid">
                <div class="security-item">
                    <strong>IOCs Blocked</strong>
                    <div class="security-value">${shift.iocs_blocked || 0}</div>
                </div>
                <div class="security-item">
                    <strong>Domains Blocked</strong>
                    <div class="security-value">${shift.domains_blocked || 0}</div>
                </div>
                <div class="security-item">
                    <strong>Malicious TPs</strong>
                    <div class="security-value">${shift.malicious_tp}</div>
                </div>
                <div class="security-item">
                    <strong>SLA Breaches</strong>
                    <div class="security-value ${(shift.response_breaches + shift.containment_breaches) === 0 ? 'metric-good' : 'metric-warning'}">${shift.response_breaches + shift.containment_breaches}</div>
                </div>
            </div>
        </div>

        <div class="detail-section staffing-section">
            <h3>👥 Full Shift Staff</h3>
            <div class="staff-grid">
                ${Object.entries(shift.staffing).map(([team, members]) => `
                    <div class="staff-team">
                        <h4>${team}</h4>
                        <div class="staff-list">
                            ${Array.isArray(members) && members.length > 0 && members[0] !== 'N/A (Excel file missing)'
        ? members.map(member => `<span class="staff-member">${member}</span>`).join('')
        : '<span class="no-staff">No staff assigned</span>'}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    // Show modal
    const modal = document.getElementById('shiftDetailsModal');
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden'; // Prevent background scrolling

    // Trigger confetti for excellent performance
    if (shift.response_breaches === 0 && shift.containment_breaches === 0 && shift.outflow >= shift.inflow) {
        setTimeout(() => {
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                createConfetti(modalContent);
            }
        }, 500);
    }
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

    // Dim skeleton rows
    document.querySelectorAll('.skeleton-row').forEach(r => { r.style.opacity = '0.1'; r.style.pointerEvents = 'none'; });

    const loadingOverlay = document.createElement('div');
    loadingOverlay.id = 'loadingOverlay';
    loadingOverlay.innerHTML = `
        <div class="loading-spinner-container">
            <div class="loading-spinner">
                <div class="spinner-ring"></div>
                <div id="loadingElapsedInside" class="spinner-elapsed">0.0s</div>
            </div>
            <div class="loading-message" id="loadingMessage">${loadingMessages[0]}</div>
            <div class="loading-subtext">Fetching shift performance data...</div>
        </div>
    `;
    const tableContainer = document.querySelector('.table-container');
    if (tableContainer) tableContainer.appendChild(loadingOverlay);

    messageInterval = setInterval(() => {
        currentMessageIndex = (currentMessageIndex + 1) % loadingMessages.length;
        const el = document.getElementById('loadingMessage');
        if (!el) return;
        el.style.opacity = '0';
        setTimeout(() => { el.textContent = loadingMessages[currentMessageIndex]; el.style.opacity = '1'; }, 300);
    }, 5000);
    window.loadingMessageInterval = messageInterval;

    window.loadingElapsedInterval = setInterval(() => {
        const elapsedEl = document.getElementById('loadingElapsedInside');
        if (!elapsedEl || window.loadingStartTime == null) return;
        const secsFloat = (performance.now() - window.loadingStartTime) / 1000;
        const display = secsFloat >= 30 ? Math.round(secsFloat) + 's' : secsFloat.toFixed(1) + 's';
        let cls = 'load-time-good'; // <30s
        if (secsFloat >= 60) cls = 'load-time-slow';
        else if (secsFloat >= 30) cls = 'load-time-warn';
        elapsedEl.textContent = display;
        elapsedEl.className = 'spinner-elapsed ' + cls;
    }, 200);
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
        setTimeout(() => { loadingOverlay.remove(); }, 300);
    }
    const skeletonRows = document.querySelectorAll('.skeleton-row');
    skeletonRows.forEach(row => {
        row.style.opacity = '1';
        row.style.pointerEvents = 'auto';
        row.style.display = '';
    });
}

function showShiftDetailsFromGranular(data) {
    const {summary, staffing, tickets, security, inflow, outflow} = data;

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
                <div class="key-metric">
                    <div class="metric-label">Tickets Inflow</div>
                    <div class="metric-value ${tickets.tickets_inflow > 15 ? 'metric-bad' : tickets.tickets_inflow > 10 ? 'metric-warning' : 'metric-good'}">${tickets.tickets_inflow}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Tickets Closed</div>
                    <div class="metric-value ${tickets.tickets_closed >= tickets.tickets_inflow ? 'metric-good' : tickets.tickets_closed < tickets.tickets_inflow * 0.5 ? 'metric-bad' : 'metric-warning'}">${tickets.tickets_closed}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Respond</div>
                    <div class="metric-value ${tickets.response_time_minutes <= 30 ? 'metric-good' : tickets.response_time_minutes <= 60 ? 'metric-warning' : 'metric-bad'}">${formatTime(tickets.response_time_minutes)}</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Contain</div>
                    <div class="metric-value ${tickets.contain_time_minutes <= 120 ? 'metric-good' : tickets.contain_time_minutes <= 240 ? 'metric-warning' : 'metric-bad'}">${formatTime(tickets.contain_time_minutes)}</div>
                </div>
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
                <div class="security-item">
                    <strong>SLA Compliance</strong>
                    <div class="security-value ${security.malicious_true_positives === 0 ? 'metric-good' : 'metric-warning'}">${security.malicious_true_positives === 0 ? '100%' : '< 100%'}</div>
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
                    <span class="metric-value ${tickets.tickets_closed >= tickets.tickets_inflow ? 'metric-good' : 'metric-warning'}">${tickets.tickets_inflow > 0 ? ((tickets.tickets_closed / tickets.tickets_inflow) * 100).toFixed(0) + '%' : 'N/A'}</span>
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
    if (security.malicious_true_positives === 0 && tickets.tickets_closed >= tickets.tickets_inflow) {
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

// Summary card update logic
function updateSummaryCards(shiftData) {
    let totalIn = 0, totalOut = 0, totalMtp = 0, totalStaff = 0, countedShifts = 0;
    shiftData.forEach(s => {
        totalIn += s.tickets_inflow || 0;
        totalOut += s.tickets_closed || 0;
        const mtpIds = (s.mtp_ticket_ids || '').split(/\s*,\s*/).filter(x => x);
        totalMtp += mtpIds.length;
        totalStaff += s.total_staff || 0;
        countedShifts += 1;
    });
    const avgPerStaff = totalStaff > 0 ? (totalOut / totalStaff).toFixed(1) : '0.0';
    const cardsContainer = document.getElementById('summaryCards');
    if (cardsContainer) cardsContainer.style.display = 'flex';
    const map = [
        ['summaryTotalIn', totalIn],
        ['summaryTotalOut', totalOut],
        ['summaryTotalMtp', totalMtp],
        ['summaryAvgPerStaff', avgPerStaff]
    ];
    map.forEach(([id, val]) => { const el = document.getElementById(id); if (el) el.textContent = val; });
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
    // Make AJAX call to get shift list data
    fetch('/api/shift-list')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Hide loading spinner
                hideLoadingSpinner();

                // Update status info
                updateStatusInfo(data.data);

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

function updateStatusInfo(shiftData) {
    const now = new Date();
    const timeOptions = { year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short', hour12: true };
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
    shiftData.forEach((shift, index) => {
        setTimeout(() => {
            const row = document.createElement('tr');
            row.className = `shift-${shift.shift.toLowerCase()} shift-status-${shift.status}`;
            row.setAttribute('data-shift', shift.shift);
            row.setAttribute('data-status', shift.status);
            const formatTime = (minutes) => {
                if (!minutes || minutes === 0) return '0:00';
                const mins = Math.floor(minutes);
                const secs = Math.round((minutes - mins) * 60);
                return `${mins}:${secs.toString().padStart(2, '0')}`;
            };
            const mtpListRaw = shift.mtp_ticket_ids || '';
            const mtpIds = mtpListRaw.split(/\s*,\s*/).filter(id => id);
            const mtpCount = mtpIds.length;
            const mtpSeverityClass = mtpCount === 0 ? 'mtp-zero' : mtpCount <= 2 ? 'mtp-low' : 'mtp-high';
            const mtpCellContent = `<span class=\"mtp-cell ${mtpSeverityClass}\" data-shift-id=\"${shift.id}\" data-mtp-ids=\"${mtpIds.join(',')}\" title=\"${mtpIds.length ? 'MTP IDs: ' + mtpIds.join(', ') : 'No MTPs'}\">${mtpCount}</span>`;
            row.innerHTML = `
                <td>${shift.date}</td>
                <td>${shift.day}</td>
                <td><strong>${shift.shift}</strong></td>
                <td>${shift.total_staff}</td>
                <td>${shift.tickets_inflow}</td>
                <td>${shift.tickets_closed}</td>
                <td>${mtpCellContent}</td>
                <td>${formatTime(shift.response_time_minutes)}</td>
                <td>${formatTime(shift.contain_time_minutes)}</td>
                <td>${shift.response_sla_breaches}</td>
                <td>${shift.containment_sla_breaches}</td>
                <td>
                    <button class="load-details-btn" onclick="loadShiftDetails('${shift.id}', this)" data-shift-id="${shift.id}">📊 Details</button>
                </td>`;
            row.style.opacity = '0';
            row.style.transform = 'translateX(-20px)';
            tbody.appendChild(row);
            setTimeout(() => {
                row.style.transition = 'all 0.5s ease';
                row.style.opacity = '1';
                row.style.transform = 'translateX(0)';
            }, 10);
        }, index * 100);
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
        animation: slideInToast 0.3s ease-out;
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
    const shiftFilters = [];
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');

    checkboxes.forEach(cb => {
        if (cb.checked && cb.value !== 'all') {
            shiftFilters.push(cb.value);
        }
    });

    var checkedTime = document.querySelector('input[name="timeRange"]:checked');
    const timeRange = (checkedTime && checkedTime.value) ? checkedTime.value : '7';

    // Re-fetch data with filters (for now just filter existing data)
    const rows = document.querySelectorAll('#shifts-tbody tr');
    rows.forEach(row => {
        var ds = row.getAttribute('data-shift');
        const shiftType = ds ? ds.toLowerCase() : null;
        const showShift = shiftFilters.length === 0 || (shiftType && shiftFilters.includes(shiftType));

        if (showShift) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });

    // Close filter menu after applying
    closeFilters();
}

function clearFilters() {
    // Reset all checkboxes to default state
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(cb => {
        cb.checked = (cb.value === 'morning' || cb.value === 'afternoon' || cb.value === 'night');
    });

    // Reset time range to 7 days
    const timeRangeEl = document.querySelector('input[name="timeRange"][value="7"]');
    if (timeRangeEl) timeRangeEl.checked = true;

    // Show all rows
    const rows = document.querySelectorAll('#shifts-tbody tr');
    rows.forEach(row => {
        row.style.display = '';
    });

    // Close filter menu
    closeFilters();
}

function applySavedFilters() {
    try {
        const saved = JSON.parse(localStorage.getItem('shiftFiltersState') || '{}');
        if (saved.shiftTypes) {
            document.querySelectorAll('input[type="checkbox"][value]')
                .forEach(cb => { cb.checked = saved.shiftTypes.includes(cb.value); });
        }
        if (saved.timeRange) {
            const radio = document.querySelector(`input[name="timeRange"][value="${saved.timeRange}"]`);
            if (radio) radio.checked = true;
        }
    } catch (_) { /* ignore */ }
}

function persistFilters() {
    const shiftTypes = Array.from(document.querySelectorAll('input[type="checkbox"]'))
        .filter(cb => cb.checked)
        .map(cb => cb.value);
    const timeRangeEl = document.querySelector('input[name="timeRange"]:checked');
    const timeRange = timeRangeEl ? timeRangeEl.value : '7';
    localStorage.setItem('shiftFiltersState', JSON.stringify({ shiftTypes, timeRange }));
}

// Override applyFilters to persist state
const _origApplyFilters = applyFilters;
applyFilters = function() { _origApplyFilters(); persistFilters(); };
const _origClearFilters = clearFilters;
clearFilters = function() { _origClearFilters(); persistFilters(); };

// MTP hover popover (preview first N IDs)
let activeMtpPopover = null;
function attachMtpPopover(mtpCell, ids) {
    const maxPreview = 8;
    mtpCell.addEventListener('mouseenter', () => {
        if (activeMtpPopover) { activeMtpPopover.remove(); activeMtpPopover = null; }
        const pop = document.createElement('div');
        pop.className = 'mtp-popover';
        const base = (typeof window !== 'undefined' && window.XSOAR_BASE) ? window.XSOAR_BASE.replace(/\/$/, '') : '';
        const preview = ids.slice(0, maxPreview).map(id => `<li><a href="${base}/Custom/caseinfoid/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${id}</a></li>`).join('');
        const more = ids.length > maxPreview ? `<div style='margin-top:4px;font-size:10px;opacity:.7;'>+${ids.length - maxPreview} more...</div>` : '';
        pop.innerHTML = `<h5>MTP Tickets</h5><ul>${preview || '<li>None</li>'}</ul>${more}`;
        mtpCell.style.position = 'relative';
        mtpCell.appendChild(pop);
        requestAnimationFrame(() => pop.classList.add('visible'));
        activeMtpPopover = pop;
    });
    ['mouseleave','click','blur'].forEach(evt => {
        mtpCell.addEventListener(evt, () => {
            if (activeMtpPopover) {
                activeMtpPopover.classList.remove('visible');
                const ref = activeMtpPopover; activeMtpPopover = null;
                setTimeout(() => ref && ref.remove(), 120);
            }
        });
    });
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
            basic_staffing: shift.basic_staffing || { total_staff: 0, teams: {} },
            detailed_staffing: shift.detailed_staffing || {}
        },
        tickets: {
            tickets_inflow: shift.tickets_inflow || 0,
            tickets_closed: shift.tickets_closed || 0,
            response_time_minutes: shift.response_time_minutes || 0,
            contain_time_minutes: shift.contain_time_minutes || 0
        },
        security: shift.security_actions || {
            iocs_blocked: 0,
            domains_blocked: 0,
            malicious_true_positives: 0
        },
        inflow: { tickets: shift.inflow_tickets || [] },
        outflow: { tickets: shift.outflow_tickets || [] }
    };

    showShiftDetailsFromGranular(data);

    if (mtpOpen) {
        const mtpIds = shift.mtp_ticket_ids ? shift.mtp_ticket_ids.split(',').map(id => id.trim()).filter(id => id) : [];
        if (mtpIds.length) openMtpModal(mtpIds, shiftId);
    }
}

// Patch populateTable to handle deep linking after cells exist (wrap original)
const _origPopulateTable = populateTable;
populateTable = function(shiftData) {
    _origPopulateTable(shiftData);
    // Deep link after small delay to ensure DOM laid out
    setTimeout(() => {
        deepLinkIfRequested(shiftData);
    }, 50);
};

// On initial load apply saved filters before fetching
applySavedFilters();
