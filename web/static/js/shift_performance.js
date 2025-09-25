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
            if (cells.length >= 11) {
                totalInflow += parseInt(cells[3].textContent) || 0;
                totalOutflow += parseInt(cells[4].textContent) || 0;
                totalMaliciousTp += parseInt(cells[5].textContent) || 0;
                totalStaff += parseInt(cells[10].textContent) || 0;
                visibleRows++;
            }
        }
    });

    // Update summary cards if they exist
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

    // Determine sort direction
    const isAscending = !table.dataset.sortAsc || table.dataset.sortAsc === 'false';
    table.dataset.sortAsc = isAscending;

    // Sort rows
    rows.sort((a, b) => {
        const aVal = parseFloat(a.cells[columnIndex].textContent) || 0;
        const bVal = parseFloat(b.cells[columnIndex].textContent) || 0;
        return isAscending ? aVal - bVal : bVal - aVal;
    });

    // Update visual indicators
    document.querySelectorAll('.performance-table th').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
    });

    const header = document.querySelectorAll('.performance-table th')[columnIndex];
    header.classList.add(isAscending ? 'sort-asc' : 'sort-desc');

    // Re-append sorted rows
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

function loadShiftDetails(shiftId, button) {
    // Show loading state
    const originalText = button.textContent;
    button.textContent = '⏳ Loading...';
    button.disabled = true;

    // Use new granular approach for better performance
    loadShiftDetailsGranular(shiftId)
        .then(data => {
            showShiftDetailsFromGranular(data);
        })
        .catch(error => {
            console.error('Error loading shift details:', error);
            showToast('❌ Network error loading shift details', 'warning');
        })
        .finally(() => {
            // Restore button state
            button.textContent = originalText;
            button.disabled = false;
        });
}

async function loadShiftDetailsGranular(shiftId) {
    // Load data in parallel using granular endpoints
    const [summaryResponse, staffingResponse, ticketsResponse, securityResponse] = await Promise.all([
        fetch(`/api/shift-summary/${shiftId}`).then(r => r.json()),
        fetch(`/api/shift-staffing/${shiftId}`).then(r => r.json()),
        fetch(`/api/shift-tickets/${shiftId}`).then(r => r.json()),
        fetch(`/api/shift-security/${shiftId}`).then(r => r.json())
    ]);

    // Check if all requests were successful
    if (!summaryResponse.success || !staffingResponse.success ||
        !ticketsResponse.success || !securityResponse.success) {
        const errors = [
            !summaryResponse.success ? summaryResponse.error : null,
            !staffingResponse.success ? staffingResponse.error : null,
            !ticketsResponse.success ? ticketsResponse.error : null,
            !securityResponse.success ? securityResponse.error : null
        ].filter(e => e).join(', ');
        throw new Error(errors);
    }

    // Combine all data
    return {
        summary: summaryResponse.data,
        staffing: staffingResponse.data,
        tickets: ticketsResponse.data,
        security: securityResponse.data
    };
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
                    <div class="metric-value ${shift.avg_response_time_min <= 30 ? 'metric-good' : shift.avg_response_time_min <= 60 ? 'metric-warning' : 'metric-bad'}">${shift.avg_response_time_min.toFixed(1)}min</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Contain</div>
                    <div class="metric-value ${shift.avg_containment_time_min <= 120 ? 'metric-good' : shift.avg_containment_time_min <= 240 ? 'metric-warning' : 'metric-bad'}">${shift.avg_containment_time_min.toFixed(1)}min</div>
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
    // Fun loading messages that rotate every 5 seconds
    const loadingMessages = [
        '🎭 Magic building...',
        '🧙‍♂️ Summoning data wizards...',
        '⚡ Charging quantum processors...',
        '🔮 Consulting crystal ball...',
        '🚀 Launching data rockets...',
        '🎪 Setting up data circus...',
        '🌟 Sprinkling fairy dust...',
        '🎨 Painting performance pixels...',
        '🎯 Targeting shift statistics...',
        '🔥 Igniting analytics engine...',
        '🎵 Composing data symphony...',
        '🎪 Training performance monkeys...',
        '⚗️ Brewing shift potions...',
        '🎪 Juggling staff schedules...',
        '🎭 Rehearsing data drama...'
    ];

    let currentMessageIndex = 0;
    let messageInterval;

    // Keep skeleton rows but make them transparent to maintain table height
    const skeletonRows = document.querySelectorAll('.skeleton-row');
    skeletonRows.forEach(row => {
        row.style.opacity = '0.1';
        row.style.pointerEvents = 'none';
    });

    // Create loading spinner overlay
    const loadingOverlay = document.createElement('div');
    loadingOverlay.id = 'loadingOverlay';
    loadingOverlay.innerHTML = `
        <div class="loading-spinner-container">
            <div class="loading-spinner"></div>
            <div class="loading-message" id="loadingMessage">${loadingMessages[0]}</div>
            <div class="loading-subtext">Fetching shift performance data...</div>
        </div>
    `;

    // Insert loading overlay into table container
    const tableContainer = document.querySelector('.table-container');
    if (tableContainer) {
        tableContainer.appendChild(loadingOverlay);
    }

    // Rotate messages every 5 seconds
    messageInterval = setInterval(() => {
        currentMessageIndex = (currentMessageIndex + 1) % loadingMessages.length;
        const messageElement = document.getElementById('loadingMessage');
        if (messageElement) {
            messageElement.style.opacity = '0';
            setTimeout(() => {
                messageElement.textContent = loadingMessages[currentMessageIndex];
                messageElement.style.opacity = '1';
            }, 300);
        }
    }, 5000);

    // Store interval ID for cleanup
    window.loadingMessageInterval = messageInterval;
}

function hideLoadingSpinner() {
    // Clear the message rotation interval
    if (window.loadingMessageInterval) {
        clearInterval(window.loadingMessageInterval);
        window.loadingMessageInterval = null;
    }

    // Remove loading overlay
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingOverlay) {
        loadingOverlay.style.opacity = '0';
        setTimeout(() => {
            loadingOverlay.remove();
        }, 300);
    }

    // Restore skeleton rows (they'll be replaced by real data)
    const skeletonRows = document.querySelectorAll('.skeleton-row');
    skeletonRows.forEach(row => {
        row.style.opacity = '1';
        row.style.pointerEvents = 'auto';
        row.style.display = '';
    });
}

function showShiftDetailsFromGranular(data) {
    const {summary, staffing, tickets, security} = data;

    // Update modal title
    const modalTitle = document.getElementById('modalTitle');
    modalTitle.textContent = `${summary.shift_name} Shift - ${summary.day_name}, ${summary.date}`;

    // Build modal content using granular data
    const modalBody = document.getElementById('modalBody');
    modalBody.innerHTML = `
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
                    <div class="metric-value ${tickets.response_time_minutes <= 30 ? 'metric-good' : tickets.response_time_minutes <= 60 ? 'metric-warning' : 'metric-bad'}">${tickets.response_time_minutes}min</div>
                </div>
                <div class="key-metric">
                    <div class="metric-label">Mean Time to Contain</div>
                    <div class="metric-value ${tickets.contain_time_minutes <= 120 ? 'metric-good' : tickets.contain_time_minutes <= 240 ? 'metric-warning' : 'metric-bad'}">${tickets.contain_time_minutes}min</div>
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

    // Format timestamp with timezone (client-side browser timezone)
    const timeOptions = {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short',
        hour12: true
    };
    const timeString = now.toLocaleString('en-US', timeOptions);

    // Update status info in bottom corner (shows user's browser timezone)
    document.getElementById('last-updated').textContent = `Last updated: ${timeString}`;
}

function populateTable(shiftData) {
    const tbody = document.getElementById('shifts-tbody');

    // Clear skeleton loading
    tbody.innerHTML = '';

    // Add each shift row with staggered animation
    shiftData.forEach((shift, index) => {
        setTimeout(() => {
            const row = document.createElement('tr');
            row.className = `shift-${shift.shift.toLowerCase()} shift-status-${shift.status}`;
            row.setAttribute('data-shift', shift.shift);
            row.setAttribute('data-status', shift.status);

            // Format time as mins:secs
            const formatTime = (minutes) => {
                if (minutes === 0) return '0:00';
                const mins = Math.floor(minutes);
                const secs = Math.round((minutes - mins) * 60);
                return `${mins}:${secs.toString().padStart(2, '0')}`;
            };

            row.innerHTML = `
                <td>${shift.date}</td>
                <td>${shift.day}</td>
                <td><strong>${shift.shift}</strong></td>
                <td>${shift.total_staff}</td>
                <td>${shift.tickets_inflow}</td>
                <td>${shift.tickets_closed}</td>
                <td>${formatTime(shift.response_time_minutes)}</td>
                <td>${formatTime(shift.contain_time_minutes)}</td>
                <td>${shift.response_sla_breaches}</td>
                <td>${shift.containment_sla_breaches}</td>
                <td>
                    <button class="load-details-btn" onclick="loadShiftDetails('${shift.id}', this)" data-shift-id="${shift.id}">
                        📊 Details
                    </button>
                </td>
            `;

            row.style.opacity = '0';
            row.style.transform = 'translateX(-20px)';
            tbody.appendChild(row);

            // Animate in
            setTimeout(() => {
                row.style.transition = 'all 0.5s ease';
                row.style.opacity = '1';
                row.style.transform = 'translateX(0)';
            }, 10);

        }, index * 100); // Staggered timing
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