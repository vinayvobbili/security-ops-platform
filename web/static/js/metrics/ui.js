/**
 * UI utilities: modals, tooltips, notifications
 */

let notesModal = null;
let exportNotesModal = null;
let exportNotesResolve = null;

/**
 * Slider tooltip functions
 */
export function updateSliderTooltip(sliderId, tooltipId, value, formatFunction = null) {
    const tooltip = document.getElementById(tooltipId);
    const slider = document.getElementById(sliderId);
    if (!tooltip || !slider) return;

    tooltip.textContent = formatFunction ? formatFunction(value) : value;

    const min = parseInt(slider.min);
    const max = parseInt(slider.max);
    const val = parseInt(value);
    const percentage = ((val - min) / (max - min)) * 100;
    tooltip.style.left = `calc(${percentage}% + ${8 - percentage * 0.16}px)`;
}

export function showSliderTooltip(tooltipId) {
    const tooltip = document.getElementById(tooltipId);
    if (tooltip) tooltip.style.display = 'block';
}

export function hideSliderTooltip(tooltipId) {
    const tooltip = document.getElementById(tooltipId);
    if (tooltip) tooltip.style.display = 'none';
}

export function setupSliderTooltip(sliderId, tooltipId, updateCallback, formatFunction = null) {
    const slider = document.getElementById(sliderId);
    if (!slider) return;

    slider.addEventListener('mousedown', () => showSliderTooltip(tooltipId));
    slider.addEventListener('touchstart', () => showSliderTooltip(tooltipId));
    slider.addEventListener('mouseup', () => hideSliderTooltip(tooltipId));
    slider.addEventListener('touchend', () => hideSliderTooltip(tooltipId));
    slider.addEventListener('mouseleave', () => hideSliderTooltip(tooltipId));

    slider.addEventListener('input', function () {
        showSliderTooltip(tooltipId);
        updateSliderTooltip(sliderId, tooltipId, this.value, formatFunction);
        if (updateCallback) updateCallback();
    });

    updateSliderTooltip(sliderId, tooltipId, slider.value, formatFunction);
}

/**
 * Format functions for sliders
 */
export function formatMttrValue(value) {
    const labels = ['All', '≤3', '>3', '>5'];
    return labels[value] || 'All';
}

export function formatMttcValue(value) {
    const labels = ['All', '≤5', '≤15', '>15'];
    return labels[value] || 'All';
}

export function formatAgeValue(value) {
    return value === 0 ? 'All' : value;
}

/**
 * Notes modal
 */
function createNotesModal() {
    if (!notesModal) {
        notesModal = document.createElement('div');
        notesModal.className = 'notes-modal-overlay';
        notesModal.innerHTML = `
            <div class="notes-modal">
                <div class="notes-modal-header">
                    <div class="notes-modal-title">📝 User Notes</div>
                    <button class="notes-modal-close" aria-label="Close">×</button>
                </div>
                <div class="notes-modal-body">
                    <table class="notes-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Note</th>
                                <th>Author</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody id="notesTableBody"></tbody>
                    </table>
                </div>
            </div>
        `;
        document.body.appendChild(notesModal);

        const closeBtn = notesModal.querySelector('.notes-modal-close');
        closeBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            hideNotesModal();
        });

        notesModal.addEventListener('click', (e) => {
            if (e.target === notesModal) hideNotesModal();
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && notesModal.classList.contains('show')) {
                hideNotesModal();
            }
        });
    }
    return notesModal;
}

export function showNotesModal(notesData) {
    const modal = createNotesModal();
    const notes = JSON.parse(notesData);
    const tbody = modal.querySelector('#notesTableBody');

    tbody.innerHTML = notes.map((note, index) => `
        <tr>
            <td class="notes-table-number">${index + 1}</td>
            <td class="notes-table-text">${note.text}</td>
            <td class="notes-table-author">${note.author}</td>
            <td class="notes-table-timestamp">${note.timestamp}</td>
        </tr>
    `).join('');

    modal.style.cssText = `
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        bottom: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 10000 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        margin: 0 !important;
        padding: 20px !important;
        transform: none !important;
    `;

    modal.classList.add('show');
    window.scrollTo({top: 0, left: 0, behavior: 'smooth'});
    document.body.style.overflow = 'hidden';
}

function hideNotesModal() {
    if (notesModal) {
        notesModal.classList.remove('show');
        notesModal.style.display = 'none';
        document.body.style.overflow = '';
    }
}

export function attachNotesModalListeners() {
    document.querySelectorAll('.notes-icon').forEach(icon => {
        icon.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            const notesData = this.getAttribute('data-notes');
            if (notesData) showNotesModal(notesData);
        });
    });
}

/**
 * Export notes confirmation modal
 */
function createExportNotesModal() {
    if (!exportNotesModal) {
        exportNotesModal = document.createElement('div');
        exportNotesModal.className = 'notes-modal-overlay export-notes-modal';
        exportNotesModal.innerHTML = `
            <div class="notes-modal export-confirmation-modal">
                <div class="notes-modal-header">
                    <div class="notes-modal-title">📝 Include User Notes in Export?</div>
                    <button class="notes-modal-close" aria-label="Close">×</button>
                </div>
                <div class="notes-modal-body export-confirmation-body">
                    <div class="export-options-grid">
                        <div class="export-option-card export-with-notes">
                            <div class="export-card-icon">📝</div>
                            <div class="export-card-title">With Notes</div>
                            <div class="export-card-description">
                                Fetch enriched notes from XSOAR API
                            </div>
                            <div class="export-card-timing">
                                <span class="timing-icon">⏱️</span>
                                <span class="timing-text">1-15 minutes (depends on ticket count)</span>
                            </div>
                        </div>
                        <div class="export-option-card export-without-notes">
                            <div class="export-card-icon">⚡</div>
                            <div class="export-card-title">Without Notes</div>
                            <div class="export-card-description">
                                Quick export with basic ticket data
                            </div>
                            <div class="export-card-timing">
                                <span class="timing-icon">🚀</span>
                                <span class="timing-text">Instant</span>
                            </div>
                        </div>
                    </div>
                    <div class="export-info-banner">
                        <span class="info-icon">ℹ️</span>
                        <span>Only filtered tickets will be enriched with notes</span>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(exportNotesModal);

        const closeBtn = exportNotesModal.querySelector('.notes-modal-close');
        closeBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            hideExportNotesModal(null);
        });

        exportNotesModal.addEventListener('click', (e) => {
            if (e.target === exportNotesModal) hideExportNotesModal(null);
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && exportNotesModal.classList.contains('show')) {
                hideExportNotesModal(null);
            }
        });

        const withNotesCard = exportNotesModal.querySelector('.export-with-notes');
        const withoutNotesCard = exportNotesModal.querySelector('.export-without-notes');

        withNotesCard.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            hideExportNotesModal(true);
        });

        withoutNotesCard.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            hideExportNotesModal(false);
        });
    }
    return exportNotesModal;
}

export function showExportNotesModal() {
    return new Promise((resolve) => {
        exportNotesResolve = resolve;
        const modal = createExportNotesModal();

        const scrollY = window.scrollY;
        modal.style.cssText = `
            position: absolute !important;
            top: ${scrollY}px !important;
            left: 0 !important;
            width: 100% !important;
            height: 100vh !important;
            z-index: 99999 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            margin: 0 !important;
            padding: 20px !important;
            background: rgba(0, 0, 0, 0.6) !important;
            backdrop-filter: blur(4px) !important;
        `;

        modal.classList.add('show');
    });
}

function hideExportNotesModal(result) {
    if (exportNotesModal) {
        exportNotesModal.classList.remove('show');
        exportNotesModal.style.display = 'none';
        if (exportNotesResolve) {
            exportNotesResolve(result);
            exportNotesResolve = null;
        }
    }
}

/**
 * Success notification
 */
export function showExportSuccessNotification(filename) {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.textContent = `✅ Export successful: ${filename}`;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 4000);
    }
}

/**
 * Loading and error states
 */
export function hideLoading() {
    const loading = document.getElementById('loading');
    if (loading) loading.style.display = 'none';
}

export function showError(message) {
    const errorDiv = document.getElementById('error');
    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    }
    hideLoading();
}

export function showDashboard() {
    document.getElementById('metricsGrid').style.display = 'grid';
    document.getElementById('chartsGrid').style.display = 'grid';
    document.getElementById('dataTableSection').style.display = 'block';
}

/**
 * Accessibility announcements
 */
export function announceTableStatus(message) {
    const liveRegion = document.getElementById('tableStatusLive');
    if (liveRegion) {
        liveRegion.textContent = message;
    }
}

/**
 * Slider label update functions - manage active state on slider labels
 */
export function updateDateSliderLabels(value) {
    updateSliderTooltip('dateRangeSlider', 'dateRangeTooltip', value);

    const dateContainer = document.getElementById('dateRangeSlider')?.parentElement;
    if (!dateContainer) return;

    // Remove active class from all preset labels
    dateContainer.querySelectorAll('.slider-labels .range-preset').forEach(span => {
        span.classList.remove('active');
    });

    // Add active class to the matching label
    const targetSpan = dateContainer.querySelector(`.slider-labels .range-preset[data-value="${value}"]`);
    if (targetSpan) targetSpan.classList.add('active');
}

export function updateMttrSliderLabels(value) {
    const mttrContainer = document.getElementById('mttrRangeSlider')?.parentElement;
    if (!mttrContainer) return;

    mttrContainer.querySelectorAll('.slider-labels span').forEach(span => {
        span.classList.remove('active');
    });
    const targetSpan = mttrContainer.querySelector(`.slider-labels span[data-value="${value}"]`);
    if (targetSpan) targetSpan.classList.add('active');
}

export function updateMttcSliderLabels(value) {
    const mttcContainer = document.getElementById('mttcRangeSlider')?.parentElement;
    if (!mttcContainer) return;

    mttcContainer.querySelectorAll('.slider-labels span').forEach(span => {
        span.classList.remove('active');
    });
    const targetSpan = mttcContainer.querySelector(`.slider-labels span[data-value="${value}"]`);
    if (targetSpan) targetSpan.classList.add('active');
}

export function updateAgeSliderLabels(value) {
    const ageContainer = document.getElementById('ageRangeSlider')?.parentElement;
    if (!ageContainer) return;

    // Remove active class from all labels
    ageContainer.querySelectorAll('.slider-labels .range-preset').forEach(span => {
        span.classList.remove('active');
    });

    // Add active class based on value
    if (value == 0) {
        const allLabel = ageContainer.querySelector('.slider-labels .range-preset[data-value="0"]');
        if (allLabel) allLabel.classList.add('active');
    } else if (value > 0 && value <= 7) {
        const sevenLabel = ageContainer.querySelector('.slider-labels .range-preset[data-value="7"]');
        if (sevenLabel) sevenLabel.classList.add('active');
    } else if (value > 7 && value <= 30) {
        const thirtyLabel = ageContainer.querySelector('.slider-labels .range-preset[data-value="30"]');
        if (thirtyLabel) thirtyLabel.classList.add('active');
    } else {
        const thirtyLabel = ageContainer.querySelector('.slider-labels .range-preset[data-value="30"]');
        if (thirtyLabel) thirtyLabel.classList.add('active');
    }
}
