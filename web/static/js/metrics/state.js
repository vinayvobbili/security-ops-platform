/**
 * Application state management
 */

export const state = {
    allData: [],
    filteredData: [],
    currentSort: {column: null, direction: 'asc'},
    showAllRows: false,
    visibleColumns: ['id', 'name', 'severity', 'status', 'affected_country', 'impact', 'type', 'owner', 'created'],
    columnOrder: ['id', 'name', 'severity', 'status', 'affected_country', 'impact', 'type', 'owner', 'created'],
    lastTableRowCount: null,
    draggedElement: null
};

/**
 * Get nested value from object using dot notation path
 */
export function getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current?.[key], obj);
}

/**
 * Update data timestamp display
 */
export function updateDataTimestamp(dataGeneratedAt) {
    const timestampElement = document.getElementById('dataTimestamp');
    if (!timestampElement) return;

    if (dataGeneratedAt) {
        const timestamp = new Date(dataGeneratedAt);
        const options = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: true,
            timeZone: 'America/New_York',
            timeZoneName: 'short'
        };
        timestampElement.textContent = timestamp.toLocaleString('en-US', options);
    } else {
        const today = new Date();
        const options = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: true,
            timeZone: 'America/New_York',
            timeZoneName: 'short'
        };
        const todayAt1201 = new Date(today);
        todayAt1201.setHours(0, 1, 0, 0);
        timestampElement.textContent = todayAt1201.toLocaleString('en-US', options);
    }
}

/**
 * Save sort preferences to localStorage
 */
export function saveSortPreferences() {
    localStorage.setItem('dashboardSort', JSON.stringify(state.currentSort));
}

/**
 * Load sort preferences from localStorage
 */
export function loadSortPreferences() {
    const saved = localStorage.getItem('dashboardSort');
    if (saved) {
        try {
            const parsed = JSON.parse(saved);
            if (parsed.column && parsed.direction) {
                state.currentSort = parsed;
                return true;
            }
        } catch (e) {
            console.error('Failed to load sort preferences:', e);
        }
    }
    return false;
}

/**
 * Save column preferences to localStorage
 */
export function saveColumnPreferences() {
    localStorage.setItem('visibleColumns', JSON.stringify(state.visibleColumns));
    localStorage.setItem('columnOrder', JSON.stringify(state.columnOrder));
}

/**
 * Load column preferences from localStorage
 */
export function loadColumnPreferences() {
    const savedVisible = localStorage.getItem('visibleColumns');
    const savedOrder = localStorage.getItem('columnOrder');

    if (savedVisible) {
        try {
            state.visibleColumns = JSON.parse(savedVisible);
        } catch (e) {
            console.error('Failed to load visible columns:', e);
        }
    }

    if (savedOrder) {
        try {
            state.columnOrder = JSON.parse(savedOrder);
        } catch (e) {
            console.error('Failed to load column order:', e);
        }
    }
}
