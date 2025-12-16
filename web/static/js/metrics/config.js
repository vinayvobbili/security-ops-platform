/**
 * Configuration and constants for meaningful metrics dashboard
 */

// App config loaded from server (team name, email domain, etc.)
export let appConfig = {
    team_name: 'TEAM',
    email_domain: 'example.com',
    company_name: 'Company'
};

// Load app config from server
export async function loadAppConfig() {
    try {
        const response = await fetch('/api/config');
        const config = await response.json();
        appConfig = {...appConfig, ...config};
    } catch (error) {
        console.warn('Failed to load app config, using defaults:', error);
    }
    return appConfig;
}

// Feature flags
export const FEATURE_FLAGS = {
    showCardTooltips: false,
    showDeltaValues: false
};

// Column configuration with all available fields
export const AVAILABLE_COLUMNS = {
    // Primary fields
    'id': {label: 'ID', category: 'Primary', path: 'id', type: 'number'},
    'name': {label: 'Name', category: 'Primary', path: 'name', type: 'string'},
    'severity': {label: 'Severity', category: 'Primary', path: 'severity', type: 'number'},
    'status': {label: 'Status', category: 'Primary', path: 'status', type: 'number'},
    'type': {label: 'Type', category: 'Primary', path: 'type', type: 'string'},
    'created': {label: 'Created', category: 'Primary', path: 'created', type: 'date'},
    'closed': {label: 'Closed', category: 'Primary', path: 'closed', type: 'date'},
    'owner': {label: 'Owner', category: 'Primary', path: 'owner', type: 'string'},

    // Custom Fields
    'affected_country': {label: 'Country', category: 'Location', path: 'affected_country', type: 'string'},
    'affected_region': {label: 'Region', category: 'Location', path: 'affected_region', type: 'string'},
    'impact': {label: 'Impact', category: 'Assessment', path: 'impact', type: 'string'},
    'automation_level': {label: 'Automation Level', category: 'Process', path: 'automation_level', type: 'string'},

    // Calculated Fields
    'is_open': {label: 'Is Open', category: 'Status', path: 'is_open', type: 'boolean'},
    'currently_aging_days': {label: 'Currently Aging (Days)', category: 'Timing', path: 'currently_aging_days', type: 'number'},
    'days_since_creation': {label: 'Days Since Creation', category: 'Timing', path: 'days_since_creation', type: 'number'},
    'resolution_time_days': {label: 'Resolution Time (Days)', category: 'Timing', path: 'resolution_time_days', type: 'number'},
    'resolution_bucket': {label: 'Resolution Bucket', category: 'Status', path: 'resolution_bucket', type: 'string'},
    'has_resolution_time': {label: 'Has Resolution Time', category: 'Status', path: 'has_resolution_time', type: 'boolean'},
    'age_category': {label: 'Age Category', category: 'Status', path: 'age_category', type: 'string'},
    'status_display': {label: 'Status Name', category: 'Display', path: 'status_display', type: 'string'},
    'severity_display': {label: 'Severity Name', category: 'Display', path: 'severity_display', type: 'string'},
    'created_display': {label: 'Created (MM/DD)', category: 'Display', path: 'created_display', type: 'string'},
    'closed_display': {label: 'Closed (MM/DD)', category: 'Display', path: 'closed_display', type: 'string'},

    // Additional fields
    'occurred': {label: 'Occurred', category: 'Timing', path: 'occurred', type: 'date'},
    'dueDate': {label: 'Due Date', category: 'Timing', path: 'dueDate', type: 'date'},
    'phase': {label: 'Phase', category: 'Process', path: 'phase', type: 'string'},
    'category': {label: 'Category', category: 'Classification', path: 'category', type: 'string'},
    'sourceInstance': {label: 'Source Instance', category: 'Technical', path: 'sourceInstance', type: 'string'},
    'openDuration': {label: 'Open Duration', category: 'Metrics', path: 'openDuration', type: 'number'},
    'timetorespond': {label: 'Time to Respond', category: 'Metrics', path: 'time_to_respond_secs', type: 'duration'},
    'timetocontain': {label: 'Time to Contain', category: 'Metrics', path: 'time_to_contain_secs', type: 'duration'},
    'notes': {label: 'User Notes', category: 'Investigation', path: 'notes', type: 'array'}
};

// Default visible columns
export const DEFAULT_VISIBLE_COLUMNS = ['id', 'name', 'severity', 'status', 'affected_country', 'impact', 'type', 'owner', 'created'];

// Color schemes for charts
export const COLOR_SCHEMES = {
    severity: ['#6c757d', '#28a745', '#ffc107', '#fd7e14', '#dc3545'],
    status: ['#ffc107', '#007bff', '#28a745', '#6c757d'],
    countries: ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'],
    sources: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FECA57', '#FF9FF3', '#54A0FF', '#5F27CD']
};

// Ensure color schemes are available globally for backwards compatibility
if (typeof window !== 'undefined' && !window.colorSchemes) {
    window.colorSchemes = COLOR_SCHEMES;
}

// Plotly configuration
export const PLOTLY_CONFIG = {
    responsive: true,
    displayModeBar: true,
    displaylogo: false
};

// Status and severity mappings
export const STATUS_MAP = {0: 'Pending', 1: 'Active', 2: 'Closed'};
export const SEVERITY_MAP = {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'};
