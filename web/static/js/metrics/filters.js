/**
 * Filter logic and UI management
 */

import {state} from './state.js';
import {appConfig} from './config.js';

// Helper function to strip team name prefix from ticket types
function stripTeamPrefix(ticketType) {
    const teamName = appConfig.team_name || 'TEAM';
    const regex = new RegExp(`^${teamName}[_\\-\\s]*`, 'i');
    return ticketType.startsWith(teamName) ? ticketType.replace(regex, '') : ticketType;
}

export function populateFilterOptions() {
    const countries = [...new Set(state.allData.map(item => item.affected_country))].filter(c => c && c !== 'Unknown').sort();
    const regions = [...new Set(state.allData.map(item => item.affected_region))].filter(r => r && r !== 'Unknown').sort();
    const impacts = [...new Set(state.allData.map(item => item.impact))].filter(i => i && i !== 'Unknown').sort();
    const ticketTypes = [...new Set(state.allData.map(item => item.type))].filter(t => t).sort();

    populateCheckboxFilter('countryFilter', countries.length > 0 ? countries : ['No Country']);
    populateCheckboxFilter('regionFilter', regions.length > 0 ? regions : ['No Region']);
    populateCheckboxFilter('impactFilter', impacts.length > 0 ? impacts : ['No Impact']);
    populateCheckboxFilter('ticketTypeFilter', ticketTypes);
}

function populateCheckboxFilter(filterId, options) {
    const container = document.getElementById(filterId);
    if (!container) return;

    container.innerHTML = options.map(option => {
        const displayValue = stripTeamPrefix(option);
        return `<label><input type="checkbox" value="${option}"> ${displayValue}</label>`;
    }).join('');
}

export function applyFilters(updateCallback) {
    const dateSlider = document.getElementById('dateRangeSlider');
    const dateRange = parseInt(dateSlider?.value || 30);

    const mttrSlider = document.getElementById('mttrRangeSlider');
    const mttrFilter = parseInt(mttrSlider?.value || 0);

    const mttcSlider = document.getElementById('mttcRangeSlider');
    const mttcFilter = parseInt(mttcSlider?.value || 0);

    const ageSlider = document.getElementById('ageRangeSlider');
    const ageFilter = parseInt(ageSlider?.value || 0);

    const countries = Array.from(document.querySelectorAll('#countryFilter input:checked')).map(cb => cb.value);
    const regions = Array.from(document.querySelectorAll('#regionFilter input:checked')).map(cb => cb.value);
    const impacts = Array.from(document.querySelectorAll('#impactFilter input:checked')).map(cb => cb.value);
    const severities = Array.from(document.querySelectorAll('#severityFilter input:checked')).map(cb => cb.value);
    const ticketTypes = Array.from(document.querySelectorAll('#ticketTypeFilter input:checked')).map(cb => cb.value);
    const statuses = Array.from(document.querySelectorAll('#statusFilter input:checked')).map(cb => cb.value);
    const automationLevels = Array.from(document.querySelectorAll('#automationFilter input:checked')).map(cb => cb.value);

    updateFilterSummary(dateRange, mttrFilter, mttcFilter, ageFilter, countries, regions, impacts, severities, ticketTypes, statuses, automationLevels);

    state.filteredData = state.allData.filter(item => {
        // Date filter
        if (item.created_days_ago !== null && item.created_days_ago > dateRange) return false;

        // Location filters
        if (countries.length > 0 || regions.length > 0) {
            let locationMatch = false;

            if (countries.length > 0) {
                const hasNoCountry = !item.affected_country || item.affected_country === 'Unknown' || item.affected_country.trim() === '';
                const shouldShowNoCountry = countries.includes('No Country') && hasNoCountry;
                const shouldShowWithCountry = countries.some(c => c !== 'No Country' && c === item.affected_country);
                locationMatch = shouldShowNoCountry || shouldShowWithCountry;
            }

            if (regions.length > 0) {
                const hasNoRegion = !item.affected_region || item.affected_region === 'Unknown' || item.affected_region.trim() === '';
                const shouldShowNoRegion = regions.includes('No Region') && hasNoRegion;
                const shouldShowWithRegion = regions.some(r => r !== 'No Region' && r === item.affected_region);
                locationMatch = shouldShowNoRegion || shouldShowWithRegion;
            }

            if (!locationMatch) return false;
        }

        // Impact filter
        if (impacts.length > 0) {
            const hasNoImpact = !item.impact || item.impact === 'Unknown' || item.impact.trim() === '';
            const shouldShowNoImpact = impacts.includes('No Impact') && hasNoImpact;
            const shouldShowWithImpact = impacts.some(i => i !== 'No Impact' && i === item.impact);
            if (!shouldShowNoImpact && !shouldShowWithImpact) return false;
        }

        if (severities.length > 0 && !severities.includes(item.severity.toString())) return false;
        if (ticketTypes.length > 0 && !ticketTypes.includes(item.type)) return false;
        if (statuses.length > 0 && !statuses.includes(item.status.toString())) return false;

        // Automation level filter
        if (automationLevels.length > 0) {
            const hasNoLevel = !item.automation_level || item.automation_level === 'Unknown' || item.automation_level.trim() === '';
            const shouldShowNoLevel = automationLevels.includes('No Level') && hasNoLevel;
            const shouldShowWithLevel = automationLevels.some(l => l !== 'No Level' && l === item.automation_level);
            if (!shouldShowNoLevel && !shouldShowWithLevel) return false;
        }

        // MTTR filter
        if (mttrFilter > 0) {
            const mttrSeconds = item.time_to_respond_secs || null;
            if (mttrSeconds == null || mttrSeconds === 0) return false;

            if (mttrFilter === 1 && mttrSeconds > 180) return false;
            if (mttrFilter === 2 && mttrSeconds <= 180) return false;
            if (mttrFilter === 3 && mttrSeconds <= 300) return false;
        }

        // MTTC filter
        if (mttcFilter > 0) {
            if (!item.has_hostname) return false;

            const mttcSeconds = item.time_to_contain_secs || null;
            if (mttcSeconds == null || mttcSeconds === 0) return false;

            if (mttcFilter === 1 && mttcSeconds > 300) return false;
            if (mttcFilter === 2 && mttcSeconds > 900) return false;
            if (mttcFilter === 3 && mttcSeconds <= 900) return false;
        }

        // Age filter - Fixed: simplified null check
        if (ageFilter > 0) {
            if (item.currently_aging_days == null) return false;
            if (Number(item.currently_aging_days) <= ageFilter) return false;
        }

        return true;
    });

    if (updateCallback) updateCallback();
}

function updateFilterSummary(dateRange, mttrFilter, mttcFilter, ageFilter, countries, regions, impacts, severities, ticketTypes, statuses, automationLevels) {
    const container = document.getElementById('activeFiltersContainer');
    if (!container) return;

    const nonRemovableFilters = container.querySelectorAll('.filter-tag.non-removable');
    container.innerHTML = Array.from(nonRemovableFilters).map(filter => filter.outerHTML).join('');

    const dateText = `Created in Last ${dateRange} day${dateRange === 1 ? '' : 's'}`;
    container.innerHTML += `<span class="filter-tag">${dateText}</span>`;

    if (mttrFilter > 0) {
        const mttrText = mttrFilter === 1 ? 'MTTR ≤3 mins' : mttrFilter === 2 ? 'MTTR >3 mins' : 'MTTR >5 mins';
        container.innerHTML += `<span class="filter-tag">${mttrText} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('mttr', '${mttrFilter}')">×</button></span>`;
    }

    if (mttcFilter > 0) {
        const mttcText = mttcFilter === 1 ? 'MTTC ≤5 mins' : mttcFilter === 2 ? 'MTTC ≤15 mins' : 'MTTC >15 mins';
        container.innerHTML += `<span class="filter-tag">${mttcText} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('mttc', '${mttcFilter}')">×</button></span>`;
    }

    if (ageFilter > 0) {
        const ageText = ageFilter === 1 ? 'Age >1 day' : `Age >${ageFilter} days`;
        container.innerHTML += `<span class="filter-tag">${ageText} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('age', '${ageFilter}')">×</button></span>`;
    }

    if (countries.length > 0) {
        countries.forEach(country => {
            container.innerHTML += `<span class="filter-tag">Country: ${country} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('country', '${country}')">×</button></span>`;
        });
    }

    if (regions.length > 0) {
        regions.forEach(region => {
            container.innerHTML += `<span class="filter-tag">Region: ${region} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('region', '${region}')">×</button></span>`;
        });
    }

    if (impacts.length > 0) {
        impacts.forEach(impact => {
            container.innerHTML += `<span class="filter-tag">Impact: ${impact} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('impact', '${impact}')">×</button></span>`;
        });
    }

    if (severities.length > 0) {
        severities.forEach(severity => {
            const severityMap = {'4': 'Critical', '3': 'High', '2': 'Medium', '1': 'Low', '0': 'Unknown'};
            const severityName = severityMap[severity] || 'Unknown';
            container.innerHTML += `<span class="filter-tag">Severity: ${severityName} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('severity', '${severity}')">×</button></span>`;
        });
    }

    if (ticketTypes.length > 0) {
        ticketTypes.forEach(type => {
            const displayType = stripTeamPrefix(type);
            container.innerHTML += `<span class="filter-tag">Type: ${displayType} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('ticketType', '${type}')">×</button></span>`;
        });
    }

    if (statuses.length > 0) {
        statuses.forEach(status => {
            const statusMap = {'0': 'Pending', '1': 'Active', '2': 'Closed'};
            const statusName = statusMap[status] || 'Unknown';
            container.innerHTML += `<span class="filter-tag">Status: ${statusName} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('status', '${status}')">×</button></span>`;
        });
    }

    if (automationLevels.length > 0) {
        automationLevels.forEach(automation => {
            const displayAutomation = automation === 'Semi-Automated' ? 'Semi-Auto' : automation;
            container.innerHTML += `<span class="filter-tag">Automation: ${displayAutomation} <button class="remove-filter-btn" onclick="window.metricsApp.removeFilter('automation', '${automation}')">×</button></span>`;
        });
    }
}

export function removeFilter(filterType, value) {
    const filterMap = {
        country: '#countryFilter',
        region: '#regionFilter',
        impact: '#impactFilter',
        severity: '#severityFilter',
        ticketType: '#ticketTypeFilter',
        status: '#statusFilter',
        automation: '#automationFilter',
        mttr: '#mttrRangeSlider',
        mttc: '#mttcRangeSlider',
        age: '#ageRangeSlider'
    };

    const selector = filterMap[filterType];
    if (!selector) return;

    if (selector.includes('Slider')) {
        const slider = document.querySelector(selector);
        if (slider) slider.value = 0;
    } else {
        const checkbox = document.querySelector(`${selector} input[value="${value}"]`);
        if (checkbox) checkbox.checked = false;
    }
}

export function resetFilters() {
    document.getElementById('dateRangeSlider').value = 30;
    document.getElementById('mttrRangeSlider').value = 0;
    document.getElementById('mttcRangeSlider').value = 0;
    document.getElementById('ageRangeSlider').value = 0;
    document.querySelectorAll('#countryFilter input, #regionFilter input, #impactFilter input, #severityFilter input, #ticketTypeFilter input, #statusFilter input, #automationFilter input').forEach(cb => cb.checked = false);
}

export function initLocationTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const countryTab = document.getElementById('countryTab');
    const regionTab = document.getElementById('regionTab');

    tabButtons.forEach(button => {
        button.addEventListener('click', function () {
            const tab = this.getAttribute('data-tab');
            tabButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');

            countryTab.classList.remove('active');
            regionTab.classList.remove('active');

            if (tab === 'country') {
                countryTab.classList.add('active');
            } else {
                regionTab.classList.add('active');
            }
        });
    });
}

export function getCurrentFilters() {
    const dateSlider = document.getElementById('dateRangeSlider');
    const mttrSlider = document.getElementById('mttrRangeSlider');
    const mttcSlider = document.getElementById('mttcRangeSlider');
    const ageSlider = document.getElementById('ageRangeSlider');

    return {
        dateRange: parseInt(dateSlider?.value || 30),
        mttrFilter: parseInt(mttrSlider?.value || 0),
        mttcFilter: parseInt(mttcSlider?.value || 0),
        ageFilter: parseInt(ageSlider?.value || 0),
        countries: Array.from(document.querySelectorAll('#countryFilter input:checked')).map(cb => cb.value),
        regions: Array.from(document.querySelectorAll('#regionFilter input:checked')).map(cb => cb.value),
        impacts: Array.from(document.querySelectorAll('#impactFilter input:checked')).map(cb => cb.value),
        severities: Array.from(document.querySelectorAll('#severityFilter input:checked')).map(cb => cb.value),
        ticketTypes: Array.from(document.querySelectorAll('#ticketTypeFilter input:checked')).map(cb => cb.value),
        statuses: Array.from(document.querySelectorAll('#statusFilter input:checked')).map(cb => cb.value),
        automationLevels: Array.from(document.querySelectorAll('#automationFilter input:checked')).map(cb => cb.value)
    };
}
