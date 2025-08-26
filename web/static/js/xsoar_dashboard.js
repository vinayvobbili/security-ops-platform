document.addEventListener('DOMContentLoaded', function() {
    const searchForm = document.getElementById('searchForm');
    const loading = document.getElementById('loading');
    const incidentsSection = document.getElementById('incidentsSection');
    const errorSection = document.getElementById('errorSection');
    const incidentsTableBody = document.getElementById('incidentsTableBody');
    const incidentCount = document.getElementById('incidentCount');
    const errorMessage = document.getElementById('errorMessage');

    // Load recent incidents on page load
    loadIncidents();

    searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        loadIncidents();
    });

    function loadIncidents() {
        const formData = new FormData(searchForm);
        const params = new URLSearchParams();
        
        for (let [key, value] of formData.entries()) {
            if (value.trim()) {
                params.append(key, value);
            }
        }

        // Show loading state
        showLoading();

        fetch(`/api/xsoar/incidents?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    displayIncidents(data.incidents);
                } else {
                    showError(data.error || 'Failed to load incidents');
                }
            })
            .catch(error => {
                hideLoading();
                showError('Network error: ' + error.message);
            });
    }

    function displayIncidents(incidents) {
        errorSection.style.display = 'none';
        incidentsSection.style.display = 'block';
        
        incidentCount.textContent = incidents.length;
        incidentsTableBody.innerHTML = '';

        if (incidents.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="8" style="text-align: center; color: #666; padding: 20px;">No incidents found</td>';
            incidentsTableBody.appendChild(row);
            return;
        }

        incidents.forEach(incident => {
            const row = document.createElement('tr');
            const created = formatDate(incident.created);
            const severity = String(incident.severity || '').toLowerCase();
            const status = String(incident.status || '').toLowerCase();
            
            row.innerHTML = `
                <td>
                    <a href="/xsoar/incident/${incident.id}" class="incident-link">
                        ${incident.id}
                    </a>
                </td>
                <td>${escapeHtml(incident.name || 'Untitled')}</td>
                <td>${escapeHtml(incident.type || 'Unknown')}</td>
                <td>
                    <span class="status-badge status-${status}">
                        ${incident.status || 'Unknown'}
                    </span>
                </td>
                <td>
                    <span class="severity-badge severity-${severity}">
                        ${incident.severity || 'Unknown'}
                    </span>
                </td>
                <td>${escapeHtml(incident.owner || 'Unassigned')}</td>
                <td>${created}</td>
                <td>
                    <button class="btn btn-secondary action-btn" onclick="viewIncident('${incident.id}')">
                        View
                    </button>
                </td>
            `;
            incidentsTableBody.appendChild(row);
        });
    }

    function showLoading() {
        loading.style.display = 'block';
        incidentsSection.style.display = 'none';
        errorSection.style.display = 'none';
    }

    function hideLoading() {
        loading.style.display = 'none';
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorSection.style.display = 'block';
        incidentsSection.style.display = 'none';
    }

    function formatDate(dateString) {
        if (!dateString) return 'Unknown';
        try {
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        } catch (e) {
            return dateString;
        }
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Global function for view buttons
    window.viewIncident = function(incidentId) {
        window.location.href = `/xsoar/incident/${incidentId}`;
    };
});