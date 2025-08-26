document.addEventListener('DOMContentLoaded', function() {
    const linkIncidentModal = document.getElementById('linkIncidentModal');
    const addParticipantModal = document.getElementById('addParticipantModal');
    const linkIncidentForm = document.getElementById('linkIncidentForm');
    const addParticipantForm = document.getElementById('addParticipantForm');
    const loadingOverlay = document.getElementById('loadingOverlay');

    // Form event listeners
    linkIncidentForm.addEventListener('submit', handleLinkIncident);
    addParticipantForm.addEventListener('submit', handleAddParticipant);

    function handleLinkIncident(e) {
        e.preventDefault();
        const linkIncidentId = document.getElementById('linkIncidentId').value.trim();
        
        if (!linkIncidentId) {
            alert('Please enter an incident ID to link');
            return;
        }

        showLoading();
        closeLinkIncidentModal();

        fetch(`/api/xsoar/incident/${window.incidentId}/link`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                link_incident_id: linkIncidentId
            })
        })
        .then(response => response.json())
        .then(data => {
            hideLoading();
            if (data.success) {
                showSuccessMessage(`Successfully linked incident ${linkIncidentId}`);
                linkIncidentForm.reset();
            } else {
                showErrorMessage(data.error || 'Failed to link incident');
            }
        })
        .catch(error => {
            hideLoading();
            showErrorMessage('Network error: ' + error.message);
        });
    }

    function handleAddParticipant(e) {
        e.preventDefault();
        const participantEmail = document.getElementById('participantEmail').value.trim();
        
        if (!participantEmail) {
            alert('Please enter a participant email');
            return;
        }

        showLoading();
        closeAddParticipantModal();

        fetch(`/api/xsoar/incident/${window.incidentId}/participant`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: participantEmail
            })
        })
        .then(response => response.json())
        .then(data => {
            hideLoading();
            if (data.success) {
                showSuccessMessage(`Successfully added participant ${participantEmail}`);
                addParticipantForm.reset();
            } else {
                showErrorMessage(data.error || 'Failed to add participant');
            }
        })
        .catch(error => {
            hideLoading();
            showErrorMessage('Network error: ' + error.message);
        });
    }

    // Global functions for modal controls
    window.showLinkIncidentModal = function() {
        linkIncidentModal.style.display = 'block';
        document.getElementById('linkIncidentId').focus();
    };

    window.closeLinkIncidentModal = function() {
        linkIncidentModal.style.display = 'none';
    };

    window.showAddParticipantModal = function() {
        addParticipantModal.style.display = 'block';
        document.getElementById('participantEmail').focus();
    };

    window.closeAddParticipantModal = function() {
        addParticipantModal.style.display = 'none';
    };

    window.refreshEntries = function() {
        showLoading();
        
        fetch(`/api/xsoar/incident/${window.incidentId}/entries`)
        .then(response => response.json())
        .then(data => {
            hideLoading();
            if (data.success) {
                updateEntriesDisplay(data.entries);
                showSuccessMessage('Entries refreshed successfully');
            } else {
                showErrorMessage(data.error || 'Failed to refresh entries');
            }
        })
        .catch(error => {
            hideLoading();
            showErrorMessage('Network error: ' + error.message);
        });
    };

    function updateEntriesDisplay(entries) {
        const entriesContainer = document.getElementById('entriesContainer');
        const entriesCount = document.getElementById('entriesCount');
        
        entriesCount.textContent = entries.length;
        
        if (entries.length === 0) {
            entriesContainer.innerHTML = '<div class="no-entries">No entries found for this incident.</div>';
            return;
        }

        let entriesHtml = '';
        entries.forEach(entry => {
            entriesHtml += `
                <div class="entry-item">
                    <div class="entry-header">
                        <div class="entry-user">${escapeHtml(entry.user || 'System')}</div>
                        <div class="entry-date">${formatDate(entry.created)}</div>
                    </div>
                    <div class="entry-content">${escapeHtml(entry.contents || '')}</div>
                    ${entry.type ? `<div class="entry-type">Type: ${escapeHtml(entry.type)}</div>` : ''}
                </div>
            `;
        });
        
        entriesContainer.innerHTML = entriesHtml;
    }

    function showLoading() {
        loadingOverlay.style.display = 'flex';
    }

    function hideLoading() {
        loadingOverlay.style.display = 'none';
    }

    function showSuccessMessage(message) {
        // Create temporary success notification
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(40, 167, 69, 0.3);
            z-index: 4000;
            animation: slideInRight 0.3s ease;
        `;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => document.body.removeChild(notification), 300);
        }, 3000);
    }

    function showErrorMessage(message) {
        // Create temporary error notification
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            background: linear-gradient(135deg, #dc3545, #e74c3c);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(220, 53, 69, 0.3);
            z-index: 4000;
            animation: slideInRight 0.3s ease;
        `;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => document.body.removeChild(notification), 300);
        }, 5000);
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

    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === linkIncidentModal) {
            closeLinkIncidentModal();
        }
        if (event.target === addParticipantModal) {
            closeAddParticipantModal();
        }
    });

    // Add CSS for animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOutRight {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
});