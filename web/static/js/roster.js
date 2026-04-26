/* SecOps Daily Roster JS */

var activeEdit = null;  // currently editing cell

// --- Toast ---
function showToast(msg, isError) {
    var t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'ro-toast ro-toast-show' + (isError ? ' ro-toast-error' : '');
    setTimeout(function() { t.className = 'ro-toast'; }, 2500);
}

// --- Confirm Dialog ---
function showConfirm(title, message, type) {
    return new Promise(function(resolve) {
        var overlay = document.getElementById('confirmOverlay');
        var icon = document.getElementById('confirmIcon');
        var titleEl = document.getElementById('confirmTitle');
        var msgEl = document.getElementById('confirmMsg');
        var okBtn = document.getElementById('confirmOk');
        var cancelBtn = document.getElementById('confirmCancel');

        var icons = { info: '\u{1F504}', success: '\u2705', danger: '\u{1F6A8}' };
        icon.textContent = icons[type] || icons.info;
        titleEl.textContent = title;
        msgEl.innerHTML = message;

        okBtn.className = 'ro-btn ro-confirm-ok ro-confirm-ok-' + (type || 'info');
        okBtn.textContent = type === 'danger' ? 'Remove' : 'Confirm';

        overlay.style.display = 'flex';
        okBtn.focus();

        function cleanup() {
            overlay.style.display = 'none';
            okBtn.onclick = null;
            cancelBtn.onclick = null;
            document.removeEventListener('keydown', onKey);
        }
        function onKey(e) {
            if (e.key === 'Escape') { cleanup(); resolve(false); }
            else if (e.key === 'Enter') { cleanup(); resolve(true); }
        }
        document.addEventListener('keydown', onKey);
        okBtn.onclick = function() { cleanup(); resolve(true); };
        cancelBtn.onclick = function() { cleanup(); resolve(false); };
        overlay.onclick = function(e) { if (e.target === overlay) { cleanup(); resolve(false); } };
    });
}

// --- API helper ---
function api(url, method, body) {
    return fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
    }).then(function(r) { return r.json(); });
}

// --- Top-level Tabs (Schedule / Team Members) ---
function switchTab(tabId) {
    cancelEdit();
    document.querySelectorAll('.ro-tab-panel').forEach(function(el) {
        el.style.display = 'none';
    });
    var panel = document.getElementById('tab-' + tabId);
    if (panel) panel.style.display = '';

    document.querySelectorAll('.ro-top-tab').forEach(function(el) {
        el.classList.remove('ro-top-tab-active');
    });
    var tab = document.querySelector('.ro-top-tab[data-tab="' + tabId + '"]');
    if (tab) tab.classList.add('ro-top-tab-active');
    location.hash = tabId;
}

// --- Cell Editing ---
function editCell(td) {
    if (td.querySelector('.ro-cell-select')) return;
    cancelEdit();

    var nameSpan = td.querySelector('.ro-cell-name');
    var current = nameSpan.textContent.trim();

    var select = document.createElement('select');
    select.className = 'ro-cell-select';

    // Empty option
    var emptyOpt = document.createElement('option');
    emptyOpt.value = '';
    emptyOpt.textContent = '\u2014';
    if (!current) emptyOpt.selected = true;
    select.appendChild(emptyOpt);

    // Team members
    TEAM_MEMBERS.forEach(function(m) {
        var opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        if (m === current) opt.selected = true;
        select.appendChild(opt);
    });

    nameSpan.style.display = 'none';
    td.appendChild(select);
    td.classList.add('ro-grid-cell-editing');
    select.focus();
    activeEdit = td;

    select.addEventListener('change', function() {
        saveCell(td, select.value);
    });
    select.addEventListener('blur', function() {
        // Small delay so click on another cell registers first
        setTimeout(function() { cancelEdit(); }, 150);
    });
    select.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') cancelEdit();
    });
}

function saveCell(td, newName) {
    var d = td.dataset;
    api('/api/roster/slot', 'PUT', {
        period_id: d.period,
        day: d.day,
        shift: d.shift,
        team: d.team,
        slot: parseInt(d.slot),
        name: newName,
    }).then(function(r) {
        if (r.success) {
            var nameSpan = td.querySelector('.ro-cell-name');
            nameSpan.textContent = newName;
            td.classList.toggle('ro-grid-cell-filled', !!newName);
            showToast('Updated');
            updateHeadcounts();
        } else {
            showToast(r.error || 'Failed', true);
        }
        finishEdit(td);
    }).catch(function() {
        showToast('Network error', true);
        finishEdit(td);
    });
}

function finishEdit(td) {
    var select = td.querySelector('.ro-cell-select');
    if (select) select.remove();
    var nameSpan = td.querySelector('.ro-cell-name');
    if (nameSpan) nameSpan.style.display = '';
    td.classList.remove('ro-grid-cell-editing');
    if (activeEdit === td) activeEdit = null;
}

function cancelEdit() {
    if (activeEdit) finishEdit(activeEdit);
}

// --- Headcount badges (today only) ---
function updateHeadcounts() {
    document.querySelectorAll('.ro-shift-headcount').forEach(function(badge) {
        var section = badge.closest('.ro-shift-section');
        if (!section) return;
        var todayCells = section.querySelectorAll('.ro-grid-cell-today.ro-grid-cell-filled');
        badge.textContent = todayCells.length ? '\ud83d\udc65 ' + todayCells.length + ' today' : '';
    });
}

// --- Avatar colors ---
var AVATAR_COLORS = [
    '#ef4444', '#f97316', '#f59e0b', '#22c55e', '#10b981',
    '#14b8a6', '#06b6d4', '#0ea5e9', '#3b82f6', '#6366f1',
    '#8b5cf6', '#a855f7', '#d946ef', '#ec4899', '#f43f5e',
];
function colorizeAvatars() {
    document.querySelectorAll('.ro-member-avatar').forEach(function(el) {
        var name = el.closest('.ro-member-card').dataset.name || '';
        var hash = 0;
        for (var i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
        el.style.background = 'linear-gradient(135deg, ' + AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length] + ', ' + AVATAR_COLORS[(Math.abs(hash) + 3) % AVATAR_COLORS.length] + ')';
    });
}

// --- Period Management ---
function createPeriod(periodId) {
    showConfirm(
        'Create Schedule',
        'Create a new empty schedule for this period?',
        'success'
    ).then(function(ok) {
        if (!ok) return;
        api('/api/roster/period', 'POST', { period_id: periodId })
            .then(function(r) {
                if (r.success) {
                    showToast('Schedule created');
                    setTimeout(function() { location.href = '/roster?period=' + periodId; }, 500);
                } else {
                    showToast(r.error || 'Failed', true);
                }
            })
            .catch(function() { showToast('Network error', true); });
    });
}

// --- Team Members ---
function openAddMember() {
    document.getElementById('memberName').value = '';
    document.getElementById('memberEmail').value = '';
    document.getElementById('memberRole').value = '';
    document.getElementById('addMemberModal').style.display = 'flex';
    document.getElementById('memberName').focus();
}

function closeAddMember(e) {
    if (e && e.target !== e.currentTarget) return;
    document.getElementById('addMemberModal').style.display = 'none';
}

function saveMember(e) {
    e.preventDefault();
    var name = document.getElementById('memberName').value.trim();
    var email = document.getElementById('memberEmail').value.trim();
    var role = document.getElementById('memberRole').value;
    if (!name) { showToast('Name is required', true); return; }

    showConfirm('Add Team Member', 'Add <b>' + name + '</b> to the roster?', 'success').then(function(ok) {
        if (!ok) return;
        api('/api/roster/team-members', 'POST', { name: name, email: email, role: role })
            .then(function(r) {
                if (r.success) {
                    showToast('Member added');
                    setTimeout(function() { location.reload(); }, 600);
                } else {
                    showToast(r.error || 'Failed', true);
                }
            })
            .catch(function() { showToast('Network error', true); });
    });
}

function openEditMember(name) {
    var details = MEMBER_DETAILS[name] || {};
    var firstName = details.first_name || '';
    var lastName = details.last_name || '';
    // If no stored details, split the display name
    if (!firstName && !lastName) {
        var parts = name.split(' ');
        firstName = parts[0] || '';
        lastName = parts.slice(1).join(' ') || '';
    }
    document.getElementById('editOldName').value = name;
    document.getElementById('editFirstName').value = firstName;
    document.getElementById('editLastName').value = lastName;
    document.getElementById('editEmail').value = details.email || '';
    document.getElementById('editMemberModal').style.display = 'flex';
    document.getElementById('editFirstName').focus();
}

function closeEditMember(e) {
    if (e && e.target !== e.currentTarget) return;
    document.getElementById('editMemberModal').style.display = 'none';
}

function saveEditMember(e) {
    e.preventDefault();
    var oldName = document.getElementById('editOldName').value;
    var firstName = document.getElementById('editFirstName').value.trim();
    var lastName = document.getElementById('editLastName').value.trim();
    var email = document.getElementById('editEmail').value.trim();
    if (!firstName && !lastName) { showToast('Name is required', true); return; }

    api('/api/roster/team-members', 'PUT', {
        old_name: oldName,
        first_name: firstName,
        last_name: lastName,
        email: email,
    }).then(function(r) {
        if (r.success) {
            showToast('Member updated');
            setTimeout(function() { location.reload(); }, 600);
        } else {
            showToast(r.error || 'Failed', true);
        }
    }).catch(function() { showToast('Network error', true); });
}

function removeMember(name) {
    showConfirm(
        'Remove Team Member',
        'Remove <b>' + name + '</b> from the roster?<br><span style="font-size:0.85em;color:#94a3b8;">This won\'t remove them from existing schedules.</span>',
        'danger'
    ).then(function(ok) {
        if (!ok) return;
        api('/api/roster/team-members', 'DELETE', { name: name })
            .then(function(r) {
                if (r.success) {
                    showToast('Member removed');
                    setTimeout(function() { location.reload(); }, 600);
                } else {
                    showToast(r.error || 'Failed', true);
                }
            })
            .catch(function() { showToast('Network error', true); });
    });
}

// --- Keyboard ---
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if (document.getElementById('confirmOverlay').style.display === 'flex') return;
        if (document.getElementById('editMemberModal').style.display === 'flex') {
            closeEditMember();
            return;
        }
        if (document.getElementById('addMemberModal').style.display === 'flex') {
            closeAddMember();
            return;
        }
        cancelEdit();
    }
});

// --- Init ---
document.addEventListener('DOMContentLoaded', function() {
    if (typeof initTheme === 'function') initTheme();
    updateHeadcounts();
    colorizeAvatars();

    // Restore active tab from URL hash
    var hash = location.hash.replace('#', '');
    if (hash && document.getElementById('tab-' + hash)) {
        switchTab(hash);
    }

    // Scroll active shift into view
    var active = document.querySelector('.ro-shift-current');
    if (active) {
        active.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
});
