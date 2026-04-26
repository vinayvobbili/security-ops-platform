/* On-Call Schedule JS */

let swapSource = null;

// --- Toast ---
function showToast(msg, isError) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'oc-toast oc-toast-show' + (isError ? ' oc-toast-error' : '');
    setTimeout(() => { t.className = 'oc-toast'; }, 3000);
}

// --- Custom Confirm Dialog ---
// type: 'info' (blue), 'success' (green), 'danger' (red), 'swap' (violet)
function showConfirm(title, message, type) {
    return new Promise(function(resolve) {
        var overlay = document.getElementById('confirmOverlay');
        var icon = document.getElementById('confirmIcon');
        var titleEl = document.getElementById('confirmTitle');
        var msgEl = document.getElementById('confirmMsg');
        var okBtn = document.getElementById('confirmOk');
        var cancelBtn = document.getElementById('confirmCancel');

        var icons = { info: '\u{1F504}', success: '\u2705', danger: '\u{1F6A8}', swap: '\u{1F500}' };
        icon.textContent = icons[type] || icons.info;
        titleEl.textContent = title;
        msgEl.innerHTML = message;

        // Style the OK button by type
        okBtn.className = 'oc-btn oc-confirm-ok oc-confirm-ok-' + (type || 'info');
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
    }).then(r => r.json());
}

// --- Rotation ---
function confirmAssign(sel, mondayDate) {
    if (sel.value === sel.dataset.original) return;
    var newName = sel.value;
    var oldName = sel.dataset.original;
    showConfirm(
        'Reassign Week',
        'Change <b>' + mondayDate + '</b> from <b>' + oldName + '</b> to <b>' + newName + '</b>?',
        'info'
    ).then(function(ok) {
        if (!ok) { sel.value = sel.dataset.original; return; }
        api('/api/oncall/rotation', 'PUT', { monday_date: mondayDate, analyst_name: newName })
            .then(r => {
                if (r.success) { showToast('Week updated'); setTimeout(() => location.reload(), 600); }
                else { showToast(r.error || 'Failed to update', true); sel.value = sel.dataset.original; }
            })
            .catch(() => { showToast('Network error', true); sel.value = sel.dataset.original; });
    });
}

// --- Swap ---
function toggleSwap(mondayDate) {
    if (!swapSource) startSwap(mondayDate);
    else if (swapSource === mondayDate) cancelSwap();
    else completeSwap(mondayDate);
}

function startSwap(mondayDate) {
    swapSource = mondayDate;
    var row = document.querySelector('[data-date="' + mondayDate + '"]');
    if (row) row.classList.add('oc-swap-source');

    document.getElementById('swapBar').style.display = 'flex';
    document.getElementById('swapStatus').textContent =
        'Select another week to swap with ' + (row ? row.dataset.analyst : mondayDate);

    document.querySelectorAll('.oc-week-future .oc-btn-swap, .oc-week-current .oc-btn-swap').forEach(btn => {
        var r = btn.closest('.oc-week');
        if (r && r.dataset.date !== mondayDate) {
            btn.textContent = 'Swap here';
            btn.classList.add('oc-btn-add');
        }
    });
}

function cancelSwap() {
    document.querySelectorAll('.oc-swap-source').forEach(el => el.classList.remove('oc-swap-source'));
    document.getElementById('swapBar').style.display = 'none';
    document.querySelectorAll('.oc-btn-swap').forEach(btn => {
        btn.textContent = 'Swap';
        btn.classList.remove('oc-btn-add');
    });
    swapSource = null;
}

function completeSwap(mondayDate2) {
    var d1 = swapSource;
    var row1 = document.querySelector('[data-date="' + d1 + '"]');
    var row2 = document.querySelector('[data-date="' + mondayDate2 + '"]');
    var name1 = row1 ? row1.dataset.analyst : d1;
    var name2 = row2 ? row2.dataset.analyst : mondayDate2;

    showConfirm(
        'Swap Weeks',
        'Swap <b>' + name1 + '</b> (' + d1 + ')<br>with <b>' + name2 + '</b> (' + mondayDate2 + ')?',
        'swap'
    ).then(function(ok) {
        cancelSwap();
        if (!ok) return;
        api('/api/oncall/swap', 'POST', { monday_date_1: d1, monday_date_2: mondayDate2 })
            .then(r => {
                if (r.success) { showToast('Weeks swapped'); setTimeout(() => location.reload(), 600); }
                else showToast(r.error || 'Swap failed', true);
            })
            .catch(() => showToast('Network error', true));
    });
}

// --- Analyst Modal ---
function openAnalystModal(originalName, name, email, phone) {
    document.getElementById('modalOriginalName').value = originalName || '';
    document.getElementById('modalName').value = name || '';
    document.getElementById('modalEmail').value = email || '';
    document.getElementById('modalPhone').value = phone || '';
    document.getElementById('modalTitle').textContent = originalName ? 'Edit Analyst' : 'Add Analyst';
    document.getElementById('analystModal').style.display = 'flex';
    document.getElementById('modalName').focus();
}

function closeAnalystModal(e) {
    if (e && e.target !== e.currentTarget) return;
    document.getElementById('analystModal').style.display = 'none';
}

function editAnalyst(btn) {
    var card = btn.closest('.oc-team-card');
    var name = card.dataset.name;
    var email = card.querySelector('.oc-team-email a');
    var phone = card.querySelector('.oc-team-phone');
    openAnalystModal(name, name, email ? email.textContent : '', phone ? phone.textContent : '');
}

function saveAnalyst(e) {
    e.preventDefault();
    var originalName = document.getElementById('modalOriginalName').value;
    var name = document.getElementById('modalName').value.trim();
    var email = document.getElementById('modalEmail').value.trim();
    var phone = document.getElementById('modalPhone').value.trim();

    if (!name) { showToast('Name is required', true); return; }

    var title = originalName ? 'Update Analyst' : 'Add Analyst';
    var msg = originalName
        ? 'Save changes to <b>' + originalName + '</b>?'
        : 'Add <b>' + name + '</b> to the on-call roster?';
    var type = originalName ? 'info' : 'success';

    showConfirm(title, msg, type).then(function(ok) {
        if (!ok) return;
        if (originalName) {
            api('/api/oncall/analysts', 'PUT', {
                original_name: originalName, name: name,
                email_address: email, phone_number: phone,
            }).then(r => {
                if (r.success) { showToast('Analyst updated'); setTimeout(() => location.reload(), 600); }
                else showToast(r.error || 'Update failed', true);
            }).catch(() => showToast('Network error', true));
        } else {
            api('/api/oncall/analysts', 'POST', {
                name: name, email_address: email, phone_number: phone,
            }).then(r => {
                if (r.success) { showToast('Analyst added'); setTimeout(() => location.reload(), 600); }
                else showToast(r.error || 'Add failed', true);
            }).catch(() => showToast('Network error', true));
        }
    });
}

function deleteAnalyst(name) {
    showConfirm(
        'Remove Analyst',
        'Remove <b>' + name + '</b> from the on-call roster?<br><span style="font-size:0.85em;color:#94a3b8;">Existing rotation entries will be kept.</span>',
        'danger'
    ).then(function(ok) {
        if (!ok) return;
        api('/api/oncall/analysts', 'DELETE', { name: name })
            .then(r => {
                if (r.success) { showToast('Analyst removed'); setTimeout(() => location.reload(), 600); }
                else showToast(r.error || 'Delete failed', true);
            })
            .catch(() => showToast('Network error', true));
    });
}

// --- Keyboard ---
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if (document.getElementById('confirmOverlay').style.display === 'flex') return; // handled by confirm
        if (swapSource) cancelSwap();
        else closeAnalystModal();
    }
});

// --- Init ---
document.addEventListener('DOMContentLoaded', function() {
    if (typeof initTheme === 'function') initTheme();
    var current = document.querySelector('.oc-week-current');
    if (current) current.scrollIntoView({ behavior: 'smooth', block: 'center' });
});
