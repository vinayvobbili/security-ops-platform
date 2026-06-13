/* Ticket Cannon Silencer & Noise Suppression — modal, field builder, toggle, category tabs */

// ── State ──
var addedFields = {};
var fieldDefs = {};       // key -> display label
var fieldExamples = {};   // key -> sample value (common fields only)
var activeCat = '';

(function() {
    try {
        var raw = document.getElementById('silencer-field-options').textContent;
        var opts = JSON.parse(raw);
        (opts.all || []).forEach(function(o) { fieldDefs[o.key] = o.label; });
        (opts.common || []).forEach(function(o) {
            fieldDefs[o.key] = o.label;
            if (o.example) fieldExamples[o.key] = o.example;
        });
    } catch (e) {
        console.error('Failed to parse silencer field options:', e);
    }
})();

// ── Toast ──
function showToast(msg, type) {
    var toast = document.getElementById('tcToast');
    toast.textContent = msg;
    toast.className = 'tc-toast tc-toast-show tc-toast-' + (type || 'success');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(function() { toast.classList.remove('tc-toast-show'); }, 3000);
}

// ── Active count ──
function updateActiveCount() {
    var panel = document.querySelector('.tc-cat-panel--visible');
    if (!panel) return;
    var rows = panel.querySelectorAll('.tc-section:first-child tbody tr[data-id]');
    var count = rows ? rows.length : 0;
    var el = document.getElementById('activeCount');
    if (el) el.textContent = count + ' active entr' + (count !== 1 ? 'ies' : 'y');
}

// ── Category tabs ──
function switchCat(cat) {
    activeCat = cat;
    document.querySelectorAll('.tc-tab').forEach(function(t) {
        t.classList.toggle('tc-tab-active', t.getAttribute('data-cat') === cat);
    });
    document.querySelectorAll('.tc-cat-panel').forEach(function(p) {
        if (p.getAttribute('data-cat-panel') === cat) {
            p.classList.add('tc-cat-panel--visible');
        } else {
            p.classList.remove('tc-cat-panel--visible');
        }
    });
    updateActiveCount();
}

// ── Toggle inactive section (per category) ──
function toggleInactiveSection(cat) {
    var body = document.getElementById('inactiveBody-' + cat);
    var arrow = document.getElementById('inactiveArrow-' + cat);
    if (body.style.display === 'none') {
        body.style.display = 'block';
        arrow.innerHTML = '&#9660;';
    } else {
        body.style.display = 'none';
        arrow.innerHTML = '&#9654;';
    }
}

// ── Modal ──
function openNewModal() {
    document.getElementById('newModal').style.display = 'flex';
    document.getElementById('newSilencerForm').reset();
    addedFields = {};
    renderFieldsList();
    // Auto-set category from active tab
    document.getElementById('silencerCat').value = activeCat;
    // Set modal title based on active tab
    var activeTab = document.querySelector('.tc-tab-active');
    var label = activeTab ? activeTab.textContent.trim() : 'Entry';
    document.getElementById('modalTitle').textContent = 'New ' + label.replace(/s$/, '');
    document.getElementById('silencerDesc').focus();
}

function closeNewModal(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('newModal').style.display = 'none';
}

// Close modal on Escape
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeNewModal();
});

// ── Field Builder ──
function onFieldKeyChange() {
    var keyEl = document.getElementById('fieldKey');
    var customEl = document.getElementById('customFieldKey');
    var valEl = document.getElementById('fieldValue');
    var hintEl = document.getElementById('fieldExampleHint');
    var key = keyEl.value;

    if (key === '__custom__') {
        customEl.style.display = '';
        customEl.focus();
        if (hintEl) hintEl.style.display = 'none';
        valEl.placeholder = 'Exact value (copy-paste from ticket)';
        return;
    }

    customEl.style.display = 'none';
    customEl.value = '';

    var ex = fieldExamples[key];
    if (ex && hintEl) {
        hintEl.textContent = '💡 Example ' + (fieldDefs[key] || key) + ': ' + ex;
        hintEl.style.display = '';
        valEl.placeholder = 'e.g. ' + ex;
    } else {
        if (hintEl) hintEl.style.display = 'none';
        valEl.placeholder = 'Exact value (copy-paste from ticket)';
    }
}

function addField() {
    var keyEl = document.getElementById('fieldKey');
    var customEl = document.getElementById('customFieldKey');
    var valEl = document.getElementById('fieldValue');

    var key = keyEl.value;
    if (key === '__custom__') {
        key = customEl.value.trim();
        if (!key) { showToast('Enter a custom field name', 'error'); return; }
    }

    var val = valEl.value.trim();

    if (!key) { showToast('Select a field from the dropdown', 'error'); return; }
    if (!val) { showToast('Enter a value for the field', 'error'); return; }
    if (addedFields[key]) { showToast('Field already added — remove it first to change the value', 'error'); return; }

    addedFields[key] = val;
    renderFieldsList();
    keyEl.value = '';
    customEl.style.display = 'none';
    customEl.value = '';
    valEl.value = '';
    keyEl.focus();
}

function removeField(key) {
    delete addedFields[key];
    renderFieldsList();
}

function renderFieldsList() {
    var container = document.getElementById('fieldsList');
    var keys = Object.keys(addedFields);
    if (keys.length === 0) {
        container.innerHTML = '<div class="tc-fields-empty">No fields added yet. Add at least one field above.</div>';
        return;
    }
    var html = '';
    keys.forEach(function(key) {
        var label = fieldDefs[key] || key;
        html += '<div class="tc-field-item">' +
            '<span class="tc-field-pill">' + escapeHtml(label) + ': <strong>' + escapeHtml(addedFields[key]) + '</strong></span>' +
            '<button type="button" class="tc-field-remove" onclick="removeField(\'' + escapeHtml(key) + '\')" title="Remove">&times;</button>' +
            '</div>';
    });
    container.innerHTML = html;
}

// ── Submit ──
async function submitSilencer(event) {
    event.preventDefault();

    if (Object.keys(addedFields).length === 0) {
        showToast('Add at least one filter field', 'error');
        return;
    }

    var expiryDate = document.getElementById('silencerExpiry').value;
    if (!expiryDate) {
        showToast('Pick an expiry date', 'error');
        return;
    }
    var data = {
        description: document.getElementById('silencerDesc').value.trim(),
        category: document.getElementById('silencerCat').value,
        expiry_date: expiryDate,
        fields: addedFields
    };

    var btn = document.getElementById('submitBtn');
    btn.disabled = true;
    btn.textContent = 'Creating...';

    try {
        var resp = await editFetch('/api/ticket-cannon/create', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        var result = await resp.json();
        if (result.status === 'success') {
            showToast('Entry created — reloading...');
            closeNewModal();
            setTimeout(function() { location.reload(); }, 600);
        } else if (result.error === 'login_required') {
            showToast('Please sign in to make changes', 'error');
        } else {
            showToast(result.message || 'Failed to create entry', 'error');
        }
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Create';
    }
}

// ── Toggle ──
async function toggleEntry(id, active, category) {
    try {
        var resp = await editFetch('/api/ticket-cannon/' + id + '/toggle', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({active: active, category: category})
        });
        var result = await resp.json();
        if (result.status === 'success') {
            showToast((active ? 'Activated' : 'Deactivated') + ' — reloading...');
            setTimeout(function() { location.reload(); }, 600);
        } else if (result.error === 'login_required') {
            showToast('Please sign in to make changes', 'error');
        } else {
            showToast(result.message || 'Toggle failed', 'error');
        }
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
    }
}

// ── Utility ──
function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
