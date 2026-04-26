/* Favorite URLs — Tab switching, inline edit, add/delete */

// ── Tab switching ──
function switchTab(category) {
    document.querySelectorAll('.fu-tab').forEach(t => t.classList.remove('fu-tab-active'));
    document.querySelectorAll('.fu-tab-content').forEach(c => c.classList.remove('fu-tab-content-active'));
    const tab = document.querySelector(`.fu-tab[data-category="${category}"]`);
    const content = document.getElementById('tab-' + category);
    if (tab) tab.classList.add('fu-tab-active');
    if (content) content.classList.add('fu-tab-content-active');
}

// ── Toast ──
function showToast(msg, type) {
    const toast = document.getElementById('fuToast');
    toast.textContent = msg;
    toast.className = 'fu-toast fu-toast-show fu-toast-' + (type || 'success');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.classList.remove('fu-toast-show'); }, 3000);
}

// ── Count ──
function updateCount() {
    const total = document.querySelectorAll('.fu-table tbody tr[data-id]').length;
    const el = document.getElementById('urlCount');
    if (el) el.textContent = total + ' item' + (total !== 1 ? 's' : '');
}

// ── Inline Edit ──
let editingId = null;

function startEdit(id, itemType) {
    if (editingId !== null) cancelEdit();
    editingId = id;
    const row = document.getElementById('row-' + id);
    if (!row) return;

    // Name field
    const nameTd = row.querySelector('td[data-field="name"]');
    const nameVal = nameTd.textContent.trim();
    nameTd.setAttribute('data-original', nameVal);
    nameTd.innerHTML = `<input class="fu-inline-input" type="text" value="${escapeHtml(nameVal)}" data-field="name">`;

    // Value field (url or phone)
    const valTd = row.querySelector('td[data-field="value"]');
    const linkEl = valTd.querySelector('a');
    const phoneEl = valTd.querySelector('.fu-phone');
    let currentVal = '';
    let currentType = itemType || 'url';
    if (linkEl) {
        currentVal = linkEl.getAttribute('href') || linkEl.textContent.trim();
        currentType = 'url';
    } else if (phoneEl) {
        currentVal = phoneEl.textContent.trim();
        currentType = 'phone';
    }
    valTd.setAttribute('data-original-val', currentVal);
    valTd.setAttribute('data-original-type', currentType);
    valTd.innerHTML = `<input class="fu-inline-input" type="text" value="${escapeHtml(currentVal)}" data-field="value">`;

    // Actions
    const actTd = row.querySelector('.fu-actions');
    actTd.setAttribute('data-original', actTd.innerHTML);
    actTd.innerHTML = `<div class="fu-edit-actions"><button class="fu-btn-save" onclick="saveEdit(${id})">Save</button><button class="fu-btn-cancel-edit" onclick="cancelEdit()">Cancel</button></div>`;

    const nameInput = row.querySelector('input[data-field="name"]');
    if (nameInput) nameInput.focus();
}

function cancelEdit() {
    if (editingId === null) return;
    const row = document.getElementById('row-' + editingId);
    if (!row) { editingId = null; return; }

    // Restore name
    const nameTd = row.querySelector('td[data-field="name"]');
    nameTd.textContent = nameTd.getAttribute('data-original') || '';

    // Restore value
    const valTd = row.querySelector('td[data-field="value"]');
    const origVal = valTd.getAttribute('data-original-val') || '';
    const origType = valTd.getAttribute('data-original-type') || 'url';
    if (origType === 'url' && origVal) {
        valTd.innerHTML = `<a href="${escapeHtml(origVal)}" target="_blank" rel="noopener" class="fu-url-link">${escapeHtml(origVal)}</a>`;
    } else if (origVal) {
        valTd.innerHTML = `<span class="fu-phone">${escapeHtml(origVal)}</span>`;
    } else {
        valTd.textContent = '';
    }

    // Restore actions
    const actTd = row.querySelector('.fu-actions');
    const origAct = actTd.getAttribute('data-original');
    if (origAct) actTd.innerHTML = origAct;
    editingId = null;
}

async function saveEdit(id) {
    const row = document.getElementById('row-' + id);
    if (!row) return;

    const nameInput = row.querySelector('input[data-field="name"]');
    const valInput = row.querySelector('input[data-field="value"]');
    const name = nameInput ? nameInput.value.trim() : '';
    const value = valInput ? valInput.value.trim() : '';

    if (!name) { showToast('Name is required', 'error'); return; }
    if (!value) { showToast('URL or phone number is required', 'error'); return; }

    // Determine type: if it looks like a URL, treat as URL
    const isUrl = value.startsWith('http://') || value.startsWith('https://') || value.includes('.');
    const data = { name: name };
    if (isUrl) {
        data.url = value;
        data.phone_number = '';
    } else {
        data.phone_number = value;
        data.url = '';
    }

    try {
        const resp = await editFetch(`/api/favorite-urls/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            const item = result.item;
            // Update name
            const nameTd = row.querySelector('td[data-field="name"]');
            nameTd.textContent = item.name || '';
            // Update value
            const valTd = row.querySelector('td[data-field="value"]');
            if (item.url) {
                valTd.innerHTML = `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener" class="fu-url-link">${escapeHtml(item.url)}</a>`;
            } else if (item.phone_number) {
                valTd.innerHTML = `<span class="fu-phone">${escapeHtml(item.phone_number)}</span>`;
            } else {
                valTd.textContent = '';
            }
            // Restore actions
            const actTd = row.querySelector('.fu-actions');
            const itemType = item.url ? 'url' : 'phone';
            actTd.innerHTML = `<button class="fu-btn-icon fu-btn-edit" onclick="startEdit(${id}, '${itemType}')" title="Edit">&#9998;</button><button class="fu-btn-icon fu-btn-delete" onclick="deleteUrl(${id})" title="Delete">&times;</button>`;
            editingId = null;
            showToast('Item updated');
        } else {
            showToast(result.error || 'Update failed', 'error');
        }
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
    }
}

// ── Delete ──
async function deleteUrl(id) {
    if (!confirm('Delete this item?')) return;
    try {
        const resp = await editFetch(`/api/favorite-urls/${id}`, { method: 'DELETE', headers: {'Content-Type': 'application/json'} });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            const row = document.getElementById('row-' + id);
            if (row) row.remove();
            updateCount();
            showToast('Item deleted');
        } else {
            showToast(result.error || 'Delete failed', 'error');
        }
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
    }
}

// ── Add Modal ──
function openAddModal() {
    document.getElementById('addModal').style.display = 'flex';
    document.getElementById('addUrlForm').reset();
    document.getElementById('addCategoryCustom').style.display = 'none';
    updateValueLabel();
    // Default to the active tab's category
    const activeTab = document.querySelector('.fu-tab-active');
    if (activeTab) {
        const category = activeTab.getAttribute('data-category');
        const sel = document.getElementById('addCategory');
        if (sel) {
            for (const opt of sel.options) {
                if (opt.value === category) { sel.value = category; break; }
            }
        }
    }
}

function closeAddModal(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('addModal').style.display = 'none';
}

function updateValueLabel() {
    const type = document.getElementById('addType').value;
    const label = document.getElementById('addValueLabel');
    const input = document.getElementById('addValue');
    if (type === 'phone') {
        label.innerHTML = 'Phone Number <span class="fu-required">*</span>';
        input.placeholder = '+1 555-0123';
    } else {
        label.innerHTML = 'URL <span class="fu-required">*</span>';
        input.placeholder = 'https://...';
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Type toggle
    const typeSel = document.getElementById('addType');
    if (typeSel) typeSel.addEventListener('change', updateValueLabel);

    // Category custom input toggle
    const catSel = document.getElementById('addCategory');
    if (catSel) {
        catSel.addEventListener('change', function() {
            const custom = document.getElementById('addCategoryCustom');
            if (this.value === '__new__') {
                custom.style.display = 'block';
                custom.required = true;
                custom.focus();
            } else {
                custom.style.display = 'none';
                custom.required = false;
            }
        });
    }
});

async function submitAddUrl(event) {
    event.preventDefault();
    const catSel = document.getElementById('addCategory');
    let category = catSel.value;
    if (category === '__new__') {
        category = document.getElementById('addCategoryCustom').value.trim();
        if (!category) { showToast('Enter a category name', 'error'); return; }
    }

    const type = document.getElementById('addType').value;
    const value = document.getElementById('addValue').value.trim();
    if (!value) { showToast('Value is required', 'error'); return; }

    const data = {
        name: document.getElementById('addName').value.trim(),
        category: category,
    };
    if (type === 'url') {
        data.url = value;
    } else {
        data.phone_number = value;
    }

    try {
        const resp = await editFetch('/api/favorite-urls', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            showToast('Item added — reloading...');
            closeAddModal();
            setTimeout(() => location.reload(), 600);
        } else {
            showToast(result.error || 'Add failed', 'error');
        }
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
    }
}

// ── Utility ──
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
