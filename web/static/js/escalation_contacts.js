/* Escalation Contacts — Tab switching, inline edit, add/delete, rebuild */

// ── Tab switching ──
function switchTab(region) {
    document.querySelectorAll('.ec-tab').forEach(t => t.classList.remove('ec-tab-active'));
    document.querySelectorAll('.ec-tab-content').forEach(c => c.classList.remove('ec-tab-content-active'));
    const tab = document.querySelector(`.ec-tab[data-region="${region}"]`);
    const content = document.getElementById('tab-' + region);
    if (tab) tab.classList.add('ec-tab-active');
    if (content) content.classList.add('ec-tab-content-active');
}

// ── Toast ──
function showToast(msg, type) {
    const toast = document.getElementById('ecToast');
    toast.textContent = msg;
    toast.className = 'ec-toast ec-toast-show ec-toast-' + (type || 'success');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.classList.remove('ec-toast-show'); }, 3000);
}

// ── Count ──
function updateCount() {
    const total = document.querySelectorAll('.ec-table tbody tr[data-id]').length;
    const el = document.getElementById('contactCount');
    if (el) el.textContent = total + ' contact' + (total !== 1 ? 's' : '');
}

// ── Search / filter across all tabs ──
let _ecSearchTimer = null;

function ecNorm(s) { return (s || '').toString().toLowerCase(); }

function ecApplyFilter(rawQ) {
    const q = ecNorm(rawQ).trim();
    const wrap = document.querySelector('.ec-search-wrap');
    if (wrap) wrap.classList.toggle('has-value', q.length > 0);

    // Reset: clear prior match-count badges
    document.querySelectorAll('.ec-tab-match-count').forEach(el => el.remove());

    let totalMatches = 0;

    document.querySelectorAll('.ec-tab-content').forEach(tabEl => {
        const region = tabEl.id.replace(/^tab-/, '');
        let tabMatches = 0;

        tabEl.querySelectorAll('.ec-team-section').forEach(section => {
            const header = section.querySelector('.ec-team-header');
            const headerText = ecNorm(header ? header.textContent : '');
            const headerHit = q && headerText.includes(q);

            const rows = section.querySelectorAll('.ec-table tbody tr, .ec-doc-block p');
            let sectionHits = 0;

            rows.forEach(row => {
                if (!q) { row.style.display = ''; return; }
                const hit = headerHit || ecNorm(row.textContent).includes(q);
                row.style.display = hit ? '' : 'none';
                if (hit) sectionHits++;
            });

            // Hide a whole section if nothing matches (keep all sections when query is empty)
            section.style.display = (!q || sectionHits > 0 || headerHit) ? '' : 'none';
            tabMatches += sectionHits || (headerHit ? 1 : 0);
        });

        // Append tab badge only during active search
        if (q) {
            const tabBtn = document.querySelector(`.ec-tab[data-region="${region}"]`);
            if (tabBtn) {
                const badge = document.createElement('span');
                badge.className = 'ec-tab-match-count' + (tabMatches === 0 ? ' is-zero' : '');
                badge.textContent = tabMatches;
                tabBtn.appendChild(badge);
            }
        }

        totalMatches += tabMatches;
    });

    // Count label + no-results banner
    const countEl = document.getElementById('contactCount');
    const noRes = document.getElementById('ecNoResults');
    const noResQ = document.getElementById('ecNoResultsQuery');
    if (!q) {
        if (noRes) noRes.style.display = 'none';
        updateCount();
    } else {
        if (countEl) countEl.textContent = totalMatches + ' match' + (totalMatches !== 1 ? 'es' : '');
        if (noRes) noRes.style.display = (totalMatches === 0) ? 'block' : 'none';
        if (noResQ) noResQ.textContent = '"' + rawQ.trim() + '"';
    }

    // If current active tab has zero matches but another tab has hits, jump there
    if (q && totalMatches > 0) {
        const active = document.querySelector('.ec-tab-active');
        const activeBadge = active ? active.querySelector('.ec-tab-match-count') : null;
        const activeHits = activeBadge ? parseInt(activeBadge.textContent, 10) : 0;
        if (activeHits === 0) {
            const firstHit = Array.from(document.querySelectorAll('.ec-tab')).find(t => {
                const b = t.querySelector('.ec-tab-match-count');
                return b && !b.classList.contains('is-zero');
            });
            if (firstHit) {
                const region = firstHit.getAttribute('data-region');
                if (region) switchTab(region);
            }
        }
    }
}

function ecClearSearch() {
    const input = document.getElementById('ecSearchInput');
    if (input) input.value = '';
    ecApplyFilter('');
    if (input) input.focus();
}

document.addEventListener('DOMContentLoaded', function() {
    const input = document.getElementById('ecSearchInput');
    const clear = document.getElementById('ecSearchClear');
    if (input) {
        input.addEventListener('input', e => {
            clearTimeout(_ecSearchTimer);
            const val = e.target.value;
            _ecSearchTimer = setTimeout(() => ecApplyFilter(val), 80);
        });
        input.addEventListener('keydown', e => {
            if (e.key === 'Escape') { e.preventDefault(); ecClearSearch(); }
        });
    }
    if (clear) clear.addEventListener('click', ecClearSearch);

    // "/" anywhere on the page focuses search (unless already typing)
    document.addEventListener('keydown', e => {
        if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
        const tag = (document.activeElement && document.activeElement.tagName) || '';
        if (['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) return;
        if (document.activeElement && document.activeElement.isContentEditable) return;
        e.preventDefault();
        if (input) { input.focus(); input.select(); }
    });
});

// ── Inline Edit ──
let editingId = null;

function startEdit(id) {
    if (editingId !== null) cancelEdit();
    editingId = id;
    const row = document.getElementById('row-' + id);
    if (!row) return;

    ['name', 'title', 'email', 'phone', 'comments'].forEach(field => {
        const td = row.querySelector(`td[data-field="${field}"]`);
        if (!td) return;
        const current = field === 'email'
            ? (td.querySelector('a') ? td.querySelector('a').textContent : td.textContent.trim())
            : td.textContent.trim();
        td.setAttribute('data-original', current);
        if (field === 'comments') {
            td.innerHTML = `<textarea class="ec-inline-input ec-inline-textarea" rows="2" data-field="${field}">${escapeHtml(current)}</textarea>`;
        } else {
            td.innerHTML = `<input class="ec-inline-input" type="text" value="${escapeHtml(current)}" data-field="${field}">`;
        }
    });

    const actTd = row.querySelector('.ec-actions');
    actTd.setAttribute('data-original', actTd.innerHTML);
    actTd.innerHTML = `<div class="ec-edit-actions"><button class="ec-btn-save" onclick="saveEdit(${id})">Save</button><button class="ec-btn-cancel-edit" onclick="cancelEdit()">Cancel</button></div>`;

    // Focus the name input
    const nameInput = row.querySelector('input[data-field="name"]');
    if (nameInput) nameInput.focus();
}

function cancelEdit() {
    if (editingId === null) return;
    const row = document.getElementById('row-' + editingId);
    if (!row) { editingId = null; return; }

    ['name', 'title', 'email', 'phone', 'comments'].forEach(field => {
        const td = row.querySelector(`td[data-field="${field}"]`);
        if (!td) return;
        const orig = td.getAttribute('data-original') || '';
        if (field === 'email' && orig) {
            td.innerHTML = `<a href="mailto:${escapeHtml(orig)}" class="ec-email-link">${escapeHtml(orig)}</a>`;
        } else {
            td.textContent = orig;
        }
    });

    const actTd = row.querySelector('.ec-actions');
    const origAct = actTd.getAttribute('data-original');
    if (origAct) actTd.innerHTML = origAct;
    editingId = null;
}

async function saveEdit(id) {
    const row = document.getElementById('row-' + id);
    if (!row) return;
    const data = {};
    ['name', 'title', 'email', 'phone', 'comments'].forEach(field => {
        const input = row.querySelector(`input[data-field="${field}"], textarea[data-field="${field}"]`);
        if (input) data[field] = input.value.trim();
    });
    if (!data.name) { showToast('Name is required', 'error'); return; }

    try {
        const resp = await editFetch(`/api/escalation-contacts/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            const c = result.contact;
            ['name', 'title', 'email', 'phone', 'comments'].forEach(field => {
                const td = row.querySelector(`td[data-field="${field}"]`);
                if (!td) return;
                const val = c[field] || '';
                if (field === 'email' && val) {
                    td.innerHTML = `<a href="mailto:${escapeHtml(val)}" class="ec-email-link">${escapeHtml(val)}</a>`;
                } else {
                    td.textContent = val;
                }
            });
            const actTd = row.querySelector('.ec-actions');
            actTd.innerHTML = `<button class="ec-btn-icon ec-btn-edit" onclick="startEdit(${id})" title="Edit">&#9998;</button><button class="ec-btn-icon ec-btn-delete" onclick="deleteContact(${id})" title="Delete">&times;</button>`;
            editingId = null;
            showToast('Contact updated');
            ecShowSyncBanner();
            ecStartPolling();
        } else {
            showToast(result.error || 'Update failed', 'error');
        }
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
    }
}

// ── Delete ──
async function deleteContact(id) {
    if (!confirm('Delete this contact?')) return;
    try {
        const resp = await editFetch(`/api/escalation-contacts/${id}`, { method: 'DELETE', headers: {'Content-Type': 'application/json'} });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            const row = document.getElementById('row-' + id);
            if (row) row.remove();
            updateCount();
            showToast('Contact deleted');
            ecShowSyncBanner();
            ecStartPolling();
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
    document.getElementById('addContactForm').reset();
    document.getElementById('addRegionCustom').style.display = 'none';
    // Default to the active tab's region
    const activeTab = document.querySelector('.ec-tab-active');
    if (activeTab) {
        const region = activeTab.getAttribute('data-region');
        const sel = document.getElementById('addRegion');
        if (sel) sel.value = region;
    }
}

function closeAddModal(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('addModal').style.display = 'none';
}

// Toggle custom region input
document.addEventListener('DOMContentLoaded', function() {
    const sel = document.getElementById('addRegion');
    if (sel) {
        sel.addEventListener('change', function() {
            const custom = document.getElementById('addRegionCustom');
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

async function submitAddContact(event) {
    event.preventDefault();
    const regionSel = document.getElementById('addRegion');
    let region = regionSel.value;
    if (region === '__new__') {
        region = document.getElementById('addRegionCustom').value.trim();
        if (!region) { showToast('Enter a region name', 'error'); return; }
    }
    const data = {
        region: region,
        team: document.getElementById('addTeam').value.trim(),
        name: document.getElementById('addName').value.trim(),
        title: document.getElementById('addTitle').value.trim(),
        email: document.getElementById('addEmail').value.trim(),
        phone: document.getElementById('addPhone').value.trim(),
        comments: document.getElementById('addComments').value.trim(),
    };
    if (!data.team || !data.name) { showToast('Region, team, and name are required', 'error'); return; }

    try {
        const resp = await editFetch('/api/escalation-contacts', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            showToast('Contact added — reloading...');
            closeAddModal();
            setTimeout(() => location.reload(), 600);
        } else {
            showToast(result.error || 'Add failed', 'error');
        }
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
    }
}

// ── Embedding Rebuild Banner ──
let _ecPollTimer = null;

function ecShowSyncBanner() {
    const b = document.getElementById('ecSyncBanner');
    if (b) b.classList.add('visible');
}

function ecHideSyncBanner() {
    const b = document.getElementById('ecSyncBanner');
    if (b) b.classList.remove('visible');
    if (_ecPollTimer) { clearInterval(_ecPollTimer); _ecPollTimer = null; }
}

function ecStartPolling() {
    if (_ecPollTimer) return;
    _ecPollTimer = setInterval(() => {
        fetch('/api/escalation-contacts/status')
            .then(r => r.json())
            .then(data => { if (!data.running) ecHideSyncBanner(); })
            .catch(() => ecHideSyncBanner());
    }, 3000);
}

// ── Utility ──
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
