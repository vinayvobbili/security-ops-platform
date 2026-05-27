/* Docs Library — upload, delete, rebuild vector store */

// ── Toast ──
function dlToast(msg, type) {
    const t = document.getElementById('dlToast');
    t.textContent = msg;
    t.className = 'dl-toast show ' + (type || 'success');
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.classList.remove('show'), 3500);
}

// ── Sync Banner ──
let _pollTimer = null;

function showSyncBanner(msg) {
    const b = document.getElementById('dlSyncBanner');
    const txt = document.getElementById('dlSyncMsg');
    if (txt) txt.textContent = msg || 'Rebuilding vector store…';
    if (b) b.classList.add('visible');
}

function hideSyncBanner() {
    const b = document.getElementById('dlSyncBanner');
    if (b) b.classList.remove('visible');
}

function startPolling() {
    if (_pollTimer) return;
    _pollTimer = setInterval(pollStatus, 3000);
}

function stopPolling() {
    if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
}

function pollStatus() {
    fetch('/api/docs-library/status')
        .then(r => r.json())
        .then(data => {
            if (data.running) {
                showSyncBanner();
                updateChunkCount(data.chroma);
            } else {
                stopPolling();
                hideSyncBanner();
                updateChunkCount(data.chroma);
                if (data.last_result) {
                    if (data.last_result.success) {
                        const newChunks = data.last_result.new_chunks;
                        const after = data.last_result.chunks_after;
                        if (newChunks !== undefined) {
                            dlToast(`Sync complete — ${newChunks} new chunks added (${after} total)`, 'success');
                        } else if (after !== undefined) {
                            dlToast(`Rebuild complete — ${after} chunks indexed`, 'success');
                        }
                    } else {
                        dlToast('Vector store update failed: ' + (data.last_result.error || 'unknown error'), 'error');
                    }
                }
            }
        })
        .catch(() => { stopPolling(); hideSyncBanner(); });
}

function updateChunkCount(chroma) {
    if (!chroma) return;
    const el = document.getElementById('dlChunkCount');
    if (el) el.textContent = chroma.total_chunks.toLocaleString();
    const badge = document.getElementById('dlStatusBadge');
    if (badge) {
        badge.className = 'dl-status-badge ' + (chroma.status || 'empty');
        const labels = { initialized: '✓ Indexed', empty: '○ Empty', error: '✕ Error', syncing: '⟳ Syncing' };
        badge.textContent = labels[chroma.status] || chroma.status;
    }
}

// ── Column Sorting (persisted in localStorage) ──
const DL_SORT_KEY = 'dlSortPref';

function getSortPref() {
    try {
        const p = JSON.parse(localStorage.getItem(DL_SORT_KEY) || 'null');
        if (p && ['name', 'size', 'mtime'].includes(p.key) && (p.dir === 'asc' || p.dir === 'desc')) {
            return p;
        }
    } catch (e) { /* ignore corrupt value */ }
    return null;
}

function saveSortPref(key, dir) {
    try { localStorage.setItem(DL_SORT_KEY, JSON.stringify({ key, dir })); } catch (e) {}
}

function rowSortValue(tr, key) {
    if (key === 'size')  return parseFloat(tr.getAttribute('data-bytes')) || 0;
    if (key === 'mtime') return parseFloat(tr.getAttribute('data-mtime')) || 0;
    return (tr.getAttribute('data-filename') || '').toLowerCase(); // name
}

function updateSortIndicators(key, dir) {
    document.querySelectorAll('.dl-table th.dl-sortable').forEach(th => {
        const active = th.getAttribute('data-sort-key') === key;
        const ind = th.querySelector('.dl-sort-ind');
        th.classList.toggle('dl-sorted', active);
        th.setAttribute('aria-sort', active ? (dir === 'desc' ? 'descending' : 'ascending') : 'none');
        if (ind) ind.textContent = active ? (dir === 'desc' ? '▼' : '▲') : '↕';
    });
}

// Reorder the table body by `key`/`dir`. Pass persist=true to remember the choice.
function applySort(key, dir, persist) {
    updateSortIndicators(key, dir);
    if (persist) saveSortPref(key, dir);

    const tbody = document.getElementById('dlTbody');
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('tr[data-filename]'));
    if (rows.length < 2) return;

    const numeric = (key === 'size' || key === 'mtime');
    const mult = (dir === 'desc') ? -1 : 1;
    rows.sort((a, b) => {
        const va = rowSortValue(a, key), vb = rowSortValue(b, key);
        const cmp = numeric ? (va - vb)
                            : va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' });
        return cmp * mult;
    });
    rows.forEach(r => tbody.appendChild(r)); // appendChild moves existing nodes in order
}

// Re-apply the current sort (used after rows are added dynamically)
function reapplySort() {
    const pref = getSortPref();
    if (pref) applySort(pref.key, pref.dir, false);
}

function setupSorting() {
    const ths = document.querySelectorAll('.dl-table th.dl-sortable');
    if (!ths.length) return;
    ths.forEach(th => {
        th.addEventListener('click', () => {
            const key = th.getAttribute('data-sort-key');
            const cur = getSortPref();
            let dir;
            if (cur && cur.key === key) {
                dir = (cur.dir === 'asc') ? 'desc' : 'asc'; // toggle on repeat click
            } else {
                dir = (key === 'name') ? 'asc' : 'desc';     // names A→Z, size/date biggest/newest first
            }
            applySort(key, dir, true);
        });
    });
    reapplySort(); // honour saved preference on load
}

// ── Upload Modal ──
let _selectedFile = null;

function openUploadModal() {
    _selectedFile = null;
    document.getElementById('dlUploadModal').style.display = 'flex';
    document.getElementById('dlFilePreview').classList.remove('visible');
    document.getElementById('dlDropZone').style.display = '';
    document.getElementById('dlConfirmBtn').disabled = true;
    document.getElementById('dlFileInput').value = '';
}

function closeUploadModal(evt) {
    if (evt && evt.target !== evt.currentTarget) return;
    document.getElementById('dlUploadModal').style.display = 'none';
    _selectedFile = null;
}

function fileTypeIcon(name) {
    const ext = (name.split('.').pop() || '').toLowerCase();
    if (ext === 'pdf') return '📄';
    if (ext === 'docx' || ext === 'doc') return '📝';
    if (ext === 'xlsx' || ext === 'xls') return '📊';
    return '📁';
}

function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function previewFile(file) {
    _selectedFile = file;
    const preview = document.getElementById('dlFilePreview');
    document.getElementById('dlPreviewIcon').textContent = fileTypeIcon(file.name);
    document.getElementById('dlPreviewName').textContent = file.name;
    document.getElementById('dlPreviewSize').textContent = fmtSize(file.size);
    preview.classList.add('visible');
    document.getElementById('dlDropZone').style.display = 'none';
    document.getElementById('dlConfirmBtn').disabled = false;
}

function clearFileSelection() {
    _selectedFile = null;
    document.getElementById('dlFilePreview').classList.remove('visible');
    document.getElementById('dlDropZone').style.display = '';
    document.getElementById('dlConfirmBtn').disabled = true;
    document.getElementById('dlFileInput').value = '';
}

// ── Drag-and-Drop ──
function setupDropZone() {
    const zone = document.getElementById('dlDropZone');
    if (!zone) return;

    zone.addEventListener('click', () => document.getElementById('dlFileInput').click());

    zone.addEventListener('dragover', e => {
        e.preventDefault();
        zone.classList.add('drag-over');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) previewFile(file);
    });

    document.getElementById('dlFileInput').addEventListener('change', e => {
        const file = e.target.files[0];
        if (file) previewFile(file);
    });
}

// ── Upload Submit ──
async function submitUpload() {
    if (!_selectedFile) return;

    // Check for an existing doc with the same name
    const escapedName = _selectedFile.name.replace(/"/g, '\\"');
    const existingRow = document.querySelector(`#dlTbody tr[data-filename="${escapedName}"]`);
    if (existingRow) {
        if (!confirm(`"${_selectedFile.name}" already exists.\n\nOverwrite it?`)) return;
    }

    const btn = document.getElementById('dlConfirmBtn');
    btn.disabled = true;
    btn.textContent = 'Uploading…';

    const formData = new FormData();
    formData.append('file', _selectedFile);

    try {
        const resp = await editFetch('/api/docs-library/upload', { method: 'POST', body: formData });
        if (!resp) { btn.disabled = false; btn.textContent = 'Upload & Rebuild Vector Store'; return; }
        const result = await resp.json();
        if (result.success) {
            closeUploadModal();
            addDocRow(result.doc);
            updateDocCount();
            dlToast('Uploaded! Rebuilding vector store in background…', 'info');
            showSyncBanner();
            startPolling();
        } else {
            dlToast(result.error || 'Upload failed', 'error');
            btn.disabled = false;
            btn.textContent = 'Upload & Rebuild Vector Store';
        }
    } catch (e) {
        dlToast('Network error: ' + e.message, 'error');
        btn.disabled = false;
        btn.textContent = 'Upload & Rebuild Vector Store';
    }
}

function addDocRow(doc) {
    const tbody = document.getElementById('dlTbody');
    if (!tbody) return;

    // Remove empty-state row if present
    const emptyRow = document.getElementById('dlEmptyRow');
    if (emptyRow) emptyRow.remove();

    const icon = fileTypeIcon(doc.filename);
    const tr = document.createElement('tr');
    tr.setAttribute('data-filename', escapeAttr(doc.filename));
    tr.setAttribute('data-bytes', doc.size != null ? doc.size : 0);
    tr.setAttribute('data-mtime', Math.floor(Date.now() / 1000));
    tr.innerHTML = `
        <td class="dl-type-icon">${icon}</td>
        <td class="dl-filename">${escapeHtml(doc.filename)}</td>
        <td class="dl-size">${escapeHtml(doc.size_str)}</td>
        <td class="dl-modified">just now</td>
        <td class="dl-td-actions">
            <a class="dl-btn-icon dl-btn-download" href="/api/docs-library/download/${encodeURIComponent(doc.filename)}" download="${escapeAttr(doc.filename)}" title="Download">&#11015;</a>
            <button class="dl-btn-icon dl-btn-delete" onclick="deleteDoc('${escapeAttr(doc.filename)}')" title="Delete">&#128465;</button>
        </td>`;
    tbody.appendChild(tr);
    reapplySort(); // keep the new row in the user's chosen order
}

function updateDocCount() {
    const rows = document.querySelectorAll('#dlTbody tr[data-filename]').length;
    const el = document.getElementById('dlDocCount');
    if (el) el.textContent = rows;
}

// ── Delete ──
async function deleteDoc(filename) {
    if (!confirm(`Delete "${filename}"?\n\nThe file will be removed but the vector store will NOT be automatically updated. Run a sync or full rebuild afterwards.`)) return;
    try {
        const resp = await editFetch('/api/docs-library/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            const row = document.querySelector(`tr[data-filename="${escapeAttr(filename)}"]`);
            if (row) row.remove();
            updateDocCount();
            dlToast(`"${filename}" deleted`, 'success');
        } else {
            dlToast(result.error || 'Delete failed', 'error');
        }
    } catch (e) {
        dlToast('Network error: ' + e.message, 'error');
    }
}

// ── Full Rebuild ──
async function triggerRebuild() {
    if (!confirm('Full rebuild will delete the existing vector store and re-index all documents from scratch.\n\nThis may take several minutes. Continue?')) return;
    try {
        const resp = await editFetch('/api/docs-library/rebuild', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        if (!resp) return;
        const result = await resp.json();
        if (result.success) {
            dlToast('Full rebuild started…', 'info');
            showSyncBanner('Full rebuild in progress…');
            startPolling();
        } else {
            dlToast(result.error || 'Rebuild failed to start', 'error');
        }
    } catch (e) {
        dlToast('Network error: ' + e.message, 'error');
    }
}

// ── Utility ──
function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
}

function escapeAttr(str) {
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Init ──
document.addEventListener('DOMContentLoaded', function () {
    if (typeof initTheme === 'function') initTheme();
    setupDropZone();
    setupSorting();
    updateDocCount();
    // Poll immediately to pick up any in-progress sync from a previous upload
    fetch('/api/docs-library/status')
        .then(r => r.json())
        .then(data => {
            updateChunkCount(data.chroma);
            if (data.running) { showSyncBanner(); startPolling(); }
        })
        .catch(() => {});
});
