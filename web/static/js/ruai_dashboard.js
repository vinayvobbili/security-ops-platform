/**
 * RUAI Dashboard — Filtering, status management, and document upload
 */
(function () {
    'use strict';

    var uploadFiles = [];

    document.addEventListener('DOMContentLoaded', function () {
        if (typeof initTheme === 'function') initTheme();
        initFilters();
        initUploadArea();
    });

    // ── Filters ─────────────────────────────────────────────────────
    function initFilters() {
        var buttons = document.querySelectorAll('#ruai-filters .ruai-filter-btn');
        buttons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                buttons.forEach(function (b) { b.classList.remove('active'); });
                btn.classList.add('active');
                applyFilter(btn.dataset.filter);
            });
        });
    }

    function applyFilter(filter) {
        var rows = document.querySelectorAll('#ruai-table-body tr');
        var withSubmitterStatuses = ['submitted', 'ai_reviewing', 'ai_reviewed'];

        rows.forEach(function (row) {
            var status = row.dataset.status;
            var show = true;

            if (filter === 'needs_review') {
                show = status === 'pending_review';
            } else if (filter === 'with_submitter') {
                show = withSubmitterStatuses.indexOf(status) !== -1;
            } else if (filter !== 'all') {
                show = status === filter;
            }

            row.style.display = show ? '' : 'none';
        });
    }

    // ── Upload Modal ────────────────────────────────────────────────
    function initUploadArea() {
        var area = document.getElementById('ruai-upload-area');
        var input = document.getElementById('ruai-file-input');
        if (!area || !input) return;

        area.addEventListener('click', function () { input.click(); });
        area.addEventListener('dragover', function (e) { e.preventDefault(); area.classList.add('dragover'); });
        area.addEventListener('dragleave', function () { area.classList.remove('dragover'); });
        area.addEventListener('drop', function (e) {
            e.preventDefault();
            area.classList.remove('dragover');
            addFiles(e.dataTransfer.files);
        });
        input.addEventListener('change', function () { addFiles(input.files); input.value = ''; });
    }

    function addFiles(fileList) {
        for (var i = 0; i < fileList.length; i++) {
            var f = fileList[i];
            if (f.size > 10 * 1024 * 1024) {
                showError('File too large (max 10 MB): ' + f.name);
                continue;
            }
            uploadFiles.push(f);
        }
        renderFileList();
        hideError();
    }

    function renderFileList() {
        var list = document.getElementById('ruai-upload-list');
        if (!list) return;
        if (uploadFiles.length === 0) { list.innerHTML = ''; return; }
        var html = '';
        uploadFiles.forEach(function (f, idx) {
            var sizeStr = f.size < 1024 ? f.size + ' B'
                : f.size < 1024 * 1024 ? (f.size / 1024).toFixed(1) + ' KB'
                : (f.size / (1024 * 1024)).toFixed(1) + ' MB';
            html += '<div class="file-item">';
            html += '<span class="remove-file" onclick="removeUploadFile(' + idx + ')">&#215;</span> ';
            html += escapeHtml(f.name) + ' (' + sizeStr + ')';
            html += '</div>';
        });
        list.innerHTML = html;
    }

    window.removeUploadFile = function (idx) {
        uploadFiles.splice(idx, 1);
        renderFileList();
    };

    window.openUploadModal = function () {
        uploadFiles = [];
        renderFileList();
        hideError();
        document.getElementById('ruai-upload-modal').classList.add('show');
    };

    window.closeUploadModal = function () {
        document.getElementById('ruai-upload-modal').classList.remove('show');
        uploadFiles = [];
        renderFileList();
    };

    window.submitUpload = function () {
        // Validate: need at least one XLSX
        var hasXlsx = uploadFiles.some(function (f) {
            return f.name.toLowerCase().endsWith('.xlsx');
        });
        if (!hasXlsx) {
            showError('Please upload the screening survey (.xlsx) file.');
            return;
        }

        var btn = document.getElementById('ruai-upload-submit');
        btn.disabled = true;
        btn.textContent = 'Creating...';
        hideError();

        var formData = new FormData();
        uploadFiles.forEach(function (f) { formData.append('documents', f); });

        fetch('/api/ruai/upload-screening', { method: 'POST', body: formData })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.status === 'success') {
                    window.location.href = '/ruai-dashboard/' + data.submission_id;
                } else {
                    showError(data.message || 'Upload failed');
                    btn.disabled = false;
                    btn.textContent = 'Create Case';
                }
            })
            .catch(function () {
                showError('Network error. Please try again.');
                btn.disabled = false;
                btn.textContent = 'Create Case';
            });
    };

    function showError(msg) {
        var el = document.getElementById('ruai-upload-error');
        if (el) { el.textContent = msg; el.style.display = 'block'; }
    }

    function hideError() {
        var el = document.getElementById('ruai-upload-error');
        if (el) { el.style.display = 'none'; }
    }

    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
})();
