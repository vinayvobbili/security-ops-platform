/**
 * RUAI Screening Form — Rules Engine, Step Navigation, AJAX Submit
 *
 * Fetches form config from /api/ruai/form-config and dynamically renders
 * sections as wizard steps with depends_on branching logic.
 */
(function () {
    'use strict';

    const DRAFT_KEY = 'ruai_screening_draft';
    let formConfig = [];
    let currentStep = 0;
    let allAnswers = {};
    let uploadedFiles = [];

    // ── Bootstrap ────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', async function () {
        if (typeof initTheme === 'function') initTheme();

        try {
            const resp = await fetch('/api/ruai/form-config');
            formConfig = await resp.json();
        } catch (err) {
            document.getElementById('ruai-form-body').innerHTML =
                '<p style="color:#dc2626">Failed to load form configuration.</p>';
            return;
        }

        loadDraft();
        renderForm();
        updateProgress();
        showStep(0);
    });

    // ── Rules engine ─────────────────────────────────────────────────
    function shouldShow(item) {
        if (item.always_show) return true;
        if (!item.depends_on) return true;
        return Object.entries(item.depends_on).every(function (entry) {
            var field = entry[0], expected = entry[1];
            return allAnswers[field] === expected;
        });
    }

    function getVisibleSections() {
        return formConfig.filter(function (s) { return shouldShow(s); });
    }

    // ── Render ───────────────────────────────────────────────────────
    function renderForm() {
        var body = document.getElementById('ruai-form-body');
        body.innerHTML = '';

        var visible = getVisibleSections();
        visible.forEach(function (section, idx) {
            var div = document.createElement('div');
            div.className = 'ruai-section';
            div.dataset.sectionId = section.id;
            div.dataset.stepIndex = idx;

            var title = '<div class="ruai-section-title">' + escapeHtml(section.title) + '</div>';
            title += '<div class="ruai-section-count">Step ' + (idx + 1) + ' of ' + visible.length + '</div>';

            var fieldsHtml = '';
            section.fields.forEach(function (field) {
                fieldsHtml += renderField(field);
            });

            // Nav buttons
            var nav = '<div class="ruai-nav-buttons">';
            nav += idx > 0
                ? '<button type="button" class="ruai-btn ruai-btn-secondary" onclick="ruaiPrev()">Previous</button>'
                : '<button type="button" class="ruai-btn ruai-btn-ghost" onclick="ruaiSaveDraft()">Save Draft</button>';

            if (idx < visible.length - 1) {
                nav += '<button type="button" class="ruai-btn ruai-btn-primary" onclick="ruaiNext()">Next</button>';
            } else {
                nav += '<button type="button" class="ruai-btn ruai-btn-success" onclick="ruaiSubmit()">Submit Screening</button>';
            }
            nav += '</div>';

            // Add file upload area to the last section
            var uploadHtml = '';
            if (idx === visible.length - 1) {
                uploadHtml = '<div class="ruai-field" style="margin-top:24px;">' +
                    '<label>Supporting Documents</label>' +
                    '<p style="font-size:0.85rem;color:#64748b;margin:0 0 8px;">Upload architecture diagrams, DFDs, PRA documents, or other supporting materials (max 10MB each).</p>' +
                    '<div id="ruai-upload-area" class="ruai-upload-area">Click or drag files here to upload</div>' +
                    '<input type="file" id="ruai-file-input" multiple style="display:none">' +
                    '<div id="ruai-upload-list" class="ruai-upload-list"></div>' +
                    '</div>';
            }

            div.innerHTML = title + fieldsHtml + uploadHtml + nav;
            body.appendChild(div);
        });

        // Bind input events for branching
        body.querySelectorAll('input, select, textarea').forEach(function (el) {
            el.addEventListener('change', onFieldChange);
            el.addEventListener('input', onFieldChange);
        });

        // Restore answers
        restoreAnswers();

        // Initialize file upload drag-and-drop
        if (document.getElementById('ruai-upload-area')) {
            window.ruaiInitUpload();
            renderFileList();
        }
    }

    function renderField(field) {
        var hidden = field.depends_on && !shouldShow(field) ? ' hidden' : '';
        var depAttr = field.depends_on ? " data-depends='" + JSON.stringify(field.depends_on) + "'" : '';
        var req = field.required ? '<span class="required">*</span>' : '';
        var ph = field.placeholder ? ' placeholder="' + escapeHtml(field.placeholder) + '"' : '';

        var html = '<div class="ruai-field' + hidden + '" data-field="' + field.name + '"' + depAttr + '>';
        html += '<label>' + escapeHtml(field.label) + req + '</label>';

        switch (field.type) {
            case 'text':
            case 'email':
                html += '<input type="' + field.type + '" name="' + field.name + '"' + ph +
                    (field.required ? ' required' : '') + '>';
                break;

            case 'textarea':
                html += '<textarea name="' + field.name + '"' + ph +
                    (field.required ? ' required' : '') + '></textarea>';
                break;

            case 'select':
                html += '<select name="' + field.name + '"' + (field.required ? ' required' : '') + '>';
                html += '<option value="">-- Select --</option>';
                (field.options || []).forEach(function (opt) {
                    html += '<option value="' + escapeHtml(opt) + '">' + escapeHtml(opt) + '</option>';
                });
                html += '</select>';
                break;

            case 'yesno':
                html += '<div class="ruai-yesno">';
                html += '<label><input type="radio" name="' + field.name + '" value="yes"' +
                    (field.required ? ' required' : '') + '> Yes</label>';
                html += '<label><input type="radio" name="' + field.name + '" value="no"' +
                    (field.required ? ' required' : '') + '> No</label>';
                html += '</div>';
                break;

            case 'checklist':
                html += '<div class="ruai-checklist">';
                (field.options || []).forEach(function (opt) {
                    html += '<label><input type="checkbox" name="' + field.name + '" value="' +
                        escapeHtml(opt) + '"> ' + escapeHtml(opt) + '</label>';
                });
                html += '</div>';
                break;

            default:
                html += '<input type="text" name="' + field.name + '"' + ph + '>';
        }

        html += '</div>';
        return html;
    }

    // ── Field change handler (branching) ─────────────────────────────
    function onFieldChange(e) {
        collectAnswers();
        updateFieldVisibility();
        saveDraft();
    }

    function collectAnswers() {
        allAnswers = {};
        document.querySelectorAll('#ruai-form-body input, #ruai-form-body select, #ruai-form-body textarea').forEach(function (el) {
            if (el.type === 'checkbox') {
                if (!allAnswers[el.name]) allAnswers[el.name] = [];
                if (el.checked) allAnswers[el.name].push(el.value);
            } else if (el.type === 'radio') {
                if (el.checked) allAnswers[el.name] = el.value;
            } else {
                if (el.value) allAnswers[el.name] = el.value;
            }
        });
    }

    function updateFieldVisibility() {
        // Update field-level visibility
        document.querySelectorAll('#ruai-form-body .ruai-field[data-depends]').forEach(function (el) {
            var deps = JSON.parse(el.dataset.depends);
            var show = Object.entries(deps).every(function (entry) {
                return allAnswers[entry[0]] === entry[1];
            });
            el.classList.toggle('hidden', !show);
        });

        // Re-render if section visibility changed
        var oldVisible = document.querySelectorAll('#ruai-form-body .ruai-section').length;
        var newVisible = getVisibleSections().length;
        if (oldVisible !== newVisible) {
            var savedStep = currentStep;
            renderForm();
            updateProgress();
            showStep(Math.min(savedStep, getVisibleSections().length - 1));
        }
    }

    // ── Step navigation ──────────────────────────────────────────────
    function showStep(idx) {
        var sections = document.querySelectorAll('#ruai-form-body .ruai-section');
        sections.forEach(function (s, i) {
            s.classList.toggle('active', i === idx);
        });
        currentStep = idx;
        updateProgress();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    window.ruaiNext = function () {
        if (!validateCurrentStep()) return;
        var visible = getVisibleSections();
        if (currentStep < visible.length - 1) {
            showStep(currentStep + 1);
        }
    };

    window.ruaiPrev = function () {
        if (currentStep > 0) {
            showStep(currentStep - 1);
        }
    };

    window.ruaiGoToStep = function (idx) {
        // Allow going back freely, forward only if current step is valid
        if (idx <= currentStep || validateCurrentStep()) {
            showStep(idx);
        }
    };

    // ── Sidebar navigation ────────────────────────────────────────────
    function updateProgress() {
        var bar = document.getElementById('ruai-progress');
        if (!bar) return;
        var visible = getVisibleSections();
        var html = '';
        visible.forEach(function (section, idx) {
            var cls = idx === currentStep ? 'active' : (idx < currentStep ? 'completed' : '');
            var icon = idx < currentStep ? '✓' : (idx + 1);
            html += '<div class="ruai-progress-step ' + cls + '" onclick="ruaiGoToStep(' + idx + ')">';
            html += '<div class="ruai-step-number">' + icon + '</div>';
            html += '<span class="ruai-progress-label">' + escapeHtml(section.title) + '</span>';
            html += '</div>';
        });
        bar.innerHTML = html;
    }

    // ── Validation ───────────────────────────────────────────────────
    function validateCurrentStep() {
        var sections = document.querySelectorAll('#ruai-form-body .ruai-section');
        var section = sections[currentStep];
        if (!section) return true;

        var valid = true;
        section.querySelectorAll('.ruai-field:not(.hidden)').forEach(function (fieldDiv) {
            var input = fieldDiv.querySelector('input, select, textarea');
            if (!input) return;

            // For radio groups, check if any is selected
            if (input.type === 'radio') {
                var name = input.name;
                var checked = section.querySelector('input[name="' + name + '"]:checked');
                var isRequired = fieldDiv.querySelector('input[required]');
                if (isRequired && !checked) {
                    fieldDiv.style.outline = '2px solid #dc2626';
                    fieldDiv.style.borderRadius = '8px';
                    valid = false;
                } else {
                    fieldDiv.style.outline = '';
                }
                return;
            }

            if (input.required && !input.value.trim()) {
                input.style.borderColor = '#dc2626';
                valid = false;
            } else {
                input.style.borderColor = '';
            }
        });

        if (!valid && typeof showToast === 'function') {
            showToast('Please fill in all required fields');
        }
        return valid;
    }

    // ── Draft persistence ────────────────────────────────────────────
    function saveDraft() {
        collectAnswers();
        try {
            localStorage.setItem(DRAFT_KEY, JSON.stringify(allAnswers));
        } catch (e) { /* storage full or unavailable */ }
    }

    window.ruaiSaveDraft = function () {
        saveDraft();
        if (typeof showToast === 'function') {
            showToast('Draft saved to browser');
        }
    };

    function loadDraft() {
        try {
            var saved = localStorage.getItem(DRAFT_KEY);
            if (saved) allAnswers = JSON.parse(saved);
        } catch (e) { allAnswers = {}; }
    }

    function restoreAnswers() {
        Object.entries(allAnswers).forEach(function (entry) {
            var name = entry[0], value = entry[1];
            if (Array.isArray(value)) {
                // Checkboxes
                value.forEach(function (v) {
                    var cb = document.querySelector('input[name="' + name + '"][value="' + CSS.escape(v) + '"]');
                    if (cb) cb.checked = true;
                });
            } else {
                var el = document.querySelector('[name="' + name + '"]');
                if (el) {
                    if (el.type === 'radio') {
                        var radio = document.querySelector('input[name="' + name + '"][value="' + CSS.escape(value) + '"]');
                        if (radio) radio.checked = true;
                    } else {
                        el.value = value;
                    }
                }
            }
        });
        updateFieldVisibility();
    }

    function clearDraft() {
        try { localStorage.removeItem(DRAFT_KEY); } catch (e) { /* */ }
    }

    // ── File upload ──────────────────────────────────────────────────
    window.ruaiInitUpload = function () {
        var area = document.getElementById('ruai-upload-area');
        var input = document.getElementById('ruai-file-input');
        if (!area || !input) return;

        area.addEventListener('click', function () { input.click(); });
        area.addEventListener('dragover', function (e) { e.preventDefault(); area.classList.add('dragover'); });
        area.addEventListener('dragleave', function () { area.classList.remove('dragover'); });
        area.addEventListener('drop', function (e) {
            e.preventDefault();
            area.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        });
        input.addEventListener('change', function () { handleFiles(input.files); input.value = ''; });
    };

    function handleFiles(fileList) {
        for (var i = 0; i < fileList.length; i++) {
            var f = fileList[i];
            if (f.size > 10 * 1024 * 1024) {
                if (typeof showToast === 'function') showToast('File too large (max 10MB): ' + f.name);
                continue;
            }
            uploadedFiles.push(f);
        }
        renderFileList();
    }

    function renderFileList() {
        var list = document.getElementById('ruai-upload-list');
        if (!list) return;
        if (uploadedFiles.length === 0) { list.innerHTML = ''; return; }
        var html = '';
        uploadedFiles.forEach(function (f, idx) {
            html += '<div class="file-item">';
            html += '<span class="remove-file" onclick="ruaiRemoveFile(' + idx + ')">×</span> ';
            html += escapeHtml(f.name) + ' (' + formatSize(f.size) + ')';
            html += '</div>';
        });
        list.innerHTML = html;
    }

    window.ruaiRemoveFile = function (idx) {
        uploadedFiles.splice(idx, 1);
        renderFileList();
    };

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // ── Submit ───────────────────────────────────────────────────────
    window.ruaiSubmit = function () {
        if (!validateCurrentStep()) return;

        collectAnswers();

        var formData = new FormData();
        // Add all answers as JSON
        formData.append('form_data', JSON.stringify(allAnswers));

        // Add files
        uploadedFiles.forEach(function (f) {
            formData.append('documents', f);
        });

        // Disable submit button
        var btn = document.querySelector('.ruai-btn-success');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Submitting...';
        }

        fetch('/submit-ruai-screening', {
            method: 'POST',
            body: formData
        })
        .then(function (resp) { return resp.json(); })
        .then(function (data) {
            var modal = document.getElementById('ruai-modal');
            var modalBody = document.getElementById('ruai-modal-body');

            if (data.status === 'success') {
                clearDraft();
                var viewUrl = '/ruai-screening/' + data.submission_id;
                modalBody.innerHTML = '<h3>Submission Received</h3><p>' + escapeHtml(data.message) + '</p>' +
                    '<a href="' + viewUrl + '" class="ruai-btn ruai-btn-primary" style="display:inline-block;margin-top:12px;text-decoration:none;">View AI Feedback</a>';
            } else {
                modalBody.innerHTML = '<h3 style="color:#dc2626">Error</h3><p>' + escapeHtml(data.message) + '</p>' +
                    '<button class="ruai-btn ruai-btn-secondary" onclick="document.getElementById(\'ruai-modal\').classList.remove(\'show\')">Close</button>';
                if (btn) { btn.disabled = false; btn.textContent = 'Submit Screening'; }
            }
            modal.classList.add('show');
        })
        .catch(function () {
            if (typeof showToast === 'function') showToast('Network error. Please try again.');
            if (btn) { btn.disabled = false; btn.textContent = 'Submit Screening'; }
        });
    };

    // ── Utility ──────────────────────────────────────────────────────
    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
})();
