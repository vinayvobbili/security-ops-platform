/* ═══════════════════════════════════════════════════════════════════════════
   S3 Bucket Scanner — Frontend
   ═══════════════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', function () {

    // ─── DOM refs ────────────────────────────────────────────────────────
    const s3TargetsList   = document.getElementById('s3TargetsList');
    const s3NoTargets     = document.getElementById('s3NoTargets');
    const s3AddBtn        = document.getElementById('s3AddTargetBtn');
    const s3AddModal      = document.getElementById('s3AddModal');
    const s3ModalClose    = document.getElementById('s3ModalClose');
    const s3ModalCancel   = document.getElementById('s3ModalCancel');
    const s3ModalSave     = document.getElementById('s3ModalSave');
    const s3ScanBtn       = document.getElementById('s3ScanBtn');
    const s3Progress      = document.getElementById('s3Progress');
    const s3ProgressBar   = document.getElementById('s3ProgressBar');
    const s3ProgressText  = document.getElementById('s3ProgressText');
    const s3ProgressDetail= document.getElementById('s3ProgressDetail');
    const s3ExecSummary   = document.getElementById('s3ExecSummary');
    const s3ExecCards     = document.getElementById('s3ExecCards');
    const s3ExecVerdict   = document.getElementById('s3ExecVerdict');
    const s3ExecTimestamp = document.getElementById('s3ExecTimestamp');
    const s3Results       = document.getElementById('s3Results');
    const s3ResultsBody   = document.getElementById('s3ResultsBody');
    const s3FilterStatus  = document.getElementById('s3FilterStatus');
    const s3ExportBtn     = document.getElementById('s3ExportBtn');
    const s3ExportCsvBtn  = document.getElementById('s3ExportCsvBtn');
    const s3DiffSummary   = document.getElementById('s3DiffSummary');
    const s3LastScan      = document.getElementById('s3LastScan');
    const s3SelectAll     = document.getElementById('s3SelectAll');

    let allResults = [];
    let lastReport = null;
    let scanning   = false;

    // ─── Init ────────────────────────────────────────────────────────────
    var urlParams = new URLSearchParams(window.location.search);
    var autoScanKey = urlParams.get('autoScan');
    var adhocBucket = urlParams.get('bucket');

    if (adhocBucket) {
        // Ad-hoc deep scan from domain monitoring: add bucket as target, then auto-scan
        var adKey = 'adhoc-' + adhocBucket.replace(/[^a-z0-9.-]/g, '');
        fetch('/api/s3-scanner/targets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'add', key: adKey, label: adhocBucket + ' (deep scan)', buckets: [adhocBucket] })
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.success) {
                window.history.replaceState({}, '', '/s3-scanner');
                loadTargets(adKey);
                loadScanHistory();
                loadLatestScan();
            } else {
                alert('Failed to add bucket target: ' + (data.error || 'Unknown error'));
                loadTargets(); loadScanHistory(); loadLatestScan();
            }
        })
        .catch(function () { loadTargets(); loadScanHistory(); loadLatestScan(); });
    } else {
        loadTargets(autoScanKey);
        loadScanHistory();
        loadLatestScan();
    }

    // ─── Select All toggle ───────────────────────────────────────────────
    s3SelectAll.addEventListener('change', function () {
        var checked = s3SelectAll.checked;
        s3TargetsList.querySelectorAll('.s3-target-cb').forEach(function (cb) {
            cb.checked = checked;
        });
        updateScanBtnLabel();
    });

    // ─── Target management ───────────────────────────────────────────────
    function loadTargets(autoScanKey) {
        fetch('/api/s3-scanner/targets')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) {
                    renderTargets(data.targets);
                    // Auto-scan if URL param present
                    if (autoScanKey && data.targets[autoScanKey]) {
                        // Uncheck all, then check only the target
                        s3TargetsList.querySelectorAll('.s3-target-cb').forEach(function (cb) {
                            cb.checked = cb.getAttribute('data-key') === autoScanKey;
                        });
                        updateScanBtnLabel();
                        // Clear URL param so refresh doesn't re-trigger
                        window.history.replaceState({}, '', '/s3-scanner');
                        startScan();
                    }
                }
            });
    }

    function renderTargets(targets) {
        s3TargetsList.innerHTML = '';
        var keys = Object.keys(targets);

        if (keys.length === 0) {
            s3NoTargets.style.display = 'block';
            s3TargetsList.style.display = 'none';
            return;
        }
        s3NoTargets.style.display = 'none';
        s3TargetsList.style.display = 'grid';

        keys.forEach(function (key) {
            var target = targets[key];
            var item = document.createElement('div');
            item.className = 's3-target-item';

            var bucketsHtml = target.buckets.map(function (b) {
                return '<span class="s3-target-bucket-pill">' + esc(b) + '</span>';
            }).join('');

            item.innerHTML =
                '<label class="s3-target-check">' +
                    '<input type="checkbox" class="s3-target-cb" data-key="' + esc(key) + '"' + (target.default_selected !== false ? ' checked' : '') + '>' +
                    '<span class="s3-target-checkmark"></span>' +
                '</label>' +
                '<div class="s3-target-info">' +
                    '<div class="s3-target-label">' + esc(target.label) +
                        '<span class="s3-target-key">' + esc(key) + '</span>' +
                    '</div>' +
                    '<div class="s3-target-buckets">' + bucketsHtml + '</div>' +
                    '<div class="s3-target-meta">' + target.buckets.length + ' bucket' + (target.buckets.length !== 1 ? 's' : '') +
                        (target.sample_count ? ' &middot; ' + target.sample_count + ' samples' : '') +
                    '</div>' +
                '</div>' +
                '<div class="s3-target-actions">' +
                    '<button class="s3-target-remove" data-key="' + esc(key) + '" title="Remove target">&times;</button>' +
                '</div>';

            s3TargetsList.appendChild(item);
        });

        // Bind remove buttons
        s3TargetsList.querySelectorAll('.s3-target-remove').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var k = this.getAttribute('data-key');
                if (confirm('Remove target "' + k + '"?')) removeTarget(k);
            });
        });

        // Update scan button count when checkboxes change
        s3TargetsList.querySelectorAll('.s3-target-cb').forEach(function (cb) {
            cb.addEventListener('change', updateScanBtnLabel);
        });
        updateScanBtnLabel();
    }

    function getSelectedKeys() {
        var cbs = s3TargetsList.querySelectorAll('.s3-target-cb:checked');
        var keys = [];
        cbs.forEach(function (cb) { keys.push(cb.getAttribute('data-key')); });
        return keys;
    }

    function updateScanBtnLabel() {
        if (scanning) return;
        var selected = getSelectedKeys().length;
        var total = s3TargetsList.querySelectorAll('.s3-target-cb').length;
        var label = selected === total ? 'Run Full Scan' : 'Scan ' + selected + ' of ' + total + ' Targets';
        s3ScanBtn.querySelector('.s3-scan-text').textContent = label;
        s3ScanBtn.disabled = selected === 0;
        // Sync select-all checkbox
        s3SelectAll.checked = selected === total && total > 0;
        s3SelectAll.indeterminate = selected > 0 && selected < total;
    }

    function removeTarget(key) {
        fetch('/api/s3-scanner/targets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'remove', key: key })
        })
        .then(function (r) { return r.json(); })
        .then(function (data) { if (data.success) renderTargets(data.targets); });
    }

    // ─── Add Target modal ────────────────────────────────────────────────
    s3AddBtn.addEventListener('click', function () { openAddModal(); });
    s3ModalClose.addEventListener('click', closeModal);
    s3ModalCancel.addEventListener('click', closeModal);
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && s3AddModal.style.display !== 'none') closeModal();
    });

    function openAddModal() {
        document.getElementById('s3NewKey').value = '';
        document.getElementById('s3NewLabel').value = '';
        document.getElementById('s3NewBuckets').value = '';
        document.getElementById('s3NewSampleCount').value = '10';
        s3AddModal.style.display = 'flex';
    }

    function closeModal() {
        s3AddModal.style.display = 'none';
        document.getElementById('s3NewKey').value = '';
        document.getElementById('s3NewLabel').value = '';
        document.getElementById('s3NewBuckets').value = '';
        document.getElementById('s3NewSampleCount').value = '10';
    }

    s3ModalSave.addEventListener('click', function () {
        var key = document.getElementById('s3NewKey').value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
        var label = document.getElementById('s3NewLabel').value.trim();
        var bucketsRaw = document.getElementById('s3NewBuckets').value.trim();
        var sampleCount = parseInt(document.getElementById('s3NewSampleCount').value, 10) || 10;

        if (!key || !label || !bucketsRaw) {
            alert('Key, label, and at least one bucket are required.');
            return;
        }

        var buckets = bucketsRaw.split('\n').map(function (b) { return b.trim(); }).filter(Boolean);

        fetch('/api/s3-scanner/targets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'add', key: key, label: label, buckets: buckets, sample_count: sampleCount })
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.success) {
                renderTargets(data.targets);
                closeModal();
            } else {
                alert(data.error || 'Failed to add target');
            }
        });
    });

    // ─── Scan ────────────────────────────────────────────────────────────
    s3ScanBtn.addEventListener('click', startScan);

    function startScan() {
        if (scanning) return;

        var selectedKeys = getSelectedKeys();
        if (selectedKeys.length === 0) return;

        scanning = true;
        allResults = [];
        lastReport = null;

        // UI state
        s3ScanBtn.disabled = true;
        s3ScanBtn.classList.add('s3-scanning');
        s3ScanBtn.querySelector('.s3-scan-text').textContent = 'Scanning...';
        s3ScanBtn.querySelector('.s3-scan-icon').textContent = '\u23F3';
        s3Progress.style.display = 'block';
        s3ProgressBar.style.width = '0%';
        s3ProgressText.textContent = 'Initializing scan...';
        s3ProgressDetail.textContent = '';
        s3ExecSummary.style.display = 'none';
        s3DiffSummary.style.display = 'none';
        s3Results.style.display = 'none';
        s3ResultsBody.innerHTML = '';
        s3FilterStatus.value = 'all';

        // Disable checkboxes during scan
        s3TargetsList.querySelectorAll('.s3-target-cb').forEach(function (cb) { cb.disabled = true; });

        var scanUrl = '/api/s3-scanner/scan?targets=' + encodeURIComponent(selectedKeys.join(','));
        var es = new EventSource(scanUrl);

        es.addEventListener('progress', function (e) {
            var d = JSON.parse(e.data);
            var pct = 0;
            if (d.total && d.current) {
                pct = Math.round((d.current / d.total) * 100);
            }
            // Don't let progress exceed 95% until complete
            s3ProgressBar.style.width = Math.min(pct, 95) + '%';
            s3ProgressText.textContent = d.message || ('Scanning... ' + pct + '%');
            if (d.bucket) {
                s3ProgressDetail.textContent = d.target + ' \u2014 ' + d.bucket;
            } else if (d.target) {
                s3ProgressDetail.textContent = d.target;
            }
        });

        es.addEventListener('result', function (e) {
            var r = JSON.parse(e.data);
            allResults.push(r);
            // Show results table as soon as first result arrives
            if (s3Results.style.display === 'none') {
                s3Results.style.display = 'block';
            }
            appendResultRow(r);
        });

        es.addEventListener('complete', function (e) {
            es.close();
            lastReport = JSON.parse(e.data);
            scanning = false;
            finishScan();
        });

        es.addEventListener('saved', function (e) {
            var d = JSON.parse(e.data);
            if (lastReport) lastReport.scan_id = d.scan_id;
            loadScanHistory();
        });

        es.addEventListener('error', function (e) {
            // SSE error could be parse error or connection drop
            if (es.readyState === EventSource.CLOSED) return;
            es.close();
            scanning = false;
            var errData = {};
            try { errData = JSON.parse(e.data); } catch (ex) { /* ignore */ }
            s3ProgressText.textContent = 'Scan error: ' + (errData.error || 'Connection lost');
            s3ProgressBar.style.width = '100%';
            s3ProgressBar.style.background = 'var(--s3-fail)';
            resetScanBtn();
        });

        es.onerror = function () {
            if (!scanning) return;
            es.close();
            scanning = false;
            s3ProgressText.textContent = 'Connection lost. Scan may have completed \u2014 check results below.';
            resetScanBtn();
        };
    }

    function stopScan() {
        if (!scanning) return;
        scanning = false;
        resetScanBtn();
    }

    function finishScan() {
        s3ProgressBar.style.width = '100%';
        s3ProgressText.textContent = 'Scan complete \u2014 ' + allResults.length + ' checks performed';
        s3ProgressDetail.textContent = '';

        resetScanBtn();
        renderExecSummary(lastReport);

        // Diff against previous scan
        var prevJson = localStorage.getItem('s3ScannerLastReport');
        var prevReport = prevJson ? JSON.parse(prevJson) : null;
        localStorage.setItem('s3ScannerLastReport', JSON.stringify(lastReport));
        if (prevReport) renderDiffSummary(prevReport, lastReport);

        var ts = new Date(lastReport.timestamp);
        s3LastScan.textContent = 'Last scan: ' + ts.toLocaleDateString() + ' ' +
            ts.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function resetScanBtn() {
        s3ScanBtn.classList.remove('s3-scanning');
        s3ScanBtn.querySelector('.s3-scan-icon').textContent = '\u25B6';
        // Re-enable checkboxes
        s3TargetsList.querySelectorAll('.s3-target-cb').forEach(function (cb) { cb.disabled = false; });
        updateScanBtnLabel();
    }

    // ─── Executive Summary ───────────────────────────────────────────────
    function renderExecSummary(report) {
        s3ExecSummary.style.display = 'block';

        var s = report.summary;
        var ts = new Date(report.timestamp);
        s3ExecTimestamp.textContent = ts.toLocaleDateString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric',
            hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
        });

        s3ExecCards.innerHTML =
            buildExecCard('\uD83D\uDD0D', s.total, 'Total Checks', 's3-card-total') +
            buildExecCard('\u2705', s.pass, 'Passed', 's3-card-pass') +
            buildExecCard('\uD83D\uDEA8', s.fail, 'Failed', 's3-card-fail') +
            buildExecCard('\u26A0\uFE0F', s.error, 'Errors', 's3-card-error') +
            buildExecCard('\u2139\uFE0F', s.info || 0, 'Info', 's3-card-info');

        if (s.fail > 0) {
            s3ExecVerdict.className = 's3-exec-verdict s3-verdict-fail';
            s3ExecVerdict.innerHTML = '\uD83D\uDEA8 PUBLIC EXPOSURE DETECTED \u2014 ' + s.fail +
                ' check' + (s.fail > 1 ? 's' : '') + ' reveal publicly accessible data';
        } else if (s.error > 0) {
            s3ExecVerdict.className = 's3-exec-verdict s3-verdict-warn';
            s3ExecVerdict.innerHTML = '\u26A0\uFE0F ' + s.error + ' check(s) errored \u2014 verify manually';
        } else {
            s3ExecVerdict.className = 's3-exec-verdict s3-verdict-pass';
            s3ExecVerdict.innerHTML = '\u2705 ALL BUCKETS SECURE \u2014 No public exposure detected';
        }
    }

    function buildExecCard(icon, value, label, cls) {
        return '<div class="s3-exec-card ' + cls + '">' +
            '<div class="s3-exec-card-icon">' + icon + '</div>' +
            '<div>' +
                '<div class="s3-exec-card-value">' + value + '</div>' +
                '<div class="s3-exec-card-label">' + label + '</div>' +
            '</div>' +
        '</div>';
    }

    // ─── Evidence Modal ─────────────────────────────────────────────────
    var evidenceStore = {};  // keyed by result index

    function showEvidenceModal(idx) {
        var data = evidenceStore[idx];
        if (!data) return;

        var html =
            '<div class="s3-modal-backdrop s3-evidence-backdrop" onclick="if(event.target===this)this.remove()">' +
            '<div class="s3-modal s3-evidence-modal">' +
                '<div class="s3-modal-header">' +
                    '<h3>\uD83D\uDD0D Evidence \u2014 ' + esc(data.bucket) + '</h3>' +
                    '<button class="s3-modal-close" onclick="this.closest(\'.s3-evidence-backdrop\').remove()">&times;</button>' +
                '</div>' +
                '<div class="s3-evidence-meta">' +
                    '<span class="s3-evidence-check">' + esc(data.check) + '</span>' +
                    '<button class="s3-btn s3-btn-primary s3-btn-sm" id="s3DlBtn_' + idx + '" onclick="downloadAllObjects(\'' + esc(data.bucket) + '\', this)">' +
                        '\u2B07 Download All Objects (Excel)' +
                    '</button>' +
                '</div>' +
                '<div class="s3-modal-body s3-evidence-body">';

        var renderedSections = 0;

        // Always show 10 sample exposed records at the top.
        // Pull objects from this check's evidence, or from the Object Enumeration
        // result for the same bucket if this check doesn't have them.
        var sampleObjects = data.objects || null;
        var sampleObjectCount = data.object_count || null;
        if (!sampleObjects) {
            // Search other results for this bucket's Object Enumeration evidence
            for (var si = 0; si < allResults.length; si++) {
                var sr = allResults[si];
                if (sr.bucket === data.bucket && sr.evidence && sr.evidence.objects && sr.evidence.objects.length > 0) {
                    sampleObjects = sr.evidence.objects;
                    sampleObjectCount = sr.evidence.object_count || sampleObjects.length;
                    break;
                }
            }
        }
        if (sampleObjects && sampleObjects.length > 0) {
            renderedSections++;
            var showCount = Math.min(sampleObjects.length, 10);
            var totalLabel = sampleObjectCount ? Number(sampleObjectCount).toLocaleString() : sampleObjects.length;
            html += '<div class="s3-evidence-section">' +
                '<div class="s3-evidence-section-header">\uD83D\uDCC4 Sample Exposed Records (showing ' + showCount + ' of ' + totalLabel + ')</div>' +
                '<table class="s3-table s3-evidence-table"><thead><tr>' +
                '<th>#</th><th>Object Key</th><th>Size</th><th>Last Modified</th><th>Download</th>' +
                '</tr></thead><tbody>';
            for (var oi = 0; oi < showCount; oi++) {
                var obj = sampleObjects[oi];
                var dlUrl = '/api/s3-scanner/download-s3-object?bucket=' + encodeURIComponent(data.bucket) +
                    '&key=' + encodeURIComponent(obj.key);
                var isFile = obj.size > 0 && !obj.key.endsWith('/');
                html += '<tr>' +
                    '<td>' + (oi + 1) + '</td>' +
                    '<td class="s3-obj-key">' + esc(obj.key) + '</td>' +
                    '<td>' + esc(obj.size_human || humanSize(obj.size || 0)) + '</td>' +
                    '<td>' + esc(obj.last_modified || '\u2014') + '</td>' +
                    '<td>' + (isFile ? '<a href="' + dlUrl + '" class="s3-btn s3-btn-sm s3-btn-outline" target="_blank">\u2B07</a>' : '') + '</td>' +
                    '</tr>';
            }
            html += '</tbody></table></div>';
        }

        // Object enumeration summary
        if (data.object_count) {
            renderedSections++;
            html += '<div class="s3-evidence-section">' +
                '<div class="s3-evidence-section-header">\uD83D\uDCC2 Object Enumeration</div>' +
                '<div class="s3-evidence-kv">' +
                    '<div class="s3-evidence-row"><span class="s3-ev-label">Object Count</span><span class="s3-ev-value">' + Number(data.object_count).toLocaleString() + '</span></div>';
            if (data.total_size_human) {
                html += '<div class="s3-evidence-row"><span class="s3-ev-label">Total Size</span><span class="s3-ev-value">' + esc(data.total_size_human) + '</span></div>';
            }
            if (data.region) {
                html += '<div class="s3-evidence-row"><span class="s3-ev-label">Region</span><span class="s3-ev-value">' + esc(data.region) + '</span></div>';
            }
            if (data.file_type_distribution) {
                html += '<div class="s3-evidence-row"><span class="s3-ev-label">File Types</span><span class="s3-ev-value">';
                Object.keys(data.file_type_distribution).forEach(function (ft) {
                    html += '<span class="s3-target-bucket-pill">' + esc(ft) + ': ' + data.file_type_distribution[ft] + '</span> ';
                });
                html += '</span></div>';
            }
            html += '</div></div>';
        }

        // Object listing (array of individual objects)
        if (data.objects && data.objects.length > 0) {
            renderedSections++;
            var showingLabel = data.objects.length < (data.object_count || 0)
                ? 'showing ' + data.objects.length + ' of ' + Number(data.object_count).toLocaleString()
                : data.objects.length + ' object' + (data.objects.length !== 1 ? 's' : '');
            html += '<div class="s3-evidence-section">' +
                '<div class="s3-evidence-section-header">\uD83D\uDCC2 Object Listing (' + showingLabel + ')</div>' +
                '<table class="s3-table s3-evidence-table"><thead><tr>' +
                '<th>Key</th><th>Size</th><th>Last Modified</th><th>Download</th>' +
                '</tr></thead><tbody>';
            data.objects.forEach(function (obj) {
                var dlUrl2 = '/api/s3-scanner/download-s3-object?bucket=' + encodeURIComponent(data.bucket) +
                    '&key=' + encodeURIComponent(obj.key);
                var isFile2 = obj.size > 0 && !obj.key.endsWith('/');
                html += '<tr>' +
                    '<td class="s3-obj-key">' + esc(obj.key) + '</td>' +
                    '<td>' + esc(obj.size_human || humanSize(obj.size || 0)) + '</td>' +
                    '<td>' + esc(obj.last_modified || '\u2014') + '</td>' +
                    '<td>' + (isFile2 ? '<a href="' + dlUrl2 + '" class="s3-btn s3-btn-sm s3-btn-outline" target="_blank">\u2B07</a>' : '') + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';
        }

        // PII findings
        if (data.pii_findings && data.pii_findings.length > 0) {
            renderedSections++;
            html += '<div class="s3-evidence-section">' +
                '<div class="s3-evidence-section-header">\uD83D\uDD11 PII Findings</div>' +
                '<table class="s3-table s3-evidence-table"><thead><tr>' +
                '<th>Type</th><th>Count</th><th>Masked Samples</th>' +
                '</tr></thead><tbody>';
            data.pii_findings.forEach(function (f) {
                html += '<tr>' +
                    '<td><span class="s3-badge s3-badge-pii">' + esc(f.type || 'Unknown') + '</span></td>' +
                    '<td>' + (f.count || 1) + '</td>' +
                    '<td class="s3-pii-samples">' + (f.samples || []).map(esc).join('<br>') + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';
        }

        // ACL grants
        if (data.acl_grants && data.acl_grants.length > 0) {
            renderedSections++;
            html += '<div class="s3-evidence-section">' +
                '<div class="s3-evidence-section-header">\uD83D\uDD13 ACL Grants</div>' +
                '<table class="s3-table s3-evidence-table"><thead><tr>' +
                '<th>Grantee</th><th>Permission</th>' +
                '</tr></thead><tbody>';
            data.acl_grants.forEach(function (g) {
                html += '<tr>' +
                    '<td>' + esc(g.grantee || g.grantee_uri || '\u2014') + '</td>' +
                    '<td><span class="s3-badge s3-badge-fail">' + esc(g.permission) + '</span></td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';
        }

        // Directory structure (may be array of strings or objects)
        if (data.directory_structure && data.directory_structure.length > 0) {
            renderedSections++;
            html += '<div class="s3-evidence-section">' +
                '<div class="s3-evidence-section-header">\uD83D\uDCC1 Exposed Directories (' + data.directory_structure.length + ')</div>' +
                '<div class="s3-directory-tree">';
            data.directory_structure.forEach(function (entry) {
                var name = typeof entry === 'string' ? entry : (entry.name || entry.key || '');
                html += '<div class="s3-dir-entry">\uD83D\uDCC1 ' + esc(name) + '</div>';
            });
            html += '</div></div>';
        }

        // Raw evidence fallback
        if (renderedSections === 0) {
            // Show all evidence data as formatted JSON
            var rawData = {};
            Object.keys(data).forEach(function (k) {
                if (k !== 'bucket' && k !== 'check' && data[k] !== null) rawData[k] = data[k];
            });
            if (Object.keys(rawData).length > 0) {
                html += '<div class="s3-evidence-section">' +
                    '<div class="s3-evidence-section-header">Evidence Data</div>' +
                    '<pre class="s3-evidence-raw">' + esc(JSON.stringify(rawData, null, 2)) + '</pre>' +
                    '</div>';
            }
        }

        html += '</div></div></div>';

        var container = document.createElement('div');
        container.innerHTML = html;
        document.body.appendChild(container.firstChild);
    }
    window.showEvidenceModal = showEvidenceModal;

    function downloadAllObjects(bucket, btn) {
        if (!bucket) return;
        var origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Listing objects...';

        var es = new EventSource('/api/s3-scanner/download-objects?bucket=' + encodeURIComponent(bucket));
        es.addEventListener('progress', function (e) {
            try {
                var d = JSON.parse(e.data);
                btn.textContent = d.status || 'Downloading...';
            } catch (_) {}
        });
        es.addEventListener('done', function (e) {
            es.close();
            try {
                var d = JSON.parse(e.data);
                var url = '/api/s3-scanner/download-file?id=' + encodeURIComponent(d.file_id) +
                    '&filename=' + encodeURIComponent(d.filename);
                var a = document.createElement('a');
                a.href = url;
                a.download = d.filename;
                a.style.display = 'none';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                btn.textContent = d.total.toLocaleString() + ' objects exported';
                btn.disabled = false;
            } catch (_) {
                btn.textContent = origText;
                btn.disabled = false;
            }
        });
        es.addEventListener('error', function (e) {
            es.close();
            try {
                var d = JSON.parse(e.data);
                btn.textContent = 'Error: ' + (d.error || 'unknown');
            } catch (_) {
                btn.textContent = origText;
            }
            btn.disabled = false;
        });
        es.onerror = function () {
            es.close();
            btn.textContent = origText;
            btn.disabled = false;
        };
    }
    window.downloadAllObjects = downloadAllObjects;

    // ─── Results Table ───────────────────────────────────────────────────
    function appendResultRow(r) {
        // Normalize: DB uses check_name, live scan uses check
        if (!r.check && r.check_name) r.check = r.check_name;

        var tr = document.createElement('tr');
        tr.setAttribute('data-status', r.status);

        var badgeCls = 's3-badge-' + r.status.toLowerCase();
        var badgeIcon = { PASS: '\u2713', FAIL: '\u2717', ERROR: '!', INFO: '\u2139' }[r.status] || '?';

        // Evidence column - button opens modal
        var evidenceHtml = '';
        var ev = r.evidence || {};
        var hasEvidence = (r.evidence && (
            ev.objects || ev.object_count ||
            ev.pii_findings || ev.pii ||
            ev.acl_grants || ev.public_grants ||
            ev.directory_structure || ev.directories ||
            ev.first_page_keys || ev.file_type_distribution ||
            ev.raw
        ));

        if (hasEvidence) {
            var idx = allResults.length - 1;
            evidenceStore[idx] = {
                bucket: r.bucket || r.target || 'Unknown',
                check: r.check || '',
                objects: ev.objects || null,
                object_count: ev.object_count || ev.first_page_keys || null,
                total_size_human: ev.total_size_human || null,
                file_type_distribution: ev.file_type_distribution || null,
                pii_findings: ev.pii_findings || ev.pii || null,
                acl_grants: ev.acl_grants || ev.public_grants || null,
                directory_structure: ev.directory_structure || ev.directories || null,
                region: ev.region || null,
                raw: ev.raw || null
            };
            var evLabel = 'View';
            if (evidenceStore[idx].acl_grants) evLabel = evidenceStore[idx].acl_grants.length + ' grant' + (evidenceStore[idx].acl_grants.length !== 1 ? 's' : '');
            else if (evidenceStore[idx].object_count) evLabel = Number(evidenceStore[idx].object_count).toLocaleString() + ' objects';
            else if (evidenceStore[idx].directory_structure) evLabel = evidenceStore[idx].directory_structure.length + ' dir' + (evidenceStore[idx].directory_structure.length !== 1 ? 's' : '');
            evidenceHtml = '<button class="s3-btn s3-btn-evidence" onclick="showEvidenceModal(' + idx + ')">' +
                '\uD83D\uDD0D ' + evLabel + '</button>';
        }

        tr.innerHTML =
            '<td><span class="s3-badge ' + badgeCls + '">' + badgeIcon + ' ' + r.status + '</span></td>' +
            '<td>' + esc(r.target || '') + '</td>' +
            '<td class="s3-bucket-cell">' + esc(r.bucket || '') + '</td>' +
            '<td>' + esc(r.check || '') + '</td>' +
            '<td>' + esc(r.detail || '') + '</td>' +
            '<td class="s3-evidence-col">' + evidenceHtml + '</td>';

        s3ResultsBody.appendChild(tr);
        applyFilterToRow(tr);
    }

    // ─── Filter Controls ─────────────────────────────────────────────────
    s3FilterStatus.addEventListener('change', function () {
        s3ResultsBody.querySelectorAll('tr').forEach(applyFilterToRow);
    });

    function applyFilterToRow(tr) {
        var f = s3FilterStatus.value;
        var statusOk = f === 'all' || tr.getAttribute('data-status') === f;
        tr.style.display = statusOk ? '' : 'none';
    }

    // ─── Export JSON ─────────────────────────────────────────────────────
    s3ExportBtn.addEventListener('click', function () {
        if (!lastReport) return;
        var blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 's3_scan_' + new Date().toISOString().slice(0, 10) + '.json';
        a.click();
        URL.revokeObjectURL(url);
    });

    // ─── Export CSV ──────────────────────────────────────────────────────
    s3ExportCsvBtn.addEventListener('click', function () {
        if (!lastReport) return;
        var csv = csvEscape('Status') + ',' +
                  csvEscape('Target') + ',' + csvEscape('Bucket') + ',' +
                  csvEscape('Check') + ',' + csvEscape('Detail') + '\n';
        (lastReport.results || allResults).forEach(function (r) {
            if (!r.check && r.check_name) r.check = r.check_name;
            csv += csvEscape(r.status) + ',' +
                   csvEscape(r.target) + ',' + csvEscape(r.bucket) + ',' +
                   csvEscape(r.check) + ',' + csvEscape(r.detail) + '\n';
        });
        var blob = new Blob([csv], { type: 'text/csv' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 's3_scan_' + new Date().toISOString().slice(0, 10) + '.csv';
        a.click();
        URL.revokeObjectURL(url);
    });

    function csvEscape(val) {
        if (val === null || val === undefined) return '';
        var s = String(val);
        if (s.includes(',') || s.includes('"') || s.includes('\n')) {
            return '"' + s.replace(/"/g, '""') + '"';
        }
        return s;
    }

    // ─── Diff against previous scan ──────────────────────────────────────
    function resultKey(r) { return (r.target || '') + '|' + (r.bucket || '') + '|' + (r.check || r.check_name || ''); }

    function renderDiffSummary(prev, curr) {
        var prevMap = {};
        (prev.results || []).forEach(function (r) { prevMap[resultKey(r)] = r.status; });
        var currMap = {};
        (curr.results || []).forEach(function (r) { currMap[resultKey(r)] = r.status; });

        var newFails = [], resolved = [], unchanged = 0;
        (curr.results || []).forEach(function (r) {
            var key = resultKey(r);
            var oldStatus = prevMap[key];
            if (!oldStatus) return; // new check - skip
            if (r.status === 'FAIL' && oldStatus !== 'FAIL') {
                newFails.push((r.check || r.check_name) + ' on ' + r.bucket);
            } else if (oldStatus === 'FAIL' && r.status !== 'FAIL') {
                resolved.push((r.check || r.check_name) + ' on ' + r.bucket);
            } else {
                unchanged++;
            }
        });

        if (newFails.length === 0 && resolved.length === 0) {
            s3DiffSummary.innerHTML =
                '<div class="s3-diff-header">' +
                    '<h3><span class="s3-icon">\uD83D\uDD04</span> Change Detection</h3>' +
                    '<span class="s3-diff-ts">vs. ' + new Date(prev.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) + '</span>' +
                '</div>' +
                '<div class="s3-diff-verdict s3-diff-nochange">No changes since last scan \u2014 ' + unchanged + ' checks unchanged</div>';
            s3DiffSummary.style.display = 'block';
            return;
        }

        var html =
            '<div class="s3-diff-header">' +
                '<h3><span class="s3-icon">\uD83D\uDD04</span> Change Detection</h3>' +
                '<span class="s3-diff-ts">vs. ' + new Date(prev.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) + '</span>' +
            '</div>' +
            '<div class="s3-diff-cards">';

        if (newFails.length > 0) {
            html += '<div class="s3-diff-card s3-diff-card-fail">' +
                '<div class="s3-diff-card-value">' + newFails.length + '</div>' +
                '<div class="s3-diff-card-label">New Failures</div>' +
                '<div class="s3-diff-card-list">' + newFails.map(esc).join('<br>') + '</div>' +
            '</div>';
        }
        if (resolved.length > 0) {
            html += '<div class="s3-diff-card s3-diff-card-resolved">' +
                '<div class="s3-diff-card-value">' + resolved.length + '</div>' +
                '<div class="s3-diff-card-label">Resolved</div>' +
                '<div class="s3-diff-card-list">' + resolved.map(esc).join('<br>') + '</div>' +
            '</div>';
        }

        html += '</div>';
        s3DiffSummary.innerHTML = html;
        s3DiffSummary.style.display = 'block';
    }

    // ─── Scan History ────────────────────────────────────────────────────
    var s3HistoryPanel   = document.getElementById('s3ScanHistory');
    var s3HistoryBody    = document.getElementById('s3HistoryBody');
    var s3HistoryBodyEl  = document.getElementById('s3HistoryTableBody');
    var s3HistoryToggle  = document.getElementById('s3HistoryToggle');
    var s3CompareBtn     = document.getElementById('s3CompareBtn');
    var _s3HistoryScans  = [];

    function toggleHistoryPanel() {
        var body = s3HistoryBody;
        if (body.style.display === 'none') {
            body.style.display = 'block';
            s3HistoryToggle.textContent = '\u25BC';
            s3HistoryToggle.classList.add('expanded');
        } else {
            body.style.display = 'none';
            s3HistoryToggle.textContent = '\u25B6';
            s3HistoryToggle.classList.remove('expanded');
        }
    }
    window.toggleHistoryPanel = toggleHistoryPanel;

    function loadScanHistory() {
        fetch('/api/s3-scanner/history?limit=30')
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (!d.success || !d.scans || d.scans.length === 0) {
                    s3HistoryPanel.style.display = 'none';
                    return;
                }
                _s3HistoryScans = d.scans;
                s3HistoryPanel.style.display = 'block';
                s3HistoryBodyEl.innerHTML = '';
                d.scans.forEach(function (scan) {
                    var ts = new Date(scan.timestamp);
                    var dateStr = ts.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + ' ' +
                                  ts.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    var targets = scan.targets_scanned || [];
                    var targetsStr = Array.isArray(targets) ? targets.join(', ') : String(targets);
                    if (targetsStr.length > 40) targetsStr = targetsStr.slice(0, 37) + '...';
                    var tr = document.createElement('tr');
                    tr.innerHTML =
                        '<td><input type="checkbox" class="s3-history-cb" data-scan-id="' + esc(scan.scan_id) + '"></td>' +
                        '<td>' + esc(dateStr) + '</td>' +
                        '<td title="' + esc(Array.isArray(targets) ? targets.join(', ') : '') + '">' + esc(targetsStr) + '</td>' +
                        '<td><span class="s3-history-badge s3-history-badge-pass">' + (scan.pass_count || 0) + '</span></td>' +
                        '<td><span class="s3-history-badge s3-history-badge-fail">' + (scan.fail || 0) + '</span></td>' +
                        '<td><span class="s3-history-badge s3-history-badge-error">' + (scan.error || 0) + '</span></td>' +
                        '<td><button class="s3-history-btn-view" onclick="loadHistoricalScan(\'' + esc(scan.scan_id) + '\')">View</button></td>';
                    s3HistoryBodyEl.appendChild(tr);
                });
                // Checkbox change handler for compare
                s3HistoryBodyEl.querySelectorAll('.s3-history-cb').forEach(function (cb) {
                    cb.addEventListener('change', function () {
                        var checked = s3HistoryBodyEl.querySelectorAll('.s3-history-cb:checked');
                        if (checked.length > 2) { this.checked = false; return; }
                        s3CompareBtn.disabled = checked.length !== 2;
                    });
                });
            })
            .catch(function () { s3HistoryPanel.style.display = 'none'; });
    }

    function loadLatestScan() {
        fetch('/api/s3-scanner/history?limit=1')
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (!d.success || !d.scans || d.scans.length === 0) return;
                loadHistoricalScan(d.scans[0].scan_id);
            })
            .catch(function () {});
    }

    function loadHistoricalScan(scanId) {
        fetch('/api/s3-scanner/scan/' + scanId)
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (!d.success) return;
                allResults = d.scan.results || [];
                lastReport = d.scan;
                s3ResultsBody.innerHTML = '';
                allResults.forEach(function (r) { appendResultRow(r); });
                s3Results.style.display = 'block';
                renderExecSummary(lastReport);
                s3ExecSummary.style.display = 'block';
            });
    }
    window.loadHistoricalScan = loadHistoricalScan;

    function compareSelectedScans() {
        var checked = s3HistoryBodyEl.querySelectorAll('.s3-history-cb:checked');
        if (checked.length !== 2) return;
        var idA = checked[0].getAttribute('data-scan-id');
        var idB = checked[1].getAttribute('data-scan-id');
        s3CompareBtn.disabled = true;
        s3CompareBtn.textContent = 'Comparing...';
        fetch('/api/s3-scanner/diff?a=' + encodeURIComponent(idA) + '&b=' + encodeURIComponent(idB))
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (!d.success) { alert(d.error || 'Comparison failed'); return; }
                var diff = d.diff;
                var tsA = new Date(diff.scan_a.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
                var tsB = new Date(diff.scan_b.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

                var html = '<div class="s3-diff-header">' +
                    '<h3><span class="s3-icon">\uD83D\uDD04</span> Scan Comparison</h3>' +
                    '<span class="s3-diff-ts">' + esc(tsA) + ' \u2192 ' + esc(tsB) + '</span></div>';

                if (diff.new_failures.length === 0 && diff.resolved.length === 0) {
                    html += '<div class="s3-diff-verdict s3-diff-nochange">No changes \u2014 ' + diff.unchanged_count + ' checks unchanged</div>';
                } else {
                    html += '<div class="s3-diff-cards">';
                    if (diff.new_failures.length > 0) {
                        html += '<div class="s3-diff-card s3-diff-card-fail">' +
                            '<div class="s3-diff-card-value">' + diff.new_failures.length + '</div>' +
                            '<div class="s3-diff-card-label">New Failures</div>' +
                            '<div class="s3-diff-card-list">' + diff.new_failures.map(function (f) { return esc(f.check_name + ' on ' + f.bucket); }).join('<br>') + '</div></div>';
                    }
                    if (diff.resolved.length > 0) {
                        html += '<div class="s3-diff-card s3-diff-card-resolved">' +
                            '<div class="s3-diff-card-value">' + diff.resolved.length + '</div>' +
                            '<div class="s3-diff-card-label">Resolved</div>' +
                            '<div class="s3-diff-card-list">' + diff.resolved.map(function (f) { return esc(f.check_name + ' on ' + f.bucket); }).join('<br>') + '</div></div>';
                    }
                    html += '</div>';
                }
                s3DiffSummary.innerHTML = html;
                s3DiffSummary.style.display = 'block';
            })
            .finally(function () { s3CompareBtn.disabled = false; s3CompareBtn.textContent = 'Compare Selected'; });
    }
    window.compareSelectedScans = compareSelectedScans;

    // ─── Utilities ───────────────────────────────────────────────────────
    function esc(text) {
        if (text === null || text === undefined) return '';
        var div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    function humanSize(bytes) {
        if (bytes === null || bytes === undefined) return '\u2014';
        bytes = Number(bytes);
        if (isNaN(bytes)) return '\u2014';
        if (bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        if (i >= units.length) i = units.length - 1;
        var val = bytes / Math.pow(1024, i);
        return val.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
    }

    function timeAgo(isoStr) {
        if (!isoStr) return '';
        var then = new Date(isoStr);
        var now = new Date();
        var diff = Math.floor((now - then) / 1000);
        if (diff < 60) return diff + 's ago';
        diff = Math.floor(diff / 60);
        if (diff < 60) return diff + 'm ago';
        diff = Math.floor(diff / 60);
        if (diff < 24) return diff + 'h ago';
        diff = Math.floor(diff / 24);
        if (diff < 30) return diff + 'd ago';
        diff = Math.floor(diff / 30);
        return diff + 'mo ago';
    }
});
