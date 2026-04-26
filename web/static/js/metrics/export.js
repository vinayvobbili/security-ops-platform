/**
 * Excel export functionality
 */

import {state} from './state.js';
import {AVAILABLE_COLUMNS} from './config.js';
import {getCurrentFilters} from './filters.js';
import {showExportNotesModal, showExportSuccessNotification} from './ui.js';

export async function exportToExcel() {
    try {
        const includeNotes = await showExportNotesModal();
        if (includeNotes === null) return;

        const exportBtn = document.getElementById('exportExcelBtn');
        const originalText = exportBtn.textContent;

        const exportColumns = [...state.visibleColumns];
        if (includeNotes && !exportColumns.includes('notes')) {
            exportColumns.push('notes');
        }

        const columnLabels = {};
        exportColumns.forEach(colId => {
            columnLabels[colId] = AVAILABLE_COLUMNS[colId]?.label || colId;
        });

        const filters = getCurrentFilters();

        if (filters.useCustomDate && filters.customDateStart && filters.customDateEnd) {
            const start = new Date(filters.customDateStart);
            const end = new Date(filters.customDateEnd);
            const spanDays = Math.round((end - start) / (1000 * 60 * 60 * 24));
            if (spanDays > 366) {
                alert(`Custom date range cannot exceed 366 days (selected ${spanDays} days). Please narrow the range.`);
                return;
            }
        }

        const exportType = includeNotes ? 'with notes' : 'without notes';
        exportBtn.textContent = `⏳ Starting export ${exportType}...`;
        exportBtn.style.background = 'linear-gradient(135deg, #0369a1 0%, #0284c7 100%)';
        exportBtn.disabled = true;

        // Show progress bar
        const progBox = document.getElementById('exportProgress');
        const progText = document.getElementById('exportProgressText');
        const progSub = document.getElementById('exportProgressSub');
        const progFill = document.getElementById('exportProgressFill');
        const progWait = document.getElementById('exportProgressWait');
        if (progBox) {
            progBox.style.display = '';
            progText.textContent = `Starting export ${exportType}…`;
            progSub.textContent = '';
            progFill.style.width = '5%';
            progWait.textContent = includeNotes
                ? 'Please wait, enriching notes can take several minutes…'
                : 'Please wait…';
            progBox.scrollIntoView({behavior: 'smooth', block: 'nearest'});
        }
        const exportStart = Date.now();
        const elapsedTimer = setInterval(() => {
            const s = Math.round((Date.now() - exportStart) / 1000);
            const str = s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
            if (progSub) progSub.textContent = `Elapsed: ${str}`;
        }, 1000);

        const startResponse = await fetch('/api/meaningful-metrics/export-async/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                filters: filters,
                visible_columns: exportColumns,
                column_labels: columnLabels,
                include_notes: includeNotes
            })
        });

        if (!startResponse.ok) {
            const error = await startResponse.json();
            throw new Error(error.error || 'Failed to start export');
        }

        const {job_id} = await startResponse.json();

        // Poll for progress (fast interval for responsive UI)
        const pollInterval = 3000;

        while (true) {
            await new Promise(resolve => setTimeout(resolve, pollInterval));

            const statusResponse = await fetch(`/api/meaningful-metrics/export-async/status/${job_id}`);
            if (!statusResponse.ok) {
                throw new Error('Failed to check export status');
            }

            const status = await statusResponse.json();

            if (status.status === 'processing') {
                const progress = status.progress || 0;
                const total = status.total || 0;
                const percentage = total > 0 ? Math.round((progress / total) * 100) : 0;

                if (includeNotes) {
                    exportBtn.textContent = `⏳ Enriching notes: ${progress}/${total} (${percentage}%)`;
                    exportBtn.style.background = 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)';
                    if (progText) progText.textContent = `Enriching notes: ${progress} / ${total} tickets (${percentage}%)`;
                } else {
                    exportBtn.textContent = `⏳ Exporting: ${percentage}%`;
                    if (progText) progText.textContent = `Exporting: ${percentage}%`;
                }
                if (progFill) progFill.style.width = `${Math.max(5, Math.min(percentage, 90))}%`;
            } else if (status.status === 'complete') {
                if (progText) progText.textContent = 'Downloading…';
                if (progFill) progFill.style.width = '95%';
                exportBtn.textContent = '⬇️ Downloading...';

                const downloadResponse = await fetch(`/api/meaningful-metrics/export-async/download/${job_id}`);
                if (!downloadResponse.ok) {
                    throw new Error('Failed to download export file');
                }

                const blob = await downloadResponse.blob();
                const url = window.URL.createObjectURL(blob);

                const now = new Date();
                const timestamp = now.getFullYear() + '-' +
                    String(now.getMonth() + 1).padStart(2, '0') + '-' +
                    String(now.getDate()).padStart(2, '0') + '_' +
                    String(now.getHours()).padStart(2, '0') + '-' +
                    String(now.getMinutes()).padStart(2, '0') + '-' +
                    String(now.getSeconds()).padStart(2, '0');

                const notesPrefix = includeNotes ? 'with_notes' : 'without_notes';
                const filename = `security_incidents_${notesPrefix}_${timestamp}.xlsx`;

                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);

                clearInterval(elapsedTimer);
                const finalSecs = Math.round((Date.now() - exportStart) / 1000);
                const finalStr = finalSecs < 60 ? `${finalSecs}s` : `${Math.floor(finalSecs / 60)}m ${finalSecs % 60}s`;
                if (progFill) progFill.style.width = '100%';
                if (progText) progText.textContent = '✅ Export complete!';
                if (progSub) progSub.textContent = `Finished in ${finalStr}`;
                exportBtn.textContent = '✅ Export Complete!';
                exportBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
                exportBtn.disabled = false;

                showExportSuccessNotification(filename);

                if (Array.isArray(status.warnings) && status.warnings.length > 0) {
                    alert(
                        'Export completed with warnings:\n\n- '
                        + status.warnings.join('\n- ')
                    );
                }

                setTimeout(() => {
                    exportBtn.textContent = originalText;
                    exportBtn.style.background = '';
                    if (progBox) progBox.style.display = 'none';
                }, 4000);

                break;
            } else if (status.status === 'failed') {
                throw new Error(status.error || 'Export failed');
            }
        }
    } catch (error) {
        console.error('Export error:', error);
        alert('Failed to export: ' + error.message);
        const exportBtn = document.getElementById('exportExcelBtn');
        exportBtn.textContent = '📥 Export to Excel';
        exportBtn.style.background = '';
        exportBtn.disabled = false;
        const progBox = document.getElementById('exportProgress');
        if (progBox) progBox.style.display = 'none';
        // elapsedTimer may not be defined if error occurred before it was created
        if (typeof elapsedTimer !== 'undefined') clearInterval(elapsedTimer);
    }
}
