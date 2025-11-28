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

        const exportType = includeNotes ? 'with notes' : 'without notes';
        exportBtn.textContent = `⏳ Starting export ${exportType}...`;
        exportBtn.style.background = 'linear-gradient(135deg, #0369a1 0%, #0284c7 100%)';
        exportBtn.disabled = true;

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
            // Throw exceptions for flow control in async operations
            throw new Error(error.error || 'Failed to start export');
        }

        const {job_id} = await startResponse.json();

        // Poll for progress
        const pollInterval = 30000;

        while (true) {
            await new Promise(resolve => setTimeout(resolve, pollInterval));

            const statusResponse = await fetch(`/api/meaningful-metrics/export-async/status/${job_id}`);
            if (!statusResponse.ok) {
                // Throw for flow control
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
                } else {
                    exportBtn.textContent = `⏳ Exporting: ${percentage}%`;
                }
            } else if (status.status === 'complete') {
                exportBtn.textContent = '⬇️ Downloading...';

                const downloadResponse = await fetch(`/api/meaningful-metrics/export-async/download/${job_id}`);
                if (!downloadResponse.ok) {
                    // Throw for flow control
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

                exportBtn.textContent = '✅ Export Complete!';
                exportBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
                exportBtn.disabled = false;

                showExportSuccessNotification(filename);

                setTimeout(() => {
                    exportBtn.textContent = originalText;
                    exportBtn.style.background = '';
                }, 4000);

                break;
            } else if (status.status === 'failed') {
                // Throw for flow control
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
    }
}
