/**
 * Dashboard PDF Export — shared utility
 * Lazy-loads html2canvas + jsPDF, captures dashboard sections into multi-page landscape PDF.
 * IIFE → window.DashboardExport
 */
(function () {
    'use strict';

    function _ensureLibs(callback) {
        var pending = 0;

        if (typeof window.html2canvas !== 'function') {
            pending++;
            var s1 = document.createElement('script');
            s1.src = 'https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js';
            s1.onload = function () { if (--pending === 0) callback(); };
            document.head.appendChild(s1);
        }

        if (typeof window.jspdf === 'undefined') {
            pending++;
            var s2 = document.createElement('script');
            s2.src = 'https://cdn.jsdelivr.net/npm/jspdf@2.5.2/dist/jspdf.umd.min.js';
            s2.onload = function () { if (--pending === 0) callback(); };
            document.head.appendChild(s2);
        }

        if (pending === 0) callback();
    }

    /**
     * Export dashboard sections to branded multi-page landscape PDF.
     * @param {string} _containerSelector - unused, kept for API compat
     * @param {object} options - {title, subtitle, sections: [selector|element, ...]}
     * @param {function} [onProgress] - called with (step, total)
     */
    function exportPdf(_containerSelector, options, onProgress) {
        options = options || {};
        var title = options.title || 'Dashboard Export';
        var subtitle = options.subtitle || '';
        var sections = options.sections || [];

        _ensureLibs(function () {
            var jsPDF = window.jspdf.jsPDF;
            var pdf = new jsPDF({ orientation: 'landscape', unit: 'px', format: 'a4' });
            var pageW = pdf.internal.pageSize.getWidth();
            var pageH = pdf.internal.pageSize.getHeight();
            var margin = 30;
            var yOffset = margin;

            // Brand header
            pdf.setFontSize(18);
            pdf.setTextColor(30, 41, 59);
            pdf.text(title, margin, yOffset + 18);
            yOffset += 24;

            if (subtitle) {
                pdf.setFontSize(10);
                pdf.setTextColor(100, 116, 139);
                var subLines = pdf.splitTextToSize(subtitle, pageW - margin * 2);
                pdf.text(subLines, margin, yOffset + 10);
                yOffset += 12 * subLines.length + 4;
            }

            pdf.setFontSize(9);
            pdf.setTextColor(148, 163, 184);
            pdf.text('Generated: ' + new Date().toLocaleString(), margin, yOffset + 10);
            yOffset += 20;

            // Draw thin accent line
            pdf.setDrawColor(59, 130, 246);
            pdf.setLineWidth(1.5);
            pdf.line(margin, yOffset, pageW - margin, yOffset);
            yOffset += 10;

            var idx = 0;
            function captureNext() {
                if (idx >= sections.length) {
                    pdf.save(title.replace(/[^a-zA-Z0-9]/g, '_') + '.pdf');
                    if (onProgress) onProgress(sections.length, sections.length);
                    return;
                }
                if (onProgress) onProgress(idx + 1, sections.length);

                var el = typeof sections[idx] === 'string'
                    ? document.querySelector(sections[idx])
                    : sections[idx];
                idx++;

                if (!el || el.offsetHeight === 0) { captureNext(); return; }

                html2canvas(el, { backgroundColor: null, useCORS: true, scale: 1.5, logging: false })
                    .then(function (canvas) {
                        var imgData = canvas.toDataURL('image/png');
                        var imgW = pageW - margin * 2;
                        var imgH = (canvas.height / canvas.width) * imgW;

                        if (yOffset + imgH > pageH - margin) {
                            pdf.addPage();
                            yOffset = margin;
                        }

                        // If single image is taller than page, scale down
                        if (imgH > pageH - margin * 2) {
                            var scale = (pageH - margin * 2) / imgH;
                            imgW *= scale;
                            imgH *= scale;
                        }

                        pdf.addImage(imgData, 'PNG', margin, yOffset, imgW, imgH);
                        yOffset += imgH + 10;
                        captureNext();
                    })
                    .catch(function () { captureNext(); });
            }
            captureNext();
        });
    }

    window.DashboardExport = { exportPdf: exportPdf };
})();
