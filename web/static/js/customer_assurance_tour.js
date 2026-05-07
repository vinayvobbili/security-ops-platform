/* Customer Assurance — guided walkthrough overlay.
 * Zero dependencies. Per-page tour definitions.
 *
 * Usage:
 *   CATour.start('landing');         // start tour for a given page
 *   CATour.reset();                  // clear "seen" flags, replay from top
 *
 * Tours auto-start on first visit; localStorage key: ca_tour_seen_<pageKey>
 */

(function () {
    'use strict';

    const TOURS = {
        landing: [
            {
                title: "Welcome to Customer Assurance",
                body: "This tool helps the company respond to customer security questionnaires faster. I'll walk you through the flow in 30 seconds. Click Next to continue.",
                target: "#ca-tour-hero",
                placement: "bottom",
            },
            {
                title: "The 5-step workflow",
                body: "Every customer security request follows these 5 steps. The tool automates steps 2 and 3, and gives analysts a clean workspace for step 4.",
                target: "#ca-tour-flow",
                placement: "top",
            },
            {
                title: "Step 1 — Intake",
                body: "The account team drops a questionnaire in. You can paste the questions as text, or upload the original file (Excel, Word, PDF).",
                target: "#ca-tour-flow-1",
                placement: "top",
            },
            {
                title: "Step 2 — Auto-split",
                body: "The tool breaks the questionnaire into individual questions, so each can be drafted independently.",
                target: "#ca-tour-flow-2",
                placement: "top",
            },
            {
                title: "Step 3 — Draft with AI",
                body: "For each question, the system retrieves the most relevant chunks from our Knowledge Base (policies, SOC 2, standard responses), then AI drafts an answer grounded in those chunks, with source citations.",
                target: "#ca-tour-flow-3",
                placement: "top",
            },
            {
                title: "Step 4 — Review & Edit",
                body: "Analysts open each draft, edit freely, and approve it — or flag it for Legal or SME review if something needs extra scrutiny.",
                target: "#ca-tour-flow-4",
                placement: "top",
            },
            {
                title: "Step 5 — Deliver",
                body: "Once all answers are approved, export the full response as a Word document and hand it back to the account team to send to the customer.",
                target: "#ca-tour-flow-5",
                placement: "top",
            },
            {
                title: "Try it now",
                body: "Click 'New Request' to start an intake, or 'View Queue' to see existing requests. If you'd like to see a populated workspace, load the demo data at the bottom.",
                target: "#ca-tour-tile-new",
                placement: "right",
            },
        ],
        new: [
            {
                title: "Intake form",
                body: "This is where an analyst logs a new customer request. Fill in the customer, segment, and request type first.",
                target: "#ca-tour-customer",
                placement: "bottom",
            },
            {
                title: "Paste or upload",
                body: "Paste the questions directly (numbered lists, bullets, or blank-line-separated paragraphs all work), or upload the original file.",
                target: "#ca-tour-questions",
                placement: "top",
            },
            {
                title: "Live split preview",
                body: "As you type, the tool shows how it will break the text into individual questions. Each item becomes an independent draft in the workspace.",
                target: "#ca-tour-preview",
                placement: "top",
            },
        ],
        queue: [
            {
                title: "Request Queue",
                body: "Every in-flight customer request shows here. Sort by due date, filter by status or customer segment. Click a row to open the drafting workspace.",
                target: "#ca-tour-table",
                placement: "top",
            },
            {
                title: "Filters",
                body: "Quickly find requests by status ('drafting', 'needs legal', 'ready') or by customer segment (National, Regional, etc.).",
                target: "#ca-tour-filters",
                placement: "bottom",
            },
        ],
        workspace: [
            {
                title: "Drafting Workspace",
                body: "This is where analysts do the real work. The header shows the customer and request context.",
                target: "#ca-tour-ws-header",
                placement: "bottom",
            },
            {
                title: "Question list (left)",
                body: "All questions for this request. Icons show status: ○ pending, ● drafted, ✓ approved, ! needs SME. Click one to edit its answer.",
                target: "#ca-tour-ws-left",
                placement: "right",
            },
            {
                title: "Draft editor (center)",
                body: "The draft answer appears here. You can freely edit, redraft, approve, or mark as needing SME review. the LLM generates the initial draft from the Knowledge Base.",
                target: "#ca-tour-ws-center",
                placement: "top",
            },
            {
                title: "Evidence & citations (right)",
                body: "The exact policy chunks the drafter pulled from, with source attribution. This is what lets analysts trust — and verify — the draft.",
                target: "#ca-tour-ws-right",
                placement: "left",
            },
            {
                title: "Actions",
                body: "Draft all pending questions at once, flag the request for Legal review, export the final response as a Word doc, or mark it delivered.",
                target: "#ca-tour-ws-actions",
                placement: "bottom",
            },
        ],
    };

    let state = {
        tourKey: null,
        steps: [],
        index: 0,
        backdrop: null,
        spotlight: null,
        tooltip: null,
        resizeHandler: null,
    };

    function ensureElements() {
        if (state.backdrop) return;
        state.backdrop = document.createElement('div');
        state.backdrop.className = 'ca-tour-backdrop';
        state.spotlight = document.createElement('div');
        state.spotlight.className = 'ca-tour-spotlight';
        state.tooltip = document.createElement('div');
        state.tooltip.className = 'ca-tour-tooltip';
        document.body.appendChild(state.backdrop);
        document.body.appendChild(state.spotlight);
        document.body.appendChild(state.tooltip);
    }

    function start(tourKey) {
        if (!TOURS[tourKey]) {
            console.warn('CATour: unknown tour', tourKey);
            return;
        }
        ensureElements();
        state.tourKey = tourKey;
        state.steps = TOURS[tourKey];
        state.index = 0;
        state.backdrop.classList.add('active');
        render();
        state.resizeHandler = () => render();
        window.addEventListener('resize', state.resizeHandler);
        window.addEventListener('scroll', state.resizeHandler, true);
    }

    function stop() {
        if (!state.backdrop) return;
        state.backdrop.classList.remove('active');
        state.spotlight.style.display = 'none';
        state.tooltip.style.display = 'none';
        if (state.resizeHandler) {
            window.removeEventListener('resize', state.resizeHandler);
            window.removeEventListener('scroll', state.resizeHandler, true);
            state.resizeHandler = null;
        }
    }

    function next() {
        if (state.index < state.steps.length - 1) {
            state.index++;
            render();
        } else {
            stop();
        }
    }

    function prev() {
        if (state.index > 0) {
            state.index--;
            render();
        }
    }

    function render() {
        const step = state.steps[state.index];
        const target = document.querySelector(step.target);

        state.spotlight.style.display = 'block';
        state.tooltip.style.display = 'block';

        if (!target) {
            // Target missing — center tooltip on screen, hide spotlight
            state.spotlight.style.display = 'none';
            state.tooltip.style.top = (window.scrollY + 200) + 'px';
            state.tooltip.style.left = 'calc(50% - 170px)';
            renderTooltipContent(step);
            return;
        }

        // Scroll target into view (smooth) then position
        const rect = target.getBoundingClientRect();
        const needsScroll = rect.top < 80 || rect.bottom > window.innerHeight - 80;
        if (needsScroll) {
            target.scrollIntoView({behavior: 'smooth', block: 'center'});
            setTimeout(() => positionElements(target, step), 350);
        } else {
            positionElements(target, step);
        }

        renderTooltipContent(step);
    }

    function positionElements(target, step) {
        const rect = target.getBoundingClientRect();
        const pageY = rect.top + window.scrollY;
        const pageX = rect.left + window.scrollX;

        // Spotlight around the target (with padding)
        const pad = 8;
        Object.assign(state.spotlight.style, {
            top: (pageY - pad) + 'px',
            left: (pageX - pad) + 'px',
            width: (rect.width + pad * 2) + 'px',
            height: (rect.height + pad * 2) + 'px',
        });

        // Tooltip placement
        const placement = step.placement || 'bottom';
        const tooltipW = 340;
        const tooltipH = state.tooltip.offsetHeight || 180;
        const gap = 20;
        let top, left, arrow;

        switch (placement) {
            case 'top':
                top = pageY - tooltipH - gap;
                left = pageX + rect.width / 2 - tooltipW / 2;
                arrow = 'arrow-down';
                break;
            case 'left':
                top = pageY + rect.height / 2 - tooltipH / 2;
                left = pageX - tooltipW - gap;
                arrow = 'arrow-right';
                break;
            case 'right':
                top = pageY + rect.height / 2 - tooltipH / 2;
                left = pageX + rect.width + gap;
                arrow = 'arrow-left';
                break;
            case 'bottom':
            default:
                top = pageY + rect.height + gap;
                left = pageX + rect.width / 2 - tooltipW / 2;
                arrow = 'arrow-up';
                break;
        }

        // Clamp to viewport
        const maxLeft = window.innerWidth + window.scrollX - tooltipW - 16;
        const minLeft = window.scrollX + 16;
        left = Math.max(minLeft, Math.min(maxLeft, left));

        const maxTop = window.innerHeight + window.scrollY - tooltipH - 16;
        const minTop = window.scrollY + 16;
        top = Math.max(minTop, Math.min(maxTop, top));

        state.tooltip.className = 'ca-tour-tooltip ' + arrow;
        state.tooltip.style.top = top + 'px';
        state.tooltip.style.left = left + 'px';
    }

    function renderTooltipContent(step) {
        const dots = state.steps.map((_, i) =>
            `<span class="ca-tour-dot ${i === state.index ? 'active' : ''}"></span>`
        ).join('');
        const isLast = state.index === state.steps.length - 1;
        const isFirst = state.index === 0;
        state.tooltip.innerHTML = `
            <div class="ca-tour-step">Step ${state.index + 1} of ${state.steps.length}</div>
            <h3 class="ca-tour-title">${escapeHtml(step.title)}</h3>
            <p class="ca-tour-body">${escapeHtml(step.body)}</p>
            <div class="ca-tour-nav">
                <div class="ca-tour-dots">${dots}</div>
                <div class="ca-tour-btns">
                    ${isFirst ? '' : '<button type="button" class="ca-btn ca-btn-ghost ca-btn-sm" data-tour-prev>Back</button>'}
                    <button type="button" class="ca-btn ca-btn-ghost ca-btn-sm" data-tour-skip>Skip</button>
                    <button type="button" class="ca-btn ca-btn-primary ca-btn-sm" data-tour-next>${isLast ? 'Done ✓' : 'Next →'}</button>
                </div>
            </div>
        `;
        state.tooltip.querySelector('[data-tour-next]')?.addEventListener('click', next);
        state.tooltip.querySelector('[data-tour-prev]')?.addEventListener('click', prev);
        state.tooltip.querySelector('[data-tour-skip]')?.addEventListener('click', stop);
    }

    function escapeHtml(s) {
        return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    // ESC to close
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && state.backdrop?.classList.contains('active')) {
            stop();
        }
    });

    // Expose API
    window.CATour = {
        start,
        stop,
        next,
        prev,
        reset() {
            Object.keys(localStorage)
                .filter(k => k.startsWith('ca_tour_seen_'))
                .forEach(k => localStorage.removeItem(k));
        },
    };
})();
