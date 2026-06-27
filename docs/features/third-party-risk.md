---
layout: doc
title: Third-Party Risk Assessment
---

# Third-Party Risk Assessment

A vendor cyber due-diligence workspace: intake a vendor, drop in their evidence,
and get draft answers to your control questions composed straight from that
evidence — ready for an analyst to review, edit, and export.

---

## Why this exists

Vendor risk assessments are slow because they're manual: an analyst reads a
stack of SOC 2 reports, policies, and questionnaires, then writes the same
control conclusions over and over. The hard part isn't judgment — it's the
hours of reading and transcription before any judgment can happen. This
workspace does the reading and the first draft, so the analyst spends their
time on the decision, not the paperwork.

---

## What it does

### Intake → queue
Each vendor gets an entry in a worklist with its assessment state, so a backlog
of due-diligence reviews is visible and trackable rather than living in inboxes.

### Per-vendor evidence
Unlike a one-size questionnaire, each vendor brings its own evidence set — there
is no fixed document cap. The workspace indexes that evidence per vendor for
retrieval.

### Evidence-grounded drafting
For each control question, the relevant passages are retrieved from the vendor's
own evidence and a local LLM drafts the answer from them — grounded in what the
vendor actually provided, not a generic template. The retrieval-and-answer
kernel is the open [`attestq`](https://pypi.org/project/attestq/) package; the
workspace injects its own LLM and embeddings as the kernel's seams.

### Review → export
Drafts land in a per-vendor workspace where an analyst confirms or rewrites each
answer, then exports the completed due-diligence form.

---

## Access

Running, editing, and exporting assessments is gated behind a dedicated
capability; the rest of the platform's role model applies as usual.
