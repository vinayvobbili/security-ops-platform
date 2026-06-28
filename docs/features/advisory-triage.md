---
layout: doc
title: Advisory Triage
---

# Security Advisory Triage

A standing queue that turns the daily firehose of vendor and open-source
security advisories into **prioritized, owned, actionable work** — with the
threat analysis written for you.

The vendor-neutral report → analysis core (ATT&CK mapping, generated rules,
STIX / Navigator exports) is the open-source
[**detflow**](https://pypi.org/project/detflow/) package, extracted from this
pipeline.

---

## Why this exists

Advisories arrive faster than anyone can read them, and most teams triage them
by gut feel: skim the title, guess the blast radius, maybe open a ticket. The
hard questions — *do we even run the affected component? is the fleet patched?
can we detect exploitation?* — get answered late or not at all. This queue
answers them up front, so the only human decision left is "act or dismiss."

---

## What it does

### 1. Triage command center
The list is a working surface, not a feed: a dense, paginated table with an
"Affects us" verdict on every row, saved-view preset chips for stakeholder
slices, bulk multi-select actions (assign / close / escalate), per-row age and
an auto-archive countdown, escalation outcome state, and an Advisories /
Campaigns split that clusters coordinated waves.

### 2. Exposure at a glance
Every row carries a software-exposure verdict computed from **Veracode SCA** —
which of our applications actually carry the affected open-source component —
so "does this touch us?" is answered before anyone opens the advisory, and the
affected application names are listed inline.

### 3. The triage dossier
Opening an advisory lands on a single-page dossier: severity spine, an
exposure band that auto-checks our software footprint and fleet posture, a
KPI ribbon (EPSS, CISA KEV, exploited-in-wild, patch), the AI assessment with
extracted IOCs/TTPs, a grounded CAPD decision scorecard, a SIEM "were we
touched?" pulse, and a shareable branded PDF.

### 4. Per-advisory threat analysis
From the advisory text plus its CVEs, an LLM generates:

- **ATT&CK techniques** the threat maps to
- Ready-to-tune **Sigma, YARA, and Suricata** rules
- An **audience-tuned brief** (analyst vs. leadership)
- **STIX 2.1 bundle** + **ATT&CK Navigator layer** exports for downstream tools

### 5. Verify remediation
When an app team says they've fixed it, one click re-runs the Veracode exposure
lens live and diffs it against the last snapshot — showing exactly what cleared
versus what still remains, with a verdict (verified / partial / regressed) and
a full re-check history.

### 6. One-click escalation
A reviewed advisory packages into tickets and notifications, with leadership
tempo KPIs tracking how fast the queue is being worked, plus cross-source
corroboration and campaign clustering across feeds.

---

## Design notes

- **The list does the triage.** Exposure verdict, age, ownership state, and
  outcome live on the row, so an analyst works the queue from the table and only
  opens the advisories that actually need a decision.
- **Analysis is the default, not an add-on.** Every advisory gets ATT&CK +
  detection content generated for it, so triage starts from "here's how we'd
  catch it," not a blank page.
- **Exposure before busywork.** Software footprint and fleet posture are
  computed on demand so analysts spend time on advisories that actually touch
  the estate.
- **Portable core.** The report → analysis logic is vendor-neutral and lives as
  the standalone [detflow](https://pypi.org/project/detflow/) package — the same
  engine behind [Detection as Code](detection-as-code).

---

[← Back to Features](index)
