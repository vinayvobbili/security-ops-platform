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
hard questions — *do we even run the affected component? who owns it? is the
fleet patched? can we detect exploitation?* — get answered late or not at all.
This queue answers them up front, so the only human decision left is "act or
dismiss."

---

## What it does

### 1. Ingest and queue
Critical advisories are polled and parked in a durable queue with notes,
close / reopen, and idempotent escalation — so nothing falls through and the
same advisory isn't worked twice.

### 2. Per-advisory threat analysis
From the advisory text plus its CVEs, an LLM generates:

- **ATT&CK techniques** the threat maps to
- Ready-to-tune **Sigma, YARA, and Suricata** rules
- An **audience-tuned brief** (analyst vs. leadership)
- **STIX 2.1 bundle** + **ATT&CK Navigator layer** exports for downstream tools

### 3. Blast-radius capabilities
Each advisory can be enriched on demand with:

- **App ownership** — which applications depend on the affected component
- **Fleet posture** — patch / version coverage across the estate
- **Attack-surface exposure** — what's internet-reachable
- **Cross-source corroboration** — the same threat seen across feeds, plus
  campaign clustering of related advisories

### 4. One-click escalation
A reviewed advisory packages into tickets and notifications, with leadership
tempo KPIs tracking how fast the queue is being worked.

---

## Design notes

- **Analysis is the default, not an add-on.** Every advisory gets ATT&CK +
  detection content generated for it, so triage starts from "here's how we'd
  catch it," not a blank page.
- **Blast radius before busywork.** Ownership, posture, and exposure are
  computed on demand so analysts spend time on advisories that actually touch
  the estate.
- **Portable core.** The report → analysis logic is vendor-neutral and lives as
  the standalone [detflow](https://pypi.org/project/detflow/) package — the same
  engine behind [Detection as Code](detection-as-code).

---

[← Back to Features](index)
