---
layout: doc
title: Active Threats Desk
---

# Active Threats Desk

An adversary-centric intake desk: paste a threat report, and an LLM turns it into
a structured, working queue — actor, IOCs, and TTPs extracted — then enriches,
plans a hunt, and contains, all from one page.

---

## Why this exists

Threat reports arrive as prose — a vendor write-up, an ISAC bulletin, a blog. The
analyst's job is to convert that prose into *work*: who is this, what are the
indicators, what do they do, are we exposed, and what do we do about it. Doing
that by hand is slow and lossy. The desk makes the report the input and a
prioritized, enriched, actionable threat the output.

---

## What it does

### Paste → structured threat
Drop in a report and an LLM extracts the actor, the IOCs (hashes, IPs, domains,
URLs), and the described TTPs into a single threat record. A deterministic IOC
backstop runs alongside the model, so even if the LLM misses something — or is
unavailable — the indicators in the text are never dropped.

### IOC reputation enrichment
Every extracted indicator is enriched across VirusTotal, AbuseIPDB, urlscan, and
Recorded Future, with reputation and context rolled up per IOC so the desk shows
which indicators are already known-bad.

### Pre-flight hunt plan
Each threat gets a pre-flight hunt plan via the shared hunt engine — the same
front door the Hunt Workbench, KEV reach-out, and domain monitoring fan out
through — so "were we touched?" is one click from the threat detail.

### One-click containment
A block action is wired straight through the shared SOAR url-block kernel, so a
confirmed-malicious indicator can be contained from the desk (human-gated, the
same kernel the domain-monitoring and workbench blocks use).

### Live auto-ingest feed
A Recorded Future auto-ingest feed populates the queue on a schedule, so the desk
works adversaries off a live feed instead of waiting on a manual paste —
idempotent via a stable source id and a high-water cursor.

---

## Design notes

- **Adversary-centric.** The unit of work is a threat actor / campaign, not an
  alert — enrichment, hunting, and containment all hang off that one record.
- **Never drop an indicator.** The LLM is primary for extraction, but a
  deterministic backstop guarantees the IOCs in the text always make it into the
  queue.
- **One hunt engine.** Hunting is consolidated onto a single engine front door,
  so a plan from the desk sees exactly what the Workbench sees, and console
  deep-links (SIEM, log search, SOAR) converge to one place.

---

[← Back to Features](index)
