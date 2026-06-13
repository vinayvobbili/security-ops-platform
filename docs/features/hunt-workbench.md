---
layout: doc
title: Threat Hunt Workbench
---

# Threat Hunt Workbench

On-demand analyst hunting: paste a piece of threat intel, get back live IOC
enrichment, behavioral SIEM hunts, ATT&CK coverage analysis, and a verdict —
without leaving the page.

---

## Why this exists

A CTI report lands. The analyst's job is to answer two questions fast: **"were
we touched?"** and **"can we even detect this?"** Doing that by hand means
extracting every IOC, fanning them out across enrichment services, hand-writing
SIEM queries for the described behaviors, and cross-referencing the techniques
against the detection catalog. The workbench does all of it from a paste.

---

## What it does

### Paste → extract
Drop in a CTI report, advisory, or blog. The workbench extracts the IOCs
(hashes, IPs, domains, URLs) and the described ATT&CK techniques.

### Live IOC fan-out
Each indicator is enriched across the integrated threat-intel services in
parallel, with reputation and context rolled up per IOC.

### "Were we touched?" — behavioral hunts
Rather than only matching the literal IOCs (which attackers rotate), an LLM
authors **behavioral SIEM hunts** from the described TTPs — so the hunt catches
the technique, not just this campaign's disposable infrastructure.

### "Can we detect this?" — coverage vs. rules
The extracted techniques are mapped against the live detection-rule catalog to
show ATT&CK **coverage gaps** — which behaviors in the report you'd see, and
which you'd miss.

### Verdict + history
Each hunt produces a consolidated verdict and is persisted, so a hunt can be
reopened, compared, and tracked. Long-running fan-outs run on an async worker so
the page stays responsive.

---

## Design notes

- **Behavioral over literal.** IOC matching is necessary but shallow; the
  high-signal output is the behavioral hunt authored from the TTPs, which
  survives the attacker rotating infrastructure.
- **Read-only.** The workbench investigates — it queries the SIEM/EDR and
  enrichment services but takes no destructive action; escalation is a separate,
  gated step.
- **Reuses the engine.** It's wired on top of the same enrichment + IOC pipeline
  the automated tipper analysis uses, so a hunt sees exactly what the pipeline
  sees.

---

[← Back to Features](index)
