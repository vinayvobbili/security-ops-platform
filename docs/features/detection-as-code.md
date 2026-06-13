---
layout: default
title: Detection as Code
---

# Detection as Code

A draft-and-approve pipeline that takes a detection from **Sigma rule** to a
reviewed, packaged **CI/CD merge request** — with a real dry-run against the
SIEM in the middle.

The vendor-neutral lint / draft / overlap / review core is the open-source
[**detflow**](https://pypi.org/project/detflow/) package, extracted from this
pipeline.

---

## Why this exists

Detection engineering is still mostly hand-work: write the rule, guess whether
it'll fire, hope it isn't a duplicate of something already in the catalog, and
push it to the SIEM. Each step is a place for a false positive, a coverage gap,
or a noisy rule to slip through. This pipeline puts a reviewer — and a real
dry-run — between "idea" and "deployed."

---

## The pipeline

### 1. Draft / paste
Start from a natural-language description (LLM drafts the Sigma) or paste an
existing Sigma rule.

### 2. Lint
Structural and semantic linting catches malformed logic, missing fields, and
common authoring mistakes before anything runs.

### 3. Compile to XQL
An LLM compiles the platform-agnostic Sigma logic into the target SIEM's query
language (XQL for Cortex XSIAM).

### 4. Real dry-run
The compiled query is executed **read-only against the live SIEM tenant** over a
bounded window — so you see the actual hit volume and shape before the rule is
ever deployed, not a guess.

### 5. Review
An LLM senior-engineer pass evaluates the rule for quality, false-positive risk,
ATT&CK mapping, and **overlap** with the existing detection catalog (is this a
duplicate of a rule you already run?).

### 6. Package
The reviewed rule is packaged into a GitLab merge request for the detection
repo. The MR open is human-gated and disabled outside production, so nothing
reaches the detection repo without a person in the loop.

---

## Design notes

- **A real dry-run beats a guess.** The single highest-value step is executing
  the compiled query against live data — hit volume is the truth about whether a
  rule is deployable, and no amount of static review substitutes for it.
- **Overlap-aware.** New detections are checked against the existing catalog, so
  the pipeline resists slowly accreting duplicate rules.
- **Gated by default.** Drafting, linting, and dry-run are safe to run anywhere;
  the only outbound action (opening the MR) is human-gated and production-only.
- **Portable core.** The lint/draft/overlap/review logic is vendor-neutral and
  lives as the standalone [detflow](https://pypi.org/project/detflow/) package.

---

[← Back to Features](index)
