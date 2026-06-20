---
layout: doc
title: SOC-in-a-Box
---

# SOC-in-a-Box

A multi-agent SOC: a team of specialized AI agents — triage, Tier-2, IR Lead,
Threat Intel, Threat Hunter, Detection Engineer, and a SOC Manager over the top
— that work a case together over a shared event bus, with a human in the loop on
every consequential action.

One LLM wears many hats. Each agent has its own role, mandate, and voice, but
they all reason over the same case and publish their findings to a common bus
that the next agent picks up.

> 📝 **Deep dive:** [Giving an AI SOC a Memory: Precedent, Proof, and the Campaigns No Analyst Sees](https://vinayvobbili.github.io/posts/soc-in-a-box-case-memory/) — the design story behind case memory, ground-truth accuracy, and cross-incident campaigns.

> 📦 **Open source:** the vendor-neutral kernel behind this — the event contract, message bus, case-memory read models, and the agent framework — is published as [aisoc on PyPI](https://pypi.org/project/aisoc/), so you can model your own SOC as an event-sourced team. The agents here are the thin integration layer that injects a live LLM, enrichment tools, and a Redis bus into it.

---

## Why this exists

A single triage prompt can label an alert. It can't *run a case* — pull the
context, weigh it against what the org has seen before, propose a containment,
and leave a record of why. SOC-in-a-Box models the SOC as a team rather than a
classifier: agents that hand off to each other, escalate, disagree, and document
their reasoning the way analysts on a shift would.

---

## How it works

### Event-sourced, not a pipeline
Agents don't call each other directly. Each one consumes events off a shared
**message bus** and publishes its own — so the flow is auditable end to end, any
agent can be added or paused without rewiring the others, and the entire history
of a case can be replayed from the log.

### Human-in-the-loop on consequences
Agents *propose* actions; people *approve* them. Anything with real-world impact
(containing a host, blocking an indicator) is recorded as a proposed action and
gated on a human decision — captured with who approved it, when, and why.

### A red-team agent in the loop
A red-team perspective runs alongside the defensive agents in shadow mode,
stress-testing verdicts instead of rubber-stamping them.

### Case memory — agents that remember
Every worked case is recorded: each role's verdict, confidence, evidence, the
tools it called, and the human decisions on top. That record powers the
cross-incident features below — agents recall similar prior cases as precedent
instead of treating every alert as the first one they've ever seen.

---

## What you can see

### Outcome Trends
A windowed rollup (7 / 30 / 90 days) of how the team is actually doing: cases
worked, verdict / severity / disposition mix, the top actors and recurring
indicators across cases, the human approval rate, and the LLM token cost broken
out per role.

### Case Interrogation
Look up any ticket the agents have worked and get the **recorded reasoning
trace** — each role's decision and stated reason, the evidence it cited, the
human-in-the-loop actions, and a decision timeline. It's read from what actually
happened, not a fresh guess, so "why was this host contained?" has a cited
answer.

### Per-role accuracy
Where ground-truth labels exist, each agent's verdicts are scored against them
and surfaced as a per-role accuracy card — an honest read on which roles are
pulling their weight.

### Campaign Radar
Cross-incident clustering: when several cases share strong indicators (an actor,
a named campaign, a hash, a domain), they're surfaced as one campaign — the view
no single analyst working one ticket ever gets.

### Augmentation status
A status strip shows whether precedent features (case recall, SOP awareness) are
live, so what you see on the page always reflects how the agents are actually
running.

---

## Design notes

- **A team, not a classifier.** The value is in the hand-offs, the escalation,
  and the disagreement — modeling how a shift works a case, not how a model
  labels an alert.
- **Replayable by construction.** Event-sourcing means every case can be
  reconstructed from the log; nothing about a verdict is lost or implicit.
- **Honest about accuracy.** Scoring the agents' own verdicts against ground
  truth — and publishing it — is the point, not a footnote.
- **Memory beats amnesia.** Recalling prior cases as precedent is what lets the
  agents get *better* over a campaign instead of re-deriving the same conclusion
  ticket by ticket.

---

[Read the deep-dive →](https://vinayvobbili.github.io/posts/soc-in-a-box-case-memory/) · [← Back to Features](index)
