---
layout: doc
title: Domain Threat Monitoring
---

# Domain Threat Monitoring

Brand-protection monitoring that doesn't stop at "a lookalike exists" — it
discovers impersonation domains, decides whether they're **weaponized**, checks
whether **you were touched**, drives the **block + takedown**, and groups
coordinated waves into **campaigns**. Correlated across Certificate
Transparency, WHOIS, dark-web and abuse feeds, with chat alerting on hits.

The lookalike engine is the open-source
[**domainflow**](https://pypi.org/project/domainflow/) toolkit
(discover / monitor / score / cluster), extracted from this portal and wired in
behind a thin adapter.

---

## Why domain monitoring matters

Brand-impersonation domains are cheap to register and high-yield for attackers
(phishing, credential harvesting, fake support). The window between a hostile
domain showing up in a CT log and an attacker weaponizing it is often hours.
Manual review can't keep up — and a list of "similar-looking domains" with no
verdict just moves the triage burden onto the analyst. The pipeline here is
built to answer the questions an analyst actually has: *is it live, is it after
us, did it hit anyone, and is it part of something bigger?*

---

## Sources

| Source | What it catches |
|---|---|
| **Certificate Transparency (crt.sh / Censys)** | New SSL certs issued for monitored domains or lookalike patterns |
| **CertStream** | Real-time CT log stream with low-latency match alerts |
| **WHOIS change tracking** | Registrant, registrar, or nameserver changes on watched domains |
| **Lookalike engine (domainflow)** | Homoglyph / typo / TLD-swap / brand+keyword permutations of brand domains, resolved for live DNS + MX |
| **Abuse feeds (Abuse.ch, AbuseIPDB)** | Confirmed-malicious correlation with the monitored domain set |
| **IntelX dark web** | Domain mentions in leak databases and dark-web sources |

---

## What it does

### 1. Discover
The lookalike engine generates the impersonation space for each brand — classic
typo-squats (homoglyph, omission, transposition, vowel-swap) plus
brand-impersonation combos (suspicious TLD swaps, `brand-login.com`-style
keyword combinations) — then resolves each candidate for live A/MX records so
only registered, reachable domains surface. A staggered scheduler spreads brands
across the morning so no single run blows its budget.

### 2. Weaponization triage
Each newly-active lookalike is scored from hard signals — is the page live, does
it have a password/login form, does the brand name appear, is it mail-capable
(MX/SPF/DMARC → BEC) — into a **P1–P4** tier, with an LLM verdict layered on top
of the deterministic heuristic. P1 = live credential-harvest clone; P4 =
registered placeholder.

### 3. IOC Hunt — "were we touched?"
For confirmed-weaponized domains, an IOC Hunt sweeps the SIEM/EDR for any
internal interaction with the hostile domain — turning "this domain is
dangerous" into "this domain was visited by N hosts." A pre-flight modal shows
the exact per-tool queries first, so the analyst can review them, open them as a
true deep-link straight into the QRadar or CrowdStrike console, or run the hunt
inline and get the result in plain terms: **0 hits**, or the hosts and users
that made contact.

### 4. Block + takedown
One-click XSOAR block raises the block ticket and links it back to the finding;
takedowns submit to PhishFort and the incident status is synced back into the
ledger so the report shows where each takedown actually stands.

### 5. Takedown SLA metrics
The leadership report computes turnaround: median time-to-respond
(detect → block/takedown), median time-to-takedown (submitted → resolved), % of
confirmed-active threats contained, and open-takedown aging.

### 6. Campaign clustering
Findings that share an actor's footprint — IP, registrant org, non-bulk
nameserver — are grouped into **campaigns** via union-find, so a coordinated
wave of fifty domains reads as one thing instead of fifty alerts. Noise
suppression (bulk registrars, shared parking IPs, privacy-proxy registrants,
over-shared pivots) keeps unrelated domains from collapsing together.

---

## Pipeline

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│  crt.sh /  │  │ CertStream │  │   WHOIS    │  │ domainflow │
│  Censys CT │  │   stream   │  │   poll     │  │  lookalike │
└──────┬─────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
       │              │               │               │
       └──────────────┴───────────────┴───────────────┘
                              │
                              ▼
                   ┌────────────────────┐
                   │  Match & dedupe    │
                   │  against watchlist │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │   Enrich with TI   │
                   │  (RF, VT, AbuseDB) │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │  Weaponization     │
                   │  score (P1–P4)     │
                   └─────────┬──────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
      ┌──────────────────┐     ┌────────────────────┐
      │ "Were we touched"│     │ Block + takedown   │
      │ SIEM/EDR hunt    │     │ (XSOAR + PhishFort)│
      └────────┬─────────┘     └─────────┬──────────┘
               └────────────┬────────────┘
                            ▼
                   ┌────────────────────┐
                   │  Findings ledger   │
                   │  + campaign cluster│
                   │  + SLA + alerting  │
                   └────────────────────┘
```

---

## Dashboard

The web app exposes a domain-monitoring page that lets reviewers:

- Browse the current watchlist and add/remove brands and patterns
- Triage recent findings with full enrichment + the P1–P4 weaponization verdict
- Fire an IOC Hunt (review queries, deep-link into the console, or run inline) and a one-click XSOAR block per finding
- Track takedown status synced live from PhishFort
- See coordinated waves grouped as campaigns
- Read a monthly Brand-Protection report with takedown SLA tiles
- Ask a built-in assistant grounded in the loaded scan ("which findings are highest-risk?", "draft a leadership summary"), plus a guided how-it-works walkthrough

A SQLite findings ledger underpins the dashboard so triage state, infrastructure
pivots, and SLA timestamps persist across runs.

---

## n8n workflows that touch this

| Workflow | Role |
|---|---|
| `cert_transparency_monitor` | Pulls CT data into the pipeline on schedule |
| `domain_typosquat_monitor` | Runs the lookalike engine for the watchlist and feeds matches to the DB |
| `intelx_dark_web_monitor` | Searches IntelX for monitored domain mentions |

See the [n8n Workflows page](n8n-workflows) for the full list.

---

## Design notes

- **Why a verdict, not just a list?** A pile of similar-looking domains is noise.
  Scoring each for *weaponization* is what lets the pipeline auto-escalate the
  P1 clones and leave the parked placeholders for batch review.
- **Why cluster?** Attackers register in waves on shared infrastructure. Grouping
  by shared IP/registrant/nameserver turns fifty alerts into one campaign with a
  story, and surfaces the pivot to block.
- **Why an open-source engine?** The discovery + clustering core is vendor-neutral
  and useful well beyond this portal, so it lives as the standalone
  [domainflow](https://pypi.org/project/domainflow/) package and is consumed here
  like any other dependency.
- **Why chat alerts, not email?** Domain hits need fast triage. Chat lets the
  analyst, the on-call, and any responder converge on the artifact in one thread.

---

[← Back to Features](index)
