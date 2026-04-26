---
layout: default
title: Domain Threat Monitoring
---

# Domain Threat Monitoring

Multi-source domain monitoring with automated correlation across Certificate Transparency, WHOIS, dark-web feeds, abuse feeds, and lookalike/typosquat detection — with chat alerting on hits.

---

## Why domain monitoring matters

Brand-impersonation domains are cheap to register and high-yield for attackers (phishing, credential harvesting, fake support). The window between a hostile domain showing up in a CT log and an attacker weaponizing it is often hours. Manual review can't keep up; you need a pipeline that watches every relevant feed continuously and only surfaces the things a human should look at.

---

## Sources

| Source | What it catches |
|---|---|
| **Certificate Transparency (Censys)** | New SSL certs issued for monitored domains or lookalike patterns |
| **CertStream** | Real-time CT log stream with low-latency match alerts |
| **WHOIS change tracking** | Registrant, registrar, or nameserver changes on watched domains |
| **dnstwist lookalikes** | Typosquat/homoglyph permutations of brand domains |
| **Abuse feeds (Abuse.ch, AbuseIPDB)** | Confirmed-malicious correlation with monitored domain set |
| **IntelX dark web** | Domain mentions in leak databases and dark-web sources |

---

## Pipeline

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│   Censys   │  │ CertStream │  │   WHOIS    │  │  dnstwist  │
│    CT      │  │   stream   │  │   poll     │  │  permute   │
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
                   │  Score & classify  │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │  Persist + alert   │
                   │   (DB + Webex)     │
                   └────────────────────┘
```

### 1. Collect
Every source runs on its own cadence — CertStream is real-time, Censys polls every few minutes, WHOIS runs daily for the watched-domain set, dnstwist generates permutations on demand and again on schedule.

### 2. Match
Each new artifact is scored against the watchlist. The watchlist is a structured set of patterns (exact domain, regex, dnstwist algorithm output) with severity weights.

### 3. Enrich
Suspected hits get enriched with threat-intel context: registrar reputation, certificate issuer, known-bad nameservers, and Recorded Future / VirusTotal lookups.

### 4. Score & alert
A simple scoring rubric (lookalike algorithm + registrar reputation + cert issuer + age + TI hits) drives alert severity. High-severity hits route to a chat room with a one-click "open ticket" button; low-severity hits land in the dashboard for review.

---

## Dashboard

The web app exposes a domain-monitoring page that lets reviewers:

- Browse the current watchlist and add/remove patterns
- Triage recent hits with the full enrichment context
- Mark hits as benign / suspicious / malicious (feeds the scoring model)
- Drill into the source artifact (cert details, WHOIS record, dnstwist diff)

---

## n8n workflows that touch this

| Workflow | Role |
|---|---|
| `cert_transparency_monitor` | Pulls Censys CT data into the pipeline on schedule |
| `domain_typosquat_monitor` | Runs dnstwist for the watchlist and feeds matches to the DB |
| `intelx_dark_web_monitor` | Searches IntelX for monitored domain mentions |

See the [n8n Workflows page](n8n-workflows) for the full list.

---

## Design notes

- **Why multiple sources?** Each feed has different latency and false-positive characteristics. CertStream is fast but noisy; Censys is comprehensive but lagged; WHOIS is slow-moving but high-signal for established attacks. Correlating across sources is what turns "noise" into "alert."
- **Why store everything?** The watchlist and scoring change over time. Keeping the raw artifacts means you can re-score historical hits when you tune the rubric.
- **Why chat alerts, not email?** Domain hits need fast triage. Chat lets the analyst, the on-call, and any responder converge on the artifact in one thread.

---

[← Back to Features](index)
