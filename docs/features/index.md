---
layout: doc
title: Features
---

# Platform Features

Explore the core capabilities of the Security Operations Automation Platform.

---

## Feature Overview

| Feature | Description |
|---------|-------------|
| [SOC-in-a-Box](soc-in-a-box) | Multi-agent SOC over an event bus — triage → IR → hunt with human-in-the-loop, case memory, and per-role accuracy |
| [LLM-Powered Assistant](llm-assistant) | AI investigation engine with 40 security tools |
| [MCP Server](mcp-server) | 31 tools exposed via Model Context Protocol; public mode with per-user PATs |
| [Self-Healing Bots](webex-bots) | 10 production chat bots (Webex + Teams) with enterprise reliability |
| [SOC Dashboard](soc-dashboard) | Real-time metrics, dashboards, and 55+ web app pages |
| [30+ Integrations](integrations) | Unified security tool ecosystem |
| [Domain Monitoring](domain-monitoring) | Discover → weaponization triage → exposure hunt → block/takedown → campaign clustering (powered by `domainflow`) |
| [Vulnerability Deep Dive](vulnerability-deep-dive) | CVE → P1–P4 verdict (EPSS/KEV/pre-auth) + which apps are affected |
| [Threat Hunt Workbench](hunt-workbench) | Paste CTI → IOC fan-out + behavioral SIEM hunts + ATT&CK coverage |
| [Detection as Code](detection-as-code) | Sigma → lint → compile → live dry-run → review → MR (powered by `detflow`) |
| [Advisory Triage](advisory-triage) | Triage command center → "Affects us" verdict + ATT&CK + Sigma/YARA/Suricata + STIX/Navigator → verify-remediation → escalation (powered by `detflow`) |
| [Customer Assurance](customer-assurance) | LLM-assisted questionnaire drafting with `.xlsx` round-trip |
| [Code Security Scanner](code-security) | Agentic read-only repo vuln audit — navigate → refute false positives → container-jailed (powered by `refutescan`) |
| [Third-Party Risk](third-party-risk) | Vendor cyber due-diligence workspace — drafts control answers from evidence (powered by `attestq`) |
| [Ambient Assistant](ambient-assistant) | Proactive room watcher — gist synthesis + screenshot vision → auto-run read-only lookups → threaded follow-ups + human-in-the-loop "Run it" cards |
| [Security Training](lessons) | Interactive SOC lessons → fresh auto-graded mixed-format quizzes → completion certificate, with anti-cheat + admin analytics (powered by `quizforge`) |
| Person-of-Interest OSINT | Streaming investigation page with HIBP, holehe, maigret, dorks + LLM commentary |
| Self-Serve Auth + PATs | Register/login/verify, per-user PATs, admin console, role-gated routes |
| [n8n Workflows](n8n-workflows) | 33 automation workflows for SOC operations |

---

## Quick Links

### [SOC-in-a-Box →](soc-in-a-box)

A team of specialized AI agents working a case together:
- Triage, Tier-2, IR Lead, Threat Intel, Threat Hunter, Detection Eng + SOC Manager
- Event-sourced bus — every case is auditable and replayable end to end
- Human-in-the-loop on every consequential action
- Case memory: agents recall similar prior cases as precedent
- Outcome trends, case interrogation, per-role accuracy, and campaign clustering

### [LLM-Powered Security Assistant →](llm-assistant)

AI-powered investigation using RAG and LangChain:
- Natural language security queries
- 40 specialized investigation tools (CrowdStrike, DFIR-IRIS, TheHive, XSOAR, and more)
- Automated IOC enrichment
- LLM-powered threat intel novelty analysis

### [Self-Healing Bot Architecture →](webex-bots)

10 production chat bots (Webex + Microsoft Teams) with:
- WebSocket keep-alive and auto-reconnect
- Connection pooling and circuit breakers
- Bot Status REST API for monitoring and control
- Health monitoring

### [Real-Time SOC Dashboard →](soc-dashboard)

Interactive web interface providing:
- Ticket aging and SLA tracking
- MTTR/MTTC trending
- Detection rules catalog
- Domain monitoring results

### [Security Integrations →](integrations)

30+ unified API clients for:
- EDR/XDR and case management (DFIR-IRIS, TheHive)
- SIEM, SOAR, and threat intelligence
- BAS (AttackIQ), identity (Active Directory, Varonis)
- Domain security (cert transparency, WHOIS, lookalike detection)
- Dark web monitoring

### [Model Context Protocol (MCP) Server →](mcp-server)

A standalone MCP server (`mcp_server/`) exposing 31 security tools to any
MCP-compatible client. One uniform schema across the entire stack — drop
into Claude Desktop, Cline, or any agent framework that speaks MCP and
get instant access to the full investigation toolbox.

### [Customer Assurance Workspace →](customer-assurance)

Web-based intake + LLM-assisted drafting for customer security questionnaires.
Auto-extracts questions from uploaded vendor `.xlsx` files, drafts first-pass
answers grounded in your controls knowledge base, lets reviewers refine, and
round-trips final answers back into the customer's original spreadsheet at
the same row + response column they came from.

### [n8n Workflow Automation →](n8n-workflows)

33 ready-to-import workflows covering:
- Alert routing, deduplication, and escalation
- Threat intel IOC sync and dark web monitoring
- Scheduled threat hunting and detection testing
- Ticket enrichment, SLA tracking, and shift handoffs

### [Domain Threat Monitoring →](domain-monitoring)

Brand-protection monitoring that goes past "a lookalike exists":
- Lookalike discovery powered by the open-source `domainflow` engine
- Weaponization triage (P1–P4) and a "were we touched?" SIEM/EDR hunt
- One-click XSOAR block + PhishFort takedown with SLA metrics
- Campaign clustering of coordinated waves by shared infrastructure
- Certificate Transparency, WHOIS, dark web, and abuse-feed correlation

### [Vulnerability Deep Dive →](vulnerability-deep-dive)

War-room CVE triage with a prioritized verdict:
- NVD / CVE.org / SCA fact-gathering with EPSS, KEV, and pre-auth signals
- LLM P1–P4 priority + attack-layer mapping
- "Which apps are affected?" via Veracode SCA + JFrog Xray exposure
- Batch, fill-holes, and re-enrich passes

### [Threat Hunt Workbench →](hunt-workbench)

On-demand analyst hunting from a paste:
- IOC extraction + live fan-out across threat-intel services
- LLM-authored **behavioral** SIEM hunts ("were we touched?")
- ATT&CK coverage-vs-rules ("can we detect this?")
- Async worker + persisted hunt history

### [Detection as Code →](detection-as-code)

Sigma → reviewed, packaged merge request:
- Lint → LLM compile to XQL → **real read-only dry-run** on the live SIEM
- LLM senior-engineer review with FP, ATT&CK, and catalog-overlap checks
- Human-gated GitLab MR; built on the open-source `detflow` core

### [Security Advisory Triage →](advisory-triage)

A triage command center that works advisories instead of just listing them:
- Dense queue with an "Affects us" verdict on every row, saved views, and
  bulk assign / close / escalate
- Per-advisory ATT&CK mapping + generated Sigma / YARA / Suricata rules
- STIX 2.1 bundle and ATT&CK Navigator layer exports
- Exposure at a glance via Veracode SCA + fleet posture, with one-click
  verify-remediation re-checks
- Cross-source corroboration, campaign clustering, and one-click escalation
- Built on the open-source `detflow` analysis core

### [Security Training & Readiness →](lessons)

Interactive analyst training that ends in a graded readiness check:

- Per-topic prep pages — training video, why-it's-risky, key concepts
- Mixed-format quizzes (multiple choice, fill-in-the-blank, match, short
  and free-response) sampled fresh and shuffled from a deep per-topic bank,
  so two analysts rarely see the same test and retakes stay novel
- Open answers graded on concepts (0..1 with feedback) by the local LLM;
  closed formats graded deterministically — 60% to pass, 80% for distinction
- Branded completion certificate (web + PDF) with a tamper-evident
  verification code, and a 30-minute timer that auto-submits at zero
- Anti-cheat fast-pass detection plus an admin command center with
  per-lesson trends and Excel export
- Generation, sampling, grading, and integrity policy delegate to the
  open-source `quizforge` core

### Person-of-Interest OSINT Tool

Streaming OSINT investigation page that pivots from a single seed identifier
(name, email, username, or domain) to a multi-source profile:

- HIBP breach lookups for exposed credentials
- `holehe` and `maigret` account-existence probing across 100+ sites
- Targeted Google dorks generated per seed type
- LLM-driven results commentary as the scan completes
- Force-directed graph view of discovered identities with a custom
  spoke-wheel layout for readability

### Self-Serve Auth + Personal Access Tokens

Production-grade auth layer fronting the platform:

- Register / verify-email / login / forgot-password flow
- Per-user Personal Access Tokens minted from `/account`
- Same PAT unlocks the Claude-Code local-LLM proxy and the public MCP
  endpoint — no service-bearer sharing
- Admin role with `/admin-users` console: PAT activity, role pills,
  one-click MCP setup snippets for bash / PowerShell / cmd shells
- 7-day sliding session, audit-trail webhooks for new logins and new
  PATs

---

[← Back to Home](/)
