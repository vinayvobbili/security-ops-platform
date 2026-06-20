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
| [LLM-Powered Assistant](llm-assistant) | AI investigation engine with 39 security tools |
| [MCP Server](mcp-server) | 30 tools exposed via Model Context Protocol; public mode with per-user PATs |
| [Self-Healing Bots](webex-bots) | 10 production chat bots (Webex + Teams) with enterprise reliability |
| [SOC Dashboard](soc-dashboard) | Real-time metrics, dashboards, and 50+ web app pages |
| [30+ Integrations](integrations) | Unified security tool ecosystem |
| [Domain Monitoring](domain-monitoring) | Discover → weaponization triage → exposure hunt → block/takedown → campaign clustering (powered by `domainflow`) |
| [Vulnerability Deep Dive](vulnerability-deep-dive) | CVE → P1–P4 verdict (EPSS/KEV/pre-auth) + which apps are affected |
| [Threat Hunt Workbench](hunt-workbench) | Paste CTI → IOC fan-out + behavioral SIEM hunts + ATT&CK coverage |
| [Detection as Code](detection-as-code) | Sigma → lint → compile → live dry-run → review → MR (powered by `detflow`) |
| [Advisory Triage](advisory-triage) | Advisory queue → ATT&CK + Sigma/YARA/Suricata + STIX/Navigator + blast radius → escalation (powered by `detflow`) |
| [Customer Assurance](customer-assurance) | LLM-assisted questionnaire drafting with `.xlsx` round-trip |
| Person-of-Interest OSINT | Streaming investigation page with HIBP, holehe, maigret, dorks + LLM commentary |
| Self-Serve Auth + PATs | Register/login/verify, per-user PATs, admin console, role-gated routes |
| [n8n Workflows](n8n-workflows) | 33 automation workflows for SOC operations |

---

## Quick Links

### [LLM-Powered Security Assistant →](llm-assistant)

AI-powered investigation using RAG and LangChain:
- Natural language security queries
- 39 specialized investigation tools (CrowdStrike, DFIR-IRIS, TheHive, XSOAR, and more)
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

A standalone MCP server (`mcp_server/`) exposing 30 security tools to any
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

A standing queue that works advisories instead of just listing them:
- Per-advisory ATT&CK mapping + generated Sigma / YARA / Suricata rules
- STIX 2.1 bundle and ATT&CK Navigator layer exports
- Blast radius: app ownership, fleet posture, attack-surface exposure
- Cross-source corroboration, campaign clustering, and one-click escalation
- Built on the open-source `detflow` analysis core

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
