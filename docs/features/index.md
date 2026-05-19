---
layout: default
title: Features
---

# Platform Features

Explore the core capabilities of the Security Operations Automation Platform.

---

## Feature Overview

| Feature | Description |
|---------|-------------|
| [LLM-Powered Assistant](llm-assistant) | AI investigation engine with 38 security tools |
| [MCP Server](mcp-server) | 30 tools exposed via Model Context Protocol; public mode with per-user PATs |
| [Self-Healing Bots](webex-bots) | 10 production chat bots (Webex + Teams) with enterprise reliability |
| [SOC Dashboard](soc-dashboard) | Real-time metrics, dashboards, and 40+ web app pages |
| [30+ Integrations](integrations) | Unified security tool ecosystem |
| [Customer Assurance](customer-assurance) | LLM-assisted questionnaire drafting with `.xlsx` round-trip |
| Person-of-Interest OSINT | Streaming investigation page with HIBP, holehe, maigret, dorks + LLM commentary |
| Self-Serve Auth + PATs | Register/login/verify, per-user PATs, admin console, role-gated routes |
| [n8n Workflows](n8n-workflows) | 33 automation workflows for SOC operations |
| [Domain Monitoring](domain-monitoring) | Multi-source domain threat monitoring |

---

## Quick Links

### [LLM-Powered Security Assistant →](llm-assistant)

AI-powered investigation using RAG and LangChain:
- Natural language security queries
- 38 specialized investigation tools (CrowdStrike, DFIR-IRIS, TheHive, XSOAR, and more)
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

Multi-source domain security monitoring:
- Certificate Transparency (Censys + CertStream)
- Domain lookalike and typosquat detection
- WHOIS registration change tracking
- Dark web and abuse feed correlation

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
