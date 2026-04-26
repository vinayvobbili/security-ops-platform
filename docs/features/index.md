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
| [LLM-Powered Assistant](llm-assistant) | AI investigation engine with 36 security tools |
| [MCP Server](mcp-server) | 31 tools exposed via Model Context Protocol |
| [Self-Healing Bots](webex-bots) | 14 production chat bots (Webex + Teams) with enterprise reliability |
| [SOC Dashboard](soc-dashboard) | Real-time metrics, dashboards, and 80+ web app pages |
| [30+ Integrations](integrations) | Unified security tool ecosystem |
| [Customer Assurance](customer-assurance) | LLM-assisted questionnaire response drafting |
| [n8n Workflows](n8n-workflows) | 35 automation workflows for SOC operations |
| [Domain Monitoring](domain-monitoring) | Multi-source domain threat monitoring |

---

## Quick Links

### [LLM-Powered Security Assistant →](llm-assistant)

AI-powered investigation using RAG and LangChain:
- Natural language security queries
- 36 specialized investigation tools (CrowdStrike, DFIR-IRIS, TheHive, XSOAR, and more)
- Automated IOC enrichment
- LLM-powered threat intel novelty analysis

### [Self-Healing Bot Architecture →](webex-bots)

14 production chat bots (Webex + Microsoft Teams) with:
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
Routes incoming requests, generates first-pass answers grounded in your
existing controls knowledge base, and lets reviewers refine before export.

### [n8n Workflow Automation →](n8n-workflows)

35 ready-to-import workflows covering:
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

---

[← Back to Home](/)
