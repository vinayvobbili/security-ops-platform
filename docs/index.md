---
layout: default
title: Home
---

# Security Operations Automation Platform

An enterprise-grade security operations platform that automates and orchestrates security workflows across 30+ integrated tools, featuring LLM-powered intelligence, an MCP-based agent toolbox, self-healing bot architecture, and 35 n8n automation workflows.

---

## Key Highlights

| Metric | Value |
|--------|-------|
| **Security Tool Integrations** | 30+ |
| **MCP Server Tools** | 31 |
| **LLM Investigation Tools** | 36 |
| **Production Chat Bots** | 14 (Webex + Teams) |
| **Web App Pages** | 80+ |
| **n8n Automation Workflows** | 35 |

---

## What This Platform Does

This platform addresses three critical challenges in modern security operations:

### 1. Integration Complexity
Security teams juggle dozens of disconnected tools. This platform unifies **30+ security tools** into cohesive, automated workflows - from EDR and SIEM to threat intelligence and ticketing systems.

### 2. Response Time
Manual investigation and response is slow. By automating routine tasks and leveraging AI for triage, this platform **significantly reduces Mean Time to Respond (MTTR)**.

### 3. Analyst Workload
SOC analysts face alert fatigue and repetitive queries. **LLM-powered assistants** handle routine investigations, freeing analysts for complex threats.

---

## Core Capabilities

### LLM-Powered Security Assistant

An AI investigation engine using Retrieval-Augmented Generation (RAG) that can:

- Query endpoint status across EDR platforms
- Search SIEM logs and investigate alerts
- Enrich indicators with threat intelligence
- Check credential breaches
- Create and update tickets automatically

[Learn more about the LLM Assistant →](features/llm-assistant)

### Self-Healing Bot Architecture

Production-grade chat bots with enterprise reliability features:

- WebSocket keep-alive and auto-reconnect
- Connection pooling and circuit breakers
- Exponential backoff with jitter
- Health monitoring and graceful degradation

[Learn more about Bot Architecture →](features/webex-bots)

### Model Context Protocol (MCP) Server

A standalone MCP server that exposes the full security toolbox to any
MCP-compatible client (Claude Desktop, Cline, etc.). 31 tools spanning EDR,
SIEM, SOAR, threat intel, ITSM, identity, and email security — all using a
single uniform schema.

### Customer Assurance Workspace

Web-based intake + LLM-assisted drafting for customer security questionnaires.
Routes incoming requests, generates first-pass answers grounded in your
existing controls knowledge base, and lets reviewers refine before export.

### Real-Time SOC Dashboard

Interactive web dashboard providing:

- Ticket aging and SLA tracking
- MTTR/MTTC trending analysis
- Alert volume analytics
- Team performance metrics

[Learn more about the Dashboard →](features/soc-dashboard)

### n8n Workflow Automation

35 ready-to-import automation workflows covering the full SOC lifecycle:

- Alert routing and deduplication
- Incident escalation and war room creation
- Threat intel IOC sync and dark web monitoring
- Scheduled threat hunting and detection testing
- Ticket enrichment, SLA tracking, and shift handoff reports
- Asset inventory sync and user offboarding checks

### Domain Threat Monitoring

Multi-source domain monitoring with automated correlation across Certificate Transparency, WHOIS, dark web, abuse feeds, and lookalike detection with Webex alerting.

### 30+ Security Integrations

Unified API clients for the security ecosystem:

| Category | Tools |
|----------|-------|
| **EDR/XDR** | CrowdStrike Falcon (+ RTR), Tanium, Vectra |
| **SIEM** | IBM QRadar, Cortex XSIAM |
| **SOAR** | Cortex XSOAR |
| **Case Management** | DFIR-IRIS, TheHive |
| **Threat Intel** | Recorded Future, VirusTotal, URLScan, AbuseIPDB, Abuse.ch, IntelX, Shodan, HIBP |
| **BAS** | AttackIQ |
| **Identity / Data** | Active Directory, Varonis |
| **Domain Security** | Certificate Transparency, WHOIS, Domain Lookalike Detection |
| **Email Security** | Abnormal Security |
| **ITSM** | ServiceNow |

[View all integrations →](features/integrations)

---

## Technical Stack

- **Backend**: Python 3.10+, Flask
- **AI/ML**: LangChain, mlx-lm (Apple Silicon), ChromaDB, FastMCP
- **Communication**: Webex Teams SDK, Microsoft Teams Bot Framework
- **Workflow**: n8n
- **Data Processing**: Pandas, NumPy
- **Quality**: Black, flake8, mypy, bandit
- **CI/CD**: GitHub Actions
- **Deployment**: Docker, Systemd

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interface Layer                      │
│     ┌──────────────────┐      ┌──────────────────┐         │
│     │  Web Dashboard   │      │   Chat Bots      │         │
│     │  (Flask)         │      │   (Webex)        │         │
│     └────────┬─────────┘      └────────┬─────────┘         │
└──────────────┼─────────────────────────┼───────────────────┘
               │                         │
┌──────────────▼─────────────────────────▼───────────────────┐
│                      AI/ML Layer                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐     │
│  │ LangChain   │  │ RAG Engine  │  │ 30+ Security    │     │
│  │ Orchestrator│  │ (ChromaDB)  │  │ Tools (MCP)     │     │
│  └─────────────┘  └─────────────┘  └─────────────────┘     │
└────────────────────────────┬───────────────────────────────┘
                             │
┌────────────────────────────▼───────────────────────────────┐
│                   Integration Layer                         │
│   EDR/XDR  │  SIEM/SOAR  │  Threat Intel  │  ITSM         │
│   ────────────────────────────────────────────────         │
│   30+ Security Tool APIs with Unified Interface            │
└────────────────────────────────────────────────────────────┘
```

[View detailed architecture →](architecture)

---

## Getting Started

> **Just want Claude Code on your own LLM?** If you came here for Anthropic's CLI
> agent pointed at a self-hosted local model (mlx-lm, Ollama, vLLM, anything
> behind a LiteLLM shim) instead of the full platform, jump to
> **[Claude Code + Local LLM Setup](CLAUDE_CODE_SETUP)** — install, env-var
> config, the protocol shim, and a 2-minute tutorial. The steps below are for
> running this repo's web app.

```bash
# Clone the repository
git clone https://github.com/vinayvobbili/security-ops-platform.git
cd security-ops-platform

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp data/samples/.env.sample .env
# Edit .env with your API credentials

# Start web dashboard
python web/app.py
```

---

## Project Links

- [GitHub Repository](https://github.com/vinayvobbili/security-ops-platform)
- [Architecture Documentation](architecture)
- [Feature Deep-Dives](features/)
- [About the Author](about)

---

*Built with Python, Flask, LangChain, and enterprise-grade reliability patterns. Designed for production SOC environments.*
