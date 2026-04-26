# Security Operations Automation Platform

An enterprise-grade security operations platform that automates and orchestrates SOC workflows across 30+ integrated tools. It pairs an LLM-powered investigation engine with self-healing chat bots, an MCP-based agent toolbox, and a library of n8n automations.

[**Documentation**](https://vinayvobbili.github.io/security-ops-platform) ·
[Architecture](https://vinayvobbili.github.io/security-ops-platform/architecture) ·
[Features](https://vinayvobbili.github.io/security-ops-platform/features/)

---

## At a glance

| Capability | Count |
|---|---|
| Security tool integrations | 30+ |
| MCP server tools | 31 |
| LLM investigation tools | 36 |
| Production chat bots (Webex + Teams) | 14 |
| Web app pages | 80+ |
| n8n automation workflows | 35 |

---

## What it does

Modern SOC teams juggle dozens of disconnected tools, drown in repetitive triage, and lose hours to context switching. This platform attacks all three:

- **Unifies the toolbox.** One Python codebase wraps EDR, SIEM, SOAR, threat intel, ITSM, identity, and email-security APIs behind a consistent client pattern (retry, pooling, OAuth2 token caching).
- **Delegates triage to LLMs.** A LangChain-based investigation engine answers analyst questions in natural language, calling 36 tools across the security stack to gather and correlate evidence.
- **Automates the rest.** 35 ready-to-import n8n workflows handle alert routing, IOC sync, threat-intel ingestion, ticket enrichment, SLA tracking, and shift handoffs.

---

## Core capabilities

### LLM-Powered Security Assistant
RAG-backed investigation engine using LangChain with native tool calling. Analysts query in plain English; the engine retrieves relevant runbooks, picks tools, executes in parallel, and synthesizes a response. Local inference via mlx-lm on Apple Silicon, ChromaDB for vector search.
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/llm-assistant)

### Model Context Protocol (MCP) Server
A standalone MCP server exposing 31 security tools via a single uniform schema — drop into Claude Desktop, Cline, or any MCP-aware agent and instantly get the full investigation toolbox.
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/mcp-server)

### Self-Healing Chat Bots
14 production bots across Webex and Microsoft Teams. WebSocket keep-alive, exponential-backoff reconnect with jitter, connection pooling, circuit breakers, and a dedicated REST API for monitoring and control. Built to survive overnight without an operator.
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/webex-bots)

### Real-Time SOC Dashboard
Flask web app with 80+ pages covering ticket aging, MTTR/MTTC trending, detection-rule catalogs, domain monitoring, alert volume analytics, and shift performance.
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/soc-dashboard)

### n8n Workflow Automation
35 importable workflows for alert routing/dedup, incident escalation and war-room creation, IOC sync, dark-web monitoring, scheduled threat hunting, ticket enrichment, SLA tracking, shift handoffs, asset inventory, and offboarding checks.
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/n8n-workflows)

### Customer Assurance Workspace
Web-based intake plus LLM-assisted drafting for customer security questionnaires. Routes incoming requests, generates first-pass answers grounded in your controls knowledge base, and lets reviewers refine before export.
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/customer-assurance)

### Domain Threat Monitoring
Multi-source monitoring with automated correlation across Certificate Transparency (Censys + CertStream), WHOIS change tracking, dark-web feeds, abuse feeds, and lookalike/typosquat detection — with chat alerting on hits.
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/domain-monitoring)

### 30+ Security Integrations
Unified API clients across EDR/XDR (CrowdStrike Falcon + RTR, Tanium, Vectra), SIEM (QRadar, Cortex XSIAM), SOAR (Cortex XSOAR), case management (DFIR-IRIS, TheHive), threat intel (Recorded Future, VirusTotal, URLScan, AbuseIPDB, Abuse.ch, IntelX, Shodan, HIBP), BAS (AttackIQ), identity (Active Directory, Varonis), email security (Abnormal, Zscaler), and ITSM (ServiceNow).
[Read more →](https://vinayvobbili.github.io/security-ops-platform/features/integrations)

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    User Interface Layer                       │
│   ┌────────────────┐    ┌────────────────┐    ┌────────────┐ │
│   │ Web Dashboard  │    │   Chat Bots    │    │ MCP Clients│ │
│   │ (Flask, 80+ pp)│    │ (Webex + Teams)│    │ (Claude++) │ │
│   └────────┬───────┘    └────────┬───────┘    └─────┬──────┘ │
└────────────┼─────────────────────┼──────────────────┼────────┘
             │                     │                  │
┌────────────▼─────────────────────▼──────────────────▼────────┐
│                          AI/ML Layer                          │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐ │
│  │ LangChain  │ │ RAG Engine │ │ MCP Server │ │ 36 Agent   │ │
│  │Orchestrator│ │ (ChromaDB) │ │ (FastMCP)  │ │ Tools      │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘ │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│                      Integration Layer                        │
│   EDR/XDR │ SIEM/SOAR │ Threat Intel │ ITSM │ Identity │ +   │
│   ───────────────────────────────────────────────────────    │
│           30+ security tool APIs, one unified client pattern  │
└──────────────────────────────────────────────────────────────┘
```

[Detailed architecture →](https://vinayvobbili.github.io/security-ops-platform/architecture)

---

## Tech stack

- **Backend**: Python 3.10+, Flask, Waitress
- **AI/ML**: LangChain, mlx-lm (Apple Silicon), ChromaDB, FastMCP
- **Communication**: Webex Teams SDK, Microsoft Bot Framework
- **Workflow**: n8n
- **Data**: Pandas, NumPy, SQLite
- **Quality**: Black, flake8, mypy, bandit, pytest
- **Deployment**: Docker, systemd, GitHub Actions

---

## Quickstart

```bash
# Clone
git clone https://github.com/vinayvobbili/security-ops-platform.git
cd security-ops-platform

# Virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Dependencies
pip install -r requirements.txt

# Configure
cp data/samples/.env.sample .env
# edit .env with your API credentials

# Run the web dashboard
python web/app.py
```

The web app comes up on port 8080 by default. Bots, the MCP server, and the scheduler each ship with systemd unit files under `deployment/systemd/` for production deployment.

---

## Project structure

```
security-ops-platform/
├── services/         # 30+ API clients (EDR, SIEM, SOAR, threat intel, ITSM, ...)
├── my_bot/           # LLM orchestration (LangChain + RAG + 36 tools)
│   ├── core/         # Tool binding, agent loop, state management
│   ├── tools/        # Investigation tools (one per security capability)
│   └── document/     # RAG document processing (ChromaDB)
├── mcp_server/       # FastMCP server exposing 31 security tools
├── webex_bots/       # Webex bot implementations + shared base classes
├── teams_bots/       # Microsoft Teams bot implementations
├── web/              # Flask web app
│   ├── app.py        # Application entrypoint
│   ├── routes/       # Blueprint-organized API + page routes
│   ├── templates/    # 80+ Jinja2 templates
│   └── static/       # CSS, JS, assets
├── n8n_workflows/    # 35 importable n8n workflow JSON files
├── src/              # Core logic, charts, components, utilities
├── deployment/       # systemd unit files, deployment scripts
├── docs/             # Jekyll source for the documentation site
└── tests/            # Test suite
```

---

## Documentation

The full docs live at **[vinayvobbili.github.io/security-ops-platform](https://vinayvobbili.github.io/security-ops-platform)**.

- [Home](https://vinayvobbili.github.io/security-ops-platform) — overview and headline metrics
- [Architecture](https://vinayvobbili.github.io/security-ops-platform/architecture) — detailed layering, data flow, design patterns
- [Features](https://vinayvobbili.github.io/security-ops-platform/features/) — deep-dives on each capability

---

## Contributing

Contributions are welcome. Please:

- Match the existing code style (Black + flake8 enforced in CI)
- Add tests for new functionality
- Update relevant docs under `docs/` if you add or change a capability
- Use descriptive commit messages

---

## License

MIT — see [LICENSE](LICENSE).

You can use, modify, and distribute this code freely. Just keep the copyright notice.
