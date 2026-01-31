# Security Operations Automation Platform

A comprehensive, enterprise-grade security operations automation platform featuring 30+ service integrations, LLM-powered security assistants, self-healing Webex bots, and real-time SOC dashboards.

[![CI Pipeline](https://github.com/vinayvobbili/security-ops-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/vinayvobbili/security-ops-platform/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Imports: isort](https://img.shields.io/badge/imports-isort-1674b1.svg)](https://pycqa.github.io/isort/)

---

## Overview

This platform automates and orchestrates security operations workflows, providing:
- **LLM-Powered Security Assistant** with 22 specialized investigation tools
- **10 Production Webex Bots** with self-healing WebSocket architecture
- **30+ Security Tool Integrations** (CrowdStrike, Tanium, QRadar, ServiceNow, etc.)
- **Real-time SOC Dashboards** with metrics, ticket aging, and trend analysis
- **Automated Incident Response** playbooks and workflows

---

## Key Features

### LLM-Powered Security Assistant

AI-powered security investigation using RAG (Retrieval-Augmented Generation):

| Tool | Description |
|------|-------------|
| CrowdStrike Tools | Host lookup, detection search, containment actions |
| QRadar Tools | Log search, offense investigation, AQL queries |
| Recorded Future | Threat intelligence, IOC enrichment, risk scoring |
| VirusTotal | Hash/URL/domain reputation analysis |
| ServiceNow | Asset lookup, ticket creation, CMDB queries |
| Tanium | Endpoint status, live queries, tag management |
| Shodan | Internet-facing asset discovery |
| AbuseIPDB | IP reputation and abuse reports |
| HIBP | Credential breach checking |
| + 13 more tools | Full investigation toolkit |

### Self-Healing Webex Bots

Production-grade bot architecture with enterprise reliability:

```
┌─────────────────────────────────────────────────────────────┐
│                    Bot Resilience Layer                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ WebSocket    │  │ Connection   │  │ Auto         │      │
│  │ Keep-alive   │  │ Pooling      │  │ Reconnect    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Exponential  │  │ Health       │  │ Graceful     │      │
│  │ Backoff      │  │ Monitoring   │  │ Degradation  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

**Available Bots:**
- `pokedex` / `hal9000` - LLM-powered security assistants
- `toodles` - Team collaboration and notifications
- `jarvis` - Automated security workflows
- `msoar` - XSOAR integration bot
- `barnacles` - Metrics and reporting
- `tars` / `money_ball` / `case` - Specialized operations

### Security Platform Integrations (30+)

| Category | Integrations |
|----------|-------------|
| **EDR/XDR** | CrowdStrike Falcon, Tanium (Cloud & On-Prem), Vectra |
| **SIEM** | IBM QRadar |
| **SOAR** | Cortex XSOAR, Custom Playbooks |
| **Threat Intel** | Recorded Future, VirusTotal, URLScan, AbuseIPDB, Abuse.ch, IntelX, Shodan |
| **Email Security** | Abnormal Security, Zscaler |
| **ITSM** | ServiceNow (CMDB, Incidents, Changes) |
| **Identity** | Have I Been Pwned (HIBP) |
| **Domain Security** | Certificate Transparency, WHOIS, Domain Lookalike Detection |
| **DevOps** | Azure DevOps |
| **Communication** | Webex, Email (OAuth2) |

### Real-Time SOC Dashboard

Flask-based web application with interactive visualizations:

- **Ticket Aging Analysis** - Track incident lifecycle and SLA compliance
- **MTTR/MTTC Metrics** - Mean time to respond and close trending
- **Volume Analytics** - Alert inflow/outflow patterns
- **Detection Efficacy** - Rule performance and noise analysis
- **Shift Performance** - Team and analyst productivity metrics
- **EPP Tagging Metrics** - Endpoint protection coverage

---

## Architecture

```mermaid
flowchart TB
    subgraph UI["User Interface Layer"]
        WEB[Web Dashboard<br/>Flask + Waitress]
        BOTS[Webex Bots<br/>10 Production Bots]
    end

    subgraph AI["AI/ML Layer"]
        LLM[LLM Orchestration<br/>LangChain + Ollama]
        RAG[RAG Pipeline<br/>ChromaDB + Embeddings]
        TOOLS[22 Security Tools<br/>Investigation Toolkit]
    end

    subgraph CORE["Core Services"]
        CACHE[Ticket Cache<br/>Thread-Safe Storage]
        METRICS[Metrics Engine<br/>MTTR/MTTC Analytics]
        SCHEDULER[Job Scheduler<br/>Automated Tasks]
    end

    subgraph INT["Integration Layer - 30+ Services"]
        direction LR
        EDR[EDR/XDR<br/>CrowdStrike, Tanium, Vectra]
        SIEM[SIEM/SOAR<br/>QRadar, XSOAR]
        INTEL[Threat Intel<br/>Recorded Future, VirusTotal]
        ITSM[ITSM<br/>ServiceNow]
    end

    WEB --> LLM
    BOTS --> LLM
    LLM --> RAG
    LLM --> TOOLS
    TOOLS --> CORE
    CORE --> INT

    classDef ui fill:#4a90d9,stroke:#2c5aa0,color:#fff
    classDef ai fill:#50c878,stroke:#228b22,color:#fff
    classDef core fill:#ffa500,stroke:#cc8400,color:#fff
    classDef int fill:#9370db,stroke:#6a0dad,color:#fff

    class WEB,BOTS ui
    class LLM,RAG,TOOLS ai
    class CACHE,METRICS,SCHEDULER core
    class EDR,SIEM,INTEL,ITSM int
```

### Data Flow

```mermaid
sequenceDiagram
    participant User
    participant Bot as Webex Bot
    participant LLM as LangChain Agent
    participant Tools as Security Tools
    participant APIs as External APIs

    User->>Bot: Security question
    Bot->>LLM: Process query
    LLM->>LLM: RAG context retrieval
    LLM->>Tools: Select appropriate tool
    Tools->>APIs: API call (with retry)
    APIs-->>Tools: Response
    Tools-->>LLM: Enriched data
    LLM-->>Bot: Formatted response
    Bot-->>User: Answer with context
```

---

## Project Structure

```
.
├── services/               # 30+ API client integrations
│   ├── crowdstrike.py     # CrowdStrike Falcon EDR
│   ├── tanium.py          # Tanium endpoint management
│   ├── qradar.py          # IBM QRadar SIEM
│   ├── service_now.py     # ServiceNow ITSM/CMDB
│   ├── recorded_future.py # Threat intelligence
│   ├── virustotal.py      # Malware analysis
│   ├── xsoar/             # Cortex XSOAR client
│   └── ...                # 23+ more integrations
│
├── webex_bots/            # 10 production Webex bots
│   ├── pokedex.py         # LLM security assistant
│   ├── hal9000.py         # Advanced LLM assistant
│   ├── toodles.py         # Team collaboration
│   └── ...                # 7 more specialized bots
│
├── my_bot/                # LLM/RAG implementation
│   ├── tools/             # 22 security investigation tools
│   ├── core/              # LLM orchestration
│   └── document/          # RAG document processing
│
├── src/
│   ├── components/        # Business logic modules
│   │   ├── tipper_analyzer/   # Threat intel analysis
│   │   ├── domain_monitoring/ # Domain security
│   │   └── web/              # Web handlers
│   ├── charts/            # Metrics visualizations
│   ├── secops/            # SOC operations modules
│   └── utils/             # Shared utilities
│
├── web/                   # Flask web application
│   ├── routes/            # API endpoints
│   ├── templates/         # HTML templates
│   └── static/            # CSS, JavaScript
│
├── tests/                 # pytest test suite
├── deployment/            # Systemd services, scripts
├── .github/workflows/     # CI/CD pipeline
└── Dockerfile             # Container deployment
```

---

## Quick Start

### Prerequisites

- Python 3.8+
- API credentials for integrated platforms
- Webex Bot tokens (for bot functionality)

### Installation

```bash
# Clone the repository
git clone https://github.com/vinayvobbili/security-ops-platform.git
cd security-ops-platform

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy sample environment file
cp data/samples/.env.sample .env
# Edit .env with your API credentials
```

### Running Components

```bash
# Start web dashboard
python web/web_server.py
# Access at http://localhost:5000

# Start LLM-powered bot
python webex_bots/pokedex.py

# Start all scheduled jobs
./startup_scripts/start_all_jobs.sh

# Run tests
pytest tests/ -v
```

### Docker Deployment

```bash
# Build image
docker build -t security-ops-platform .

# Run container
docker run -d -p 5000:5000 --env-file .env security-ops-platform
```

---

## Technical Highlights

### Enterprise Reliability Patterns

- **Retry with Exponential Backoff** - Configurable retry logic with jitter
- **Connection Pooling** - HTTP session reuse (60 max connections)
- **Circuit Breakers** - Graceful degradation on service failures
- **Thread-Safe Token Management** - File locking for OAuth token refresh
- **Atomic File Operations** - Write-to-temp + rename pattern

### Security Best Practices

- **OAuth2 Token Management** - Secure token caching and refresh
- **SSL/TLS Handling** - Certificate chain bundling for proxies
- **Encrypted Secrets** - Age encryption for sensitive configuration
- **API Rate Limiting** - Intelligent throttling (429 handling)

### Observability

- **Structured Logging** - Module-level filtering, rotation
- **Health Endpoints** - Readiness and liveness checks
- **Metrics Collection** - Performance tracking and SLA monitoring

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=src --cov=services --cov-report=term-missing

# Run specific test category
pytest tests/ -v -k "test_services"
```

Test coverage includes:
- Service client mocking and error handling
- Retry logic and backoff calculations
- Component integration tests
- Bot command parsing

---

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/ci.yml`) includes:
- **Linting** - Black, flake8, isort, mypy
- **Testing** - pytest with coverage reporting
- **Security** - Bandit security linter, dependency vulnerability scanning
- **Build Verification** - Module import validation

---

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines
- [SECURITY.md](SECURITY.md) - Security policy and best practices
- [docs/AGENTS.md](docs/AGENTS.md) - AI assistant configuration

## Development

```bash
# Using Makefile (recommended)
make help              # Show all available commands
make install-dev       # Install with dev dependencies
make test              # Run tests
make lint              # Run linters
make format            # Format code
make security          # Run security scans
make check             # Run all checks
```

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

## Author

**Vinay Vobbilichetty** - Security Automation Engineer

Specializing in SOAR platform development, incident response automation, and LLM-powered security tools. Currently pursuing MS in Cybersecurity at NC State University.

- [LinkedIn](https://linkedin.com/in/vinay-vobbilichetty)
- [GitHub](https://github.com/vinayvobbili)

---

*Built with Python, Flask, LangChain, and enterprise-grade reliability patterns. Designed for production SOC environments.*
