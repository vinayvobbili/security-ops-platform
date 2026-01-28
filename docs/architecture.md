---
layout: default
title: Architecture
---

# System Architecture

This platform follows a layered architecture designed for scalability, reliability, and maintainability in production SOC environments.

---

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                       USER INTERFACE LAYER                          │
│                                                                     │
│   ┌─────────────────────┐         ┌─────────────────────┐          │
│   │   Web Dashboard     │         │    Chat Bots        │          │
│   │   ─────────────     │         │    ──────────       │          │
│   │   • SOC Metrics     │         │    • LLM Assistant  │          │
│   │   • Ticket Aging    │         │    • Team Collab    │          │
│   │   • Analytics       │         │    • Automation     │          │
│   │   • Forms           │         │    • Notifications  │          │
│   └──────────┬──────────┘         └──────────┬──────────┘          │
└──────────────┼───────────────────────────────┼──────────────────────┘
               │                               │
               ▼                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          AI/ML LAYER                                │
│                                                                     │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│   │  LLM            │  │  RAG Pipeline   │  │  Security       │    │
│   │  Orchestration  │  │                 │  │  Tools          │    │
│   │  ─────────────  │  │  ─────────────  │  │  ─────────────  │    │
│   │  LangChain      │  │  ChromaDB       │  │  22 Tools       │    │
│   │  Ollama         │  │  Embeddings     │  │  Investigation  │    │
│   │  Tool Binding   │  │  Doc Processing │  │  Enrichment     │    │
│   └────────┬────────┘  └────────┬────────┘  └────────┬────────┘    │
└────────────┼────────────────────┼────────────────────┼──────────────┘
             │                    │                    │
             ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        CORE SERVICES LAYER                          │
│                                                                     │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│   │  Ticket Cache   │  │  Metrics        │  │  Job            │    │
│   │                 │  │  Engine         │  │  Scheduler      │    │
│   │  Thread-safe    │  │  MTTR/MTTC      │  │  Automated      │    │
│   │  Storage        │  │  Analytics      │  │  Tasks          │    │
│   └────────┬────────┘  └────────┬────────┘  └────────┬────────┘    │
└────────────┼────────────────────┼────────────────────┼──────────────┘
             │                    │                    │
             ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      INTEGRATION LAYER                              │
│                                                                     │
│   ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐         │
│   │  EDR/XDR  │ │ SIEM/SOAR │ │  Threat   │ │   ITSM    │         │
│   │           │ │           │ │  Intel    │ │           │         │
│   │CrowdStrike│ │  QRadar   │ │ Recorded  │ │ServiceNow │         │
│   │  Tanium   │ │   XSOAR   │ │ Future    │ │  CMDB     │         │
│   │  Vectra   │ │           │ │ VirusTotal│ │           │         │
│   └───────────┘ └───────────┘ └───────────┘ └───────────┘         │
│                                                                     │
│              30+ Security Platform API Integrations                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Security Investigation Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  User    │     │   Bot    │     │   LLM    │     │  Tools   │
│          │     │          │     │          │     │          │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ "Investigate   │                │                │
     │  this IP"      │                │                │
     │───────────────>│                │                │
     │                │                │                │
     │                │ Process query  │                │
     │                │───────────────>│                │
     │                │                │                │
     │                │                │ RAG context    │
     │                │                │ retrieval      │
     │                │                │────┐           │
     │                │                │    │           │
     │                │                │<───┘           │
     │                │                │                │
     │                │                │ Select tools   │
     │                │                │───────────────>│
     │                │                │                │
     │                │                │                │ Query APIs
     │                │                │                │ (with retry)
     │                │                │                │────┐
     │                │                │                │    │
     │                │                │                │<───┘
     │                │                │                │
     │                │                │  Enriched data │
     │                │                │<───────────────│
     │                │                │                │
     │                │ Formatted      │                │
     │                │ response       │                │
     │                │<───────────────│                │
     │                │                │                │
     │ Answer with    │                │                │
     │ context        │                │                │
     │<───────────────│                │                │
     │                │                │                │
```

---

## Project Structure

```
security-ops-platform/
│
├── services/                 # Integration Layer - 30+ API clients
│   ├── crowdstrike.py       # CrowdStrike Falcon EDR
│   ├── tanium.py            # Tanium endpoint management
│   ├── qradar.py            # IBM QRadar SIEM
│   ├── service_now.py       # ServiceNow ITSM
│   ├── recorded_future.py   # Threat intelligence
│   ├── virustotal.py        # Malware analysis
│   ├── xsoar/               # Cortex XSOAR client
│   ├── abnormal_security.py # Email security
│   ├── vectra.py            # Network detection
│   └── ...                  # 20+ more integrations
│
├── my_bot/                   # AI/ML Layer
│   ├── core/                # LLM orchestration (LangChain + Ollama)
│   ├── tools/               # 22 security investigation tools
│   ├── document/            # RAG document processing (ChromaDB)
│   └── utils/               # AI utilities
│
├── webex_bots/              # User Interface - Chat Bots
│   ├── pokedex.py           # LLM-powered security assistant
│   ├── hal9000.py           # Advanced LLM assistant
│   ├── toodles.py           # Team collaboration
│   ├── jarvis.py            # Automated workflows
│   ├── barnacles.py         # Metrics and reporting
│   └── base/                # Shared bot architecture
│
├── web/                      # User Interface - Web Dashboard
│   ├── web_server.py        # Flask application
│   ├── routes/              # API endpoints (7 blueprints)
│   ├── templates/           # HTML templates (30+)
│   └── static/              # CSS, JS, assets
│
├── src/                      # Core Services
│   ├── components/          # Business logic modules
│   ├── charts/              # Metrics visualizations
│   ├── secops/              # SOC operations
│   └── utils/               # Shared utilities
│
├── tests/                    # Test suite
├── deployment/               # Systemd services, scripts
└── .github/workflows/        # CI/CD pipeline
```

---

## Design Patterns

### Enterprise Reliability Patterns

The platform implements several patterns for production reliability:

#### Retry with Exponential Backoff

```python
# All API clients implement intelligent retry
retry_config = {
    'max_retries': 3,
    'base_delay': 1.0,
    'max_delay': 30.0,
    'exponential_base': 2,
    'jitter': True
}
```

#### Connection Pooling

```python
# HTTP session reuse for performance
session_config = {
    'pool_connections': 10,
    'pool_maxsize': 60,
    'max_retries': 3
}
```

#### Circuit Breaker

Services gracefully degrade when dependencies fail, preventing cascade failures.

#### Thread-Safe Token Management

OAuth2 tokens are cached with file locking to prevent race conditions during refresh.

---

### LLM Integration Pattern

The platform uses LangChain's native tool calling with a clean architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM Orchestration                         │
│                                                             │
│   1. User Query                                             │
│      ↓                                                      │
│   2. LLM with bound tools receives query                    │
│      ↓                                                      │
│   3. RAG retrieves relevant context                         │
│      ↓                                                      │
│   4. LLM decides which tools to invoke                      │
│      ↓                                                      │
│   5. Tools execute and return results                       │
│      ↓                                                      │
│   6. LLM synthesizes final response                         │
│      ↓                                                      │
│   7. Response returned to user                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Principles:**
- Native tool calling (no manual parsing)
- Tools return data; LLM formats responses
- Simple @tool decorators over complex managers
- Trust the LLM to orchestrate appropriately

---

### Bot Resilience Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Bot Resilience Layer                      │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ WebSocket    │  │ Connection   │  │ Auto         │      │
│  │ Keep-alive   │  │ Pooling      │  │ Reconnect    │      │
│  │              │  │              │  │              │      │
│  │ Heartbeat    │  │ Session      │  │ Exponential  │      │
│  │ monitoring   │  │ reuse        │  │ backoff      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Exponential  │  │ Health       │  │ Graceful     │      │
│  │ Backoff      │  │ Monitoring   │  │ Degradation  │      │
│  │              │  │              │  │              │      │
│  │ With jitter  │  │ Readiness    │  │ Fallback     │      │
│  │ to prevent   │  │ and liveness │  │ responses    │      │
│  │ thundering   │  │ checks       │  │ when LLM     │      │
│  │ herd         │  │              │  │ unavailable  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Defense in Depth

| Layer | Controls |
|-------|----------|
| **Authentication** | OAuth2 tokens, API keys, encrypted secrets |
| **Transport** | SSL/TLS verification, certificate chain support |
| **Input** | Parameterized queries, input sanitization |
| **Storage** | Age encryption, no hardcoded credentials |
| **Monitoring** | Structured logging, audit trails |

### Secrets Management

```
┌─────────────────────────────────────────────────────────────┐
│                   Secrets Architecture                       │
│                                                             │
│   Environment Variables                                     │
│         ↓                                                   │
│   .env file (never committed)                               │
│         ↓                                                   │
│   Age-encrypted files (optional)                            │
│         ↓                                                   │
│   External secrets manager (production)                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Deployment Architecture

### Container Deployment

```dockerfile
# Multi-stage build for minimal image size
FROM python:3.11-slim

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . /app
WORKDIR /app

# Run with production WSGI server
CMD ["python", "-m", "waitress", "--port=5000", "web.web_server:app"]
```

### Service Management

```
┌─────────────────────────────────────────────────────────────┐
│                   Systemd Services                           │
│                                                             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│   │ web.service │  │ bot.service │  │ scheduler   │        │
│   │             │  │             │  │ .service    │        │
│   │ Flask app   │  │ Chat bots   │  │ Cron jobs   │        │
│   └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                             │
│   Auto-restart on failure │ Logging to journald            │
└─────────────────────────────────────────────────────────────┘
```

---

## CI/CD Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                  GitHub Actions Pipeline                     │
│                                                             │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐ │
│   │  Lint   │ -> │  Test   │ -> │Security │ -> │  Build  │ │
│   │         │    │         │    │  Scan   │    │         │ │
│   │ black   │    │ pytest  │    │ bandit  │    │ Docker  │ │
│   │ flake8  │    │ coverage│    │ safety  │    │ image   │ │
│   │ isort   │    │         │    │         │    │         │ │
│   │ mypy    │    │         │    │         │    │         │ │
│   └─────────┘    └─────────┘    └─────────┘    └─────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

[← Back to Home](/) | [View Features →](features/)
