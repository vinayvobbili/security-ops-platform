---
layout: default
title: Security Integrations
---

# Security Tool Integrations

Unified API clients for 30+ security platforms with enterprise reliability patterns.

---

## Overview

The platform provides consistent, production-grade integrations across the security tool ecosystem. Each client implements:

- Retry logic with exponential backoff
- Connection pooling
- OAuth2 token management
- Structured error handling
- Rate limit handling

---

## Integration Catalog

### Endpoint Detection & Response (EDR/XDR)

| Platform | Capabilities |
|----------|--------------|
| **CrowdStrike Falcon** | Host lookup, detection search, containment, RTR sessions, IOC management |
| **Tanium** | Endpoint queries, sensor management, live response, tag management |
| **Vectra** | Network detection, host scoring, threat hunting |

### Security Information & Event Management (SIEM)

| Platform | Capabilities |
|----------|--------------|
| **IBM QRadar** | Log search, AQL queries, offense investigation, reference sets |

### Security Orchestration (SOAR)

| Platform | Capabilities |
|----------|--------------|
| **Cortex XSOAR** | Incident management, playbook execution, indicator enrichment |
| **Custom Playbooks** | Automated response workflows |

### Threat Intelligence

| Platform | Capabilities |
|----------|--------------|
| **Recorded Future** | IP/domain/hash intelligence, risk scores, threat context |
| **VirusTotal** | Hash/URL/domain reputation, sandbox analysis |
| **URLScan.io** | Website scanning, DOM capture, screenshot |
| **AbuseIPDB** | IP reputation, abuse reports |
| **Abuse.ch** | Malware bazaar, threat feeds |
| **IntelligenceX** | Data leak search, dark web monitoring |
| **Shodan** | Internet-facing asset discovery, vulnerability scanning |

### Email Security

| Platform | Capabilities |
|----------|--------------|
| **Abnormal Security** | Email threat detection, case investigation |
| **Zscaler** | URL categorization, web filtering status |

### IT Service Management (ITSM)

| Platform | Capabilities |
|----------|--------------|
| **ServiceNow** | Incident creation, CMDB queries, change management |

### Identity & Access

| Platform | Capabilities |
|----------|--------------|
| **Have I Been Pwned** | Email breach checking, password exposure |

### Domain Security

| Platform | Capabilities |
|----------|--------------|
| **Certificate Transparency** | SSL certificate monitoring |
| **WHOIS** | Domain registration lookup |
| **Domain Lookalike Detection** | Typosquat and brand impersonation |

### Communication

| Platform | Capabilities |
|----------|--------------|
| **Webex Teams** | Bot messaging, adaptive cards, room management |
| **Email (OAuth2)** | Automated notifications |

### DevOps

| Platform | Capabilities |
|----------|--------------|
| **Azure DevOps** | Pipeline integration, work items |

---

## Client Architecture

Each integration client follows a consistent pattern:

```
┌─────────────────────────────────────────────────────────────┐
│                    Service Client                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 Configuration                         │   │
│  │  • API endpoints      • Credentials (from env)       │   │
│  │  • Timeout settings   • Retry configuration          │   │
│  └──────────────────────────────────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 HTTP Session                          │   │
│  │  • Connection pooling  • Keep-alive                  │   │
│  │  • SSL verification    • Proxy support               │   │
│  └──────────────────────────────────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 Retry Layer                           │   │
│  │  • Exponential backoff • Jitter                      │   │
│  │  • 429 handling        • Circuit breaker             │   │
│  └──────────────────────────────────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 API Methods                           │   │
│  │  • Type hints          • Structured responses        │   │
│  │  • Error handling      • Logging                     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Reliability Patterns

### Retry with Exponential Backoff

```python
retry_config = {
    'max_retries': 3,
    'base_delay': 1.0,
    'max_delay': 30.0,
    'exponential_base': 2,
    'jitter': True  # Prevents thundering herd
}
```

### OAuth2 Token Management

Thread-safe token caching with automatic refresh:

- Tokens cached to reduce API calls
- File locking prevents race conditions
- Automatic refresh before expiration

### Rate Limit Handling

Intelligent 429 response handling:

- Respects Retry-After headers
- Implements backoff when no header present
- Tracks rate limit state per endpoint

---

## Adding New Integrations

New service clients follow the established pattern:

1. Create client class in `services/`
2. Implement configuration from environment variables
3. Use shared HTTP session utilities
4. Add retry logic wrapper
5. Write unit tests with mocked responses

---

[← Back to Features](index)
