---
layout: default
title: Self-Healing Bot Architecture
---

# Self-Healing Bot Architecture

Production-grade chat bots with enterprise reliability patterns for 24/7 SOC operations — 14 bots in production across Webex Teams and Microsoft Teams.

---

## Overview

The platform runs 14 production chat bots — 11 on Webex Teams, 3 on Microsoft Teams — each with self-healing capabilities that keep them running without manual intervention.

### Bot roles

| Role | Purpose |
|---|---|
| **Security Assistant Bot** | LLM-powered investigation assistant with full tool access |
| **Windows Triage Agent** | Specialized triage for Windows endpoint alerts |
| **Notification Service** | Team collaboration and routine notifications |
| **Orchestration Service** | Automated security workflows |
| **Alert Triage Service** | Frontline alert triage and routing |
| **Threat-Intel Service** | IOC enrichment and threat-intel queries |
| **Case Orchestrator** | SOAR ticket lifecycle management |
| **Metrics Service** | Operational metrics and reporting |
| **Peer-Status Service** | Cross-team status sync |
| **Control-Efficacy Analytics** | Detection coverage and BAS results |
| **Teams Integrations** | Three Microsoft Teams bots for ticket lookup, host status, and on-call lookups |

---

## Reliability Features

### WebSocket Keep-Alive

Maintains persistent connections with heartbeat monitoring to detect disconnections before they cause message loss.

### Auto-Reconnect with Exponential Backoff

```
Connection Lost
     │
     ▼
┌─────────────┐
│ Wait 1s     │ ──► Retry
└─────────────┘
     │ Failed
     ▼
┌─────────────┐
│ Wait 2s     │ ──► Retry
└─────────────┘
     │ Failed
     ▼
┌─────────────┐
│ Wait 4s     │ ──► Retry (with jitter)
└─────────────┘
     │
     ▼
   Continue...
```

### Connection Pooling

HTTP sessions are reused across requests, reducing latency and connection overhead:

- Pool size: 10 connections
- Max connections: 60
- Automatic retry on transient failures

### Health Monitoring

Each bot exposes health endpoints for monitoring:

- **Readiness**: Bot is ready to receive messages
- **Liveness**: Bot process is running and responsive
- **Metrics**: Message counts, response times, error rates

### Graceful Degradation

When external services fail, bots provide fallback responses rather than failing completely:

- Cached responses for common queries
- Informative error messages
- Automatic retry on transient failures

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Bot Resilience Layer                      │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ WebSocket    │  │ Connection   │  │ Auto         │      │
│  │ Keep-alive   │  │ Pooling      │  │ Reconnect    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Exponential  │  │ Health       │  │ Graceful     │      │
│  │ Backoff      │  │ Monitoring   │  │ Degradation  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Bot Application Layer                     │
│                                                             │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐      │
│   │Security │  │ Notify  │  │Workflow │  │ Others  │      │
│   │Assistant│  │ Service │  │ Service │  │  ...    │      │
│   └─────────┘  └─────────┘  └─────────┘  └─────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Webex Teams API                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Deployment

### Systemd Service

Bots run as systemd services for automatic startup and restart:

```ini
[Unit]
Description=Security Bot Service
After=network.target

[Service]
Type=simple
User=secops
ExecStart=/usr/bin/python3 /opt/security-ops/webex_bots/security_assistant.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Bot Status API

A dedicated REST API for monitoring and managing bot health:

- Check status of all bots (running, stopped, errored)
- Start, stop, and restart individual bots
- View resource metrics (uptime, CPU, memory)
- Audit logging for administrative actions

### Process Management

- Automatic restart on crash
- Log rotation via journald
- Resource limits to prevent runaway processes

---

## Key Design Principles

1. **Fail Fast, Recover Faster**: Detect failures quickly, reconnect automatically
2. **No Single Point of Failure**: Bots operate independently
3. **Observable**: Comprehensive logging and metrics
4. **Defensive**: Validate inputs, handle edge cases gracefully

---

[← Back to Features](index) | [View Integrations →](integrations)
