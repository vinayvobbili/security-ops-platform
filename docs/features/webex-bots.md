---
layout: default
title: Self-Healing Bot Architecture
---

# Self-Healing Bot Architecture

Production-grade chat bots with enterprise reliability patterns for 24/7 SOC operations.

---

## Overview

The platform includes 10 production Webex bots, each with self-healing capabilities that ensure continuous operation without manual intervention.

### Available Bots

| Bot | Purpose |
|-----|---------|
| **Pokedex** | LLM-powered security investigation assistant |
| **Hal9000** | Advanced LLM assistant with extended capabilities |
| **Toodles** | Team collaboration and notifications |
| **Jarvis** | Automated security workflows |
| **Barnacles** | Metrics collection and reporting |
| **MSOAR** | XSOAR integration and incident management |
| **Tars** | Specialized operations |
| **Money_Ball** | Analytics and statistics |
| **Case** | Case management assistance |

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
│   │ Pokedex │  │ Toodles │  │ Jarvis  │  │ Others  │      │
│   │   LLM   │  │  Collab │  │Workflow │  │   ...   │      │
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
ExecStart=/usr/bin/python3 /opt/security-ops/webex_bots/pokedex.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

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
