---
layout: default
title: SOC Dashboard
---

# Real-Time SOC Dashboard

Interactive web dashboard for security operations metrics, ticket management, and team performance tracking.

---

## Overview

The Flask-based dashboard provides SOC managers and analysts with real-time visibility into operations, enabling data-driven decisions and SLA compliance tracking.

---

## Key Features

### Ticket Aging Analysis

Track incident lifecycle and identify bottlenecks:

- Age distribution by severity
- SLA breach alerts
- Escalation tracking
- Historical trends

### MTTR/MTTC Metrics

Monitor response efficiency:

| Metric | Description |
|--------|-------------|
| **MTTR** | Mean Time to Respond - time from alert to first action |
| **MTTC** | Mean Time to Close - total incident lifecycle |
| **MTTA** | Mean Time to Acknowledge - initial triage time |

### Volume Analytics

Understand alert patterns:

- Inflow/outflow rates
- Peak hours identification
- Source distribution
- Category breakdown

### Detection Efficacy

Measure security tool performance:

- True/false positive rates
- Detection rule effectiveness
- Noise analysis
- Tuning recommendations

### Shift Performance

Team productivity metrics:

- Tickets per analyst
- Response time by shift
- Workload distribution
- Trend analysis

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard                             │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                   Flask Application                   │   │
│  │                                                       │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ │   │
│  │  │ Metrics │  │ Forms   │  │ XSOAR   │  │ Chat    │ │   │
│  │  │ Routes  │  │ Routes  │  │ Routes  │  │ Routes  │ │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘ │   │
│  └──────────────────────────────────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Template Engine                      │   │
│  │            30+ HTML templates with charts             │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Data Sources                              │
│                                                             │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│   │ Ticket  │  │ XSOAR   │  │ SIEM    │  │ Cache   │       │
│   │ Systems │  │         │  │ Metrics │  │         │       │
│   └─────────┘  └─────────┘  └─────────┘  └─────────┘       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Route Blueprints

The dashboard is organized into 7 Flask blueprints:

| Blueprint | Purpose |
|-----------|---------|
| **metrics** | MTTR, ticket aging, volume analytics |
| **forms** | Operational forms and workflows |
| **xsoar** | SOAR integration and incident management |
| **chat** | LLM assistant web interface |
| **security_tools** | Tool-specific interfaces |
| **monitoring** | Health checks and system status |
| **utilities** | General utilities |

---

## Visualization Stack

- **Charts**: Generated with Python (Pandas, Matplotlib)
- **Interactivity**: JavaScript for filtering and drill-down
- **Responsive**: Mobile-friendly layouts
- **Auto-refresh**: Configurable update intervals

---

## Deployment

### Production Server

Uses Waitress WSGI server for production reliability:

```python
from waitress import serve
from web.web_server import app

serve(app, host='0.0.0.0', port=5000, threads=4)
```

### Development

```bash
# Start development server
python web/web_server.py

# Access at http://localhost:5000
```

---

[← Back to Features](index) | [View Integrations →](integrations)
