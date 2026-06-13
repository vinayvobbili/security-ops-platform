---
layout: doc
title: n8n Workflow Automation
---

# n8n Workflow Automation

35 ready-to-import [n8n](https://n8n.io) workflows covering the full SOC lifecycle. Import them into your own n8n instance, point them at your tools, and you've automated a quarter of your runbook in an afternoon.

---

## Why n8n?

n8n is a low-code workflow tool — visual node graphs, JavaScript escape hatches, self-hostable, and free. For SOC work it hits a sweet spot: faster than building a Flask app for every webhook, easier to hand off to a non-Python teammate than a custom script, and the "what does this do?" answer is the canvas itself.

The platform's Python codebase handles the heavy lifting (LLM agents, complex correlation, data engineering); n8n handles the glue (poll an API, dedupe, route to chat, open a ticket).

---

## Workflows by category

### Alert ingest & routing
| Workflow | What it does |
|---|---|
| `alert_deduplication` | Hash-based dedupe across sources before paging |
| `cross_system_correlation` | Merge alerts from EDR + SIEM + email security on shared IOCs |
| `qradar_offense_alerts` | Stream new QRadar offenses into chat with severity-based routing |
| `crowdstrike_webex_alerts` | CrowdStrike detections → Webex with one-click triage actions |
| `abnormal_email_alerts` | Abnormal email threat alerts with auto-remediation hooks |

### Incident response
| Workflow | What it does |
|---|---|
| `incident_escalation` | Auto-escalate stale tickets based on age + severity |
| `major_incident_war_room` | Spin up a Webex room, page on-call, post the IR runbook |
| `network_evidence_collector` | Pull packet captures and flow records on demand |
| `reimaged_host_tracking` | Track endpoints through the reimage lifecycle |

### Threat intelligence
| Workflow | What it does |
|---|---|
| `cve_vulnerability_alerts` | New-CVE feed scoring + chat alert on high-impact entries |
| `hibp_breach_monitor` | HIBP polling for monitored corporate domains |
| `intelx_dark_web_monitor` | IntelX dark-web search for brand and credential leaks |
| `phishing_url_analysis` | URL detonation pipeline (URLScan + sandbox) |

### Domain & brand monitoring
| Workflow | What it does |
|---|---|
| `cert_transparency_monitor` | CT log subscriber matching against monitored domains |
| `domain_typosquat_monitor` | Lookalike detection feeding into the domain monitoring DB |

### Detection engineering
| Workflow | What it does |
|---|---|
| `detection_testing` | Scheduled execution of detection-rule unit tests |
| `epp_tagging_approval` | EPP tag-change approval flow with audit trail |

### SOC operations
| Workflow | What it does |
|---|---|
| `failed_login_monitor` | Brute-force pattern detection across auth sources |
| `oncall_schedule_manager` | On-call rotation handoff and notification |
| `azdo_work_item_sync` | Bidirectional sync between SOAR tickets and Azure DevOps work items |

…plus 15 more covering shift handoff reports, asset inventory sync, offboarding checks, ticket SLA tracking, scheduled hunts, and IOC sync between threat-intel platforms.

---

## How to use these

```bash
# Each file is a self-contained n8n workflow export
ls n8n_workflows/*.json

# In n8n: Workflows → Import from File → pick the JSON
# Then: configure the credentials and webhooks the workflow expects
```

Most workflows assume:

- **Webex** for chat notifications (swap to Slack/Teams by replacing one node)
- **An n8n credential** for each external service the workflow touches
- **A webhook URL** that you'll wire up to the source system

The workflows aren't tied to this platform — they're standalone n8n exports. They were built and run alongside the rest of the platform but you can use them independently.

---

## Design principles

1. **Idempotent.** A workflow that fires twice on the same alert should produce the same outcome.
2. **Observable.** Every workflow logs to a structured store so you can answer "did this fire?" without reading the canvas.
3. **Bounded.** Workflows have explicit timeouts and retry caps; nothing loops forever.
4. **Composable.** Workflows trigger each other through webhooks, never hardcoded paths.

---

[← Back to Features](index)
