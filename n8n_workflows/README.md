# n8n Workflows for SOC Automation

A comprehensive collection of n8n workflows designed for your Security Operations Center, Incident Response, Threat Hunting, and Detection Engineering teams.

## Quick Start

1. Open n8n: `http://metcirt-lab-17.metnet.net:8080/`
2. Go to **Workflows** → **Import from File**
3. Select any `.json` file from this directory
4. Configure credentials (see [Credentials Setup](#credentials-setup))
5. Activate the workflow

---

## Workflow Catalog (35 Workflows)

### Alert & Detection Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `crowdstrike_webex_alerts.json` | Schedule (5 min) | Polls CrowdStrike incidents, enriches with VT/Shodan/AbuseIPDB, posts to Webex |
| `qradar_offense_alerts.json` | Schedule (5 min) | Monitors QRadar offenses, enriches source IPs, posts to Webex |
| `vectra_detection_alerts.json` | Schedule (5 min) | Monitors Vectra NDR detections with threat/certainty scoring |
| `abnormal_email_alerts.json` | Schedule (5 min) | Monitors Abnormal Security for phishing/BEC threats |
| `failed_login_monitor.json` | Schedule (15 min) | Detects brute force, password spray, and compromised accounts |
| `alert_deduplication.json` | Webhook | Deduplicates alerts using hostname+detection+6hr window, reduces noise 60-80% |

### Incident Response Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `incident_escalation.json` | Webhook | Smart escalation based on severity, time, VIP status, keywords |
| `major_incident_war_room.json` | Webhook | Creates Webex war room, assembles team, collects evidence |
| `cross_system_correlation.json` | Webhook | Correlates incidents across CrowdStrike/QRadar/Vectra/XSOAR |
| `network_evidence_collector.json` | Webhook | Automated evidence collection from QRadar, Zscaler, DNS logs |
| `runbook_suggestion.json` | Webhook | Suggests relevant GDnR runbooks based on incident type |

### XSOAR & Ticket Management

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `xsoar_ticket_enrichment.json` | Webhook | Auto-enriches new XSOAR tickets with multi-source intel |
| `sla_risk_smart_escalation.json` | Schedule (5 min) | Monitors SLA risk, smart routing based on blocking reason |
| `ticket_aging_metrics.json` | Schedule (daily/weekly) | Generates aging reports and trends |
| `shift_handoff_report.json` | Schedule (shift times) | Comprehensive shift handoff with carry-over items |

### Threat Intelligence

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `threat_intel_ioc_sync.json` | Schedule (6 hrs) | Pulls IOCs from abuse.ch feeds, syncs to CrowdStrike/QRadar |
| `hibp_breach_monitor.json` | Schedule (daily) | Monitors Have I Been Pwned for new breaches |
| `intelx_dark_web_monitor.json` | Schedule (daily) | Searches IntelligenceX for company data leaks |
| `phishing_url_analysis.json` | Webhook | Multi-source URL analysis (URLScan, VT, WHOIS) |
| `domain_typosquat_monitor.json` | Schedule (daily) | Detects lookalike/typosquatting domains |
| `cert_transparency_monitor.json` | Schedule (6 hrs) | Monitors CT logs for unauthorized certificates on your domains |

### Threat Hunting & Detection Engineering

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `threat_hunt_runner.json` | Schedule (configurable) | Runs predefined hunting queries across CrowdStrike/QRadar |
| `detection_testing.json` | Webhook | Validates detection rules with atomic tests |
| `cve_vulnerability_alerts.json` | Schedule (6 hrs) | Monitors NVD for critical CVEs affecting your stack |

### Asset & Endpoint Management

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `tanium_asset_inventory.json` | Schedule (weekly) | Exports Tanium inventory with stale endpoint detection |
| `servicenow_cmdb_sync.json` | Schedule (4 hrs) | Syncs CMDB with security tools, identifies gaps |
| `epp_tagging_approval.json` | Webhook | EPP ring tagging with approval workflow |
| `reimaged_host_tracking.json` | Schedule (hourly) | Tracks reimaged hosts, flags suspicious unplanned reimages |
| `user_offboarding_check.json` | Webhook | Validates user offboarding across security tools |
| `user_offboarding_scheduled.json` | Schedule (weekly) | Cross-references HR terminations with tool access |

### Zscaler & Network Security

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `zscaler_url_blocklist.json` | Webhook | Manual URL blocking with approval |
| `zscaler_urlhaus_auto_block.json` | Schedule | Auto-blocks URLs from URLhaus threat feed |

### Reporting & Metrics

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `soc_daily_metrics.json` | Schedule (daily 8 AM) | Daily KPI report from CrowdStrike/QRadar/XSOAR |
| `ticket_aging_metrics.json` | Schedule (daily/weekly) | Ticket aging analysis and trends |

### Team & Operations

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `oncall_schedule_manager.json` | Schedule + Webhook | On-call announcements, rotations, swap requests |
| `azdo_work_item_sync.json` | Schedule (15 min) | Syncs Azure DevOps security work items |

---

## Credentials Setup

Configure these credentials in n8n (**Settings** → **Credentials**):

### Security Platforms

| Credential Name | Type | Configuration |
|-----------------|------|---------------|
| CrowdStrike API | Header Auth | `Authorization: Bearer <token>` (OAuth2 flow in workflow) |
| QRadar API | Header Auth | `SEC: <api_token>` |
| XSOAR API | Header Auth | `Authorization: <api_key>` |
| Tanium API | Header Auth | `session: <token>` |
| Vectra API | Header Auth | `Authorization: Token <token>` |
| Zscaler API | Custom | See workflow for auth flow |
| Abnormal Security | Header Auth | `Authorization: Bearer <token>` |

### Threat Intelligence

| Credential Name | Type | Configuration |
|-----------------|------|---------------|
| VirusTotal | Header Auth | `x-apikey: <key>` |
| Shodan | Query Param | `key=<api_key>` |
| AbuseIPDB | Header Auth | `Key: <api_key>` |
| URLScan.io | Header Auth | `API-Key: <key>` |
| IntelligenceX | Header Auth | `x-key: <api_key>` |
| HIBP | Header Auth | `hibp-api-key: <key>` |

### Collaboration

| Credential Name | Type | Configuration |
|-----------------|------|---------------|
| Webex Bot | Header Auth | `Authorization: Bearer <bot_token>` |
| ServiceNow | Basic/OAuth2 | Username/password or OAuth2 |
| Azure DevOps | Basic Auth | PAT token as password |

---

## Webex Room Configuration

Update these room IDs in workflows that post to Webex:

```javascript
// Replace YOUR_WEBEX_ROOM_ID with actual room IDs
webex_room_id_soc_alerts           // General SOC alerts
webex_room_id_response_sla_risk    // SLA risk notifications
webex_room_id_containment_sla_risk // Containment status
webex_room_id_aging_tickets        // Ticket metrics
webex_room_id_soc_shift_updates    // Shift handoffs
webex_room_id_epp_crowdstrike_tagging // EPP tagging
webex_room_id_domain_monitoring    // Domain alerts
webex_room_id_threat_hunting       // Hunt results
webex_room_id_detection_engineering // Detection updates
```

Get room IDs:
```bash
curl -s -H "Authorization: Bearer YOUR_BOT_TOKEN" \
  "https://webexapis.com/v1/rooms" | jq '.items[] | {title, id}'
```

---

## Workflow Categories by Use Case

### For SOC Analysts
- `crowdstrike_webex_alerts.json` - Real-time incident alerts
- `qradar_offense_alerts.json` - SIEM offense monitoring
- `alert_deduplication.json` - Reduce alert fatigue
- `shift_handoff_report.json` - Smooth shift transitions
- `sla_risk_smart_escalation.json` - Never miss an SLA

### For Incident Responders
- `incident_escalation.json` - Smart escalation paths
- `major_incident_war_room.json` - Rapid team assembly
- `cross_system_correlation.json` - Full incident context
- `network_evidence_collector.json` - Automated evidence gathering
- `xsoar_ticket_enrichment.json` - Auto-enriched tickets

### For Threat Hunters
- `threat_hunt_runner.json` - Scheduled hunting queries
- `threat_intel_ioc_sync.json` - Fresh IOCs from feeds
- `intelx_dark_web_monitor.json` - Dark web monitoring
- `domain_typosquat_monitor.json` - Lookalike detection

### For Detection Engineers
- `detection_testing.json` - Validate detection rules
- `cve_vulnerability_alerts.json` - Stay ahead of CVEs
- `threat_hunt_runner.json` - Query-based detection development

### For Security Leadership
- `soc_daily_metrics.json` - Daily KPI dashboards
- `ticket_aging_metrics.json` - Operational health
- `hibp_breach_monitor.json` - Credential exposure alerts

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        TRIGGERS                              │
│  Schedule (cron)  │  Webhook (events)  │  Manual             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    DATA COLLECTION                           │
│  CrowdStrike │ QRadar │ XSOAR │ Vectra │ Tanium │ Zscaler  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    ENRICHMENT (Parallel)                     │
│  VirusTotal │ Shodan │ AbuseIPDB │ URLScan │ IntelX │ HIBP │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROCESSING                                │
│  Deduplication │ Correlation │ Risk Scoring │ Formatting    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    ACTIONS                                   │
│  Webex Alert │ XSOAR Ticket │ Zscaler Block │ Email │ Log  │
└─────────────────────────────────────────────────────────────┘
```

---

## Alert Format Standard

All workflows use consistent alert formatting:

```markdown
[EMOJI] **Alert Type**

**ID:** `incident_id`
**Severity:** score/100 | **Status:** status
**Timestamp:** ISO8601

---
**Description:** details

**Key Indicators:**
- Hostname: `HOST001`
- IP: `10.0.0.1`
- User: `jsmith`

---
**Enrichment:**
🔴 VirusTotal: 5 malicious
🟢 AbuseIPDB: Score 12%
Shodan: Ports 22, 80, 443

---
[View in Console](link)
```

Severity indicators:
- 🔴 Critical (80+)
- 🟠 High (50-79)
- 🟡 Medium (30-49)
- 🟢 Low (<30)

---

## Customization Tips

### Adjust Polling Intervals
```javascript
// In Schedule Trigger node
"minutesInterval": 5  // Change to desired interval
```

### Add New Enrichment Sources
1. Add HTTP Request node after "Extract IP" node
2. Connect to Merge node
3. Update Format Message code to include new data

### Change Severity Thresholds
```javascript
// In Code nodes
if (severity >= 80) severityEmoji = '🔴';  // Adjust threshold
```

### Route to Different Channels
```javascript
// Add IF node to check severity
// Route high severity to urgent channel
// Route low severity to digest channel
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Auth failures | Check credential configuration, token expiry |
| No data returned | Verify API endpoints, check time filters |
| Webex not sending | Confirm bot token, verify bot is in room |
| Rate limiting | Add Wait nodes, reduce polling frequency |
| Enrichment timeout | Set `continueOnFail: true`, add timeout |

### Debug Mode
1. Open workflow in n8n
2. Click "Execute Workflow" manually
3. Click each node to see input/output data
4. Check execution logs for errors

---

## Maintenance

### Weekly
- Review execution logs for failures
- Check credential expirations
- Validate alert volumes are normal

### Monthly
- Update threat intel feed URLs if changed
- Review and tune deduplication windows
- Update on-call schedules

### Quarterly
- Review workflow effectiveness
- Add new detection queries to hunt runner
- Update MITRE ATT&CK mappings

---

## Contributing

To add a new workflow:
1. Create workflow in n8n UI
2. Export as JSON
3. Add to this directory
4. Update this README
5. Commit to repo

---

## Related Resources

- [n8n Documentation](https://docs.n8n.io/)
- [Webex API Reference](https://developer.webex.com/docs/api/v1/messages)
- [CrowdStrike API Docs](https://falcon.crowdstrike.com/documentation)
- [QRadar API Guide](https://www.ibm.com/docs/en/qsip)
- Your internal GDnR runbooks

---

*Generated for The Whole Truth - Security Operations Automation Platform*
