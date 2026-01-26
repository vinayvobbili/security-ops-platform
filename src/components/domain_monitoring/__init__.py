"""Domain Monitoring Component - Daily lookalike and dark web monitoring.

This package provides comprehensive domain monitoring capabilities:

## Overview

Scheduled by all_jobs.py to run daily at 8 AM ET. Sends alerts to Webex
when threats are detected. Results are saved to web-accessible JSON.

## Monitoring Capabilities

1. **Lookalike Domain Detection**
   - New domain registrations similar to monitored domains
   - Parked domains becoming active (HIGH PRIORITY)
   - MX record changes (email capability)
   - IP/GeoIP changes

2. **Threat Intelligence Enrichment**
   - VirusTotal reputation scoring
   - Recorded Future risk scores
   - abuse.ch malware/C2 feeds
   - AbuseIPDB malicious IP detection

3. **Dark Web & Leak Monitoring**
   - IntelligenceX Tor/I2P search
   - GitHub/Pastebin public leaks
   - HIBP credential breaches

4. **Infrastructure Monitoring**
   - Certificate Transparency logs
   - WHOIS registration changes
   - Shodan exposed services/vulnerabilities

## Package Structure

- `config.py` - Configuration, constants, client initialization
- `card_helpers.py` - Adaptive Card building utilities
- `enrichment.py` - VirusTotal/RF threat intel enrichment
- `orchestrator.py` - Main monitoring orchestration
- `alerts/` - Alert sending functions by category

## Usage

```python
from src.components.domain_monitoring import run_daily_monitoring, ALERT_ROOM_ID_PROD

# Run with production alerts
run_daily_monitoring(room_id=ALERT_ROOM_ID_PROD)

# Run with test alerts (default)
run_daily_monitoring()
```

## Configuration

Domains are configured in:
`data/transient/domain_monitoring/config.json`

```json
{
    "monitored_domains": ["example.com", "company.org"]
}
```
"""

from .config import ALERT_ROOM_ID_PROD, ALERT_ROOM_ID_TEST
from .orchestrator import run_daily_monitoring

__all__ = [
    "run_daily_monitoring",
    "ALERT_ROOM_ID_PROD",
    "ALERT_ROOM_ID_TEST",
]
