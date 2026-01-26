"""Alert functions for domain monitoring.

This subpackage contains all alert-sending functions organized by category:
- lookalike_alerts: New lookalike domains, became-active, MX changes
- threat_intel_alerts: VirusTotal, CT logs, abuse.ch, AbuseIPDB
- leak_alerts: Dark web, HIBP breaches, IntelX findings
- infrastructure_alerts: Shodan exposures, IP/GeoIP changes
- daily_summary: End-of-day summary card
"""

from .lookalike_alerts import (
    send_lookalike_alert,
    send_became_active_alert,
    send_mx_changes_alert,
    send_infrastructure_changes_alert,
)
from .threat_intel_alerts import (
    send_vt_alert,
    send_ct_alert,
    send_whois_alert,
    send_abusech_alert,
    send_abuseipdb_alert,
)
from .leak_alerts import (
    send_dark_web_alert,
    send_hibp_alert,
    send_intelx_alert,
)
from .daily_summary import send_daily_summary

__all__ = [
    # Lookalike alerts
    "send_lookalike_alert",
    "send_became_active_alert",
    "send_mx_changes_alert",
    "send_infrastructure_changes_alert",
    # Threat intel alerts
    "send_vt_alert",
    "send_ct_alert",
    "send_whois_alert",
    "send_abusech_alert",
    "send_abuseipdb_alert",
    # Leak alerts
    "send_dark_web_alert",
    "send_hibp_alert",
    "send_intelx_alert",
    # Summary
    "send_daily_summary",
]
