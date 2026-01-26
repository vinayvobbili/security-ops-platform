"""Daily monitoring summary alert.

Sends a concise end-of-day summary card with critical findings only.
Full details available on the web report.
"""

from datetime import datetime
from typing import Any, Dict, List, Tuple

from webexteamssdk import WebexTeamsAPI
from webexpythonsdk.models.cards import (
    AdaptiveCard, TextBlock, Container, options, HorizontalAlignment,
)
from webexpythonsdk.models.cards.actions import OpenUrl

from ..config import EASTERN_TZ
from ..card_helpers import get_container_style, send_adaptive_card


def send_daily_summary(webex_api: WebexTeamsAPI, results: Dict[str, Any], report_url: str) -> None:
    """Send a concise daily monitoring summary. Critical IOCs only, details on web."""
    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    # Collect critical findings (specific IOCs, not just counts)
    critical_items: List[Tuple[str, str]] = []  # (icon, description)
    warning_count = 0

    for domain, domain_data in results.get("domains", {}).items():
        # Active lookalikes - CRITICAL (show specific domains)
        lookalikes = domain_data.get("lookalikes", {})
        if lookalikes.get("success"):
            for d in lookalikes.get("became_active", [])[:2]:  # Top 2
                if not d.get("is_defensive"):
                    critical_items.append(("🎭", f"{d['domain']} is NOW ACTIVE"))
            warning_count += lookalikes.get("new_count", 0)

        # Dark web mentions - CRITICAL (show source)
        intelx = domain_data.get("intelx", {})
        if intelx.get("success"):
            for f in intelx.get("darkweb_findings", [])[:2]:  # Top 2
                source = f.get("name", "unknown source")[:30]
                critical_items.append(("🌑", f"{domain} on dark web: {source}"))
            warning_count += len(intelx.get("leak_findings", []))

        # CVEs - CRITICAL (show CVE ID)
        shodan = domain_data.get("shodan", {})
        if shodan.get("success"):
            for v in shodan.get("vulnerabilities", [])[:2]:  # Top 2
                critical_items.append(("🔓", f"{v['cve']} on {v['ip']}"))
            warning_count += len(shodan.get("exposed_services", []))

        # Malware/C2 - CRITICAL
        abusech = domain_data.get("abusech", {})
        if abusech.get("success"):
            for m in abusech.get("malicious_domains", [])[:2]:
                critical_items.append(("☠️", f"{m.get('domain', domain)} - malware"))

        # Count warnings (not shown in detail)
        hibp = domain_data.get("hibp", {})
        if hibp.get("success"):
            warning_count += hibp.get("emails_breached", 0)

        ct_logs = domain_data.get("ct_logs", {})
        if ct_logs.get("success"):
            warning_count += len(ct_logs.get("high_risk_domains", []))

    # Determine status
    if critical_items:
        status_icon = "🔴"
        status_text = "CRITICAL"
        header_color = "red"
    elif warning_count > 0:
        status_icon = "🟡"
        status_text = "WARNINGS"
        header_color = "yellow"
    else:
        status_icon = "🟢"
        status_text = "ALL CLEAR"
        header_color = "green"

    # Build concise card
    body = [
        Container(
            style=get_container_style(header_color),
            items=[
                TextBlock(
                    text=f"{status_icon} Domain Monitoring: {status_text}",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text=timestamp,
                    size=options.FontSize.SMALL,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
    ]

    # Show critical items (max 5)
    if critical_items:
        body.append(TextBlock(
            text="⚡ Investigate Now:",
            size=options.FontSize.SMALL,
            weight=options.FontWeight.BOLDER
        ))
        for icon, desc in critical_items[:5]:
            body.append(TextBlock(
                text=f"{icon} {desc}",
                size=options.FontSize.SMALL,
                wrap=True
            ))
        if len(critical_items) > 5:
            body.append(TextBlock(
                text=f"   ... +{len(critical_items) - 5} more critical",
                size=options.FontSize.SMALL,
                isSubtle=True
            ))

    # Show warning summary (just count)
    if warning_count > 0:
        body.append(TextBlock(
            text=f"⚠️ {warning_count} warnings to review",
            size=options.FontSize.SMALL,
            isSubtle=True
        ))

    # All clear message
    if not critical_items and warning_count == 0:
        body.append(TextBlock(
            text="✅ No threats detected today",
            size=options.FontSize.MEDIUM,
            horizontalAlignment=HorizontalAlignment.CENTER
        ))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=report_url, title="View Full Report →")
    ])

    send_adaptive_card(webex_api, card, "Domain Monitoring Summary")
