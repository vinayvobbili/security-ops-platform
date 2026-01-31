"""Daily monitoring summary alert.

Sends a concise end-of-day summary card with critical findings only.
Full details available on the web report.

Outstanding threats persist in alerts until acknowledged via:
  - acknowledge_threat(domain) - remove single threat
  - acknowledge_all_threats() - clear all
"""

from datetime import datetime
from typing import Any, Dict, List, Tuple

from webexteamssdk import WebexTeamsAPI
from webexpythonsdk.models.cards import (
    AdaptiveCard, TextBlock, Container, options, HorizontalAlignment,
)
from webexpythonsdk.models.cards.actions import OpenUrl

from services.cert_transparency import get_outstanding_threats

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

        # Brand CT impersonation - CRITICAL (semantic attacks like acme-loan.com)
        brand_ct = domain_data.get("brand_ct_search", {})
        if brand_ct.get("success"):
            for imp in brand_ct.get("new_domains", [])[:3]:  # Top 3
                imp_domain = imp.get("domain", "unknown")
                issuer = imp.get("issuer", "Unknown CA")[:20]
                critical_items.append(("🎣", f"{imp_domain} has SSL cert ({issuer})"))

        # Watchlist domains with certs - CRITICAL
        watchlist = domain_data.get("watchlist", {})
        if watchlist.get("success"):
            for w in watchlist.get("domains_with_certs", [])[:2]:
                critical_items.append(("🎣", f"{w.get('domain', 'unknown')} has SSL cert"))

        # Count warnings (not shown in detail)
        hibp = domain_data.get("hibp", {})
        if hibp.get("success"):
            warning_count += hibp.get("emails_breached", 0)

        ct_logs = domain_data.get("ct_logs", {})
        if ct_logs.get("success"):
            warning_count += len(ct_logs.get("high_risk_domains", []))

    # Outstanding threats - these persist until acknowledged
    # (Even if analyst missed yesterday's alert, they'll see it today)
    outstanding = get_outstanding_threats()

    # Add outstanding threats not already in critical_items
    already_shown = {desc.split()[0] for _, desc in critical_items}  # Extract domain from description
    for threat in outstanding[:5]:  # Top 5 outstanding
        domain = threat.get("domain", "unknown")
        if domain not in already_shown:
            days_ago = ""
            if threat.get("discovered_at"):
                try:
                    disc_date = datetime.fromisoformat(threat["discovered_at"].replace("Z", "+00:00"))
                    days = (datetime.now(EASTERN_TZ) - disc_date.astimezone(EASTERN_TZ)).days
                    if days > 0:
                        days_ago = f" ({days}d ago)"
                except (ValueError, TypeError):
                    pass
            critical_items.append(("⚠️", f"{domain} - unacknowledged{days_ago}"))

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
