"""Daily monitoring summary alert.

Sends an end-of-day summary card with all monitoring results.
"""

from datetime import datetime
from typing import Any, Dict

from webexteamssdk import WebexTeamsAPI
from webexpythonsdk.models.cards import (
    AdaptiveCard, TextBlock, ColumnSet, Column, Container, options, HorizontalAlignment,
)
from webexpythonsdk.models.cards.actions import OpenUrl

from ..config import EASTERN_TZ
from ..card_helpers import get_container_style, send_adaptive_card


def send_daily_summary(webex_api: WebexTeamsAPI, results: Dict[str, Any], report_url: str) -> None:
    """Send daily monitoring summary using a visually appealing Adaptive Card."""
    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    # Calculate overall stats
    total_lookalikes = results.get("total_new_lookalikes", 0)
    total_became_active = results.get("total_became_active", 0)
    total_hibp = results.get("total_hibp_breaches", 0)

    # Calculate IntelX breakdown from per-domain results
    intelx_darkweb = 0
    intelx_leaks = 0
    for domain_data in results.get("domains", {}).values():
        intelx = domain_data.get("intelx", {})
        if intelx.get("success"):
            intelx_darkweb += len(intelx.get("darkweb_findings", []))
            intelx_leaks += len(intelx.get("leak_findings", []))

    # Determine overall health
    critical_count = total_became_active + (1 if intelx_darkweb > 0 else 0)
    warning_count = total_lookalikes + (1 if intelx_leaks > 0 else 0) + (1 if total_hibp > 0 else 0)

    if critical_count > 0:
        health_icon = "🔴"
        health_text = "CRITICAL FINDINGS"
    elif warning_count > 0:
        health_icon = "🟡"
        health_text = "WARNINGS DETECTED"
    else:
        health_icon = "🟢"
        health_text = "ALL CLEAR"

    # Determine header color based on health
    header_gradient = "red" if critical_count > 0 else "yellow" if warning_count > 0 else "green"

    body = [
        # Header with dynamic gradient based on health status
        Container(
            style=get_container_style(header_gradient),
            items=[
                TextBlock(
                    text="📊 Daily Domain Monitoring Summary",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text=f"{health_icon} {health_text}",
                    size=options.FontSize.MEDIUM,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text=f"⏰ {timestamp}",
                    size=options.FontSize.SMALL,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),

        # Top-level Stats Row
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(total_lookalikes), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if total_lookalikes > 0 else options.Colors.DEFAULT),
                TextBlock(text="New Lookalikes", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(total_became_active), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if total_became_active > 0 else options.Colors.DEFAULT),
                TextBlock(text="Became Active", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(intelx_darkweb), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if intelx_darkweb > 0 else options.Colors.DEFAULT),
                TextBlock(text="Dark Web", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(intelx_leaks), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING if intelx_leaks > 0 else options.Colors.DEFAULT),
                TextBlock(text="Leaks", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),

        # Separator
        TextBlock(text="━" * 45, size=options.FontSize.SMALL, isSubtle=True),
    ]

    # Per-domain details
    for domain, domain_results in results.get("domains", {}).items():
        # Domain header
        body.append(TextBlock(
            text=f"🌐 {domain}",
            size=options.FontSize.MEDIUM,
            weight=options.FontWeight.BOLDER
        ))

        # Build check results table
        checks = []

        # Lookalikes
        lookalikes = domain_results.get("lookalikes", {})
        if lookalikes.get("success"):
            total = lookalikes.get("total_registered", 0)
            new = lookalikes.get("new_count", 0)
            active = lookalikes.get("became_active_count", 0)
            if active > 0:
                checks.append(("Lookalikes", f"{total} total, {new} new, {active} ACTIVE", "🔴"))
            elif new > 0:
                checks.append(("Lookalikes", f"{total} total, {new} new", "🟡"))
            else:
                checks.append(("Lookalikes", f"{total} total registered", "✅"))

        # Data Leaks
        dark_web = domain_results.get("dark_web", {})
        if dark_web.get("success"):
            findings = dark_web.get("total_findings", 0)
            high_risk = len(dark_web.get("high_risk_findings", []))
            if high_risk > 0:
                checks.append(("Data Leaks", f"{findings} findings, {high_risk} high-risk", "⚠️"))
            else:
                checks.append(("Data Leaks", f"{findings} findings", "✅"))

        # IntelX Dark Web
        intelx = domain_results.get("intelx", {})
        if intelx.get("success"):
            darkweb = len(intelx.get("darkweb_findings", []))
            leaks = len(intelx.get("leak_findings", []))
            if darkweb > 0:
                checks.append(("Dark Web", f"{darkweb} Tor/I2P, {leaks} leaks", "🌑"))
            elif leaks > 0:
                checks.append(("Dark Web", f"{leaks} leak mentions", "⚠️"))
            else:
                checks.append(("Dark Web", "No findings", "✅"))

        # SSL Certs
        ct_logs = domain_results.get("ct_logs", {})
        if ct_logs.get("success"):
            ct_findings = len(ct_logs.get("high_risk_domains", []))
            if ct_findings > 0:
                checks.append(("SSL Certs", f"{ct_findings} lookalikes with certs", "🔐"))
            else:
                checks.append(("SSL Certs", "No new certs on lookalikes", "✅"))

        # HIBP
        hibp = domain_results.get("hibp", {})
        if hibp.get("success"):
            breached = hibp.get("emails_breached", 0)
            if breached > 0:
                checks.append(("Credentials", f"{breached} breached emails", "🔓"))
            else:
                checks.append(("Credentials", "No breaches found", "✅"))
        elif hibp.get("error") and "not configured" not in str(hibp.get("error", "")).lower():
            checks.append(("Credentials", "Not configured", "⚪"))

        # Shodan (vulns = vulnerabilities)
        shodan = domain_results.get("shodan", {})
        if shodan.get("success"):
            vulns = shodan.get("total_vulns", 0)
            ports = shodan.get("total_ports", 0)
            if vulns > 0:
                checks.append(("Infrastructure", f"{vulns} vulns, {ports} ports", "🔴"))
            elif ports > 0:
                checks.append(("Infrastructure", f"{ports} open ports", "🔍"))

        # Render checks as table rows
        for check_name, check_value, check_icon in checks:
            body.append(ColumnSet(columns=[
                Column(width="auto", items=[TextBlock(text=check_icon, size=options.FontSize.SMALL)]),
                Column(width="1", items=[TextBlock(text=check_name, size=options.FontSize.SMALL, weight=options.FontWeight.BOLDER)]),
                Column(width="2", items=[TextBlock(text=check_value, size=options.FontSize.SMALL, isSubtle=True)])
            ]))

        body.append(TextBlock(text=" ", size=options.FontSize.SMALL))  # Spacer

    # Footer
    body.append(TextBlock(text="━" * 45, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(
        text="🔄 Monitoring runs daily at 8:00 AM ET",
        size=options.FontSize.SMALL,
        isSubtle=True,
        horizontalAlignment=HorizontalAlignment.CENTER
    ))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=report_url, title="📋 View Full Report")
    ])

    send_adaptive_card(webex_api, card, "Daily Domain Monitoring Summary")
