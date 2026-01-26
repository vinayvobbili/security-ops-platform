"""Data leak and dark web alerts.

Alerts for public leaks (GitHub/Pastebin), HIBP breaches,
Shodan exposures, and IntelX dark web findings.
"""

from datetime import datetime
from typing import Any, Dict

from webexteamssdk import WebexTeamsAPI
from webexpythonsdk.models.cards import (
    AdaptiveCard, TextBlock, ColumnSet, Column, Container, options, HorizontalAlignment,
)
from webexpythonsdk.models.cards.actions import OpenUrl

from ..config import EASTERN_TZ, WEB_BASE_URL
from ..card_helpers import get_container_style, send_adaptive_card


def send_dark_web_alert(webex_api: WebexTeamsAPI, domain: str, result: Dict[str, Any]) -> None:
    """Send Webex alert for public leak findings (GitHub/Pastebin)."""
    high_risk = result.get("high_risk_findings", [])
    if not high_risk:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    # Count by source (psbdmp = Pastebin dump)
    github_count = sum(1 for f in high_risk if f.get("source") == "github")
    urlscan_count = sum(1 for f in high_risk if f.get("source") == "urlscan.io")
    pastebin_count = sum(1 for f in high_risk if f.get("source") == "psbdmp")

    body = [
        Container(
            style=get_container_style("yellow"),
            items=[
                TextBlock(
                    text="⚠️ Public Leak Alert",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        TextBlock(text="Sources: GitHub, Pastebin, URLScan (public internet)", size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(high_risk)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="High Risk", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(github_count), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER),
                TextBlock(text="GitHub", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(pastebin_count), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER),
                TextBlock(text="Pastebin", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(urlscan_count), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER),
                TextBlock(text="URLScan", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="1", items=[TextBlock(text="Source", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text="Details", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Risk", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for finding in high_risk[:8]:
        source = finding.get("source", "unknown").upper()
        if finding.get("source") == "github":
            details = f"{finding.get('repo', '')}\n{finding.get('path', '')[:30]}"
        elif finding.get("source") == "urlscan.io":
            details = finding.get("domain", finding.get("url", ""))[:40]
        else:
            details = finding.get("title", finding.get("url", ""))[:40]

        risk_level = finding.get("risk_level", "HIGH")
        risk_color = options.Colors.ATTENTION if risk_level == "HIGH" else options.Colors.WARNING

        body.append(ColumnSet(columns=[
            Column(width="1", items=[TextBlock(text=source[:8], size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text=details, size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=f"🔴 {risk_level}", size=options.FontSize.SMALL, color=risk_color)])
        ]))

    if len(high_risk) > 8:
        body.append(TextBlock(text=f"... and {len(high_risk) - 8} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Public leak alert for {domain} (GitHub/Pastebin)")


def send_hibp_alert(webex_api: WebexTeamsAPI, domain: str, hibp_result: Dict[str, Any]) -> None:
    """Send alert when domain emails are found in data breaches."""
    breached_emails = hibp_result.get("breached_emails", [])

    if not breached_emails:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')
    total_breaches = sum(item.get("breach_count", 0) for item in breached_emails)

    body = [
        Container(
            style=get_container_style("purple"),
            items=[
                TextBlock(
                    text="🔓 Credential Breach Alert",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(breached_emails)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Emails Exposed", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(total_breaches), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Total Breaches", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Email", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Breaches", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text="Notable", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for item in breached_emails[:6]:
        email = item.get("email", "")[:25]
        breach_count = item.get("breach_count", 0)
        breaches = item.get("breaches", [])
        breach_name = breaches[0].get("Name", "?")[:15] if breaches and isinstance(breaches[0], dict) else "?"

        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=email, size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=str(breach_count), size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text=breach_name, size=options.FontSize.SMALL)])
        ]))

    if len(breached_emails) > 6:
        body.append(TextBlock(text=f"... and {len(breached_emails) - 6} more emails", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url="https://haveibeenpwned.com/DomainSearch", title="🔗 Check on HIBP"),
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Credential breach alert for {domain}")


def send_shodan_alert(webex_api: WebexTeamsAPI, domain: str, shodan_result: Dict[str, Any]) -> None:
    """Send alert when Shodan finds exposed services or vulnerabilities."""
    exposed_services = shodan_result.get("exposed_services", [])
    vulnerabilities = shodan_result.get("vulnerabilities", [])
    total_ports = shodan_result.get("total_ports", 0)

    if not exposed_services and not vulnerabilities:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    body = [
        Container(
            style=get_container_style("yellow"),
            items=[
                TextBlock(
                    text="🔍 Infrastructure Exposure",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(total_ports), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER),
                TextBlock(text="Open Ports", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(len(vulnerabilities)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if vulnerabilities else options.Colors.DEFAULT),
                TextBlock(text="CVEs", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(len(exposed_services)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING if exposed_services else options.Colors.DEFAULT),
                TextBlock(text="Risky Services", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
    ]

    if vulnerabilities:
        body.append(TextBlock(text="🔴 Vulnerabilities:", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL, color=options.Colors.ATTENTION))
        for vuln in vulnerabilities[:4]:
            body.append(TextBlock(text=f"• {vuln['ip']} - {vuln['cve']}", size=options.FontSize.SMALL))
        if len(vulnerabilities) > 4:
            body.append(TextBlock(text=f"... and {len(vulnerabilities) - 4} more", isSubtle=True, size=options.FontSize.SMALL))

    if exposed_services:
        body.append(TextBlock(text="⚠️ Risky Services:", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL, color=options.Colors.WARNING))
        for svc in exposed_services[:4]:
            product = svc.get('product', 'Unknown')[:20]
            body.append(TextBlock(text=f"• {svc['ip']}:{svc['port']} - {product}", size=options.FontSize.SMALL))
        if len(exposed_services) > 4:
            body.append(TextBlock(text=f"... and {len(exposed_services) - 4} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"https://www.shodan.io/search?query=hostname:{domain}", title="🔗 View on Shodan"),
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Infrastructure exposure alert for {domain}")


def send_intelx_alert(webex_api: WebexTeamsAPI, domain: str, intelx_result: Dict[str, Any]) -> None:
    """Send alert for actual dark web (Tor/I2P) findings only.

    Only alerts on true dark web content (.onion, I2P), not leaks or pastes.
    """
    darkweb_findings = intelx_result.get("darkweb_findings", [])

    if not darkweb_findings:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    body = [
        Container(
            style=get_container_style("purple"),
            items=[
                TextBlock(
                    text="🌑 Dark Web Alert",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text="Tor (.onion) and I2P Networks",
                    size=options.FontSize.SMALL,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(darkweb_findings)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Tor/I2P Mentions", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="3", items=[TextBlock(text="Source", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Date", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for finding in darkweb_findings[:8]:
        name = finding.get("name", "Unknown")[:50]
        date = finding.get("date", "")[:10] if finding.get("date") else "-"
        body.append(ColumnSet(columns=[
            Column(width="3", items=[TextBlock(text=name, size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=date, size=options.FontSize.SMALL)])
        ]))

    if len(darkweb_findings) > 8:
        body.append(TextBlock(text=f"... and {len(darkweb_findings) - 8} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Dark web alert for {domain}")
