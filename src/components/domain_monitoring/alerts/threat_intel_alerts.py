"""Threat intelligence alerts.

Alerts for VirusTotal, Certificate Transparency, WHOIS,
abuse.ch, and AbuseIPDB findings.
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


def send_ct_alert(webex_api: WebexTeamsAPI, domain: str, ct_result: Dict[str, Any]) -> None:
    """Send alert when new SSL certificates are found for lookalike domains."""
    high_risk = ct_result.get("high_risk_domains", [])
    if not high_risk:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')
    total_certs = sum(item.get("cert_count", 0) for item in high_risk)

    body = [
        Container(
            style=get_container_style("gray"),
            items=[
                TextBlock(
                    text="🔐 SSL Certificate Alert",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        TextBlock(text="⚠️ New SSL certs on lookalikes indicate phishing preparation", size=options.FontSize.SMALL, color=options.Colors.WARNING),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(high_risk)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING),
                TextBlock(text="Domains", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(total_certs), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING),
                TextBlock(text="New Certs", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Domain", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Certs", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text="Issuer", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for item in high_risk[:6]:
        issuer = "Unknown"
        if item.get("certificates"):
            issuer = item["certificates"][0].get("issuer_name", "Unknown")[:20]
        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=item['domain'], size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=str(item['cert_count']), size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text=issuer, size=options.FontSize.SMALL)])
        ]))

    if len(high_risk) > 6:
        body.append(TextBlock(text=f"... and {len(high_risk) - 6} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"New SSL certificates detected for {domain} lookalikes")


def send_whois_alert(webex_api: WebexTeamsAPI, domain: str, whois_result: Dict[str, Any]) -> None:
    """Send alert when WHOIS changes are detected for lookalike domains."""
    high_severity = whois_result.get("high_severity_changes", [])
    newly_registered = whois_result.get("newly_registered", [])

    if not high_severity and not newly_registered:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    body = [
        Container(
            style=get_container_style("blue"),
            items=[
                TextBlock(
                    text="📋 WHOIS Changes Alert",
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
                TextBlock(text=str(len(newly_registered)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING if newly_registered else options.Colors.DEFAULT),
                TextBlock(text="New Domains", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(len(high_severity)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if high_severity else options.Colors.DEFAULT),
                TextBlock(text="High Severity", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
    ]

    if newly_registered:
        body.append(TextBlock(text="🆕 Newly Registered:", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL))
        for item in newly_registered[:4]:
            registrar = item.get("registrar", "Unknown")[:25] if item.get("registrar") else "Unknown"
            body.append(TextBlock(text=f"• {item['domain']} ({registrar})", size=options.FontSize.SMALL, wrap=True))
        if len(newly_registered) > 4:
            body.append(TextBlock(text=f"... and {len(newly_registered) - 4} more", isSubtle=True, size=options.FontSize.SMALL))

    if high_severity:
        body.append(TextBlock(text="⚠️ High Severity Changes:", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL, color=options.Colors.ATTENTION))
        for item in high_severity[:4]:
            changes_text = ", ".join([c.get("field", "?") for c in item.get("changes", [])])[:30]
            body.append(TextBlock(text=f"• {item['domain']}: {changes_text}", size=options.FontSize.SMALL, wrap=True))
        if len(high_severity) > 4:
            body.append(TextBlock(text=f"... and {len(high_severity) - 4} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"WHOIS changes detected for {domain} lookalikes")


def send_vt_alert(webex_api: WebexTeamsAPI, domain: str, vt_result: Dict[str, Any]) -> None:
    """Send alert when VirusTotal detects malicious lookalike domains."""
    high_risk = vt_result.get("high_risk", [])
    medium_risk = vt_result.get("medium_risk", [])

    if not high_risk and not medium_risk:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    body = [
        Container(
            style=get_container_style("red"),
            items=[
                TextBlock(
                    text="🛡️ Threat Detection Alert",
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
                TextBlock(text=str(len(high_risk)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="🔴 High Risk", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(len(medium_risk)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING),
                TextBlock(text="🟠 Medium Risk", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Domain", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Malicious", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Risk", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for item in high_risk[:4]:
        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=item['domain'], size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=str(item['malicious']), size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="🔴 HIGH", size=options.FontSize.SMALL, color=options.Colors.ATTENTION)])
        ]))

    for item in medium_risk[:2]:
        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=item['domain'], size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=str(item['malicious']), size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="🟠 MED", size=options.FontSize.SMALL, color=options.Colors.WARNING)])
        ]))

    remaining = len(high_risk) + len(medium_risk) - 6
    if remaining > 0:
        body.append(TextBlock(text=f"... and {remaining} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Threat detection alert for {domain} lookalikes")


def send_abusech_alert(webex_api: WebexTeamsAPI, domain: str, abusech_result: Dict[str, Any]) -> None:
    """Send alert when abuse.ch detects malware/C2 on lookalike domains."""
    malicious_domains = abusech_result.get("malicious_domains", [])

    if not malicious_domains:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    body = [
        Container(
            style=get_container_style("red"),
            items=[
                TextBlock(
                    text="☠️ Malware/C2 Detection",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        TextBlock(text="⚠️ Lookalike domains found in threat intelligence feeds!", size=options.FontSize.SMALL, color=options.Colors.ATTENTION),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(malicious_domains)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Malicious Domains", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Domain", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text="Threats", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for item in malicious_domains[:6]:
        mal_domain = item.get("domain", "")
        threat_types = item.get("threat_types", [])
        threats_str = ", ".join(threat_types)[:25] if threat_types else "Malware"

        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=mal_domain, size=options.FontSize.SMALL, wrap=True)]),
            Column(width="2", items=[TextBlock(text=f"🔴 {threats_str}", size=options.FontSize.SMALL, color=options.Colors.ATTENTION)])
        ]))

    if len(malicious_domains) > 6:
        body.append(TextBlock(text=f"... and {len(malicious_domains) - 6} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url="https://urlhaus.abuse.ch/", title="🔗 URLhaus"),
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Malware/C2 detection alert for {domain} lookalikes")


def send_abuseipdb_alert(webex_api: WebexTeamsAPI, domain: str, abuseipdb_result: Dict[str, Any]) -> None:
    """Send alert when AbuseIPDB detects malicious IPs on lookalike domains."""
    domains_with_malicious = abuseipdb_result.get("domains_with_malicious_ips", [])

    if not domains_with_malicious:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')
    total_ips = sum(len(d.get("malicious_ips", [])) for d in domains_with_malicious)
    max_score = max((d.get("max_abuse_score", 0) for d in domains_with_malicious), default=0)

    body = [
        Container(
            style=get_container_style("red"),
            items=[
                TextBlock(
                    text="🚨 Malicious IP Detection",
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
                TextBlock(text=str(len(domains_with_malicious)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Domains", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(total_ips), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Bad IPs", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=f"{max_score}%", size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Max Score", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Domain", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="IPs", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Score", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for item in domains_with_malicious[:6]:
        lookalike = item.get("domain", "")
        malicious_ips = item.get("malicious_ips", [])
        item_max_score = item.get("max_abuse_score", 0)

        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=lookalike, size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=str(len(malicious_ips)), size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text=f"🔴 {item_max_score}%", size=options.FontSize.SMALL, color=options.Colors.ATTENTION)])
        ]))

    if len(domains_with_malicious) > 6:
        body.append(TextBlock(text=f"... and {len(domains_with_malicious) - 6} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url="https://www.abuseipdb.com/", title="🔗 AbuseIPDB"),
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Malicious IP detection alert for {domain} lookalikes")
