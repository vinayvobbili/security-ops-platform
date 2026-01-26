"""Lookalike domain alerts.

Alerts for new lookalike domains, domains becoming active,
MX record changes, and infrastructure changes.
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


def send_lookalike_alert(webex_api: WebexTeamsAPI, domain: str, result: Dict[str, Any]) -> None:
    """Send Webex alert for new lookalike domains."""
    new_domains = result.get("new_domains", [])
    if not new_domains:
        return

    # Filter out defensive registrations
    actionable_domains = [d for d in new_domains if not d.get("is_defensive")]
    defensive_count = len(new_domains) - len(actionable_domains)

    if not actionable_domains:
        return

    active_domains = [d for d in actionable_domains if d.get("parked") is False]
    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')
    active_count = len(active_domains)
    rf_high_risk = sum(1 for d in actionable_domains if (d.get("rf_risk_score") or 0) >= 65)

    body = [
        TextBlock(
            text="🚨 New Lookalike Domains Detected",
            size=options.FontSize.LARGE,
            weight=options.FontWeight.BOLDER,
            color=options.Colors.ATTENTION
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(actionable_domains)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER),
                TextBlock(text="Actionable", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(active_count), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if active_count > 0 else options.Colors.DEFAULT),
                TextBlock(text="Active", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(rf_high_risk), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if rf_high_risk > 0 else options.Colors.DEFAULT),
                TextBlock(text="RF High", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(defensive_count), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.GOOD if defensive_count > 0 else options.Colors.DEFAULT),
                TextBlock(text="Defensive", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Domain", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="Status", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="RF", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for d in actionable_domains[:8]:
        status = "🟢 Active" if d.get("parked") is False else "🅿️ Parked" if d.get("parked") is True else "❓"
        rf_score = d.get("rf_risk_score")
        if rf_score is not None:
            rf_icon = "🔴" if rf_score >= 90 else "🟠" if rf_score >= 65 else "🟡" if rf_score >= 25 else "🟢"
            rf_text = f"{rf_icon} {rf_score}"
        else:
            rf_text = "—"

        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=d['domain'], size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=status, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text=rf_text, size=options.FontSize.SMALL)])
        ]))

    if len(actionable_domains) > 8:
        body.append(TextBlock(text=f"... and {len(actionable_domains) - 8} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"New lookalike domains detected for {domain}")


def send_became_active_alert(webex_api: WebexTeamsAPI, domain: str, result: Dict[str, Any]) -> None:
    """Send HIGH PRIORITY alert when parked domains become active."""
    became_active = result.get("became_active", [])
    if not became_active:
        return

    actionable_became_active = [d for d in became_active if not d.get("is_defensive")]
    defensive_count = len(became_active) - len(actionable_became_active)

    if not actionable_became_active:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')
    high_threat = sum(1 for d in actionable_became_active if d.get("vt_reputation", {}).get("threat_level") == "HIGH")
    rf_high_risk = sum(1 for d in actionable_became_active if (d.get("rf_risk_score") or 0) >= 65)
    has_mx = sum(1 for d in actionable_became_active if d.get("dns_mx"))

    body = [
        Container(
            style=get_container_style("red"),
            items=[
                TextBlock(
                    text="🚨 HIGH PRIORITY ALERT",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text="Parked Domains Now ACTIVE",
                    size=options.FontSize.MEDIUM,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        TextBlock(text="⚠️ Previously parked domains are now hosting content!", size=options.FontSize.SMALL, color=options.Colors.ATTENTION),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(actionable_became_active)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION),
                TextBlock(text="Now Active", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(high_threat), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if high_threat > 0 else options.Colors.DEFAULT),
                TextBlock(text="VT High", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(rf_high_risk), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.ATTENTION if rf_high_risk > 0 else options.Colors.DEFAULT),
                TextBlock(text="RF High", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(has_mx), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING if has_mx > 0 else options.Colors.DEFAULT),
                TextBlock(text="Email", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Domain", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="IP", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="VT", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text="RF", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for d in actionable_became_active[:6]:
        ip = d.get("dns_a", ["-"])[0][:15] if d.get("dns_a") else "-"
        vt = d.get("vt_reputation", {})
        threat = vt.get("threat_level", "?") if vt and "error" not in vt else "?"
        threat_icon = "🔴" if threat == "HIGH" else "🟠" if threat == "MEDIUM" else "🟡" if threat == "LOW" else "⚪"
        mx_flag = " 📧" if d.get("dns_mx") else ""

        rf_score = d.get("rf_risk_score")
        if rf_score is not None:
            rf_icon = "🔴" if rf_score >= 90 else "🟠" if rf_score >= 65 else "🟡" if rf_score >= 25 else "🟢"
            rf_text = f"{rf_icon} {rf_score}"
        else:
            rf_text = "—"

        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=f"{d['domain']}{mx_flag}", size=options.FontSize.SMALL, wrap=True)]),
            Column(width="1", items=[TextBlock(text=ip, size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text=f"{threat_icon}", size=options.FontSize.SMALL)]),
            Column(width="1", items=[TextBlock(text=rf_text, size=options.FontSize.SMALL)])
        ]))

    if len(actionable_became_active) > 6:
        body.append(TextBlock(text=f"... and {len(actionable_became_active) - 6} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"HIGH PRIORITY: Parked domains now active for {domain}")


def send_mx_changes_alert(webex_api: WebexTeamsAPI, domain: str, result: Dict[str, Any]) -> None:
    """Send alert when lookalike domains get new MX records."""
    mx_changes = result.get("mx_changes", [])
    if not mx_changes:
        return

    new_mx_domains = [d for d in mx_changes if d.get("change_type") == "new_mx_records"]
    if not new_mx_domains:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    body = [
        Container(
            style=get_container_style("yellow"),
            items=[
                TextBlock(
                    text="📧 Email Infrastructure Alert",
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    color=options.Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                )
            ]
        ),
        TextBlock(text=f"Monitoring: {domain}", size=options.FontSize.SMALL, isSubtle=True),
        TextBlock(text="⚠️ Lookalike domains now have email capability", size=options.FontSize.SMALL, color=options.Colors.WARNING),
        ColumnSet(columns=[
            Column(width="1", items=[
                TextBlock(text=str(len(new_mx_domains)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER,
                         color=options.Colors.WARNING),
                TextBlock(text="Email Ready", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
        ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text="Domain", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)]),
            Column(width="2", items=[TextBlock(text="MX Server", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL)])
        ])
    ]

    for d in new_mx_domains[:6]:
        mx = d.get("new_mx_records", ["-"])[0][:25] if d.get("new_mx_records") else "-"
        body.append(ColumnSet(columns=[
            Column(width="2", items=[TextBlock(text=d['domain'], size=options.FontSize.SMALL, wrap=True)]),
            Column(width="2", items=[TextBlock(text=mx, size=options.FontSize.SMALL)])
        ]))

    if len(new_mx_domains) > 6:
        body.append(TextBlock(text=f"... and {len(new_mx_domains) - 6} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"New email infrastructure detected for {domain} lookalikes")


def send_infrastructure_changes_alert(webex_api: WebexTeamsAPI, domain: str, result: Dict[str, Any]) -> None:
    """Send alert for IP and GeoIP changes."""
    ip_changes = result.get("ip_changes", [])
    geoip_changes = result.get("geoip_changes", [])

    if not ip_changes and not geoip_changes:
        return

    timestamp = datetime.now(EASTERN_TZ).strftime('%Y-%m-%d %I:%M %p %Z')

    body = [
        Container(
            style=get_container_style("blue"),
            items=[
                TextBlock(
                    text="🔄 Infrastructure Changes",
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
                TextBlock(text=str(len(ip_changes)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER),
                TextBlock(text="IP Changes", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ]),
            Column(width="1", items=[
                TextBlock(text=str(len(geoip_changes)), size=options.FontSize.EXTRA_LARGE,
                         weight=options.FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER),
                TextBlock(text="GeoIP Changes", size=options.FontSize.SMALL,
                         horizontalAlignment=HorizontalAlignment.CENTER, isSubtle=True)
            ])
        ]),
        TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True),
    ]

    if ip_changes:
        body.append(TextBlock(text="IP Address Changes:", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL))
        for d in ip_changes[:4]:
            new_ips = ", ".join(d.get("new_ips", []))[:20] if d.get("new_ips") else ""
            body.append(TextBlock(text=f"• {d['domain']}: {new_ips}", size=options.FontSize.SMALL, wrap=True))
        if len(ip_changes) > 4:
            body.append(TextBlock(text=f"... and {len(ip_changes) - 4} more", isSubtle=True, size=options.FontSize.SMALL))

    if geoip_changes:
        body.append(TextBlock(text="GeoIP Changes:", weight=options.FontWeight.BOLDER, size=options.FontSize.SMALL))
        for d in geoip_changes[:4]:
            body.append(TextBlock(text=f"• {d['domain']}: {d.get('previous_geoip', '?')} → {d.get('current_geoip', '?')}",
                                 size=options.FontSize.SMALL, wrap=True))
        if len(geoip_changes) > 4:
            body.append(TextBlock(text=f"... and {len(geoip_changes) - 4} more", isSubtle=True, size=options.FontSize.SMALL))

    body.append(TextBlock(text="─" * 40, size=options.FontSize.SMALL, isSubtle=True))
    body.append(TextBlock(text=f"⏰ {timestamp}", size=options.FontSize.SMALL, isSubtle=True,
                         horizontalAlignment=HorizontalAlignment.RIGHT))

    card = AdaptiveCard(body=body, actions=[
        OpenUrl(url=f"{WEB_BASE_URL}/domain-monitoring", title="📊 View Full Report")
    ])

    send_adaptive_card(webex_api, card, f"Infrastructure changes detected for {domain} lookalikes")
