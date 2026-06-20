"""Pokedex Webex card for Detection Engineer tuning reports.

One card per timer run. Lists the proposals in worst-first order (most
FPs/benign TPs at the top). The engineer-on-the-loop can scan the card
and decide what to ship into the rules catalog.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from src.utils.xsoar_helpers import build_incident_url


EASTERN = ZoneInfo("America/New_York")


def _fmt_eastern(dt: datetime) -> str:
    return dt.astimezone(EASTERN).strftime("%m/%d/%Y %I:%M %p %Z")


# change_risk → container style + text color
RISK_CONTAINER_STYLE = {
    "low":    "good",
    "medium": "warning",
    "high":   "attention",
}

RISK_TEXT_COLOR = {
    "low":    "Good",
    "medium": "Warning",
    "high":   "Attention",
}


MAX_PROPOSALS_CARD = 5


def _linkify_ticket_id(ticket_id: str) -> str:
    if not ticket_id:
        return "—"
    return f"[#{ticket_id}]({build_incident_url(ticket_id)})"


def render_card(window_start: datetime, window_end: datetime,
                total_alerts_examined: int,
                proposals: list[dict[str, Any]]) -> dict[str, Any]:
    body: list[dict[str, Any]] = []

    # Hero
    body.append({
        "type": "Container", "style": "accent", "bleed": True,
        "items": [
            {"type": "TextBlock", "text": "🔧 Detection Engineering Review",
             "size": "Large", "weight": "Bolder", "wrap": True},
            {"type": "TextBlock",
             "text": f"{_fmt_eastern(window_start)}  →  {_fmt_eastern(window_end)}",
             "isSubtle": True, "spacing": "Small", "wrap": True},
        ],
    })

    # KPI strip
    body.append({
        "type": "ColumnSet", "spacing": "Medium",
        "columns": [
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": "Alerts examined", "isSubtle": True,
                 "size": "Small", "spacing": "None"},
                {"type": "TextBlock", "text": str(total_alerts_examined),
                 "size": "ExtraLarge", "weight": "Bolder", "spacing": "None"},
            ]},
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": "Rules flagged", "isSubtle": True,
                 "size": "Small", "spacing": "None"},
                {"type": "TextBlock", "text": str(len(proposals)),
                 "size": "ExtraLarge", "weight": "Bolder", "spacing": "None",
                 "color": "Warning" if proposals else "Default"},
            ]},
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": "Proposals shown", "isSubtle": True,
                 "size": "Small", "spacing": "None"},
                {"type": "TextBlock",
                 "text": str(min(len(proposals), MAX_PROPOSALS_CARD)),
                 "size": "ExtraLarge", "weight": "Bolder", "spacing": "None"},
            ]},
        ],
    })

    if not proposals:
        body.append({
            "type": "TextBlock", "spacing": "Large",
            "text": ("No rules crossed the tuning threshold in this window — "
                     "detection surface looks healthy."),
            "wrap": True, "isSubtle": True,
        })
    else:
        body.append({"type": "TextBlock", "text": "Tuning proposals",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})

        for p in proposals[:MAX_PROPOSALS_CARD]:
            body.append(_proposal_container(p))

        if len(proposals) > MAX_PROPOSALS_CARD:
            body.append({
                "type": "TextBlock",
                "text": (f"+ {len(proposals) - MAX_PROPOSALS_CARD} more in the "
                         f"bus event — open the SOC Timeline to see them all."),
                "wrap": True, "isSubtle": True, "spacing": "Medium",
            })

    # Sign-off
    body.append({
        "type": "TextBlock", "text": "— Detection Engineer",
        "isSubtle": True, "size": "Small", "spacing": "Large",
        "horizontalAlignment": "Right",
    })

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.2",
        "body": body,
    }


def _proposal_container(p: dict[str, Any]) -> dict[str, Any]:
    risk = (p.get("change_risk") or "medium").lower()
    style = RISK_CONTAINER_STYLE.get(risk, "warning")
    risk_color = RISK_TEXT_COLOR.get(risk, "Warning")

    fp = int(p.get("false_positive_count") or 0)
    benign = int(p.get("benign_tp_count") or 0)
    total = int(p.get("total_count") or 0)
    confidence = float(p.get("confidence") or 0.0)

    rule_name = p.get("rule_name") or "(unnamed rule)"

    items: list[dict[str, Any]] = [
        # Header row: rule name + risk badge
        {"type": "ColumnSet", "columns": [
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": rule_name,
                 "weight": "Bolder", "wrap": True, "spacing": "None"},
            ]},
            {"type": "Column", "width": "auto", "items": [
                {"type": "TextBlock",
                 "text": f"risk: {risk.upper()}",
                 "color": risk_color, "weight": "Bolder",
                 "horizontalAlignment": "Right", "spacing": "None"},
            ]},
        ]},
        # Counts row
        {"type": "TextBlock",
         "text": (f"**{fp}** FP  •  **{benign}** Benign-TP  •  **{total}** total fires"
                  f"  •  confidence **{confidence:.0%}**"),
         "wrap": True, "spacing": "Small", "isSubtle": True},
    ]

    entities = p.get("top_entities") or []
    if entities:
        items.append({
            "type": "TextBlock",
            "text": "Top: " + "  ".join(f"`{e}`" for e in entities[:5]),
            "wrap": True, "spacing": "Small",
        })

    rec = (p.get("tuning_recommendation") or "").strip()
    if rec:
        items.append({
            "type": "TextBlock", "text": f"💡 {rec}",
            "wrap": True, "spacing": "Small",
        })

    sample_ids = p.get("sample_ticket_ids") or []
    if sample_ids:
        items.append({
            "type": "TextBlock",
            "text": "Samples: " + "  ".join(_linkify_ticket_id(t)
                                            for t in sample_ids[:5]),
            "wrap": True, "spacing": "Small", "isSubtle": True,
        })

    return {
        "type": "Container",
        "style": style,
        "spacing": "Medium",
        "items": items,
    }


def render_fallback_markdown(window_start: datetime, window_end: datetime,
                             total_alerts_examined: int,
                             proposals: list[dict[str, Any]]) -> str:
    lines = [
        "## 🔧 Detection Engineering Review",
        f"**Window:** {_fmt_eastern(window_start)} → {_fmt_eastern(window_end)}",
        (f"**Alerts examined:** {total_alerts_examined}  •  "
         f"**Rules flagged:** {len(proposals)}"),
        "",
    ]
    if not proposals:
        lines.append("No rules crossed the tuning threshold in this window — "
                     "detection surface looks healthy.")
    else:
        for p in proposals[:MAX_PROPOSALS_CARD]:
            rule = p.get("rule_name") or "(unnamed)"
            fp = int(p.get("false_positive_count") or 0)
            benign = int(p.get("benign_tp_count") or 0)
            total = int(p.get("total_count") or 0)
            risk = (p.get("change_risk") or "medium").upper()
            conf = float(p.get("confidence") or 0.0)
            rec = (p.get("tuning_recommendation") or "").strip()
            samples = " ".join(_linkify_ticket_id(t)
                               for t in (p.get("sample_ticket_ids") or [])[:5])
            lines += [
                f"### {rule}  _[risk: {risk}]_",
                (f"**{fp}** FP • **{benign}** Benign-TP • **{total}** total • "
                 f"confidence **{conf:.0%}**"),
                f"💡 {rec}" if rec else "",
                f"Samples: {samples}" if samples else "",
                "",
            ]
        if len(proposals) > MAX_PROPOSALS_CARD:
            lines.append(f"_+ {len(proposals) - MAX_PROPOSALS_CARD} more in the bus event._")
    lines += ["", "— Detection Engineer"]
    return "\n".join(l for l in lines if l is not None)
