"""Pokedex Webex card for Threat Hunter sweeps.

One card per timer run. Findings listed worst-first (most tickets at the
top). Each finding has a kind badge so the responder can scan and pick
which hunts to chase.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from src.utils.xsoar_helpers import build_incident_url


EASTERN = ZoneInfo("America/New_York")


def _fmt_eastern(dt: datetime) -> str:
    return dt.astimezone(EASTERN).strftime("%m/%d/%Y %I:%M %p %Z")


# Finding kind → container style + badge color
KIND_STYLE = {
    "host_repeat":     "warning",
    "shared_pivot":    "attention",
    "potential_miss":  "attention",
}

KIND_COLOR = {
    "host_repeat":     "Warning",
    "shared_pivot":    "Attention",
    "potential_miss":  "Attention",
}

KIND_LABEL = {
    "host_repeat":     "HOST REPEAT",
    "shared_pivot":    "SHARED PIVOT",
    "potential_miss":  "POTENTIAL MISS",
}

KIND_EMOJI = {
    "host_repeat":     "🔁",
    "shared_pivot":    "🕸️",
    "potential_miss":  "🫥",
}


MAX_FINDINGS_CARD = 6


def _linkify_ticket_id(ticket_id: str) -> str:
    if not ticket_id:
        return "—"
    return f"[#{ticket_id}]({build_incident_url(ticket_id)})"


def render_card(window_start: datetime, window_end: datetime,
                hunts_examined: int,
                findings: list[dict[str, Any]]) -> dict[str, Any]:
    body: list[dict[str, Any]] = []

    # Hero
    body.append({
        "type": "Container", "style": "accent", "bleed": True,
        "items": [
            {"type": "TextBlock", "text": "🔭 Threat Hunter Sweep",
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
                {"type": "TextBlock", "text": "Alerts hunted", "isSubtle": True,
                 "size": "Small", "spacing": "None"},
                {"type": "TextBlock", "text": str(hunts_examined),
                 "size": "ExtraLarge", "weight": "Bolder", "spacing": "None"},
            ]},
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": "Findings", "isSubtle": True,
                 "size": "Small", "spacing": "None"},
                {"type": "TextBlock", "text": str(len(findings)),
                 "size": "ExtraLarge", "weight": "Bolder", "spacing": "None",
                 "color": "Warning" if findings else "Default"},
            ]},
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": "Shown", "isSubtle": True,
                 "size": "Small", "spacing": "None"},
                {"type": "TextBlock",
                 "text": str(min(len(findings), MAX_FINDINGS_CARD)),
                 "size": "ExtraLarge", "weight": "Bolder", "spacing": "None"},
            ]},
        ],
    })

    if not findings:
        body.append({
            "type": "TextBlock", "spacing": "Large",
            "text": ("No hunting signal in this window — recurring hosts, shared "
                     "pivots, and confirmed-malicious tickets all reconciled cleanly. "
                     "Reactive coverage looks sound."),
            "wrap": True, "isSubtle": True,
        })
    else:
        body.append({"type": "TextBlock", "text": "Findings",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for f in findings[:MAX_FINDINGS_CARD]:
            body.append(_finding_container(f))

        if len(findings) > MAX_FINDINGS_CARD:
            body.append({
                "type": "TextBlock",
                "text": (f"+ {len(findings) - MAX_FINDINGS_CARD} more in the bus event."),
                "wrap": True, "isSubtle": True, "spacing": "Medium",
            })

    # Sign-off
    body.append({
        "type": "TextBlock", "text": "— Threat Hunter",
        "isSubtle": True, "size": "Small", "spacing": "Large",
        "horizontalAlignment": "Right",
    })

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.2",
        "body": body,
    }


def _finding_container(f: dict[str, Any]) -> dict[str, Any]:
    kind = (f.get("kind") or "host_repeat").lower()
    style = KIND_STYLE.get(kind, "warning")
    color = KIND_COLOR.get(kind, "Warning")
    label = KIND_LABEL.get(kind, kind.upper())
    emoji = KIND_EMOJI.get(kind, "🔍")
    confidence = float(f.get("confidence") or 0.0)
    ticket_count = int(f.get("ticket_count") or len(f.get("related_tickets") or []))
    indicator = f.get("indicator") or "(no indicator)"

    items: list[dict[str, Any]] = [
        {"type": "ColumnSet", "columns": [
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock",
                 "text": f"{emoji} **{indicator}**",
                 "weight": "Bolder", "wrap": True, "spacing": "None"},
            ]},
            {"type": "Column", "width": "auto", "items": [
                {"type": "TextBlock",
                 "text": label,
                 "color": color, "weight": "Bolder",
                 "horizontalAlignment": "Right", "spacing": "None"},
            ]},
        ]},
        {"type": "TextBlock",
         "text": (f"**{ticket_count}** ticket{'s' if ticket_count != 1 else ''}  •  "
                  f"confidence **{confidence:.0%}**"),
         "wrap": True, "spacing": "Small", "isSubtle": True},
    ]

    entities = f.get("affected_entities") or []
    if entities:
        items.append({
            "type": "TextBlock",
            "text": "  ".join(f"`{e}`" for e in entities[:6]),
            "wrap": True, "spacing": "Small",
        })

    desc = (f.get("description") or "").strip()
    if desc:
        items.append({"type": "TextBlock", "text": desc, "wrap": True, "spacing": "Small"})

    invest = (f.get("suggested_investigation") or "").strip()
    if invest:
        items.append({"type": "TextBlock", "text": f"🔬 {invest}",
                     "wrap": True, "spacing": "Small"})

    tickets = f.get("related_tickets") or []
    if tickets:
        items.append({
            "type": "TextBlock",
            "text": "Related: " + "  ".join(_linkify_ticket_id(t) for t in tickets[:5]),
            "wrap": True, "spacing": "Small", "isSubtle": True,
        })

    return {
        "type": "Container", "style": style, "spacing": "Medium",
        "items": items,
    }


def render_fallback_markdown(window_start: datetime, window_end: datetime,
                             hunts_examined: int,
                             findings: list[dict[str, Any]]) -> str:
    lines = [
        "## 🔭 Threat Hunter Sweep",
        f"**Window:** {_fmt_eastern(window_start)} → {_fmt_eastern(window_end)}",
        (f"**Alerts hunted:** {hunts_examined}  •  **Findings:** {len(findings)}"),
        "",
    ]
    if not findings:
        lines.append("No hunting signal in this window — reactive coverage looks sound.")
    else:
        for f in findings[:MAX_FINDINGS_CARD]:
            kind = (f.get("kind") or "").upper()
            indicator = f.get("indicator") or "?"
            ticket_count = int(f.get("ticket_count") or 0)
            conf = float(f.get("confidence") or 0.0)
            desc = (f.get("description") or "").strip()
            invest = (f.get("suggested_investigation") or "").strip()
            samples = " ".join(_linkify_ticket_id(t)
                               for t in (f.get("related_tickets") or [])[:5])
            lines += [
                f"### {indicator}  _[{kind}]_",
                (f"**{ticket_count}** tickets • confidence **{conf:.0%}**"),
                desc if desc else "",
                f"🔬 {invest}" if invest else "",
                f"Related: {samples}" if samples else "",
                "",
            ]
        if len(findings) > MAX_FINDINGS_CARD:
            lines.append(f"_+ {len(findings) - MAX_FINDINGS_CARD} more in the bus event._")
    lines += ["", "— Threat Hunter"]
    return "\n".join(l for l in lines if l is not None)
