"""Sleuth Webex card for Tier 2 escalations to the IR Lead.

Sent only when Tier 2's ``escalation_decision`` == ``escalate_to_ir_lead``.
Non-escalation Tier 2 reviews stay quiet (bus event + verdict_store only)
so we don't drown the room.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from src.components.soc_in_box.schemas import Tier2Analysis
from src.utils.xsoar_helpers import build_incident_url

logger = logging.getLogger(__name__)


_TICKET_REF_RE = re.compile(r"#?(\d{4,})")


def _linkify_ticket_id(ticket_id: str) -> str:
    """Return Markdown link for a single ticket id, e.g. ``[#901001](url)``."""
    if not ticket_id:
        return "—"
    return f"[#{ticket_id}]({build_incident_url(ticket_id)})"


def _linkify_ticket_refs(text: str) -> str:
    """Find any ``#NNNN`` or bare 4+ digit ticket references in free-form text
    and replace them with Markdown links. LLM-emitted ``similar_incidents``
    strings are the main consumer."""
    if not text:
        return text

    def _sub(match: re.Match) -> str:
        tid = match.group(1)
        return f"[#{tid}]({build_incident_url(tid)})"

    return _TICKET_REF_RE.sub(_sub, text)


VERDICT_DISPLAY = {
    "true_positive_malicious":           "TP — Malicious",
    "true_positive_malicious_contained": "TP — Contained",
    "true_positive_benign":               "TP — Benign",
    "false_positive":                     "False Positive",
    "close_ticket":                       "Close",
}

VERDICT_COLOR = {
    "true_positive_malicious":           "Attention",
    "true_positive_malicious_contained": "Warning",
    "true_positive_benign":               "Warning",
    "false_positive":                     "Good",
    "close_ticket":                       "Default",
}


def _render_card(analysis: Tier2Analysis, triage_event: dict[str, Any]) -> dict[str, Any]:
    from src.components.soc_in_box.sandbox import (
        is_sandbox_ticket, sandbox_banner_card_block,
    )
    body: list[dict[str, Any]] = []

    if is_sandbox_ticket(analysis.ticket_id):
        body.append(sandbox_banner_card_block())

    # Hero — attention-styled because this is a "wake the IR Lead" event
    body.append({
        "type": "Container",
        "style": "attention",
        "bleed": True,
        "items": [
            {"type": "TextBlock", "text": "🚨 Tier 2 → IR Lead Escalation",
             "size": "Large", "weight": "Bolder", "wrap": True},
            {"type": "TextBlock",
             "text": f"Ticket {_linkify_ticket_id(analysis.ticket_id)}  •  Priority {analysis.priority_score}/10",
             "isSubtle": True, "spacing": "Small", "wrap": True},
        ],
    })

    # KPI row — verdict transition + confidence
    body.append({
        "type": "ColumnSet", "spacing": "Medium",
        "columns": [
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": "Sentinel said",
                 "isSubtle": True, "size": "Small", "spacing": "None"},
                {"type": "TextBlock",
                 "text": VERDICT_DISPLAY.get(analysis.original_verdict, analysis.original_verdict),
                 "weight": "Bolder",
                 "color": VERDICT_COLOR.get(analysis.original_verdict, "Default"),
                 "spacing": "None"},
            ]},
            {"type": "Column", "width": "auto", "items": [
                {"type": "TextBlock", "text": "→", "size": "Large",
                 "weight": "Bolder", "spacing": "None"},
            ]},
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": "Tier 2 refined",
                 "isSubtle": True, "size": "Small", "spacing": "None"},
                {"type": "TextBlock",
                 "text": VERDICT_DISPLAY.get(analysis.refined_verdict, analysis.refined_verdict),
                 "weight": "Bolder",
                 "color": VERDICT_COLOR.get(analysis.refined_verdict, "Default"),
                 "spacing": "None"},
            ]},
            {"type": "Column", "width": "auto", "items": [
                {"type": "TextBlock", "text": "Confidence",
                 "isSubtle": True, "size": "Small", "spacing": "None"},
                {"type": "TextBlock", "text": f"{analysis.confidence:.0%}",
                 "weight": "Bolder", "spacing": "None"},
            ]},
        ],
    })

    # Host + user
    host = analysis.hostname or "—"
    user = analysis.username or "—"
    body.append({
        "type": "FactSet", "spacing": "Medium",
        "facts": [
            {"title": "Host", "value": host},
            {"title": "User", "value": user},
        ],
    })

    # Tier 2 narrative
    body.append({"type": "TextBlock", "text": "Tier 2 Investigation",
                 "weight": "Bolder", "size": "Medium", "spacing": "Large"})
    body.append({"type": "TextBlock", "text": analysis.tier2_summary or "(no summary)",
                 "wrap": True})

    # Similar incidents — linkify any embedded ticket refs
    if analysis.similar_incidents:
        body.append({"type": "TextBlock", "text": "Similar past incidents",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for s in analysis.similar_incidents[:5]:
            body.append({"type": "TextBlock",
                         "text": f"• {_linkify_ticket_refs(s)}",
                         "wrap": True, "spacing": "Small"})

    # Next steps
    if analysis.next_steps:
        body.append({"type": "TextBlock", "text": "Recommended next steps",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for s in analysis.next_steps[:6]:
            body.append({"type": "TextBlock", "text": f"• {s}", "wrap": True,
                         "spacing": "Small"})

    # Sign-off
    body.append({
        "type": "TextBlock",
        "text": "— Tier 2 Analyst",
        "isSubtle": True, "size": "Small", "spacing": "Large",
        "horizontalAlignment": "Right",
    })

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.2",
        "body": body,
    }


def _render_fallback_markdown(analysis: Tier2Analysis) -> str:
    """Plain-Markdown fallback for clients that don't render the card."""
    from src.components.soc_in_box.sandbox import (
        is_sandbox_ticket, sandbox_banner_md,
    )
    lines = [
        *([sandbox_banner_md()] if is_sandbox_ticket(analysis.ticket_id) else []),
        f"## 🚨 Tier 2 → IR Lead Escalation",
        f"**Ticket {_linkify_ticket_id(analysis.ticket_id)}** • Priority {analysis.priority_score}/10",
        "",
        f"**Sentinel:** {VERDICT_DISPLAY.get(analysis.original_verdict, analysis.original_verdict)}  →  "
        f"**Tier 2:** {VERDICT_DISPLAY.get(analysis.refined_verdict, analysis.refined_verdict)} "
        f"(confidence {analysis.confidence:.0%})",
        f"**Host:** {analysis.hostname or '—'}  •  **User:** {analysis.username or '—'}",
        "",
        analysis.tier2_summary or "(no summary)",
    ]
    if analysis.similar_incidents:
        lines += ["", "**Similar incidents:**"]
        lines += [f"- {_linkify_ticket_refs(s)}" for s in analysis.similar_incidents[:5]]
    if analysis.next_steps:
        lines += ["", "**Next steps:**"]
        lines += [f"- {s}" for s in analysis.next_steps[:6]]
    lines += ["", "— Tier 2 Analyst"]
    return "\n".join(lines)


def send_escalation_card(analysis: Tier2Analysis,
                         triage_event: dict[str, Any]) -> Optional[str]:
    """Send a Tier 2 escalation card to Sleuth's dev test space.

    Returns the Webex message id, or None on failure.
    """
    from my_config import get_config
    from webexteamssdk import WebexTeamsAPI
    cfg = get_config()
    token = cfg.webex_bot_access_token_sleuth
    if not token:
        logger.warning("tier2_webex: WEBEX_BOT_ACCESS_TOKEN_SLEUTH not set, skipping")
        return None
    room = cfg.webex_room_id_soc_in_a_box or cfg.webex_room_id_dev_test_space
    if not room:
        logger.warning("tier2_webex: no Webex room configured, skipping")
        return None
    try:
        api = WebexTeamsAPI(access_token=token)
        msg = api.messages.create(
            roomId=room,
            markdown=_render_fallback_markdown(analysis),
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": _render_card(analysis, triage_event),
            }],
        )
        return getattr(msg, "id", None)
    except Exception as exc:
        logger.error("tier2_webex: send failed: %s", exc)
        return None
