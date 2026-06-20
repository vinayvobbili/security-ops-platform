"""Sleuth Webex card + XSOAR note for the Threat Intel agent.

Card lands AFTER the IR Lead's card on every confirmed incident — it
gives the responder actor / campaign / MITRE context to read alongside
the response plan.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from src.components.soc_in_box.schemas import ThreatIntelReport
from src.utils.xsoar_helpers import build_incident_url

logger = logging.getLogger(__name__)


_TICKET_REF_RE = re.compile(r"#?(\d{4,})")


def _linkify_ticket_id(ticket_id: str) -> str:
    if not ticket_id:
        return "—"
    return f"[#{ticket_id}]({build_incident_url(ticket_id)})"


def _linkify_ticket_refs(text: str) -> str:
    if not text:
        return text

    def _sub(match: re.Match) -> str:
        tid = match.group(1)
        return f"[#{tid}]({build_incident_url(tid)})"

    return _TICKET_REF_RE.sub(_sub, text)


# Reputation → text color in the Adaptive Card
REPUTATION_COLOR = {
    "malicious":  "Attention",
    "suspicious": "Warning",
    "clean":      "Good",
    "unknown":    "Default",
}

# Severity adjustment → container style
SEV_ADJ_STYLE = {
    "raise":   "attention",
    "lower":   "good",
    "confirm": "emphasis",
    "none":    "default",
}

SEV_ADJ_EMOJI = {
    "raise":   "⬆️",
    "lower":   "⬇️",
    "confirm": "✔️",
    "none":    "",
}


def _render_card(report: ThreatIntelReport,
                 ir_plan_ctx: dict[str, Any],
                 triage_ctx: dict[str, Any]) -> dict[str, Any]:
    from src.components.soc_in_box.sandbox import (
        is_sandbox_ticket, sandbox_banner_card_block,
    )
    body: list[dict[str, Any]] = []

    if is_sandbox_ticket(report.ticket_id):
        body.append(sandbox_banner_card_block())

    # Hero — accent-styled since TI is informational, not alarming
    body.append({
        "type": "Container", "style": "accent", "bleed": True,
        "items": [
            {"type": "TextBlock", "text": "🌐 Threat Intel — Actor & Campaign Context",
             "size": "Large", "weight": "Bolder", "wrap": True},
            {"type": "TextBlock",
             "text": (f"Ticket {_linkify_ticket_id(report.ticket_id)}  •  "
                      f"Confidence {report.confidence:.0%}"),
             "isSubtle": True, "spacing": "Small", "wrap": True},
        ],
    })

    # Intel summary
    if report.intel_summary:
        body.append({"type": "TextBlock", "text": report.intel_summary,
                     "wrap": True, "spacing": "Medium"})

    # Attribution panel
    if report.likely_actor:
        body.append({
            "type": "Container", "style": "emphasis", "spacing": "Medium",
            "items": [
                {"type": "ColumnSet", "columns": [
                    {"type": "Column", "width": "stretch", "items": [
                        {"type": "TextBlock", "text": "Likely actor",
                         "isSubtle": True, "size": "Small", "spacing": "None"},
                        {"type": "TextBlock", "text": report.likely_actor,
                         "weight": "Bolder", "size": "Large", "spacing": "None",
                         "color": "Attention"},
                    ]},
                    {"type": "Column", "width": "auto", "items": [
                        {"type": "TextBlock", "text": "Attribution conf.",
                         "isSubtle": True, "size": "Small", "spacing": "None"},
                        {"type": "TextBlock", "text": f"{report.actor_confidence:.0%}",
                         "weight": "Bolder", "size": "Large", "spacing": "None"},
                    ]},
                ]},
                ({"type": "TextBlock", "text": report.actor_evidence,
                  "wrap": True, "isSubtle": True, "spacing": "Small"}
                 if report.actor_evidence else {"type": "TextBlock", "text": " ", "size": "Small"}),
            ],
        })
    else:
        body.append({
            "type": "TextBlock",
            "text": "_Attribution: not enough convergent signal to name an actor._",
            "wrap": True, "isSubtle": True, "spacing": "Medium",
        })

    # Campaigns
    if report.campaigns:
        body.append({"type": "TextBlock", "text": "Campaigns",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        body.append({
            "type": "TextBlock",
            "text": "  ".join(f"**`{c}`**" for c in report.campaigns[:6]),
            "wrap": True, "spacing": "Small",
        })

    # MITRE techniques
    if report.mitre_techniques:
        body.append({"type": "TextBlock", "text": "🗺️ MITRE ATT&CK techniques",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        body.append({
            "type": "TextBlock",
            "text": "  ".join(f"`{t}`" for t in report.mitre_techniques[:10]),
            "wrap": True, "spacing": "Small",
        })

    # IOC reputation table
    if report.iocs_examined:
        body.append({"type": "TextBlock", "text": "🔎 IOC reputation",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for ioc in report.iocs_examined[:8]:
            rep = (ioc.get("reputation") or "unknown").lower()
            color = REPUTATION_COLOR.get(rep, "Default")
            body.append({
                "type": "ColumnSet", "spacing": "Small",
                "columns": [
                    {"type": "Column", "width": "auto", "items": [
                        {"type": "TextBlock",
                         "text": f"`{(ioc.get('type') or '?').lower()}`",
                         "isSubtle": True, "spacing": "None"},
                    ]},
                    {"type": "Column", "width": "stretch", "items": [
                        {"type": "TextBlock",
                         "text": f"`{ioc.get('value') or '—'}`",
                         "wrap": True, "spacing": "None"},
                    ]},
                    {"type": "Column", "width": "auto", "items": [
                        {"type": "TextBlock",
                         "text": rep.upper(),
                         "weight": "Bolder", "color": color, "spacing": "None"},
                    ]},
                    {"type": "Column", "width": "auto", "items": [
                        {"type": "TextBlock",
                         "text": f"_{(ioc.get('source') or '?').lower()}_",
                         "isSubtle": True, "spacing": "None"},
                    ]},
                ],
            })

    # Historical incidents
    if report.related_historical_incidents:
        body.append({"type": "TextBlock", "text": "Related historical incidents",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for s in report.related_historical_incidents[:5]:
            body.append({
                "type": "TextBlock",
                "text": f"• {_linkify_ticket_refs(str(s))}",
                "wrap": True, "spacing": "Small",
            })

    # Severity adjustment callout (only if not "none")
    if report.severity_adjustment != "none":
        style = SEV_ADJ_STYLE.get(report.severity_adjustment, "default")
        emoji = SEV_ADJ_EMOJI.get(report.severity_adjustment, "")
        body.append({
            "type": "Container", "style": style, "spacing": "Large",
            "items": [
                {"type": "TextBlock",
                 "text": f"{emoji} Severity adjustment: **{report.severity_adjustment.upper()}**",
                 "weight": "Bolder", "wrap": True},
                ({"type": "TextBlock", "text": report.severity_adjustment_reason,
                  "wrap": True, "spacing": "Small"}
                 if report.severity_adjustment_reason else
                 {"type": "TextBlock", "text": " ", "size": "Small"}),
            ],
        })

    # Sign-off
    body.append({
        "type": "TextBlock", "text": "— Threat Intel",
        "isSubtle": True, "size": "Small", "spacing": "Large",
        "horizontalAlignment": "Right",
    })

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.2",
        "body": body,
    }


def _render_fallback_markdown(report: ThreatIntelReport) -> str:
    from src.components.soc_in_box.sandbox import (
        is_sandbox_ticket, sandbox_banner_md,
    )
    lines = [
        *([sandbox_banner_md()] if is_sandbox_ticket(report.ticket_id) else []),
        "## 🌐 Threat Intel — Actor & Campaign Context",
        (f"**Ticket {_linkify_ticket_id(report.ticket_id)}** • "
         f"Confidence {report.confidence:.0%}"),
        "",
        report.intel_summary or "_(no summary)_",
    ]
    if report.likely_actor:
        lines += ["", f"**Likely actor:** {report.likely_actor}  "
                  f"(confidence {report.actor_confidence:.0%})"]
        if report.actor_evidence:
            lines.append(f"_{report.actor_evidence}_")
    if report.campaigns:
        lines += ["", "**Campaigns:** " + ", ".join(f"`{c}`" for c in report.campaigns[:6])]
    if report.mitre_techniques:
        lines += ["", "**MITRE:** " + " ".join(f"`{t}`" for t in report.mitre_techniques[:10])]
    if report.iocs_examined:
        lines += ["", "**IOCs:**"]
        for ioc in report.iocs_examined[:8]:
            rep = (ioc.get("reputation") or "unknown").upper()
            lines.append(f"- `{ioc.get('value', '—')}` ({(ioc.get('type') or '?')}): "
                         f"**{rep}** _({ioc.get('source') or '?'})_")
    if report.severity_adjustment != "none":
        lines += ["", (f"**Severity adjustment:** {report.severity_adjustment.upper()}"
                       + (f" — {report.severity_adjustment_reason}"
                          if report.severity_adjustment_reason else ""))]
    lines += ["", "— Threat Intel"]
    return "\n".join(lines)


def render_xsoar_note(report: ThreatIntelReport) -> str:
    """Markdown body for the war-room entry the TI agent writes to the
    XSOAR ticket alongside the IR Lead's plan note.
    """
    lines = [
        "## 🌐 SOC-in-a-Box Threat Intel",
        (f"**Confidence:** {report.confidence:.0%}"
         + (f"  •  **Likely actor:** {report.likely_actor}  "
            f"(confidence {report.actor_confidence:.0%})"
            if report.likely_actor else "")),
        "",
        "### Summary",
        report.intel_summary or "_(none)_",
    ]
    if report.actor_evidence:
        lines += ["", "### Attribution evidence", report.actor_evidence]
    if report.campaigns:
        lines += ["", "### Campaigns", ", ".join(f"`{c}`" for c in report.campaigns)]
    if report.mitre_techniques:
        lines += ["", "### MITRE ATT&CK techniques",
                  " ".join(f"`{t}`" for t in report.mitre_techniques)]
    if report.iocs_examined:
        lines += ["", "### IOC reputation"]
        for ioc in report.iocs_examined[:12]:
            rep = (ioc.get("reputation") or "unknown").upper()
            lines.append(f"- `{ioc.get('value', '—')}` ({(ioc.get('type') or '?')}): "
                         f"**{rep}** _({ioc.get('source') or '?'})_")
    if report.related_historical_incidents:
        lines += ["", "### Related historical incidents"]
        for s in report.related_historical_incidents[:8]:
            lines.append(f"- {s}")
    if report.severity_adjustment != "none":
        lines += ["", (f"### Severity adjustment recommendation\n"
                       f"**{report.severity_adjustment.upper()}**"
                       + (f" — {report.severity_adjustment_reason}"
                          if report.severity_adjustment_reason else ""))]
    lines += ["", "_Generated by SOC-in-a-Box Threat Intel agent. Advisory only — IR "
              "Lead retains the severity call._"]
    return "\n".join(lines)


def send_ti_card(report: ThreatIntelReport,
                 ir_plan_ctx: dict[str, Any],
                 triage_ctx: dict[str, Any]) -> Optional[str]:
    """Send the TI card to the SOC-in-a-Box room (falls back to dev test space)."""
    from my_config import get_config
    from webexteamssdk import WebexTeamsAPI
    cfg = get_config()
    token = cfg.webex_bot_access_token_sleuth
    if not token:
        logger.warning("threat_intel_webex: WEBEX_BOT_ACCESS_TOKEN_SLEUTH not set, skipping")
        return None
    room = cfg.webex_room_id_soc_in_a_box or cfg.webex_room_id_dev_test_space
    if not room:
        logger.warning("threat_intel_webex: no Webex room configured, skipping")
        return None
    try:
        api = WebexTeamsAPI(access_token=token)
        msg = api.messages.create(
            roomId=room,
            markdown=_render_fallback_markdown(report),
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": _render_card(report, ir_plan_ctx, triage_ctx),
            }],
        )
        return getattr(msg, "id", None)
    except Exception as exc:
        logger.error("threat_intel_webex: send failed: %s", exc)
        return None
