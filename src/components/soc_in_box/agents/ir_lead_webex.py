"""Pokedex Webex card for IR Lead response plans.

Sent on every ``IRPlan`` emission (i.e. every Tier 2 → IR Lead escalation).
The card is the human handoff — bridge call instruction, structured action
queue, stakeholder list — so the on-call lead can act without rummaging
through the bus.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from src.components.soc_in_box.schemas import IRPlan
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


# SEV → Adaptive Card container style + accent color
SEV_CONTAINER_STYLE = {
    "SEV-1": "attention",   # red — page everyone
    "SEV-2": "attention",   # red — bring in the lead
    "SEV-3": "warning",     # amber — contained but real
    "SEV-4": "emphasis",    # gray — minor
}

SEV_TEXT_COLOR = {
    "SEV-1": "Attention",
    "SEV-2": "Attention",
    "SEV-3": "Warning",
    "SEV-4": "Default",
}

SEV_EMOJI = {
    "SEV-1": "🚨",
    "SEV-2": "🚨",
    "SEV-3": "⚠️",
    "SEV-4": "ℹ️",
}


def _action_section(title: str, items: list[str],
                    color: Optional[str] = None) -> list[dict[str, Any]]:
    if not items:
        return []
    blocks: list[dict[str, Any]] = [{
        "type": "TextBlock", "text": title,
        "weight": "Bolder", "size": "Medium", "spacing": "Large",
        **({"color": color} if color else {}),
    }]
    for i in items[:8]:
        blocks.append({
            "type": "TextBlock", "text": f"• {i}", "wrap": True, "spacing": "Small",
        })
    return blocks


def _build_hitl_url(action_id: str, decision: str) -> str:
    """Resolve the HITL approve/reject URL from config (gdnr.the-company.com fallback)."""
    from my_config import get_config
    try:
        base = (get_config().web_server_url or "http://gdnr.the-company.com").rstrip("/")
    except Exception:
        base = "http://gdnr.the-company.com"
    return f"{base}/soc-hitl/decide?action_id={action_id}&decision={decision}"


def _render_card(plan: IRPlan, tier2_ctx: dict[str, Any],
                 triage_ctx: dict[str, Any],
                 hitl_action_id: Optional[str] = None,
                 hitl_approver_role: str = "",
                 hitl_approver_name: str = "") -> dict[str, Any]:
    from src.components.soc_in_box.sandbox import (
        is_sandbox_ticket, sandbox_banner_card_block,
    )
    body: list[dict[str, Any]] = []

    if is_sandbox_ticket(plan.ticket_id):
        body.append(sandbox_banner_card_block())

    sev_style = SEV_CONTAINER_STYLE.get(plan.severity, "default")
    sev_color = SEV_TEXT_COLOR.get(plan.severity, "Default")
    sev_emoji = SEV_EMOJI.get(plan.severity, "")

    # Hero — SEV-styled
    bridge_chip = "  •  🔔 BRIDGE REQUIRED" if plan.bridge_required else ""
    body.append({
        "type": "Container", "style": sev_style, "bleed": True,
        "items": [
            {"type": "TextBlock",
             "text": f"{sev_emoji} {plan.severity} — IR Response Plan{bridge_chip}",
             "size": "Large", "weight": "Bolder", "wrap": True},
            {"type": "TextBlock",
             "text": (f"Ticket {_linkify_ticket_id(plan.ticket_id)}  •  "
                      f"Priority {plan.priority_score}/10  •  "
                      f"Confidence {plan.confidence:.0%}"),
             "isSubtle": True, "spacing": "Small", "wrap": True},
        ],
    })

    # Host / user / runbook FactSet
    facts = [
        {"title": "Host", "value": plan.hostname or "—"},
        {"title": "User", "value": plan.username or "—"},
    ]
    if plan.runbook:
        facts.append({"title": "Runbook", "value": plan.runbook})
    body.append({"type": "FactSet", "spacing": "Medium", "facts": facts})

    # Summary
    if plan.ir_summary:
        body.append({"type": "TextBlock", "text": "Executive summary",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        body.append({"type": "TextBlock", "text": plan.ir_summary, "wrap": True})

    # Action sections — color the headers so the eye finds them fast
    body.extend(_action_section("🛡️ Containment", plan.containment_actions,
                                color="Attention"))
    body.extend(_action_section("🧹 Eradication", plan.eradication_actions,
                                color="Warning"))
    body.extend(_action_section("♻️ Recovery", plan.recovery_actions,
                                color="Good"))

    # Notifications — chips-style list
    if plan.notifications:
        body.append({"type": "TextBlock", "text": "📣 Notify",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        body.append({
            "type": "TextBlock",
            "text": "  ".join(f"**`{n}`**" for n in plan.notifications[:8]),
            "wrap": True, "spacing": "Small",
        })

    # Tier 2 context callback (linkified ticket refs in similar incidents)
    similar = (tier2_ctx or {}).get("similar_incidents") or []
    if similar:
        body.append({"type": "TextBlock", "text": "Similar past incidents (from Tier 2)",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for s in similar[:5]:
            body.append({
                "type": "TextBlock",
                "text": f"• {_linkify_ticket_refs(str(s))}",
                "wrap": True, "spacing": "Small",
            })

    # HITL banner — only when there's a containment action to approve
    if hitl_action_id:
        # Build the "this is for you, NAME / ROLE" line
        if hitl_approver_name and hitl_approver_role:
            addressee = f"**{hitl_approver_name}**  •  _{hitl_approver_role}_"
        elif hitl_approver_name:
            addressee = f"**{hitl_approver_name}**"
        elif hitl_approver_role:
            addressee = f"**{hitl_approver_role}**"
        else:
            addressee = "**On-call approver**"
        body.append({
            "type": "Container", "style": "warning", "bleed": True,
            "spacing": "Large",
            "items": [
                {"type": "TextBlock",
                 "text": f"🎯 Action required from: {addressee}",
                 "weight": "Bolder", "size": "Medium", "wrap": True,
                 "color": "Attention"},
                {"type": "TextBlock",
                 "text": ("AI agents will not execute containment without your "
                          "approval. Review the actions above, then choose."),
                 "isSubtle": True, "wrap": True, "spacing": "Small"},
            ],
        })

    # Sign-off
    body.append({
        "type": "TextBlock",
        "text": "— IR Lead",
        "isSubtle": True, "size": "Small", "spacing": "Large",
        "horizontalAlignment": "Right",
    })

    card: dict[str, Any] = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.2",
        "body": body,
    }

    # HITL action buttons — open the Flask confirmation page in browser
    if hitl_action_id:
        card["actions"] = [
            {"type": "Action.OpenUrl",
             "title": "✅ Approve & Execute Containment",
             "url": _build_hitl_url(hitl_action_id, "approve")},
            {"type": "Action.OpenUrl",
             "title": "🛑 Reject Plan",
             "url": _build_hitl_url(hitl_action_id, "reject")},
        ]

    return card


def _render_fallback_markdown(plan: IRPlan) -> str:
    from src.components.soc_in_box.sandbox import (
        is_sandbox_ticket, sandbox_banner_md,
    )
    sev_emoji = SEV_EMOJI.get(plan.severity, "")
    bridge = "  •  🔔 **BRIDGE REQUIRED**" if plan.bridge_required else ""
    lines = [
        *([sandbox_banner_md()] if is_sandbox_ticket(plan.ticket_id) else []),
        f"## {sev_emoji} {plan.severity} — IR Response Plan{bridge}",
        (f"**Ticket {_linkify_ticket_id(plan.ticket_id)}** • "
         f"Priority {plan.priority_score}/10 • Confidence {plan.confidence:.0%}"),
        f"**Host:** {plan.hostname or '—'}  •  **User:** {plan.username or '—'}"
        + (f"  •  **Runbook:** {plan.runbook}" if plan.runbook else ""),
        "",
        plan.ir_summary or "(no summary)",
    ]
    if plan.containment_actions:
        lines += ["", "**Containment:**"]
        lines += [f"- {a}" for a in plan.containment_actions[:8]]
    if plan.eradication_actions:
        lines += ["", "**Eradication:**"]
        lines += [f"- {a}" for a in plan.eradication_actions[:8]]
    if plan.recovery_actions:
        lines += ["", "**Recovery:**"]
        lines += [f"- {a}" for a in plan.recovery_actions[:8]]
    if plan.notifications:
        lines += ["", "**Notify:** " + ", ".join(f"`{n}`" for n in plan.notifications[:8])]
    lines += ["", "— IR Lead"]
    return "\n".join(lines)


def render_xsoar_note(plan: IRPlan) -> str:
    """Markdown body for the XSOAR war-room entry the IR Lead writes back to the
    ticket. Same content as the Webex card, formatted for inline XSOAR display
    so the human responder has the plan in the ticket without chasing a chat
    message.
    """
    sev_emoji = SEV_EMOJI.get(plan.severity, "")
    bridge = "  •  🔔 **BRIDGE REQUIRED**" if plan.bridge_required else ""
    lines = [
        f"## {sev_emoji} SOC-in-a-Box IR Lead Plan — {plan.severity}{bridge}",
        (f"**Priority:** {plan.priority_score}/10  •  "
         f"**Confidence:** {plan.confidence:.0%}"
         + (f"  •  **Runbook:** `{plan.runbook}`" if plan.runbook else "")),
        f"**Host:** {plan.hostname or '—'}  •  **User:** {plan.username or '—'}",
        "",
        "### Executive summary",
        plan.ir_summary or "_(none)_",
    ]
    if plan.containment_actions:
        lines += ["", "### 🛡️ Containment"]
        lines += [f"- {a}" for a in plan.containment_actions[:10]]
    if plan.eradication_actions:
        lines += ["", "### 🧹 Eradication"]
        lines += [f"- {a}" for a in plan.eradication_actions[:10]]
    if plan.recovery_actions:
        lines += ["", "### ♻️ Recovery"]
        lines += [f"- {a}" for a in plan.recovery_actions[:10]]
    if plan.notifications:
        lines += ["", "### 📣 Notify",
                  ", ".join(f"`{n}`" for n in plan.notifications[:10])]
    lines += ["", "_Generated by SOC-in-a-Box IR Lead. Plan is advisory — execute via "
              "normal IR procedures._"]
    return "\n".join(lines)


def send_ir_plan_card(plan: IRPlan,
                      tier2_ctx: dict[str, Any],
                      triage_ctx: dict[str, Any],
                      hitl_action_id: Optional[str] = None,
                      hitl_approver_role: str = "",
                      hitl_approver_name: str = "") -> Optional[str]:
    """Send the IR Lead's plan card to Pokedex's dev test space.

    If ``hitl_action_id`` is set, the card includes Approve/Reject buttons
    that link to the Flask HITL endpoint.
    """
    from my_config import get_config
    from webexteamssdk import WebexTeamsAPI
    cfg = get_config()
    token = cfg.webex_bot_access_token_pokedex
    if not token:
        logger.warning("ir_lead_webex: WEBEX_BOT_ACCESS_TOKEN_POKEDEX not set, skipping")
        return None
    room = cfg.webex_room_id_soc_in_a_box or cfg.webex_room_id_dev_test_space
    if not room:
        logger.warning("ir_lead_webex: no Webex room configured, skipping")
        return None
    try:
        api = WebexTeamsAPI(access_token=token)
        msg = api.messages.create(
            roomId=room,
            markdown=_render_fallback_markdown(plan),
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": _render_card(plan, tier2_ctx, triage_ctx,
                                        hitl_action_id=hitl_action_id,
                                        hitl_approver_role=hitl_approver_role,
                                        hitl_approver_name=hitl_approver_name),
            }],
        )
        return getattr(msg, "id", None)
    except Exception as exc:
        logger.error("ir_lead_webex: send failed: %s", exc)
        return None
