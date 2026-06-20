"""SOC Manager agent — periodic shift summary, wired to the SOC.

The windowed rollup (replay the audit window, aggregate verdict/priority stats,
ask the model for a short shift narrative, publish a ``ShiftSummary``) now lives
in the vendor-neutral ``aisoc`` package — extracted from this module. What stays
here is the *environment* (the live bus + the corporate-gateway model, injected
through the aisoc seams) plus the IR-specific Webex surface: the rich Adaptive
Card (Eastern-time window, verdict colors, XSOAR ticket links) and its Markdown
fallback.

CLI::

    python -m src.components.soc_in_box.agents.soc_manager \\
        --window-hours 8 [--dry-run] [--no-webex] [--no-llm] [--room <id>]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime
from typing import Any, Optional
from zoneinfo import ZoneInfo

from aisoc.agents.soc_manager import DEFAULT_WINDOW_HOURS, WindowStats
from aisoc.agents.soc_manager import run_once as _aisoc_run_once

logger = logging.getLogger(__name__)


ROLE_NAME = "soc_manager"

EASTERN = ZoneInfo("America/New_York")


def _fmt_eastern(dt: datetime) -> str:
    """User-facing timestamp format: MM/DD/YYYY HH:MM AM/PM EDT/EST."""
    return dt.astimezone(EASTERN).strftime("%m/%d/%Y %I:%M %p %Z")


# Verdict display strings (mirror web/routes/soc_timeline.py).
# `close_ticket` is the bus's "no verdict" sentinel — not a real classification.
VERDICT_DISPLAY = {
    "true_positive_malicious":           "TP — Malicious",
    "true_positive_malicious_contained": "TP — Contained",
    "true_positive_benign":               "TP — Benign",
    "false_positive":                     "False Positive",
    "close_ticket":                       "(no verdict)",
}


def _priority_bucket(score: int) -> str:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 1:
        return "low"
    return "unknown"


# -- markdown render -----------------------------------------------------

def render_markdown(stats: WindowStats, narrative: str) -> str:
    """Render the shift summary for Webex.

    Webex strips Markdown tables and parses ``_text_`` as bold, so we use
    bulleted lists instead of tables and avoid underscores entirely.
    """
    parts = [
        "## 🛰️ Shift Summary",
        (f"**Window:** {_fmt_eastern(stats.window_start)} → "
         f"{_fmt_eastern(stats.window_end)}  "
         f"&nbsp;•&nbsp; **Triaged:** {stats.total_alerts}"),
        "",
        narrative,
        "",
    ]

    if stats.verdict_counts or stats.no_verdict_count:
        parts.append("**Verdicts**")
        for v, c in stats.verdict_counts.most_common():
            parts.append(f"- {VERDICT_DISPLAY.get(v, v)}: **{c}**")
        if stats.no_verdict_count:
            parts.append(f"- No verdict: **{stats.no_verdict_count}** "
                         f"(Sentinel produced no classification — LLM gap)")
        parts.append("")

    if stats.top_tickets:
        parts.append(f"**Top {len(stats.top_tickets)} by Priority**")
        for t in stats.top_tickets:
            host = t["hostname"] or "—"
            v_display = VERDICT_DISPLAY.get(t["verdict"], t["verdict"])
            summary = (t["summary"] or "").strip()
            parts.append(
                f"- **{_xsoar_ticket_link(t['ticket_id'])}** (pri {t['priority_score']}, "
                f"{v_display}, host {host}) — {summary}"
            )
        parts.append("")

    parts.append("— SOC Manager")
    return "\n".join(parts)


# -- adaptive card ------------------------------------------------------

# Verdict → Adaptive Card text color (Webex: Default/Dark/Light/Accent/Good/Warning/Attention)
VERDICT_CARD_COLOR = {
    "true_positive_malicious":           "Attention",   # red
    "true_positive_malicious_contained": "Warning",     # amber
    "true_positive_benign":               "Warning",     # amber-ish
    "false_positive":                     "Good",        # green
    "close_ticket":                       "Default",     # gray
}

# Priority bucket → container style
PRIORITY_CONTAINER_STYLE = {
    "high":    "attention",
    "medium":  "warning",
    "low":     "emphasis",
    "unknown": "default",
}

def _xsoar_ticket_link(ticket_id: str) -> str:
    """Markdown link for a ticket id, e.g. ``[#777001](xsoar-url)``."""
    if not ticket_id:
        return "—"
    from src.utils.xsoar_helpers import build_incident_url
    return f"[#{ticket_id}]({build_incident_url(ticket_id)})"


def render_adaptive_card(stats: WindowStats, narrative: str) -> dict[str, Any]:
    """Build a Webex-compatible Adaptive Card 1.2 payload."""
    body: list[dict[str, Any]] = []

    # Hero header — accent-styled container with title + window
    body.append({
        "type": "Container",
        "style": "accent",
        "bleed": True,
        "items": [
            {"type": "TextBlock", "text": "🛰️ Shift Summary",
             "size": "Large", "weight": "Bolder", "wrap": True},
            {"type": "TextBlock",
             "text": f"{_fmt_eastern(stats.window_start)}  →  {_fmt_eastern(stats.window_end)}",
             "isSubtle": True, "spacing": "Small", "wrap": True},
        ],
    })

    # KPI strip — Triaged + dominant verdict
    kpi_cols: list[dict[str, Any]] = [{
        "type": "Column", "width": "auto",
        "items": [
            {"type": "TextBlock", "text": "Triaged", "isSubtle": True, "size": "Small", "spacing": "None"},
            {"type": "TextBlock", "text": str(stats.total_alerts),
             "size": "ExtraLarge", "weight": "Bolder", "spacing": "None"},
        ],
    }]
    if stats.verdict_counts:
        top_v, top_c = stats.verdict_counts.most_common(1)[0]
        kpi_cols.append({
            "type": "Column", "width": "stretch",
            "items": [
                {"type": "TextBlock", "text": "Dominant verdict", "isSubtle": True, "size": "Small", "spacing": "None"},
                {"type": "TextBlock", "text": VERDICT_DISPLAY.get(top_v, top_v),
                 "size": "Medium", "weight": "Bolder", "spacing": "None",
                 "color": VERDICT_CARD_COLOR.get(top_v, "Default")},
                {"type": "TextBlock", "text": f"{top_c} alert{'s' if top_c != 1 else ''}",
                 "isSubtle": True, "size": "Small", "spacing": "None"},
            ],
        })
    body.append({"type": "ColumnSet", "spacing": "Medium", "columns": kpi_cols})

    # Narrative
    body.append({
        "type": "TextBlock", "text": narrative, "wrap": True,
        "spacing": "Medium",
    })

    # Verdict breakdown — colored FactSet-style rows
    if stats.verdict_counts or stats.no_verdict_count:
        body.append({"type": "TextBlock", "text": "Verdicts",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for v, c in stats.verdict_counts.most_common():
            body.append({
                "type": "ColumnSet", "spacing": "Small",
                "columns": [
                    {"type": "Column", "width": "stretch", "items": [{
                        "type": "TextBlock", "text": VERDICT_DISPLAY.get(v, v),
                        "color": VERDICT_CARD_COLOR.get(v, "Default"),
                        "weight": "Bolder", "wrap": True,
                    }]},
                    {"type": "Column", "width": "auto", "items": [{
                        "type": "TextBlock", "text": f"**{c}**",
                        "horizontalAlignment": "Right",
                    }]},
                ],
            })
        if stats.no_verdict_count:
            body.append({
                "type": "ColumnSet", "spacing": "Small",
                "columns": [
                    {"type": "Column", "width": "stretch", "items": [{
                        "type": "TextBlock", "text": "No verdict (Sentinel LLM gap)",
                        "color": "Default", "isSubtle": True,
                        "italic": True, "wrap": True,
                    }]},
                    {"type": "Column", "width": "auto", "items": [{
                        "type": "TextBlock", "text": f"{stats.no_verdict_count}",
                        "isSubtle": True, "horizontalAlignment": "Right",
                    }]},
                ],
            })

    # Top tickets — each in a styled container with priority color
    if stats.top_tickets:
        body.append({"type": "TextBlock",
                     "text": f"Top {len(stats.top_tickets)} by Priority",
                     "weight": "Bolder", "size": "Medium", "spacing": "Large"})
        for t in stats.top_tickets:
            bucket = _priority_bucket(int(t.get("priority_score") or 0))
            v_display = VERDICT_DISPLAY.get(t["verdict"], t["verdict"])
            host = t["hostname"] or "—"
            user = t.get("username") or ""
            host_line = f"host **{host}**" + (f" • user `{user}`" if user else "")
            body.append({
                "type": "Container",
                "style": PRIORITY_CONTAINER_STYLE.get(bucket, "default"),
                "spacing": "Small",
                "items": [
                    {"type": "ColumnSet", "columns": [
                        {"type": "Column", "width": "auto", "items": [{
                            "type": "TextBlock", "text": f"P{t['priority_score']}",
                            "weight": "Bolder", "size": "Large", "spacing": "None",
                        }]},
                        {"type": "Column", "width": "stretch", "items": [
                            {"type": "TextBlock",
                             "text": f"**{_xsoar_ticket_link(t['ticket_id'])}**  •  {v_display}",
                             "wrap": True, "spacing": "None"},
                            {"type": "TextBlock", "text": host_line,
                             "isSubtle": True, "size": "Small", "spacing": "None", "wrap": True},
                            {"type": "TextBlock", "text": (t["summary"] or "").strip(),
                             "wrap": True, "spacing": "Small"},
                        ]},
                    ]},
                ],
            })

    # Sign-off
    body.append({
        "type": "TextBlock",
        "text": "— SOC Manager",
        "isSubtle": True, "size": "Small", "spacing": "Large", "horizontalAlignment": "Right",
    })

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.2",
        "body": body,
    }


# -- webex ---------------------------------------------------------------

def send_to_webex(markdown: str, card: dict[str, Any], room_id: str) -> Optional[str]:
    """Send Adaptive Card (with Markdown fallback text) via WebexTeamsAPI.

    Uses the **Pokedex** bot identity — SOC-in-a-Box agents all speak as Pokedex
    so the user-facing voice stays consistent. Returns Webex message id.
    """
    from my_config import get_config
    from webexteamssdk import WebexTeamsAPI
    cfg = get_config()
    token = cfg.webex_bot_access_token_pokedex
    if not token:
        logger.warning("soc_manager: WEBEX_BOT_ACCESS_TOKEN_POKEDEX not set, skipping send")
        return None
    attachment = {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": card,
    }
    try:
        api = WebexTeamsAPI(access_token=token)
        msg = api.messages.create(
            roomId=room_id,
            markdown=markdown,
            attachments=[attachment],
        )
        return getattr(msg, "id", None)
    except Exception as exc:
        logger.error("soc_manager: Webex send failed: %s", exc)
        return None


# -- orchestration -------------------------------------------------------

def _stats_from_result(result: dict[str, Any]) -> WindowStats:
    """Rebuild the WindowStats the card renderers want from aisoc's result dict.

    The rich card needs only the window, totals, verdict counts (incl. the
    no-verdict sentinel bucket) and the top tickets — all returned by aisoc's
    ``run_once``. The aggregation-only fields (host/priority-bucket counters)
    aren't rendered, so they stay at their dataclass defaults.
    """
    return WindowStats(
        window_start=datetime.fromisoformat(result["window_start"]),
        window_end=datetime.fromisoformat(result["window_end"]),
        total_alerts=result["total_alerts"],
        verdict_counts=Counter(result["verdict_counts"]),
        no_verdict_count=result.get("no_verdict_count", 0),
        top_tickets=result["top_tickets"],
    )


def run_once(*,
             window_hours: float = DEFAULT_WINDOW_HOURS,
             dry_run: bool = False,
             send_webex: bool = True,
             use_llm: bool = True,
             room_id: Optional[str] = None) -> dict[str, Any]:
    """One shift-summary cycle over the live bus, with a rich Pokedex Webex card.

    The aggregate/narrate/publish is aisoc's ``run_once``, fed our live Redis bus
    and the summary model (this windowed role calls no tools). We then render the
    IR Adaptive Card from the returned stats and send it.
    """
    from src.components.soc_in_box.aisoc_seams import soc_bus, soc_summary_model

    result = _aisoc_run_once(
        bus=soc_bus(),
        model=soc_summary_model() if use_llm else None,
        window_hours=window_hours,
        dry_run=dry_run,
        use_llm=use_llm,
    )

    stats = _stats_from_result(result)
    narrative = result["narrative"]
    markdown = render_markdown(stats, narrative)
    card = render_adaptive_card(stats, narrative)

    webex_msg_id: Optional[str] = None
    if send_webex and not dry_run:
        from my_config import get_config
        cfg = get_config()
        # SOC-in-a-Box room is the primary target; falls back to dev test space
        # if the env var isn't set. --room still overrides both.
        target_room = (
            room_id
            or cfg.webex_room_id_soc_in_a_box
            or cfg.webex_room_id_dev_test_space
        )
        if target_room:
            webex_msg_id = send_to_webex(markdown, card, target_room)
        else:
            logger.warning("soc_manager: no Webex room configured, skipping send")

    result["markdown"] = markdown
    result["card"] = card
    result["webex_message_id"] = webex_msg_id
    return result


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SOC-in-a-Box shift summary")
    p.add_argument("--window-hours", type=float, default=DEFAULT_WINDOW_HOURS)
    p.add_argument("--dry-run", action="store_true",
                   help="Compute + print; do not publish to bus or send Webex")
    p.add_argument("--no-webex", action="store_true",
                   help="Publish bus event but skip Webex send")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip LLM narrative; use deterministic stub")
    p.add_argument("--room", default=None, help="Override Webex room id")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _build_argparser().parse_args(argv)
    result = run_once(
        window_hours=args.window_hours,
        dry_run=args.dry_run,
        send_webex=not args.no_webex,
        use_llm=not args.no_llm,
        room_id=args.room,
    )
    if args.dry_run:
        print(result["markdown"])
        print("\n--- adaptive card ---")
        print(json.dumps(result["card"], indent=2, default=str))
        print("\n--- status ---")
        print(json.dumps({k: v for k, v in result.items()
                          if k not in {"markdown", "card"}},
                         indent=2, default=str))
    else:
        logger.info("soc_manager: done (webex_msg_id=%s, dry_run=%s)",
                    result.get("webex_message_id"), result["dry_run"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
