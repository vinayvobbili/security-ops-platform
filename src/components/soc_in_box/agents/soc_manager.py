"""SOC Manager agent — periodic shift summary over the bus.

Unlike Tier 1 (event-driven), SOC Manager is invoked on a timer. Each run:

1. Replays ``soc.audit`` over a configurable window (default last 8h).
2. Filters to ``alert.triaged`` events.
3. Aggregates deterministic stats (counts by verdict, top tickets by priority).
4. Asks the LLM for a 2-paragraph narrative (exec summary + analyst takeaways).
5. Publishes a ``ShiftSummary`` event to ``soc.cases``.
6. Sends the Markdown report to Webex (dev test space by default).

CLI::

    python -m src.components.soc_in_box.agents.soc_manager \
        --window-hours 8 [--dry-run] [--no-webex] [--no-llm] [--room <id>]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

from langchain_core.messages import HumanMessage, SystemMessage

from src.components.soc_in_box.bus import (
    STREAM_AUDIT, STREAM_CASES, get_redis_client, publish, replay,
)
from src.components.soc_in_box.schemas import ShiftSummary

logger = logging.getLogger(__name__)


ROLE_NAME = "soc_manager"
DEFAULT_WINDOW_HOURS = 8
TOP_TICKETS_LIMIT = 5

EASTERN = ZoneInfo("America/New_York")


def _fmt_eastern(dt: datetime) -> str:
    """User-facing timestamp format: MM/DD/YYYY HH:MM AM/PM EDT/EST."""
    return dt.astimezone(EASTERN).strftime("%m/%d/%Y %I:%M %p %Z")


# Verdict display strings (mirror web/routes/soc_timeline.py).
# `close_ticket` is the bus's "no verdict" sentinel — not a real classification.
# Aggregation filters it out into a separate counter, but stray references
# (e.g. a top ticket's verdict field) render as "(no verdict)" for honesty.
VERDICT_DISPLAY = {
    "true_positive_malicious":           "TP — Malicious",
    "true_positive_malicious_contained": "TP — Contained",
    "true_positive_benign":               "TP — Benign",
    "false_positive":                     "False Positive",
    "close_ticket":                       "(no verdict)",
}


# -- aggregation ---------------------------------------------------------

@dataclass
class WindowStats:
    window_start: datetime
    window_end: datetime
    total_alerts: int = 0
    verdict_counts: Counter = field(default_factory=Counter)
    # `close_ticket` is the bus's sentinel for "no real verdict" (e.g. m1 LLM
    # offline, Sentinel structured-output failure) — not a classification. Track
    # those separately so they don't pollute the dominant-verdict KPI.
    no_verdict_count: int = 0
    priority_bucket_counts: Counter = field(default_factory=Counter)
    host_counts: Counter = field(default_factory=Counter)
    top_tickets: list[dict[str, Any]] = field(default_factory=list)


def _parse_event_ts(raw: Any) -> Optional[datetime]:
    """Pydantic serializes datetimes to ISO strings — re-parse for filtering."""
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _priority_bucket(score: int) -> str:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 1:
        return "low"
    return "unknown"


def aggregate(events: list[dict[str, Any]],
              window_start: datetime,
              window_end: datetime) -> WindowStats:
    """Compute stats over the window. Caller already filtered by stream."""
    stats = WindowStats(window_start=window_start, window_end=window_end)

    triaged: list[dict[str, Any]] = []
    for e in events:
        if e.get("event_type") != "alert.triaged":
            continue
        ts = _parse_event_ts(e.get("timestamp"))
        if ts is None or ts < window_start or ts > window_end:
            continue
        triaged.append(e)

    stats.total_alerts = len(triaged)
    for e in triaged:
        v = e.get("verdict") or ""
        if v in {"", "close_ticket", "unknown"}:
            stats.no_verdict_count += 1
        else:
            stats.verdict_counts[v] += 1
        stats.priority_bucket_counts[_priority_bucket(int(e.get("priority_score") or 0))] += 1
        host = e.get("hostname") or ""
        if host:
            stats.host_counts[host] += 1

    triaged.sort(key=lambda e: int(e.get("priority_score") or 0), reverse=True)
    for e in triaged[:TOP_TICKETS_LIMIT]:
        stats.top_tickets.append({
            "ticket_id": e.get("ticket_id") or "",
            "priority_score": int(e.get("priority_score") or 0),
            "verdict": e.get("verdict") or "",
            "hostname": e.get("hostname") or "",
            "username": e.get("username") or "",
            "summary": (e.get("summary") or "")[:160],
        })

    return stats


# -- narrative -----------------------------------------------------------

SYSTEM_PROMPT = """You are the SOC Manager agent for the company's Detection & Response team.
You write a SHORT shift summary for the on-call lead based on triage activity.

Constraints:
- Maximum 100 words total. Tight is better than complete.
- One short paragraph if volume is light; two paragraphs only if there is genuinely a second beat to call out (recurring host, high-priority item, escalation candidate).
- Plain prose. No bullets, no headings, no markdown.
- Cite ticket ids and hostnames only when they materially change the picture. Don't restate raw counts the reader can see in the bulleted breakdown below.
- Never pad. If there is nothing notable, say so in one sentence and stop.
"""


def build_llm_prompt(stats: WindowStats) -> str:
    lines = [
        f"Window: {stats.window_start.isoformat()} → {stats.window_end.isoformat()}",
        f"Total triaged alerts: {stats.total_alerts}",
        "",
        "Verdict counts:",
    ]
    if stats.verdict_counts:
        for v, c in stats.verdict_counts.most_common():
            lines.append(f"  - {VERDICT_DISPLAY.get(v, v)}: {c}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Priority buckets:")
    for bucket in ("high", "medium", "low", "unknown"):
        c = stats.priority_bucket_counts.get(bucket, 0)
        if c:
            lines.append(f"  - {bucket}: {c}")

    if stats.host_counts:
        repeats = [(h, c) for h, c in stats.host_counts.most_common(5) if c > 1]
        if repeats:
            lines.append("")
            lines.append("Hosts seen more than once:")
            for h, c in repeats:
                lines.append(f"  - {h}: {c}")

    if stats.top_tickets:
        lines.append("")
        lines.append(f"Top {len(stats.top_tickets)} by priority:")
        for t in stats.top_tickets:
            lines.append(
                f"  - #{t['ticket_id']} pri={t['priority_score']} "
                f"verdict={VERDICT_DISPLAY.get(t['verdict'], t['verdict'])} "
                f"host={t['hostname'] or '-'}: {t['summary']}"
            )

    return "\n".join(lines)


def generate_narrative(stats: WindowStats) -> str:
    """Call the failover LLM. Falls back to a deterministic stub on error.

    Quiet windows (zero alerts) skip the LLM entirely — there's nothing to
    summarize and LLMs pad. The stub is a single sentence.
    """
    if stats.total_alerts == 0:
        return _fallback_narrative(stats)
    try:
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm()
        prompt = build_llm_prompt(stats)
        resp = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
        text = (resp.content or "").strip() if hasattr(resp, "content") else str(resp).strip()
        if not text:
            raise RuntimeError("LLM returned empty content")
        return text
    except Exception as exc:
        logger.warning("soc_manager LLM narrative failed, using fallback: %s", exc)
        return _fallback_narrative(stats)


def _fallback_narrative(stats: WindowStats) -> str:
    if stats.total_alerts == 0:
        return "No triage activity in this window — Sentinel is idle or paused."
    top_v = stats.verdict_counts.most_common(1)[0][0] if stats.verdict_counts else ""
    top_v_display = VERDICT_DISPLAY.get(top_v, top_v)
    return (f"{stats.total_alerts} alerts triaged; dominant verdict was {top_v_display}. "
            "Breakdown below. (LLM narrative unavailable.)")


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

def run_once(*,
             window_hours: float = DEFAULT_WINDOW_HOURS,
             dry_run: bool = False,
             send_webex: bool = True,
             use_llm: bool = True,
             room_id: Optional[str] = None) -> dict[str, Any]:
    """Single shift-summary cycle. Returns a small status dict."""
    now = datetime.now(timezone.utc)
    window_end = now
    window_start = now - timedelta(hours=window_hours)

    client = get_redis_client()
    events = replay(client, STREAM_AUDIT, start="-", end="+", count=None)
    stats = aggregate(events, window_start, window_end)
    logger.info("soc_manager: window=%sh total=%s verdicts=%s",
                window_hours, stats.total_alerts, dict(stats.verdict_counts))

    narrative = generate_narrative(stats) if use_llm else _fallback_narrative(stats)
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

    if not dry_run:
        event = ShiftSummary(
            correlation_id=window_start.isoformat(),
            produced_by=ROLE_NAME,
            window_start=window_start,
            window_end=window_end,
            total_alerts=stats.total_alerts,
            verdict_counts=dict(stats.verdict_counts),
            top_tickets=stats.top_tickets,
            narrative_markdown=narrative,
            webex_message_id=webex_msg_id,
        )
        publish(client, STREAM_CASES, event)
        logger.info("soc_manager: published shift.summary event_id=%s", event.event_id)

    return {
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "total_alerts": stats.total_alerts,
        "verdict_counts": dict(stats.verdict_counts),
        "top_tickets": stats.top_tickets,
        "narrative": narrative,
        "markdown": markdown,
        "card": card,
        "webex_message_id": webex_msg_id,
        "dry_run": dry_run,
    }


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
