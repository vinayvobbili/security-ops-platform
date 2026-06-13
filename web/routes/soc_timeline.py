"""SOC-in-a-Box timeline — live feed of triage events from the bus.

Reads the ``soc.audit`` Redis Stream (the fan-out mirror) and renders the
most recent N events. v1 supports URL-param filtering by event type and
verdict; richer filters (time range, host, ticket ID) come later.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from flask import Blueprint, render_template, request

from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)

soc_timeline_bp = Blueprint("soc_timeline", __name__)


DEFAULT_LIMIT = 200
MAX_LIMIT = 2000


# Verdict → display class mapping (CSS classes in soc_timeline.html)
VERDICT_BADGE_CLASS = {
    "true_positive_malicious":           "verdict-malicious",
    "true_positive_malicious_contained": "verdict-contained",
    "true_positive_benign":               "verdict-benign-tp",
    "false_positive":                     "verdict-fp",
    "close_ticket":                       "verdict-close",
}

VERDICT_DISPLAY = {
    "true_positive_malicious":           "TP — Malicious",
    "true_positive_malicious_contained": "TP — Contained",
    "true_positive_benign":               "TP — Benign",
    "false_positive":                     "False Positive",
    # Bus sentinel for "no real verdict" — not a classification. Render as such.
    "close_ticket":                       "(no verdict)",
}


def _load_events(limit: int) -> tuple[list[dict[str, Any]], str]:
    """Fetch events from the soc.audit stream. Returns (events, error_message)."""
    try:
        from src.components.soc_in_box import bus
        client = bus.get_redis_client()
        events = bus.replay(client, bus.STREAM_AUDIT, start="-", end="+", count=None)
        # Newest first
        events.reverse()
        return events[:limit], ""
    except Exception as exc:
        logger.warning("soc_timeline: bus read failed: %s", exc)
        return [], f"Bus unavailable: {exc}"


def _apply_filters(events: list[dict[str, Any]], event_type: str, verdict: str,
                   ticket: str = "") -> list[dict[str, Any]]:
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    if verdict:
        events = [e for e in events if e.get("verdict") == verdict]
    if ticket:
        events = [
            e for e in events
            if str(e.get("ticket_id") or "") == ticket
            or str(e.get("correlation_id") or "") == ticket
        ]
    return events


def _decorate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate each event with display-ready fields."""
    out = []
    for e in events:
        v = e.get("verdict") or ""
        e["_verdict_class"] = VERDICT_BADGE_CLASS.get(v, "verdict-unknown")
        e["_verdict_display"] = VERDICT_DISPLAY.get(v, v) if v else ""
        # Truncate noisy fields for table display
        e["_summary_short"] = (e.get("summary") or "")[:140]
        e["_action_short"] = (e.get("recommended_action") or "")[:80]
        out.append(e)
    return out


@soc_timeline_bp.route("/soc-timeline")
@log_web_activity
def display_soc_timeline():
    try:
        limit = min(MAX_LIMIT, max(1, int(request.args.get("limit", DEFAULT_LIMIT))))
    except ValueError:
        limit = DEFAULT_LIMIT
    event_type = (request.args.get("type") or "").strip()
    verdict = (request.args.get("verdict") or "").strip()
    ticket = (request.args.get("ticket") or "").strip()

    events, error = _load_events(limit)
    filtered = _apply_filters(events, event_type, verdict, ticket)
    filtered = _decorate(filtered)

    # Stats over the UN-filtered window so the user can see counts even
    # when a filter is applied.
    verdict_counts = Counter(e.get("verdict") for e in events if e.get("verdict"))
    type_counts = Counter(e.get("event_type") for e in events)

    return render_template(
        "soc_timeline.html",
        events=filtered,
        total_events=len(events),
        filtered_count=len(filtered),
        verdict_counts=verdict_counts,
        type_counts=type_counts,
        limit=limit,
        event_type_filter=event_type,
        verdict_filter=verdict,
        ticket_filter=ticket,
        error=error,
        verdict_display=VERDICT_DISPLAY,
    )
