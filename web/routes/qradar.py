"""QRadar Explorer routes — offenses dashboard + detail API."""

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)

qradar_bp = Blueprint("qradar", __name__)


def _get_client():
    """Lazy-import QRadar client to avoid circular imports at module level."""
    from services.qradar import QRadarClient
    return QRadarClient()


def _epoch_ms_to_iso(epoch_ms):
    """Convert epoch milliseconds to ISO-like display string."""
    try:
        return datetime.fromtimestamp(int(epoch_ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OSError, TypeError):
        return None


def _enrich_offense(o: dict) -> dict:
    """Add display-friendly fields to a raw QRadar offense dict."""
    o["start_time_display"] = _epoch_ms_to_iso(o.get("start_time"))
    o["last_updated_display"] = _epoch_ms_to_iso(o.get("last_updated_time"))
    return o


@qradar_bp.route("/qradar")
@log_web_activity
def qradar_page():
    return render_template("qradar.html")


@qradar_bp.route("/api/qradar/offenses")
@log_web_activity
def api_offenses():
    """Fetch offenses. Query params: status, hours_back, limit."""
    client = _get_client()
    if not client.is_configured():
        return jsonify({"error": "QRadar API not configured"}), 503

    status = request.args.get("status", "OPEN").upper()
    hours_back = int(request.args.get("hours_back", "24"))
    limit = min(int(request.args.get("limit", "50")), 200)

    filters = []
    if status != "ALL":
        filters.append(f"status={status}")
    if hours_back > 0:
        cutoff_ms = int((datetime.now(timezone.utc).timestamp() - hours_back * 3600) * 1000)
        filters.append(f"start_time > {cutoff_ms}")

    filter_query = " AND ".join(filters) if filters else None
    sort_field = "-start_time" if hours_back > 0 else "-last_updated_time"

    result = client.get_offenses(filter_query=filter_query, sort=sort_field, limit=limit)

    if "error" in result:
        return jsonify({"error": result["error"]}), 502

    offenses = [_enrich_offense(o) for o in result.get("offenses", [])]
    return jsonify({"offenses": offenses, "count": len(offenses)})


@qradar_bp.route("/api/qradar/offense/<int:offense_id>")
@log_web_activity
def api_offense_detail(offense_id):
    """Get full details + notes + sample events for a single offense."""
    client = _get_client()
    if not client.is_configured():
        return jsonify({"error": "QRadar API not configured"}), 503

    offense = client.get_offense(offense_id)
    if "error" in offense:
        return jsonify({"error": offense["error"]}), 502

    _enrich_offense(offense)

    # Fetch notes
    notes_result = client.get_offense_notes(offense_id)
    notes = notes_result.get("notes", []) if "error" not in notes_result else []

    # Fetch sample events (5, with 30s timeout — fast)
    events = client.get_offense_events(offense_id, limit=5, timeout=30)

    # Resolve the triggering rule name
    rule_name = None
    rules = offense.get("rules", [])
    if rules:
        first_rule = rules[0] if isinstance(rules[0], dict) else {"id": rules[0]}
        rule_id = first_rule.get("id")
        if rule_id:
            rule_detail = client.get_rule(rule_id)
            if "error" not in rule_detail:
                rule_name = rule_detail.get("name")

    return jsonify({
        "offense": offense,
        "notes": notes,
        "events": events,
        "rule_name": rule_name,
    })
