"""Public-facing per-app log viewer.

Mission Control (the bot status dashboard) exposes log access *and* control
actions (start/stop/restart) we don't want in front of the general public. This
page mirrors only the read-only slice: a table of apps, each with a "View Logs"
button that opens that app's journalctl tail in a new tab.

Logs are served straight through this web app via `journalctl --user`, the same
mechanism the vendor-sidecar log pages use — so there's no dependency on the
Mission Control viewer ports (8032-8047), which aren't publicly exposed.

Routes:
    GET /app-logs              table of apps + View Logs buttons
    GET /app-logs/<key>        log viewer page (auto-refreshing tail)
    GET /app-logs/<key>/data   JSON {service, lines: [...]} from journalctl
"""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, render_template_string

from src.utils.logging_utils import log_web_activity
from web.routes._vendor_logs import _LOGS_HTML, _journalctl_lines

app_logs_bp = Blueprint("app_logs", __name__)

# App display name -> systemd --user service. Mirrors the BOTS dict in
# deployment/bot_status_api.py, which can't be imported here (it builds a Flask
# app and requires LOG_VIEWER_* at import time). Keep in sync when the fleet
# changes.
APPS = [
    {"key": "webserver", "name": "Web App", "emoji": "🌐", "service": "ir-web-app.service"},
    {"key": "jobs", "name": "IR Scheduler", "emoji": "⏰", "service": "ir-scheduler.service"},
    {"key": "epp", "name": "EPP Scheduler", "emoji": "🛡️", "service": "ir-epp-scheduler.service"},
    {"key": "ai", "name": "AI Scheduler", "emoji": "🧠", "service": "ai-scheduler.service"},
    {"key": "de", "name": "DE Scheduler", "emoji": "🔍", "service": "de-scheduler.service"},
    {"key": "pokedex", "name": "Pokedex", "emoji": "🔮", "service": "ir-pokedex.service"},
    {"key": "toodles", "name": "Toodles", "emoji": "🎯", "service": "ir-toodles.service"},
    {"key": "msoar", "name": "MSOAR", "emoji": "🤖", "service": "ir-msoar.service"},
    {"key": "moneyball", "name": "MoneyBall", "emoji": "💰", "service": "ir-money-ball.service"},
    {"key": "jarvis", "name": "Jarvis", "emoji": "🛡️", "service": "ir-jarvis.service"},
    {"key": "barnacles", "name": "Barnacles", "emoji": "⚓", "service": "ir-barnacles.service"},
    {"key": "tars", "name": "TARS", "emoji": "☁️", "service": "ir-tars.service"},
    {"key": "case", "name": "CASE", "emoji": "🏢", "service": "ir-case.service"},
    {"key": "winai", "name": "Win.AI", "emoji": "📚", "service": "win-ai.service"},
    {"key": "mcp-public", "name": "MCP Public", "emoji": "🔌", "service": "ir-mcp-public.service"},
    {"key": "soc-tier2", "name": "SOC Tier 2", "emoji": "🔍", "service": "ir-soc-tier2.service"},
    {"key": "soc-ir-lead", "name": "SOC IR Lead", "emoji": "🚨", "service": "ir-soc-ir-lead.service"},
    {"key": "soc-threat-intel", "name": "SOC Threat Intel", "emoji": "🌐", "service": "ir-soc-threat-intel.service"},
    # Vendor sidecars (containerized; foreground `docker run` user units, so the
    # container's stdout/stderr lands in the unit journal).
    {"key": "snr", "name": "SNR — Signal to Noise", "emoji": "🛰️", "service": "ir-snr.service"},
    {"key": "zero-hour", "name": "Zero Hour", "emoji": "⚡", "service": "ir-zero-hour.service"},
    {"key": "aj-threat-hunting", "name": "AJ Threat Hunting", "emoji": "🎯", "service": "ir-aj-threat-hunting.service"},
]
APPS_BY_KEY = {a["key"]: a for a in APPS}


@app_logs_bp.route("/app-logs")
@log_web_activity
def app_logs_index():
    return render_template("app_logs.html", apps=APPS)


@app_logs_bp.route("/app-logs/<key>")
@log_web_activity
def app_logs_view(key):
    app = APPS_BY_KEY.get(key)
    if not app:
        abort(404)
    return render_template_string(
        _LOGS_HTML,
        title=f"{app['emoji']} {app['name']}",
        service=app["service"],
        back_href="/app-logs",
        data_url=f"/app-logs/{key}/data",
    )


@app_logs_bp.route("/app-logs/<key>/data")
def app_logs_data(key):
    app = APPS_BY_KEY.get(key)
    if not app:
        abort(404)
    return jsonify({"service": app["service"], "lines": _journalctl_lines(app["service"])})
