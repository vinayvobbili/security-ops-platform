"""Threat Hunt Workbench — on-demand, analyst-driven threat hunting page.

Paste a CTI report / IOCs+TTPs and get a live answer to two questions about our
own environment: "Were we touched?" (IOC fan-out + LLM-authored behavioral hunts
that execute against the SIEMs) and "Can we detect this?" (MITRE coverage vs the
detection-rule catalog). Long hunts run in a background worker; the page polls.

All work is read-only telemetry search + detection-catalog lookup. Every run is
persisted with an audit trail so the team shares a revisitable hunt history.
"""

import logging

from flask import Blueprint, jsonify, render_template, request

from services import hunt_workbench
from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)

hunt_workbench_bp = Blueprint("hunt_workbench", __name__)

_MAX_NARRATIVE = 200_000


def _actor() -> str:
    """Authenticated user email for audit, or 'anonymous'."""
    try:
        from web.auth.helpers import current_user, current_pat_user
        u = current_user() or current_pat_user()
        if u and u.get("email"):
            return u["email"]
    except Exception:
        pass
    return "anonymous"


@hunt_workbench_bp.route("/hunt-workbench")
@log_web_activity
def hunt_workbench_page():
    return render_template("hunt_workbench.html")


@hunt_workbench_bp.route("/hunt-workbench/submit", methods=["POST"])
@log_web_activity
def hunt_workbench_submit():
    """Kick off a new hunt. Returns the job id to poll."""
    data = request.get_json(silent=True) or {}
    narrative = (data.get("narrative") or "").strip()
    if not narrative:
        return jsonify({"error": "Paste a CTI report, or a set of IOCs / TTPs, to hunt."}), 400
    if len(narrative) > _MAX_NARRATIVE:
        narrative = narrative[:_MAX_NARRATIVE]

    title = (data.get("title") or "").strip()[:200]

    ioc_tools = data.get("ioc_tools")
    if not isinstance(ioc_tools, list):
        ioc_tools = None
    options = {
        "ioc_tools": ioc_tools,
        "lookback": data.get("lookback"),
        "behavioral": bool(data.get("behavioral", True)),
    }

    try:
        job_id = hunt_workbench.submit(narrative, title=title, actor=_actor(), options=options)
    except Exception as e:
        logger.exception("Hunt submit failed")
        return jsonify({"error": f"Could not start hunt: {type(e).__name__}: {e}"}), 500
    return jsonify({"job_id": job_id})


@hunt_workbench_bp.route("/hunt-workbench/job/<job_id>")
@log_web_activity
def hunt_workbench_job(job_id):
    """Poll a hunt's status + results."""
    job = hunt_workbench.get_job(job_id)
    if not job:
        return jsonify({"error": "Hunt not found."}), 404
    return jsonify(job)


@hunt_workbench_bp.route("/hunt-workbench/recent")
@log_web_activity
def hunt_workbench_recent():
    """Recent hunts for the history rail."""
    try:
        limit = min(int(request.args.get("limit", 25)), 100)
    except (TypeError, ValueError):
        limit = 25
    return jsonify({"jobs": hunt_workbench.list_recent(limit)})
