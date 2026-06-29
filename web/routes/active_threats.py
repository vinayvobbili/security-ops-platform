"""Active-Threat Intake routes — the adversary-centric queue.

Sibling to ``github_advisories`` (cs-advisories). Reads are public on the
internal SOC network; mutations (ingest a report, set status, save notes) are
``@login_required``. Slices 2-5 add enrichment, the hunt wire, the block wire,
and the Recorded Future auto-pull on top of this skeleton.
"""
from __future__ import annotations

import logging

from flask import (Blueprint, abort, jsonify, redirect, render_template,
                   request, url_for)

from services import active_threats as at
from services import active_threats_block as block
from services import active_threats_db as db
from services import active_threats_enrich as enrich
from services import active_threats_hunt as hunt
from src.utils.logging_utils import log_web_activity
from web.auth.helpers import current_user, login_required

logger = logging.getLogger(__name__)

active_threats_bp = Blueprint("active_threats", __name__)


def _user_email() -> str:
    u = current_user()
    if not u:
        return ""
    return (getattr(u, "email", None) or (u.get("email") if isinstance(u, dict) else "") or "")


def _is_production() -> bool:
    try:
        from my_config import get_config
        return bool(get_config().is_production)
    except Exception:
        return False


@active_threats_bp.route("/active-threats")
@log_web_activity
def active_threats_list():
    archived = request.args.get("closed") in ("1", "true", "yes")
    threats = db.list_threats(include_closed=archived)
    if archived:
        threats = [t for t in threats if t.get("status") == "closed"]
    return render_template(
        "active_threats_list.html",
        threats=threats,
        counts=db.status_counts(),
        severities=db.severity_counts(),
        ioc_total=db.ioc_total(),
        threat_types=db.THREAT_TYPES,
        archived_view=archived,
        is_authenticated=bool(current_user()),
    )


@active_threats_bp.route("/active-threats/<key>")
@log_web_activity
def active_threats_detail(key):
    threat = db.get_threat(key)
    if not threat:
        abort(404)
    return render_template(
        "active_threats_detail.html",
        threat=threat,
        enrichment=threat.get("enrichment") if isinstance(threat.get("enrichment"), dict) else {},
        hunt=db.get_hunt(threat.get("source_id") or key),
        block_state=db.get_block(threat.get("source_id") or key),
        blockable=block.blockable_iocs(threat),
        is_production=_is_production(),
        statuses=db.STATUSES,
        is_authenticated=bool(current_user()),
    )


@active_threats_bp.route("/api/active-threats/intake", methods=["POST"])
@login_required
def api_intake():
    payload = request.get_json(silent=True) or request.form
    text = (payload.get("report") or payload.get("text") or "").strip()
    if len(text) < 20:
        return jsonify({"ok": False, "error": "Paste a threat report (at least a couple of sentences)."}), 400
    try:
        result = at.ingest_report(text, source="manual", created_by=_user_email())
    except Exception as e:
        logger.exception("[ActiveThreats] intake failed")
        return jsonify({"ok": False, "error": f"Extraction failed: {e}"}), 500
    if not result.get("ok"):
        return jsonify(result), 400
    result["url"] = url_for("active_threats.active_threats_detail", key=result["key"])
    return jsonify(result)


@active_threats_bp.route("/api/active-threats/<key>/status", methods=["POST"])
@login_required
def api_set_status(key):
    payload = request.get_json(silent=True) or request.form
    status = (payload.get("status") or "").strip()
    if status not in db.STATUSES:
        return jsonify({"ok": False, "error": "unknown status"}), 400
    ok = db.set_status(key, status)
    return jsonify({"ok": ok, "status": status})


@active_threats_bp.route("/api/active-threats/<key>/notes", methods=["POST"])
@login_required
def api_save_notes(key):
    payload = request.get_json(silent=True) or request.form
    ok = db.save_notes(key, (payload.get("notes") or "").strip())
    return jsonify({"ok": ok})


@active_threats_bp.route("/api/active-threats/<key>/enrich", methods=["POST"])
@login_required
def api_enrich(key):
    """Kick off IOC-reputation enrichment (VT/AbuseIPDB/urlscan/RF) in the
    background. Returns immediately; the page polls the enrichment endpoint."""
    if not db.get_threat(key):
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        result = enrich.start_enrichment(key)
    except Exception as e:
        logger.exception("[ActiveThreats] enrich kickoff failed")
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify(result)


@active_threats_bp.route("/api/active-threats/<key>/enrichment")
@log_web_activity
def api_enrichment(key):
    """Poll endpoint — current enrichment blob (read-public on the SOC net)."""
    if not db.get_threat(key):
        return jsonify({"status": "missing"}), 404
    return jsonify(db.get_enrichment(key) or {"status": "none"})


@active_threats_bp.route("/api/active-threats/<key>/hunt", methods=["POST"])
@login_required
def api_hunt(key):
    """Kick off a telemetry hunt (QRadar/CrowdStrike/XSIAM) for this threat's
    IOCs via the unified hunt engine. Returns immediately; the page polls."""
    if not db.get_threat(key):
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        result = hunt.start_hunt(key)
    except Exception as e:
        logger.exception("[ActiveThreats] hunt kickoff failed")
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify(result)


@active_threats_bp.route("/api/active-threats/<key>/hunt")
@log_web_activity
def api_hunt_poll(key):
    """Poll endpoint — current hunt blob (read-public on the SOC net)."""
    if not db.get_threat(key):
        return jsonify({"status": "missing"}), 404
    return jsonify(db.get_hunt(key) or {"status": "none"})


@active_threats_bp.route("/api/active-threats/<key>/hunt-plan")
@log_web_activity
def api_hunt_plan(key):
    """Pre-flight plan — the queries each source would run for this threat's
    IOCs, plus console deep-links. Network-free, so it answers synchronously;
    read-public like the other previews (no telemetry is touched)."""
    if not db.get_threat(key):
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify(hunt.preflight_plan(key))


@active_threats_bp.route("/api/active-threats/<key>/block", methods=["POST"])
@login_required
def api_block(key):
    """Push selected malicious domain/URL IOCs into containment via the shared
    XSOAR URL-block kernel. HARD-disabled off-prod (the kernel acts on the PROD
    XSOAR tenant). Returns immediately; the page polls."""
    if not db.get_threat(key):
        return jsonify({"ok": False, "error": "not found"}), 404
    if not _is_production():
        return jsonify({"ok": False, "disabled": True,
                        "error": "Blocking is disabled on the dev instance "
                                 "(it would act on the production XSOAR tenant)."}), 403
    payload = request.get_json(silent=True) or request.form
    values = payload.get("values") or payload.getlist("values") if hasattr(payload, "getlist") \
        else (payload.get("values") or [])
    if isinstance(values, str):
        values = [values]
    try:
        result = block.start_block(key, list(values), owner=_user_email())
    except Exception as e:
        logger.exception("[ActiveThreats] block kickoff failed")
        return jsonify({"ok": False, "error": str(e)}), 500
    status = 200 if result.get("ok") else (403 if result.get("disabled") else 400)
    return jsonify(result), status


@active_threats_bp.route("/api/active-threats/<key>/block")
@log_web_activity
def api_block_poll(key):
    """Poll endpoint — current block blob (read-public on the SOC net)."""
    if not db.get_threat(key):
        return jsonify({"status": "missing"}), 404
    return jsonify(db.get_block(key) or {"status": "none"})
