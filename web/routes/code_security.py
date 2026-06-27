"""Code Security Scanner — agentic repo vulnerability scanning.

Point the scanner at a code repository (a local path on the host, or a git URL it
can clone) and it audits the source the way a security researcher would: a local
LLM navigates the repo and records candidate vulnerabilities, then a second LLM
pass validates each one (refute-first) before it reaches the analyst. Findings
come back with a data-flow rationale, severity, confidence score, and repro steps.

Slice 1 is READ-ONLY — it scans and reports. It never writes to the repo, opens
a merge request, or generates a patch (Slice 2/3). The scan runs in a background
worker; the page polls for progress. Every scan is persisted with an audit trail.
"""

import logging

from flask import Blueprint, jsonify, render_template, request

from services import code_security
from src.utils.logging_utils import log_web_activity
from web.auth.helpers import current_pat_user, current_user, login_required

logger = logging.getLogger(__name__)

code_security_bp = Blueprint("code_security", __name__)

_MAX_SOURCE = 2_000


def _actor() -> str:
    try:
        from web.auth.helpers import current_user, current_pat_user
        u = current_user() or current_pat_user()
        if u and u.get("email"):
            return u["email"]
    except Exception:
        pass
    return "anonymous"


@code_security_bp.route("/code-security")
@log_web_activity
def code_security_page():
    # The page itself is open to any visitor so the capability is discoverable.
    # Running a scan (and reading its results) stays gated — see the actions
    # below — because a scan reads arbitrary local paths / clones any URL.
    authenticated = bool(current_user() or current_pat_user())
    return render_template("code_security.html",
                           vuln_classes=code_security.VULN_CLASSES,
                           authenticated=authenticated)


@code_security_bp.route("/code-security/submit", methods=["POST"])
@log_web_activity
@login_required
def code_security_submit():
    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip()
    if not source:
        return jsonify({"error": "Enter a repository path on this box, or a git URL to clone."}), 400
    if len(source) > _MAX_SOURCE:
        return jsonify({"error": "Source path/URL is too long."}), 400
    branch = (data.get("branch") or "").strip()[:200]
    title = (data.get("title") or "").strip()[:200]
    options = {}
    try:
        scan_id = code_security.submit(source=source, branch=branch, title=title,
                                       actor=_actor(), options=options)
    except Exception as e:
        logger.exception("Code-security submit failed")
        return jsonify({"error": f"Could not start scan: {type(e).__name__}: {e}"}), 500
    return jsonify({"scan_id": scan_id})


@code_security_bp.route("/code-security/scan/<scan_id>")
@log_web_activity
@login_required
def code_security_scan(scan_id):
    scan = code_security.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify(scan)


@code_security_bp.route("/code-security/recent")
@log_web_activity
@login_required
def code_security_recent():
    try:
        limit = min(int(request.args.get("limit", 25)), 100)
    except (TypeError, ValueError):
        limit = 25
    return jsonify({"scans": code_security.list_recent(limit)})
