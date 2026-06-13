"""Detection-as-Code pipeline — Sigma → XSIAM, run like CI/CD.

Paste a Sigma rule and the pipeline lints it, compiles it to XSIAM XQL, dry-runs
that XQL read-only against the live tenant, runs an LLM detection-engineering
review, and packages a GitLab merge request. The pipeline runs in a background
worker (the page polls and watches the stages light up).

Opening the merge request is an explicit, human-gated action and is disabled
outright on the dev instance (it always targets the prod detection repo). Every
run + deploy is logged with an audit trail.
"""

import logging

from flask import Blueprint, jsonify, render_template, request

from services import detection_pipeline
from src.utils.logging_utils import log_web_activity
from web.auth.helpers import current_user, login_required
from web.auth.rbac import has_capability, require_capability, SEND_EXTERNAL, RUN_DRYRUN

logger = logging.getLogger(__name__)

detection_as_code_bp = Blueprint("detection_as_code", __name__)

_MAX_RULE = 60_000


def _actor() -> str:
    try:
        from web.auth.helpers import current_user, current_pat_user
        u = current_user() or current_pat_user()
        if u and u.get("email"):
            return u["email"]
    except Exception:
        pass
    return "anonymous"


@detection_as_code_bp.route("/detection-as-code")
@log_web_activity
@login_required
def detection_as_code_page():
    return render_template("detection_as_code.html")


@detection_as_code_bp.route("/detection-as-code/submit", methods=["POST"])
@log_web_activity
@login_required
def detection_as_code_submit():
    data = request.get_json(silent=True) or {}
    source_type = "xql" if str(data.get("source_type") or "sigma").lower() == "xql" else "sigma"
    rule_source = (data.get("rule_source") or "").strip()
    if not rule_source:
        msg = "Paste an XQL query to run the pipeline." if source_type == "xql" else "Paste a Sigma rule to run the pipeline."
        return jsonify({"error": msg}), 400
    if len(rule_source) > _MAX_RULE:
        rule_source = rule_source[:_MAX_RULE]
    title = (data.get("title") or "").strip()[:200]
    # The live XSIAM dry-run is opt-in (it burns Cortex compute units) and is the
    # one tenant-touching action — so it, and only it, needs the run.dryrun
    # capability. Offline runs (lint/compile/review/package) are open to any
    # logged-in user.
    run_dry_run = bool(data.get("run_dry_run"))
    if run_dry_run and not has_capability(current_user(), RUN_DRYRUN):
        return jsonify({"error": "The live XSIAM dry-run needs the “run.dryrun” capability "
                                 "(Detection Engineer). Submit without it to lint, compile and "
                                 "review offline, or ask an admin for access."}), 403
    try:
        job_id = detection_pipeline.submit(rule_source=rule_source, title=title, actor=_actor(),
                                           source_type=source_type, run_dry_run=run_dry_run)
    except Exception as e:
        logger.exception("Detection-as-code submit failed")
        return jsonify({"error": f"Could not start: {type(e).__name__}: {e}"}), 500
    return jsonify({"job_id": job_id})


@detection_as_code_bp.route("/detection-as-code/draft", methods=["POST"])
@log_web_activity
@login_required
def detection_as_code_draft():
    """Draft a Sigma rule from a plain-English description (optional front door)."""
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Describe the behavior you want to detect."}), 400
    try:
        res = detection_pipeline.draft_sigma_from_text(text[:4000])
    except Exception as e:
        logger.exception("Sigma drafting failed")
        return jsonify({"error": f"Could not draft: {type(e).__name__}: {e}"}), 500
    return jsonify(res), (200 if res.get("sigma") else 400)


@detection_as_code_bp.route("/detection-as-code/draft-xql", methods=["POST"])
@log_web_activity
@login_required
def detection_as_code_draft_xql():
    """Draft an XSIAM XQL query directly from plain English (direct-XQL lane)."""
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Describe the behavior you want to detect."}), 400
    try:
        res = detection_pipeline.draft_xql_from_text(text[:4000])
    except Exception as e:
        logger.exception("XQL drafting failed")
        return jsonify({"error": f"Could not draft: {type(e).__name__}: {e}"}), 500
    return jsonify(res), (200 if res.get("xql") else 400)


@detection_as_code_bp.route("/detection-as-code/job/<job_id>")
@log_web_activity
@login_required
def detection_as_code_job(job_id):
    job = detection_pipeline.get_job(job_id)
    if not job:
        return jsonify({"error": "Pipeline run not found."}), 404
    return jsonify(job)


@detection_as_code_bp.route("/detection-as-code/recent")
@log_web_activity
@login_required
def detection_as_code_recent():
    try:
        limit = min(int(request.args.get("limit", 25)), 100)
    except (TypeError, ValueError):
        limit = 25
    return jsonify({"jobs": detection_pipeline.list_recent(limit)})


@detection_as_code_bp.route("/detection-as-code/deploy", methods=["POST"])
@log_web_activity
@require_capability(SEND_EXTERNAL)
def detection_as_code_deploy():
    """Approve-and-open the GitLab merge request. Disabled on the dev instance."""
    data = request.get_json(silent=True) or {}
    job_id = (data.get("job_id") or "").strip()
    if not job_id:
        return jsonify({"ok": False, "error": "missing job_id"}), 400
    res = detection_pipeline.open_merge_request(job_id, _actor())
    if res.get("ok"):
        code = 200
    elif res.get("error") in ("deploy_disabled_in_dev", "gitlab_not_configured"):
        code = 403
    else:
        code = 400
    return jsonify(res), code
