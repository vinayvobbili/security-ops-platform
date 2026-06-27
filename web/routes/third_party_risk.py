"""Third-Party Cyber Risk Assessment page — routes blueprint.

Vendor cyber due-diligence workspace for the Third-Party Cyber Risk team. An
analyst opens an assessment, uploads the vendor's evidence + the Aravo export,
the system evaluates each baseline control against that evidence, the analyst
reviews/edits, and exports a populated DD Form. See `tpcra_handler` for the DB +
evidence-retrieval + evaluation logic.
"""

import logging
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file, abort

from src.utils.logging_utils import log_web_activity
from src.components.web import tpcra_handler as handler
from web.auth.helpers import login_required, current_user
from web.auth.rbac import require_capability, has_capability, DATA_DESTRUCTIVE, TPCRA_MANAGE

logger = logging.getLogger(__name__)

third_party_risk_bp = Blueprint("third_party_risk", __name__)


# ------------------------------------------------------------------ Pages

@third_party_risk_bp.route("/vendor-risk-assessment")
@log_web_activity
def landing():
    """Landing page: overview, KPI cards, entry tiles, methodology modal."""
    assessments = handler.list_assessments()
    stats = {
        "total":      len(assessments),
        "evaluating": sum(1 for a in assessments if a["status"] == "evaluating"),
        "in_review":  sum(1 for a in assessments if a["status"] == "in_review"),
        "ready":      sum(1 for a in assessments if a["status"] == "ready"),
        "delivered":  sum(1 for a in assessments if a["status"] == "delivered"),
    }
    return render_template("vendor_risk_landing.html", stats=stats)


@third_party_risk_bp.route("/vendor-risk-assessment/new")
@require_capability(TPCRA_MANAGE)
@log_web_activity
def new_assessment_form():
    return render_template(
        "vendor_risk_new.html",
        tiers=handler.VENDOR_TIERS,
        assessment_types=handler.ASSESSMENT_TYPES,
    )


@third_party_risk_bp.route("/vendor-risk-assessment/assessments")
@log_web_activity
def queue():
    status = request.args.get("status") or None
    assessments = handler.list_assessments(status=status)
    for a in assessments:
        controls = handler.list_controls(a["id"])
        a["control_count"] = len(controls)
        a["evaluated_count"] = sum(1 for c in controls if c.get("status") in ("evaluated", "confirmed"))
    user = current_user()
    return render_template(
        "vendor_risk_queue.html",
        assessments=assessments,
        active_status=status,
        statuses=handler.ASSESSMENT_STATUSES,
        current_email=(user or {}).get("email"),
    )


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>")
@log_web_activity
def workspace(assessment_id: int):
    a = handler.get_assessment(assessment_id)
    if not a:
        abort(404)
    controls = handler.list_controls(assessment_id)
    for c in controls:
        c["citations"] = handler.get_citations(c["id"])
    return render_template(
        "vendor_risk_workspace.html",
        assessment=a,
        controls=controls,
        documents=handler.list_documents(assessment_id),
        evidence=handler.evidence_stats(assessment_id),
        audit=handler.get_audit_log(assessment_id),
        determinations=handler.DETERMINATIONS,
        risk_ratings=handler.RISK_RATINGS,
        statuses=handler.ASSESSMENT_STATUSES,
    )


# ------------------------------------------------------------------ Actions

@third_party_risk_bp.route("/vendor-risk-assessment/submit", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def submit_assessment():
    form = request.form
    required = ["vendor_name", "title"]
    missing = [k for k in required if not (form.get(k) or "").strip()]
    if missing:
        return jsonify({"status": "error", "message": f"Missing: {', '.join(missing)}"}), 400

    user = current_user()
    owner = (user or {}).get("email")
    try:
        aid = handler.create_assessment(
            vendor_name=form["vendor_name"].strip(),
            title=form["title"].strip(),
            vendor_tier=(form.get("vendor_tier") or "").strip() or None,
            assessment_type=(form.get("assessment_type") or "").strip() or None,
            aravo_ref=(form.get("aravo_ref") or "").strip() or None,
            scope_notes=(form.get("scope_notes") or "").strip() or None,
            owner=owner,
        )
    except Exception as e:
        logger.error(f"[tpcra] create failed: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Failed to create assessment"}), 500

    handler.seed_baseline_controls(aid)

    # Save uploads by their declared role (vendor_evidence default).
    saved = 0
    for f in request.files.getlist("documents"):
        if handler.save_upload(aid, f, kind="vendor_evidence"):
            saved += 1
    for f in request.files.getlist("aravo_export"):
        if handler.save_upload(aid, f, kind="aravo_export"):
            saved += 1
    for f in request.files.getlist("baseline_control"):
        if handler.save_upload(aid, f, kind="baseline_control"):
            saved += 1
    if saved:
        handler.log_audit(aid, "uploaded", f"{saved} document(s) attached")

    return jsonify({
        "status": "success",
        "assessment_id": aid,
        "redirect": f"/vendor-risk-assessment/assessments/{aid}",
    })


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/upload", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def upload_documents(assessment_id: int):
    if not handler.get_assessment(assessment_id):
        return jsonify({"status": "error", "message": "Not found"}), 404
    kind = (request.form.get("kind") or "vendor_evidence").strip()
    saved = []
    for f in request.files.getlist("documents"):
        rec = handler.save_upload(assessment_id, f, kind=kind)
        if rec:
            saved.append(rec["filename"])
    if saved:
        handler.log_audit(assessment_id, "uploaded", f"{len(saved)} document(s): {', '.join(saved)}")
    return jsonify({"status": "success", "saved": saved, "count": len(saved)})


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/index", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def index_documents(assessment_id: int):
    if not handler.get_assessment(assessment_id):
        return jsonify({"status": "error", "message": "Not found"}), 404
    reset = bool((request.get_json(silent=True) or {}).get("reset", False))
    try:
        result = handler.ingest_assessment_documents(assessment_id, reset=reset)
        return jsonify({"status": "success", **result})
    except Exception as e:
        logger.error(f"[tpcra] index failed a#{assessment_id}: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/evaluate-all", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def evaluate_all(assessment_id: int):
    if not handler.get_assessment(assessment_id):
        return jsonify({"status": "error", "message": "Not found"}), 404
    # Make sure evidence is indexed before evaluating.
    stats = handler.evidence_stats(assessment_id)
    if stats["pending_count"] > 0:
        handler.ingest_assessment_documents(assessment_id)
    result = handler.start_eval_all(assessment_id)
    return jsonify({"status": "success", **result})


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/evaluate-all/status")
@log_web_activity
def evaluate_all_status(assessment_id: int):
    if not handler.get_assessment(assessment_id):
        return jsonify({"status": "error", "message": "Not found"}), 404
    return jsonify({"status": "success", **handler.eval_all_status(assessment_id)})


@third_party_risk_bp.route("/vendor-risk-assessment/controls/<int:control_id>/evaluate", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def evaluate_one(control_id: int):
    control = handler.get_control(control_id)
    if not control:
        return jsonify({"status": "error", "message": "Not found"}), 404
    handler.ingest_assessment_documents(control["assessment_id"])
    try:
        result = handler.evaluate_control(control_id)
        return jsonify({"status": "success", **result})
    except Exception as e:
        logger.error(f"[tpcra] evaluate failed control#{control_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@third_party_risk_bp.route("/vendor-risk-assessment/controls/<int:control_id>/save", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def save_control(control_id: int):
    if not handler.get_control(control_id):
        return jsonify({"status": "error", "message": "Not found"}), 404
    data = request.get_json(silent=True) or {}
    handler.save_control_determination(
        control_id,
        determination=(data.get("determination") or "").strip() or None,
        evidence_summary=(data.get("evidence_summary") or "").strip() or None,
        validation_source=(data.get("validation_source") or "").strip() or None,
        notes_gaps=(data.get("notes_gaps") or "").strip() or None,
        status="confirmed",
    )
    return jsonify({"status": "success"})


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/synthesize-risk", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def synthesize_risk(assessment_id: int):
    if not handler.get_assessment(assessment_id):
        return jsonify({"status": "error", "message": "Not found"}), 404
    try:
        result = handler.synthesize_risk(assessment_id)
        return jsonify({"status": "success", **result})
    except Exception as e:
        logger.error(f"[tpcra] risk synth failed a#{assessment_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/risk", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def save_risk(assessment_id: int):
    if not handler.get_assessment(assessment_id):
        return jsonify({"status": "error", "message": "Not found"}), 404
    data = request.get_json(silent=True) or {}
    handler.set_risk_ratings(
        assessment_id,
        inherent_risk=(data.get("inherent_risk") or "").strip() or None,
        residual_risk=(data.get("residual_risk") or "").strip() or None,
        overall_statement=(data.get("overall_statement") or "").strip() or None,
    )
    return jsonify({"status": "success"})


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/status", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def set_status(assessment_id: int):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"status": "error", "message": "status required"}), 400
    try:
        handler.update_assessment_status(assessment_id, new_status, actor="analyst")
        return jsonify({"status": "success"})
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/export", methods=["POST"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def export_assessment(assessment_id: int):
    path = handler.export_dd_form_docx(assessment_id)
    if not path:
        return jsonify({"status": "error", "message": "Export failed"}), 500
    return send_file(str(path), as_attachment=True, download_name=path.name)


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>/documents/<int:doc_id>/download")
@login_required
@log_web_activity
def download_document(assessment_id: int, doc_id: int):
    doc = handler.get_document(doc_id)
    if not doc or doc.get("assessment_id") != assessment_id:
        abort(404)
    path = Path(doc["path"])
    if not path.exists():
        abort(404)
    return send_file(str(path), as_attachment=True, download_name=doc.get("filename") or path.name)


@third_party_risk_bp.route("/vendor-risk-assessment/assessments/<int:assessment_id>", methods=["DELETE"])
@require_capability(TPCRA_MANAGE)
@log_web_activity
def delete_assessment(assessment_id: int):
    a = handler.get_assessment(assessment_id)
    if not a:
        return jsonify({"status": "error", "message": "Not found"}), 404
    user = current_user() or {}
    email = (user.get("email") or "").strip().lower()
    owner = (a.get("owner") or "").strip().lower()
    is_owner = bool(email) and email == owner
    if not (is_owner or has_capability(user, DATA_DESTRUCTIVE)):
        return jsonify({"status": "error", "message": "You can only delete your own assessments."}), 403
    if handler.delete_assessment(assessment_id):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Not found"}), 404
