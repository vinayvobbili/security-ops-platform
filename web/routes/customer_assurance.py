"""Customer Assurance page — routes blueprint.

Drafting assistant for customer security questionnaires. Analysts intake a
request, the system retrieves relevant policy/evidence chunks, an LLM drafts
answers, analysts review/edit/export. See `customer_assurance_handler` for DB
+ retrieval + drafting logic.
"""

import logging
import re
from typing import List, Dict, Any

from flask import Blueprint, jsonify, render_template, request, send_file, abort

from src.utils.logging_utils import log_web_activity
from src.components.web import customer_assurance_handler as handler

logger = logging.getLogger(__name__)

customer_assurance_bp = Blueprint("customer_assurance", __name__)


def _current_mode() -> str:
    """Read the ca_mode cookie. Defaults to 'demo' for safety."""
    return (request.cookies.get("ca_mode") or "demo").lower()


def _force_demo() -> bool:
    return _current_mode() != "live"


# ------------------------------------------------------------------ Helpers

_QUESTION_SPLITTER = re.compile(r"^\s*(?:\d+[.)]|[-*•])\s*", re.MULTILINE)


def _split_into_questions(raw_text: str) -> List[Dict[str, Any]]:
    """Split pasted questionnaire text into individual questions.

    Heuristic: numbered lines (1., 2), bullets, or blank-line separated.
    Always returns at least 1 item if the text is non-empty.
    """
    if not raw_text or not raw_text.strip():
        return []

    # Try numbered/bulleted first
    parts = _QUESTION_SPLITTER.split(raw_text)
    parts = [p.strip() for p in parts if p and p.strip()]

    # If that produced <=1 segment, fall back to blank-line split
    if len(parts) <= 1:
        parts = [p.strip() for p in re.split(r"\n\s*\n", raw_text) if p.strip()]

    # Final fallback: one long question
    if not parts:
        parts = [raw_text.strip()]

    return [{"question": p, "section": None} for p in parts]


# ------------------------------------------------------------------ Pages

@customer_assurance_bp.route("/customer-assurance")
@log_web_activity
def landing():
    """Landing page: overview of the flow, entry tiles, walkthrough trigger."""
    exclude = _force_demo() is False  # Live mode → exclude demo records
    stats = {
        "total":       len(handler.list_requests(exclude_demo=exclude)),
        "drafting":    len(handler.list_requests(status="drafting", exclude_demo=exclude)),
        "needs_legal": len(handler.list_requests(status="needs_legal", exclude_demo=exclude)),
        "ready":       len(handler.list_requests(status="ready", exclude_demo=exclude)),
        "delivered":   len(handler.list_requests(status="delivered", exclude_demo=exclude)),
    }
    kb = handler.kb_stats()
    return render_template(
        "customer_assurance_landing.html",
        stats=stats,
        kb=kb,
        mode=_current_mode(),
    )


@customer_assurance_bp.route("/customer-assurance/new")
@log_web_activity
def new_request_form():
    """Intake form."""
    return render_template(
        "customer_assurance_new.html",
        segments=handler.SEGMENTS,
        request_types=handler.REQUEST_TYPES,
        source_formats=handler.SOURCE_FORMATS,
        priorities=handler.PRIORITIES,
    )


@customer_assurance_bp.route("/customer-assurance/requests")
@log_web_activity
def queue():
    """Queue of all requests — sortable + filterable."""
    status = request.args.get("status") or None
    segment = request.args.get("segment") or None
    exclude = not _force_demo()  # Live mode hides demo records
    reqs = handler.list_requests(status=status, segment=segment, exclude_demo=exclude)
    # Attach question counts
    for r in reqs:
        qs = handler.list_questions(r["id"])
        r["question_count"] = len(qs)
        r["drafted_count"] = sum(1 for q in qs if q.get("draft_answer"))
        r["approved_count"] = sum(1 for q in qs if q.get("status") == "approved")
    return render_template(
        "customer_assurance_queue.html",
        requests=reqs,
        active_status=status,
        active_segment=segment,
        segments=handler.SEGMENTS,
        statuses=handler.REQUEST_STATUSES,
        mode=_current_mode(),
    )


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>")
@log_web_activity
def workspace(request_id: int):
    """Drafting workspace — 3-pane view for reviewing/editing answers."""
    req = handler.get_request(request_id)
    if not req:
        abort(404)
    questions = handler.list_questions(request_id)
    for q in questions:
        q["citations"] = handler.get_citations(q["id"])
    audit = handler.get_audit_log(request_id)
    kb_has_docs = handler.kb_stats().get("chunk_count", 0) > 0
    mode = _current_mode()

    # Detect which source produced the most recent drafts (read audit log)
    last_draft_source = None
    for entry in audit:
        if entry.get("action") == "drafted":
            detail = (entry.get("detail") or "")
            if "gateway" in detail:
                last_draft_source = "gateway"
            elif "demo fallback" in detail:
                last_draft_source = "fallback"
            elif "demo mode" in detail:
                last_draft_source = "demo"
            else:
                last_draft_source = "gateway"  # plain "drafted" = real path
            break

    return render_template(
        "customer_assurance_workspace.html",
        req=req,
        questions=questions,
        audit=audit,
        kb_has_docs=kb_has_docs,
        mode=mode,
        last_draft_source=last_draft_source,
        statuses=handler.REQUEST_STATUSES,
    )


@customer_assurance_bp.route("/customer-assurance/kb")
@log_web_activity
def kb_admin():
    """Knowledge base admin — list sources, reindex, stats."""
    return render_template(
        "customer_assurance_kb.html",
        kb=handler.kb_stats(),
    )


# ------------------------------------------------------------------ Actions

@customer_assurance_bp.route("/customer-assurance/submit", methods=["POST"])
@log_web_activity
def submit_request():
    """Create a new request from the intake form."""
    form = request.form
    required = ["customer_name", "customer_segment", "request_type", "title"]
    missing = [k for k in required if not (form.get(k) or "").strip()]
    if missing:
        return jsonify({"status": "error", "message": f"Missing: {', '.join(missing)}"}), 400

    try:
        rid = handler.create_request(
            customer_name=form["customer_name"].strip(),
            customer_segment=form["customer_segment"].strip(),
            request_type=form["request_type"].strip(),
            title=form["title"].strip(),
            account_team_contact=(form.get("account_team_contact") or "").strip() or None,
            source_format=(form.get("source_format") or "").strip() or None,
            due_date=(form.get("due_date") or "").strip() or None,
            priority=(form.get("priority") or "").strip() or None,
            raw_text=(form.get("raw_text") or "").strip() or None,
            notes=(form.get("notes") or "").strip() or None,
            assigned_to=(form.get("assigned_to") or "").strip() or None,
        )
    except Exception as e:
        logger.error(f"[customer_assurance] create_request failed: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Failed to create request"}), 500

    # Split questions from raw_text (or from an uploaded file, handled separately)
    raw = (form.get("raw_text") or "").strip()
    items = _split_into_questions(raw)
    if items:
        handler.add_questions(rid, items)

    # Also save any uploaded files
    for f in request.files.getlist("documents"):
        handler.save_upload(rid, f, kind="inbound_questionnaire")

    return jsonify({
        "status": "success",
        "request_id": rid,
        "redirect": f"/customer-assurance/requests/{rid}",
    })


@customer_assurance_bp.route("/customer-assurance/preview-split", methods=["POST"])
@log_web_activity
def preview_split():
    """Live preview of how pasted text will split into questions."""
    raw = (request.json or {}).get("raw_text", "") if request.is_json else request.form.get("raw_text", "")
    items = _split_into_questions(raw)
    return jsonify({"count": len(items), "questions": [i["question"] for i in items]})


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>/draft-all", methods=["POST"])
@log_web_activity
def draft_all(request_id: int):
    """Draft all pending questions in a request."""
    force_demo = _force_demo()
    questions = handler.list_questions(request_id)
    results = []
    for q in questions:
        if q.get("draft_answer"):
            continue
        try:
            result = handler.draft_question(q["id"], force_demo=force_demo)
            results.append({"question_id": q["id"], "ok": True, "source": result.get("source", "llm")})
        except Exception as e:
            logger.error(f"[customer_assurance] draft_question failed q#{q['id']}: {e}")
            results.append({"question_id": q["id"], "ok": False, "error": str(e)})
    handler.update_request_status(request_id, "drafting")
    return jsonify({"status": "success", "drafted": len([r for r in results if r["ok"]]), "results": results, "mode": _current_mode()})


@customer_assurance_bp.route("/customer-assurance/questions/<int:question_id>/draft", methods=["POST"])
@log_web_activity
def draft_one(question_id: int):
    """Redraft a single question."""
    try:
        result = handler.draft_question(question_id, force_demo=_force_demo())
        return jsonify({"status": "success", "mode": _current_mode(), **result})
    except Exception as e:
        logger.error(f"[customer_assurance] redraft failed q#{question_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>/approve-all", methods=["POST"])
@log_web_activity
def approve_all(request_id: int):
    """Mark every drafted question as approved (final_answer = draft_answer)."""
    qs = handler.list_questions(request_id)
    approved = 0
    for q in qs:
        if q.get("draft_answer") and q.get("status") in ("drafted", "needs_sme"):
            final = q.get("final_answer") or q["draft_answer"]
            handler.save_final_answer(q["id"], final, status="approved")
            approved += 1
    handler.update_request_status(request_id, "ready")
    handler.log_audit(request_id, "approved_all", f"{approved} question(s) approved")
    return jsonify({"status": "success", "approved": approved})


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>/answers")
@log_web_activity
def request_answers_text(request_id: int):
    """Return a plain-text bundle of all answers for the request (for clipboard copy)."""
    req = handler.get_request(request_id)
    if not req:
        return jsonify({"status": "error"}), 404
    qs = handler.list_questions(request_id)
    lines = [f"{req['customer_name']} — {req['title']}", "=" * 60, ""]
    for q in qs:
        if q.get("section"):
            lines.append(f"[{q['section']}]")
        lines.append(f"Q{q['seq']}. {q['question']}")
        ans = q.get("final_answer") or q.get("draft_answer") or "[No response drafted]"
        lines.append(f"A: {ans}")
        lines.append("")
    return jsonify({"status": "success", "text": "\n".join(lines)})


@customer_assurance_bp.route("/customer-assurance/questions/<int:question_id>/save", methods=["POST"])
@log_web_activity
def save_answer(question_id: int):
    """Save an analyst's edited final answer + status."""
    data = request.get_json(silent=True) or {}
    final_answer = (data.get("final_answer") or "").strip()
    status = data.get("status", "approved")
    if not final_answer:
        return jsonify({"status": "error", "message": "final_answer is required"}), 400
    try:
        handler.save_final_answer(question_id, final_answer, status=status)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>/status", methods=["POST"])
@log_web_activity
def set_status(request_id: int):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"status": "error", "message": "status required"}), 400
    try:
        handler.update_request_status(request_id, new_status, actor=data.get("actor", "analyst"))
        return jsonify({"status": "success"})
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>/flag-legal", methods=["POST"])
@log_web_activity
def flag_legal(request_id: int):
    data = request.get_json(silent=True) or {}
    note = (data.get("note") or "").strip()
    handler.flag_legal_review(request_id, note, actor=data.get("actor", "analyst"))
    return jsonify({"status": "success"})


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>/export", methods=["POST"])
@log_web_activity
def export_request(request_id: int):
    path = handler.export_request_docx(request_id)
    if not path:
        return jsonify({"status": "error", "message": "Export failed (python-docx may be missing)"}), 500
    return send_file(str(path), as_attachment=True, download_name=path.name)


@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>", methods=["DELETE"])
@log_web_activity
def delete_request(request_id: int):
    password = (request.get_json(silent=True) or {}).get("password", "")
    if password != "customerassurance123":
        return jsonify({"status": "error", "message": "Incorrect password"}), 403
    if handler.delete_request(request_id):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Not found"}), 404


# ------------------------------------------------------------------ Audit log

@customer_assurance_bp.route("/customer-assurance/requests/<int:request_id>/audit")
@log_web_activity
def request_audit(request_id: int):
    """Return audit log entries for a request as JSON."""
    log = handler.get_audit_log(request_id)
    return jsonify({"status": "success", "entries": log})


# ------------------------------------------------------------------ KB admin

@customer_assurance_bp.route("/customer-assurance/kb/upload", methods=["POST"])
@log_web_activity
def kb_upload():
    """Save uploaded file(s) into KB_SOURCE_DIR for later ingestion."""
    files = request.files.getlist("documents")
    if not files:
        return jsonify({"status": "error", "message": "No files provided"}), 400

    from werkzeug.utils import secure_filename
    saved: List[str] = []
    allowed = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".md"}
    for f in files:
        if not f or not f.filename:
            continue
        name = secure_filename(f.filename)
        if not name:
            continue
        from pathlib import Path as _P
        ext = _P(name).suffix.lower()
        if ext not in allowed:
            continue
        dest = handler.KB_SOURCE_DIR / name
        f.save(str(dest))
        saved.append(name)
    return jsonify({"status": "success", "saved": saved, "count": len(saved)})


@customer_assurance_bp.route("/customer-assurance/kb/reindex", methods=["POST"])
@log_web_activity
def kb_reindex():
    """Run ingest on KB_SOURCE_DIR → chroma_kb."""
    data = request.get_json(silent=True) or {}
    reset = bool(data.get("reset", False))
    try:
        result = handler.ingest_kb_source(reset=reset)
        return jsonify({"status": "success", **result})
    except Exception as e:
        logger.error(f"[customer_assurance] reindex failed: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@customer_assurance_bp.route("/customer-assurance/kb/load-demo", methods=["POST"])
@log_web_activity
def kb_load_demo():
    """Create placeholder KB source files so the KB admin page looks populated
    during demos. Each file is a tiny text file with the document name as
    content. No real embedding — just visual.
    """
    from src.components.web.customer_assurance_demo import DEMO_KB_FILENAMES
    created = 0
    for fname in DEMO_KB_FILENAMES:
        dest = handler.KB_SOURCE_DIR / fname
        if dest.exists():
            continue
        dest.write_text(
            f"[Demo placeholder] {fname}\n"
            f"This is a demo stub for the Customer Assurance KB page. "
            f"Replace with the real document before going live.\n"
        )
        created += 1
    return jsonify({"status": "success", "created": created, "total": len(DEMO_KB_FILENAMES)})


@customer_assurance_bp.route("/customer-assurance/kb/clear", methods=["POST"])
@log_web_activity
def kb_clear():
    """Remove all source files from KB_SOURCE_DIR (does not touch chroma)."""
    import os as _os
    removed = 0
    for fname in _os.listdir(handler.KB_SOURCE_DIR):
        fpath = handler.KB_SOURCE_DIR / fname
        if fpath.is_file():
            fpath.unlink()
            removed += 1
    return jsonify({"status": "success", "removed": removed})


# ------------------------------------------------------------------ Demo controls

@customer_assurance_bp.route("/customer-assurance/demo/seed", methods=["POST"])
@log_web_activity
def demo_seed():
    """Seed sample data. Used for the Monday demo."""
    wipe = (request.get_json(silent=True) or {}).get("wipe", False)
    result = handler.seed_demo_data(wipe=wipe)
    return jsonify({"status": "success", **result})


@customer_assurance_bp.route("/customer-assurance/demo/reset", methods=["POST"])
@log_web_activity
def demo_reset():
    """Wipe all requests and reseed fresh demo data."""
    result = handler.seed_demo_data(wipe=True)
    return jsonify({"status": "success", **result})
