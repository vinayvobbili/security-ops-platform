"""Phishing sentiment analysis page.

Paste raw email source / a body, or upload an .eml, and get a sentiment +
social-engineering read from the local LLM alongside the deterministic signals
(sender/reply-to mismatch, embedded URLs, attachments, auth results).
"""

import logging

from io import BytesIO

from flask import Blueprint, jsonify, render_template, request, send_file

from services.phish_triage import analyze_email
from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)

phish_sentiment_bp = Blueprint("phish_sentiment", __name__)

_MAX_CHARS = 200_000  # generous ceiling so a full raw email with headers fits
_MAX_ATTACH_BYTES = 30 * 1024 * 1024  # 30 MB per standalone attachment


def _read_uploaded_attachments():
    """Read standalone attachment files off the request into triage dicts.

    Nothing is persisted — bytes live only for the duration of the request (and
    are re-sent by the browser on a detonate). Returns a list of
    ``{filename, content_type, _bytes}`` dicts, skipping empties/oversized files.
    """
    out = []
    for f in request.files.getlist("attachments"):
        if not f or not f.filename:
            continue
        data = f.read(_MAX_ATTACH_BYTES + 1)
        if not data or len(data) > _MAX_ATTACH_BYTES:
            continue
        out.append({"filename": f.filename, "content_type": f.mimetype or "", "_bytes": data})
    return out


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


def _audit(action: str, **details) -> None:
    """Emit a structured audit line. No persistence of email content — only who
    did what, when, and the minimal identifiers (hashes/verdicts) needed for a
    SOC audit trail. Lands in the app logs (viewable at /app-logs)."""
    parts = " ".join(f"{k}={v}" for k, v in details.items() if v not in (None, ""))
    logger.info("[PHISH-AUDIT] user=%s action=%s %s", _actor(), action, parts)


@phish_sentiment_bp.route("/phishing-sentiment")
@log_web_activity
def phishing_sentiment_page():
    return render_template("phish_sentiment.html")


@phish_sentiment_bp.route("/phishing-sentiment/analyze", methods=["POST"])
@log_web_activity
def phishing_sentiment_analyze():
    """Analyze pasted text / an uploaded .eml and/or standalone attachments. Returns JSON."""
    text = ""
    upload = request.files.get("email_file")
    if upload and upload.filename:
        try:
            text = upload.read().decode("utf-8", "replace")
        except Exception as e:
            return jsonify({"error": f"Could not read uploaded file: {e}"}), 400
    if not text.strip():
        text = (request.form.get("email_text") or "").strip()
    if len(text) > _MAX_CHARS:
        text = text[:_MAX_CHARS]

    extra_attachments = _read_uploaded_attachments()

    if not text.strip() and not extra_attachments:
        return jsonify({"error": "Paste an email, upload an .eml, or attach a file to analyze."}), 400

    try:
        result = analyze_email(text, extra_attachments=extra_attachments)
    except Exception as e:
        logger.exception("Phishing analysis failed")
        return jsonify({"error": f"Analysis failed: {type(e).__name__}: {e}"}), 500

    verdict = (result.get("verdict") or {})
    _audit("analyze",
           verdict=verdict.get("verdict"),
           classification=verdict.get("classification"),
           subject=(result.get("signals") or {}).get("subject", "")[:80],
           attachments=len((result.get("signals") or {}).get("attachments") or []),
           uploaded_files=len(extra_attachments))
    return jsonify(result)


@phish_sentiment_bp.route("/phishing-sentiment/report", methods=["POST"])
@log_web_activity
def phishing_sentiment_report():
    """Render the current analysis result to a styled PDF and return it."""
    result = request.get_json(silent=True)
    if not isinstance(result, dict) or not result.get("verdict"):
        return jsonify({"error": "No analysis result to report. Run an analysis first."}), 400
    try:
        from services.phish_report import build_pdf
        pdf_bytes = build_pdf(result)
    except Exception as e:
        logger.exception("PDF report generation failed")
        return jsonify({"error": f"Report generation failed: {type(e).__name__}: {e}"}), 500

    _audit("download_report", verdict=(result.get("verdict") or {}).get("verdict"))

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="phishing-analysis-report.pdf",
    )


@phish_sentiment_bp.route("/phishing-sentiment/detonate", methods=["POST"])
@log_web_activity
def phishing_sentiment_detonate():
    """Explicit, analyst-initiated WildFire detonation of one attachment.

    This SUBMITS the file to the WildFire cloud (via XSOAR Prod) — never
    auto-run; the analyst clicks Detonate per attachment. The original email
    (and/or the standalone files) is re-sent by the browser and matched by
    SHA256 server-side, so nothing is persisted between requests.

    Returns the resolved verdict, or 'pending' if the sandbox is still running
    when the poll window expires.
    """
    import hashlib

    text = ""
    upload = request.files.get("email_file")
    if upload and upload.filename:
        try:
            text = upload.read().decode("utf-8", "replace")
        except Exception as e:
            return jsonify({"error": f"Could not read uploaded file: {e}"}), 400
    if not text.strip():
        text = (request.form.get("email_text") or "").strip()

    target_sha = (request.form.get("sha256") or "").strip().lower()
    if not target_sha:
        return jsonify({"error": "Need the attachment hash to detonate."}), 400

    # Candidate bytes come from the re-sent email's embedded attachments AND any
    # re-sent standalone uploads. Match the requested SHA256 across both.
    standalone = _read_uploaded_attachments()
    if not text.strip() and not standalone:
        return jsonify({"error": "Re-submit the original email or the attached file to detonate."}), 400

    try:
        from services.phish_triage import parse_email
        from services.wildfire import detonate

        candidates = []
        if text.strip():
            candidates.extend(parse_email(text).get("attachments") or [])
        candidates.extend(standalone)

        match = None
        for att in candidates:
            b = att.get("_bytes") or b""
            if b and hashlib.sha256(b).hexdigest().lower() == target_sha:
                match = att
                break
        if not match:
            return jsonify({"error": "Attachment not found in the submitted email or uploads."}), 404

        actor = _actor()
        # Audit the submission BEFORE it runs — so an attempt is recorded even if
        # the detonation later errors or times out.
        _audit("detonate_submit", sha256=target_sha, filename=match.get("filename"))
        result = detonate(match["_bytes"], match.get("filename", "attachment"), actor=actor)
    except Exception as e:
        logger.exception("WildFire detonation failed")
        return jsonify({"error": f"Detonation failed: {type(e).__name__}: {e}"}), 500

    _audit("detonate_result", sha256=target_sha, filename=match.get("filename"),
           status=result.get("status"), verdict=result.get("verdict"))
    return jsonify(result)
