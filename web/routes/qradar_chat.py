"""QRadar AQL Explorer routes — chat page + API endpoints."""

import json
import logging
import tempfile

from flask import Blueprint, jsonify, render_template, request, current_app, send_file

from src.utils.logging_utils import log_web_activity, get_client_ip
from src.components.web import qradar_chat_handler as qr_chat
from web.extensions import limiter

logger = logging.getLogger(__name__)
qradar_chat_bp = Blueprint("qradar_chat", __name__)

# Lazy-init QRadar client and LLM
_qr_client = None
_qr_llm = None


def _get_qr_client():
    global _qr_client
    if _qr_client is None:
        from services.qradar import QRadarClient
        _qr_client = QRadarClient()
    return _qr_client


def _get_qr_llm():
    global _qr_llm
    if _qr_llm is None:
        from my_bot.utils.llm_factory import create_llm
        _qr_llm = create_llm(
            max_tokens=2048, timeout=300,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
    return _qr_llm


# ── Page route ──

@qradar_chat_bp.route("/qradar-chat")
@log_web_activity
def qradar_chat_page():
    """Render the QRadar AQL Explorer page."""
    client = _get_qr_client()
    configured = client.is_configured()
    categories = qr_chat.get_categories()
    return render_template("qradar_chat.html", categories=categories, configured=configured)


# ── API endpoints ──

@qradar_chat_bp.route("/api/qradar-chat/categories")
@limiter.limit("10 per minute")
@log_web_activity
def api_qradar_categories():
    """List log source categories."""
    return jsonify({"success": True, "categories": qr_chat.get_categories()})


@qradar_chat_bp.route("/api/qradar-chat/schema/<category_id>")
@limiter.limit("10 per minute")
@log_web_activity
def api_qradar_schema(category_id):
    """Get schema for a log source category."""
    schema = qr_chat.get_category_schema(category_id)
    chips = qr_chat.get_category_chips(category_id)
    return jsonify({"success": True, "schema": schema, "chips": chips})


@qradar_chat_bp.route("/api/qradar-chat/stream", methods=["POST"])
@limiter.limit("10 per minute")
@log_web_activity
def api_qradar_chat_stream():
    """Streaming chat: NL -> AQL -> execute -> explain."""
    try:
        data = request.get_json()
        user_message = (data.get("message") or "").strip()
        category_id = (data.get("category_id") or "").strip()
        session_id = (data.get("session_id") or "").strip()
        client_history = data.get("history")

        if not user_message:
            return jsonify({"success": False, "error": "Message is required"}), 400
        if len(user_message) > 2000:
            return jsonify({"success": False, "error": "Message too long (max 2000 chars)"}), 400
        if not category_id:
            return jsonify({"success": False, "error": "Category is required"}), 400
        if not session_id:
            return jsonify({"success": False, "error": "Session ID is required"}), 400

        client = _get_qr_client()
        if not client.is_configured():
            return jsonify({"success": False, "error": "QRadar API not configured"}), 503

        llm = _get_qr_llm()
        client_ip = get_client_ip()

        def generate():
            try:
                for payload in qr_chat.handle_chat_stream(
                    user_message, category_id, session_id, llm, client,
                    client_ip=client_ip, history=client_history,
                ):
                    if payload.get("keepalive"):
                        yield ": keepalive\n\n"
                    else:
                        yield f"data: {json.dumps(payload)}\n\n"
            except Exception as err:
                logger.error("QRadar chat stream error: %s", err, exc_info=True)
                err_str = str(err)
                if "incomplete chunked read" in err_str or "RemoteProtocolError" in err_str:
                    msg = "LLM connection dropped mid-response — the inference server may be overloaded. Please try again."
                else:
                    msg = err_str
                yield f"data: {json.dumps({'error': msg})}\n\n"

        return current_app.response_class(
            generate(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    except Exception as exc:
        logger.error("QRadar chat error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": str(exc)}), 500


@qradar_chat_bp.route("/api/qradar-chat/clear", methods=["POST"])
@limiter.limit("10 per minute")
@log_web_activity
def api_qradar_chat_clear():
    """Clear QRadar chat session history."""
    data = request.get_json(silent=True) or {}
    session_id = (data.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"success": False, "error": "Session ID is required"}), 400
    qr_chat.clear_history(session_id)
    return jsonify({"success": True})


@qradar_chat_bp.route("/api/qradar-chat/export/xlsx", methods=["POST"])
@limiter.limit("10 per minute")
@log_web_activity
def api_qradar_export_xlsx():
    """Export query results as a professionally formatted Excel file."""
    try:
        import pandas as pd
        from src.utils.excel_formatting import apply_professional_formatting

        data = request.get_json()
        headers = data.get("headers", [])
        rows = data.get("rows", [])
        category_name = data.get("category_name", "QRadar")

        if not headers or not rows:
            return jsonify({"success": False, "error": "No data to export"}), 400

        df = pd.DataFrame(rows, columns=headers)

        col_widths = {}
        for col in headers:
            max_len = max(len(str(col)), df[col].astype(str).str.len().max())
            col_widths[col.lower()] = min(max(max_len + 4, 12), 60)

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp_path = tmp.name

        df.to_excel(tmp_path, index=False, sheet_name=category_name[:31])
        apply_professional_formatting(tmp_path, column_widths=col_widths)

        safe_name = "".join(c if c.isalnum() or c in "-_ " else "" for c in category_name)
        filename = f"QRadar - {safe_name}.xlsx"

        return send_file(
            tmp_path,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as exc:
        logger.error("QRadar Excel export error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": str(exc)}), 500
