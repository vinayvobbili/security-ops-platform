"""Docs Library routes — page + document management API."""

import logging
import threading

from flask import Blueprint, jsonify, render_template, request, send_from_directory

from src.utils.logging_utils import log_web_activity
from src.components.web.edit_auth import notify_edit_async
from web.auth import helpers

logger = logging.getLogger(__name__)

docs_library_bp = Blueprint("docs_library", __name__)

# Module-level sync status (updated by background thread)
_sync_status: dict = {"running": False, "last_result": None}


def _run_sync():
    _sync_status["running"] = True
    try:
        from src.components.web import docs_library_handler as h
        _sync_status["last_result"] = h.sync_vector_store()
    except Exception as exc:
        logger.error("Background sync failed: %s", exc, exc_info=True)
        _sync_status["last_result"] = {"success": False, "error": str(exc)}
    finally:
        _sync_status["running"] = False


def _run_rebuild():
    _sync_status["running"] = True
    try:
        from src.components.web import docs_library_handler as h
        _sync_status["last_result"] = h.rebuild_vector_store()
    except Exception as exc:
        logger.error("Background rebuild failed: %s", exc, exc_info=True)
        _sync_status["last_result"] = {"success": False, "error": str(exc)}
    finally:
        _sync_status["running"] = False


@docs_library_bp.route("/docs-library")
@log_web_activity
def docs_library_page():
    from src.components.web import docs_library_handler as h
    docs = h.list_docs()
    stats = h.get_chroma_stats()
    return render_template("docs_library.html", docs=docs, stats=stats)


@docs_library_bp.route("/api/docs-library/upload", methods=["POST"])
@log_web_activity
def upload_doc():
    if not helpers.current_user():
        return jsonify({"success": False, "error": "login_required"}), 401
    try:
        from src.components.web import docs_library_handler as h
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file provided"}), 400
        f = request.files["file"]
        if not f or not f.filename:
            return jsonify({"success": False, "error": "No file selected"}), 400
        doc_info = h.save_uploaded_file(f)
        if not _sync_status["running"]:
            threading.Thread(target=_run_sync, daemon=True).start()
        notify_edit_async("Docs Library", f"Uploaded `{doc_info['filename']}`")
        return jsonify({"success": True, "doc": doc_info, "syncing": True})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        logger.error("Upload error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500


@docs_library_bp.route("/api/docs-library/delete", methods=["POST"])
@log_web_activity
def delete_doc():
    if not helpers.current_user():
        return jsonify({"success": False, "error": "login_required"}), 401
    try:
        from src.components.web import docs_library_handler as h
        data = request.get_json()
        if not data or not data.get("filename"):
            return jsonify({"success": False, "error": "filename required"}), 400
        deleted = h.delete_doc(data["filename"])
        if not deleted:
            return jsonify({"success": False, "error": "File not found"}), 404
        notify_edit_async("Docs Library", f"Deleted `{data['filename']}`")
        return jsonify({"success": True})
    except Exception as exc:
        logger.error("Delete error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred"}), 500


@docs_library_bp.route("/api/docs-library/rebuild", methods=["POST"])
@log_web_activity
def rebuild_store():
    if not helpers.current_user():
        return jsonify({"success": False, "error": "login_required"}), 401
    if _sync_status["running"]:
        return jsonify({"success": False, "error": "A rebuild is already in progress"}), 409
    threading.Thread(target=_run_rebuild, daemon=True).start()
    notify_edit_async("Docs Library", "Triggered full vector store rebuild")
    return jsonify({"success": True, "message": "Full rebuild started"})


@docs_library_bp.route("/api/docs-library/download/<path:filename>", methods=["GET"])
@log_web_activity
def download_doc(filename):
    from src.components.web import docs_library_handler as h
    # send_from_directory already prevents path traversal; pass filename as-is
    return send_from_directory(h._DOCS_DIR, filename, as_attachment=True)


@docs_library_bp.route("/api/docs-library/status", methods=["GET"])
@log_web_activity
def sync_status():
    from src.components.web import docs_library_handler as h
    chroma = h.get_chroma_stats()
    return jsonify({
        "running": _sync_status["running"],
        "last_result": _sync_status["last_result"],
        "chroma": chroma,
    })
