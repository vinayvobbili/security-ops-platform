"""Meeting Recap routes.

Upload an audio/video meeting recording, get back a diarized transcript and an
LLM-generated structured summary. The transcription itself runs on the
inference Mac via services/transcription.py; this blueprint handles the upload,
the background job orchestration, and the SQLite-backed history.
"""

import logging
import os
import re
import uuid
from pathlib import Path

from flask import Blueprint, abort, jsonify, render_template, request, send_file

from src.components.web import recap_handler
from src.components.web.recap_job_manager import get_manager
from src.utils.logging_utils import get_client_ip, log_web_activity
from web.auth.helpers import login_required
from web.auth.rbac import require_capability, DATA_DESTRUCTIVE

logger = logging.getLogger(__name__)

recap_bp = Blueprint("recap", __name__)

VALID_MEETING_TYPES = {"incident_bridge", "team_meeting", "customer_requirements"}

# Audio/video extensions we'll accept. Anything else gets rejected at upload
# so we don't waste a slot in the job queue on garbage.
ALLOWED_EXTENSIONS = {
    ".mp3", ".wav", ".m4a", ".flac", ".ogg", ".aac",  # audio
    ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v",  # video (audio extracted server-side via ffmpeg)
}


def _safe_filename(filename: str) -> str:
    """Sanitize an upload filename — strip path components and unsafe chars."""
    name = os.path.basename(filename or "")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:200] or "upload.bin"


@recap_bp.route("/recap")
@recap_bp.route("/recap/<int:recap_id>")
@log_web_activity
def recap_page(recap_id: int | None = None):
    if recap_id is not None and recap_handler.get_recap(recap_id) is None:
        abort(404)
    return render_template("recap.html", initial_recap_id=recap_id)


@recap_bp.route("/api/recap/upload", methods=["POST"])
@login_required
@log_web_activity
def api_recap_upload():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"error": "No file uploaded"}), 400

    ext = Path(upload.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({
            "error": f"Unsupported file type: {ext}. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
        }), 400

    meeting_type = request.form.get("meeting_type", "").strip()
    if meeting_type not in VALID_MEETING_TYPES:
        return jsonify({"error": f"meeting_type must be one of {sorted(VALID_MEETING_TYPES)}"}), 400

    meeting_date = request.form.get("meeting_date", "").strip() or None
    meeting_start_time = request.form.get("meeting_start_time", "").strip() or None
    if meeting_start_time and not re.fullmatch(r"\d{2}:\d{2}", meeting_start_time):
        return jsonify({"error": "meeting_start_time must be 24-hour HH:MM"}), 400
    attendees = request.form.get("attendees", "").strip() or None

    language = (request.form.get("language") or "").strip().lower() or recap_handler.DEFAULT_LANGUAGE
    if language not in recap_handler.SUPPORTED_LANGUAGES:
        return jsonify({
            "error": f"Unsupported language '{language}'. Supported: {sorted(recap_handler.SUPPORTED_LANGUAGES.keys())}"
        }), 400

    generate_video = request.form.get("generate_video", "0").strip().lower() in ("1", "true", "yes", "on")

    # Save to data/recaps/audio/<uuid>_<safe_filename>
    recap_handler.AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_filename(upload.filename)
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    audio_path = recap_handler.AUDIO_DIR / stored_name
    upload.save(str(audio_path))
    file_size = audio_path.stat().st_size
    logger.info(f"Recap upload saved: {stored_name} ({file_size} bytes, type={meeting_type}, language={language})")

    # Create job and kick off pipeline thread
    manager = get_manager()
    job_id = manager.create_job(
        requested_by=get_client_ip(),
        audio_filename=safe_name,
        meeting_type=meeting_type,
    )
    manager.start_pipeline_thread(
        job_id=job_id,
        pipeline_func=recap_handler.run_recap_pipeline,
        audio_path=str(audio_path),
        meeting_type=meeting_type,
        meeting_date=meeting_date,
        meeting_start_time=meeting_start_time,
        attendees=attendees,
        language=language,
        generate_video=generate_video,
    )

    return jsonify({"job_id": job_id})


@recap_bp.route("/api/recap/status/<job_id>", methods=["GET"])
@log_web_activity
def api_recap_status(job_id):
    job = get_manager().get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.to_dict())


@recap_bp.route("/api/recap/jobs/active", methods=["GET"])
@log_web_activity
def api_recap_jobs_active():
    jobs = [j.to_dict() for j in get_manager().list_active()]
    return jsonify({"jobs": jobs})


@recap_bp.route("/api/recap/<int:recap_id>", methods=["GET"])
@log_web_activity
def api_recap_get(recap_id):
    recap = recap_handler.get_recap(recap_id)
    if not recap:
        return jsonify({"error": "Recap not found"}), 404
    return jsonify(recap)


@recap_bp.route("/api/recap/<int:recap_id>/video.mp4", methods=["GET"])
@log_web_activity
def api_recap_video(recap_id):
    if recap_handler.get_recap(recap_id) is None:
        abort(404)
    path = recap_handler.get_recap_video_path(recap_id)
    if not path.exists():
        abort(404)
    return send_file(path, mimetype="video/mp4", conditional=True)


@recap_bp.route("/api/recap/list", methods=["GET"])
@log_web_activity
def api_recap_list():
    return jsonify({"recaps": recap_handler.list_recaps()})


@recap_bp.route("/api/recap/<int:recap_id>/speakers", methods=["POST"])
@login_required
@log_web_activity
def api_recap_rename_speakers(recap_id):
    data = request.get_json(silent=True) or {}
    mapping = data.get("mapping")
    if not isinstance(mapping, dict):
        return jsonify({"error": "Body must be {'mapping': {SPEAKER_00: 'Alice', ...}}"}), 400
    if not recap_handler.update_speaker_names(recap_id, mapping):
        return jsonify({"error": "Recap not found"}), 404
    return jsonify({"success": True})


@recap_bp.route("/api/recap/<int:recap_id>", methods=["DELETE"])
@require_capability(DATA_DESTRUCTIVE)
@log_web_activity
def api_recap_delete(recap_id):
    if not recap_handler.delete_recap(recap_id):
        return jsonify({"error": "Recap not found"}), 404
    return jsonify({"success": True})


@recap_bp.route("/api/recap/languages", methods=["GET"])
@log_web_activity
def api_recap_languages():
    """Return the supported summary languages as [{code, name}, ...]."""
    langs = [{"code": code, "name": name} for code, name in recap_handler.SUPPORTED_LANGUAGES.items()]
    return jsonify({"languages": langs, "default": recap_handler.DEFAULT_LANGUAGE})


@recap_bp.route("/api/recap/<int:recap_id>/translate", methods=["POST"])
@login_required
@log_web_activity
def api_recap_translate(recap_id):
    data = request.get_json(silent=True) or {}
    language = (data.get("language") or "").strip().lower()
    if language not in recap_handler.SUPPORTED_LANGUAGES:
        return jsonify({
            "error": f"Unsupported language '{language}'. Supported: {sorted(recap_handler.SUPPORTED_LANGUAGES.keys())}"
        }), 400
    try:
        recap = recap_handler.translate_recap(recap_id, language)
    except RuntimeError as e:
        logger.warning(f"Translate failed for recap {recap_id}: {e}")
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        logger.exception(f"Translate failed for recap {recap_id}")
        return jsonify({"error": f"Translation failed: {e}"}), 500
    if recap is None:
        return jsonify({"error": "Recap not found"}), 404
    return jsonify(recap)
