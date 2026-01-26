"""Utility routes: slideshow, APT names, audio, health, countdown timer."""

import os
from datetime import datetime
from flask import Blueprint, jsonify, render_template, request, send_file, current_app

from src.utils.logging_utils import log_web_activity
from src.components.web import (
    slideshow_handler,
    apt_handler,
    audio_handler,
    health_handler,
    countdown_timer_handler,
)
from web.config import PUBLIC_CONFIG, EASTERN, WEB_SERVER_PORT, CONFIG

utilities_bp = Blueprint('utilities', __name__)


@utilities_bp.route("/")
@log_web_activity
def get_ir_dashboard_slide_show():
    """Renders the HTML template with the ordered list of image files."""
    image_files = slideshow_handler.get_image_files(current_app.static_folder, EASTERN)
    return render_template("slide-show.html", image_files=image_files, show_burger=True)


@utilities_bp.route("/<path:filename>.pac")
def proxy_pac_file(filename):
    """Handle PAC file requests to reduce log clutter."""
    pac_content = """function FindProxyForURL(url, host) {
    return "DIRECT";
}"""
    return pac_content, 200, {'Content-Type': 'application/x-ns-proxy-autoconfig'}


@utilities_bp.route('/favicon.ico')
def favicon():
    """Serve the favicon icon."""
    return current_app.send_static_file('icons/company-fav-icon.png')


@utilities_bp.route("/api/apt-names", methods=["GET"])
@log_web_activity
def api_apt_names():
    """API endpoint to get APT workbook summary (region sheets only)."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    info = apt_handler.get_apt_workbook_info(base_dir)
    return jsonify(info)


@utilities_bp.route("/api/apt-other-names", methods=["GET"])
@log_web_activity
def api_apt_other_names():
    """API endpoint to get other names for a given APT common name."""
    common_name = request.args.get("common_name")
    current_app.logger.info(f"[APT API] Received common_name: '{common_name}' from request")

    if not common_name:
        return jsonify({"error": "Missing required parameter: common_name"}), 400

    should_include_metadata = request.args.get("should_include_metadata")
    if should_include_metadata is not None:
        should_include_metadata = should_include_metadata.lower() == "true"
    else:
        should_include_metadata = False

    response_format = request.args.get("response_format") or request.args.get("format", "html")
    response_format = response_format.lower()

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results = apt_handler.get_apt_other_names(common_name, base_dir, should_include_metadata)

    if response_format == "json":
        return jsonify(results)
    else:
        return render_template(
            "apt_other_names_results.html",
            common_name=common_name,
            results=results,
            should_include_metadata=should_include_metadata
        )


@utilities_bp.route("/apt-other-names-search", methods=["GET"])
@log_web_activity
def apt_other_names_search():
    """Render the APT Other Names search form page."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    try:
        apt_names = apt_handler.get_all_apt_names(base_dir)
        current_app.logger.info(f"[APT Search] Loaded {len(apt_names)} APT names for dropdown")
    except Exception as exc:
        current_app.logger.error(f"[APT Search] Error loading APT names: {str(exc)}")
        apt_names = []

    return render_template("apt_other_names_search.html", apt_names=apt_names)


@utilities_bp.route('/api/random-audio', methods=['GET'])
def random_audio():
    """Return a random mp3 filename from the static/audio directory."""
    audio_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'audio')
    filename = audio_handler.get_random_audio_file(audio_dir)

    if not filename:
        return jsonify({'error': 'No audio files found'}), 404

    return jsonify({'filename': filename})


@utilities_bp.route("/healthz")
def healthz():
    """Lightweight health probe endpoint for load balancers / monitoring."""
    try:
        # Get server start time from app config
        server_start_time = current_app.config.get('SERVER_START_TIME', datetime.now(EASTERN))
        health = health_handler.get_server_health(
            EASTERN,
            server_start_time,
            getattr(CONFIG, 'team_name', 'unknown'),
            WEB_SERVER_PORT,
            request.environ
        )
        return jsonify(health), 200
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


@utilities_bp.route("/api/config")
def api_public_config():
    """Return public config values for JavaScript clients."""
    return jsonify(PUBLIC_CONFIG)


@utilities_bp.route('/api/countdown-timer')
def countdown_timer():
    """Generate an animated countdown timer GIF for emails."""
    try:
        deadline_str = request.args.get('deadline')
        if not deadline_str:
            return jsonify({'error': 'deadline parameter required'}), 400

        img_buffer = countdown_timer_handler.generate_countdown_timer(deadline_str)
        return send_file(img_buffer, mimetype='image/gif', as_attachment=False)

    except ValueError as val_err:
        current_app.logger.error(f"Invalid deadline format: {val_err}", exc_info=True)
        return jsonify({'error': str(val_err)}), 400
    except Exception as exc:
        current_app.logger.error(f"Error generating countdown timer: {exc}", exc_info=True)
        error_buffer = countdown_timer_handler.generate_error_timer()
        return send_file(error_buffer, mimetype='image/gif', as_attachment=False)
