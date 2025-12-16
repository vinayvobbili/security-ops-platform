#!/usr/bin/python3

# Standard library imports
import json
import logging
import os
import sys
import threading
from datetime import date, datetime, timedelta

_CURRENT_DIR = os.path.dirname(__file__)
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Third-party imports
import pytz
from flask import Flask, abort, jsonify, render_template, request, session, send_file

# Local imports with graceful degradation
try:
    from my_bot.core.my_model import ask, ask_stream
    from my_bot.core.state_manager import get_state_manager
    POKEDEX_AVAILABLE = True
except Exception as e:
    print(f"⚠️ Pokedex components unavailable: {e}. Continuing with limited functionality.")
    POKEDEX_AVAILABLE = False

    def ask(*_args, **_kwargs):
        return "Model not available in this environment"

    def ask_stream(*_args, **_kwargs):
        yield "Model not available in this environment"

    def get_state_manager():
        return None

from my_config import get_config
from services import xsoar
from services.xsoar import XsoarEnvironment
from src.utils.logging_utils import is_scanner_request, log_web_activity, setup_logging

# Import all component handlers
from src.components.web import (
    slideshow_handler,
    msoc_form_handler,
    speak_up_handler,
    xsoar_import_handler,
    approved_testing_handler,
    travel_handler,
    apt_handler,
    audio_handler,
    pokedex_handler,
    xsoar_dashboard_handler,
    shift_performance_handler,
    meaningful_metrics_handler,
    health_handler,
    toodles_handler,
    employee_reach_out_handler,
    countdown_timer_handler,
    proxy_server,
)
from src.components.web.async_export_manager import get_export_manager

CONFIG = get_config()

# Server configuration constants
SHOULD_START_PROXY = True
USE_DEBUG_MODE = CONFIG.web_server_debug_mode_on
PROXY_PORT = 8081
WEB_SERVER_PORT = CONFIG.web_server_port
COMPANY_EMAIL_DOMAIN = '@' + CONFIG.my_web_domain

# Public config values that can be exposed to templates and JavaScript
# These are non-sensitive values that help with branding/customization
PUBLIC_CONFIG = {
    'company_name': CONFIG.company_name,
    'team_name': CONFIG.team_name,
    'email_domain': CONFIG.my_web_domain,
    'security_email': f"security@{CONFIG.my_web_domain}",
    'logs_viewer_url': CONFIG.logs_viewer_url,
}

# Configure logging
setup_logging(
    bot_name='web_server',
    log_level=logging.INFO,
    info_modules=['__main__', 'src.components.web.meaningful_metrics_handler'],
    rotate_on_startup=False  # Keep logs continuous, rely on RotatingFileHandler for size-based rotation
)

logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('waitress').setLevel(logging.WARNING)

# Initialize logger before startup marker
logger = logging.getLogger(__name__)

# Log clear startup marker for visual separation in logs
import signal
import atexit
logger.warning("=" * 100)
logger.warning(f"🚀 WEB SERVER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
app.secret_key = CONFIG.flask_secret_key if hasattr(CONFIG, 'flask_secret_key') else 'your-secret-key-change-this'
eastern = pytz.timezone('US/Eastern')


@app.context_processor
def inject_public_config():
    """Inject public config values into all templates for branding/customization."""
    return {'config': PUBLIC_CONFIG}

# Store server start time
SERVER_START_TIME = datetime.now(eastern)

blocked_ip_ranges = []

# Initialize XSOAR handlers
prod_list_handler = xsoar.ListHandler(XsoarEnvironment.PROD)
prod_ticket_handler = xsoar.TicketHandler(XsoarEnvironment.PROD)
dev_ticket_handler = xsoar.TicketHandler(XsoarEnvironment.DEV)

logger = logging.getLogger(__name__)

# --- Server detection utilities ---
from functools import lru_cache

_server_detection_ran = False


@lru_cache(maxsize=1)
def _runtime_server_info_sample() -> dict:
    """Cached placeholder before first request."""
    return {
        'server_type': 'unknown_startup',
        'server_software': 'unknown',
        'debug_mode': app.debug,
        'pid': os.getpid()
    }


def detect_server_type(server_software: str) -> str:
    server_software_lower = (server_software or '').lower()
    if 'waitress' in server_software_lower:
        return 'waitress'
    if 'gunicorn' in server_software_lower:
        return 'gunicorn'
    if 'uwsgi' in server_software_lower:
        return 'uwsgi'
    if 'werkzeug' in server_software_lower:
        return 'flask-dev'
    return 'unknown'


def _log_real_server():
    """Log WSGI server details (invoked once on first real request)."""
    try:
        env = request.environ
        server_software = env.get('SERVER_SOFTWARE', 'unknown')
        server_type = detect_server_type(server_software)
        _runtime_server_info_sample.cache_clear()

        @lru_cache(maxsize=1)
        def _runtime_server_info_sample_override():
            return {
                'server_type': server_type,
                'server_software': server_software,
                'debug_mode': app.debug,
                'pid': os.getpid()
            }

        globals()['_runtime_server_info_sample'] = _runtime_server_info_sample_override
        print(f"[ServerDetect] Running under {server_type} ({server_software}) debug={app.debug} pid={os.getpid()}")
    except Exception as exc:
        print(f"[ServerDetect] Failed to detect server: {exc}")


@app.before_request
def _maybe_server_detect():
    global _server_detection_ran
    if not _server_detection_ran:
        _log_real_server()
        _server_detection_ran = True


@app.before_request
def block_ip():
    """Block requests from configured IP ranges and scanner probes."""
    if blocked_ip_ranges:
        import ipaddress
        if any(
            ipaddress.ip_network(request.remote_addr).subnet_of(ipaddress.ip_network(blocked_ip_range))
            for blocked_ip_range in blocked_ip_ranges
        ):
            abort(403)

    if is_scanner_request():
        return abort(404)


# --- Routes ---

@app.route("/")
@log_web_activity
def get_ir_dashboard_slide_show():
    """Renders the HTML template with the ordered list of image files."""
    image_files = slideshow_handler.get_image_files(app.static_folder, eastern)
    return render_template("slide-show.html", image_files=image_files, show_burger=True)


@app.route("/<path:filename>.pac")
def proxy_pac_file(filename):
    """Handle PAC file requests to reduce log clutter."""
    pac_content = """function FindProxyForURL(url, host) {
    return "DIRECT";
}"""
    return pac_content, 200, {'Content-Type': 'application/x-ns-proxy-autoconfig'}


@app.route("/msoc-form")
@log_web_activity
def display_msoc_form():
    """Displays the MSOC form."""
    return render_template("msoc_form.html", show_burger=False)


@app.route("/submit-msoc-form", methods=['POST'])
@log_web_activity
def handle_msoc_form_submission():
    """Handles MSOC form submissions and processes the data."""
    result = msoc_form_handler.handle_msoc_form_submission(
        request.form,
        prod_ticket_handler,
        CONFIG.xsoar_dev_ui_base_url
    )
    return jsonify(result)


@app.route("/speak-up-form")
@log_web_activity
def display_speak_up_form():
    """Displays the Speak Up form."""
    return render_template("speak_up_form.html")


@app.route("/submit-speak-up-form", methods=['POST'])
@log_web_activity
def handle_speak_up_form_submission():
    """Handles the Speak Up form submissions and processes the data."""
    result = speak_up_handler.handle_speak_up_form_submission(
        request.form,
        prod_ticket_handler,
        CONFIG.xsoar_dev_ui_base_url,
        CONFIG.team_name
    )
    return jsonify(result)


@app.route('/xsoar-ticket-import-form', methods=['GET'])
@log_web_activity
def xsoar_ticket_import_form():
    return render_template('xsoar-ticket-import-form.html')


@app.route("/import-xsoar-ticket", methods=['POST'])
@log_web_activity
def import_xsoar_ticket():
    source_ticket_number = request.form.get('source_ticket_number')
    file_data = request.files.get('file')
    destination_ticket_number, destination_ticket_link = xsoar_import_handler.import_ticket(
        source_ticket_number,
        file_data,
        dev_ticket_handler
    )
    return jsonify({
        'source_ticket_number': source_ticket_number,
        'destination_ticket_number': destination_ticket_number,
        'destination_ticket_link': destination_ticket_link
    })


@app.route("/get-approved-testing-entries", methods=['GET'])
@log_web_activity
def get_approved_testing_entries():
    """Fetches approved testing records and displays them in separate HTML tables."""
    records = approved_testing_handler.get_approved_testing_entries(prod_list_handler, CONFIG.team_name)

    if not records:
        return "<h2>No Approved Testing Records Found</h2>"

    return render_template(
        'approved_testing.html',
        ENDPOINTS=records.get("ENDPOINTS", []),
        USERNAMES=records.get("USERNAMES", []),
        IP_ADDRESSES=records.get("IP_ADDRESSES", []),
        CIDR_BLOCKS=records.get("CIDR_BLOCKS", [])
    )


@app.route("/get-current-upcoming-travel-records", methods=['GET'])
@log_web_activity
def get_upcoming_travel():
    """Fetches upcoming travel records and displays them."""
    records = travel_handler.get_current_upcoming_travel_records(prod_list_handler)
    return render_template('upcoming_travel.html', travel_records=records)


@app.route("/travel-form")
@log_web_activity
def display_travel_form():
    """Displays the Upcoming Travel Notification form."""
    today = date.today().isoformat()
    return render_template("upcoming_travel_notification_form.html", today=today)


@app.route("/submit-travel-form", methods=['POST'])
@log_web_activity
def handle_travel_form_submission():
    """Handles the Upcoming Travel Notification form submissions and processes the data."""
    response = travel_handler.submit_travel_form(
        request.form,
        prod_list_handler,
        eastern,
        request.remote_addr
    )
    return jsonify({'status': 'success', 'response': response})


@app.route("/red-team-testing-form")
@log_web_activity
def display_red_team_testing_form():
    """Displays the Red Team Testing form."""
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    return render_template("red_team_testing_form.html", tomorrow=tomorrow)


@app.route("/submit-red-team-testing-form", methods=['POST'])
@log_web_activity
def handle_red_team_testing_form_submission():
    """Handles the Red Team Testing form submissions and processes the data."""
    try:
        approved_testing_handler.submit_red_team_testing_form(
            request.form,
            prod_list_handler,
            CONFIG.team_name,
            COMPANY_EMAIL_DOMAIN,
            eastern,
            request.remote_addr
        )
        return jsonify({'status': 'success'})
    except ValueError as val_err:
        return jsonify({'status': 'error', 'message': str(val_err)}), 400


@app.route('/favicon.ico')
def favicon():
    """Serve the favicon icon."""
    return app.send_static_file('icons/metlife-fav-icon.png')


@app.route("/api/apt-names", methods=["GET"])
@log_web_activity
def api_apt_names():
    """API endpoint to get APT workbook summary (region sheets only)."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    info = apt_handler.get_apt_workbook_info(base_dir)
    return jsonify(info)


@app.route("/api/apt-other-names", methods=["GET"])
@log_web_activity
def api_apt_other_names():
    """API endpoint to get other names for a given APT common name."""
    common_name = request.args.get("common_name")
    app.logger.info(f"[APT API] Received common_name: '{common_name}' from request")

    if not common_name:
        return jsonify({"error": "Missing required parameter: common_name"}), 400

    should_include_metadata = request.args.get("should_include_metadata")
    if should_include_metadata is not None:
        should_include_metadata = should_include_metadata.lower() == "true"
    else:
        should_include_metadata = False

    response_format = request.args.get("response_format") or request.args.get("format", "html")
    response_format = response_format.lower()

    base_dir = os.path.dirname(os.path.abspath(__file__))
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


@app.route("/apt-other-names-search", methods=["GET"])
@log_web_activity
def apt_other_names_search():
    """Render the APT Other Names search form page."""
    base_dir = os.path.dirname(os.path.abspath(__file__))

    try:
        apt_names = apt_handler.get_all_apt_names(base_dir)
        app.logger.info(f"[APT Search] Loaded {len(apt_names)} APT names for dropdown")
    except Exception as exc:
        app.logger.error(f"[APT Search] Error loading APT names: {str(exc)}")
        apt_names = []

    return render_template("apt_other_names_search.html", apt_names=apt_names)


@app.route('/api/random-audio', methods=['GET'])
def random_audio():
    """Return a random mp3 filename from the static/audio directory."""
    audio_dir = os.path.join(os.path.dirname(__file__), 'static', 'audio')
    filename = audio_handler.get_random_audio_file(audio_dir)

    if not filename:
        return jsonify({'error': 'No audio files found'}), 404

    return jsonify({'filename': filename})


@app.route('/pokedex')
@log_web_activity
def pokedex_chat():
    """Pokedex AI chat interface"""
    return render_template('pokedex_chat.html')


@app.route('/api/pokedex-status')
def api_pokedex_status():
    """Health check endpoint for Pokédex chat availability"""
    status = pokedex_handler.check_pokedex_status(get_state_manager)
    return jsonify(status)


@app.route('/api/pokedex-chat', methods=['POST'])
@log_web_activity
def api_pokedex_chat():
    """API endpoint for Pokedex chat messages"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        response_text = pokedex_handler.handle_pokedex_chat(
            user_message,
            session_id,
            request.remote_addr,
            ask
        )

        return jsonify({'success': True, 'response': response_text})

    except Exception as exc:
        logger.error(f"Error in Pokedex chat API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to get response from AI. Please try again.'}), 500


@app.route('/api/pokedex-chat-stream', methods=['POST'])
@log_web_activity
def api_pokedex_chat_stream():
    """Streaming API endpoint for Pokédex chat messages using Server-Sent Events"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        def generate():
            """Generator function for Server-Sent Events"""
            try:
                for token in pokedex_handler.handle_pokedex_chat_stream(
                    user_message,
                    session_id,
                    request.remote_addr,
                    ask_stream,
                    get_state_manager
                ):
                    yield f"data: {json.dumps({'token': token})}\n\n"

                yield f"data: {json.dumps({'done': True})}\n\n"

            except Exception as stream_err:
                logger.error(f"Error in streaming response: {stream_err}", exc_info=True)
                yield f"data: {json.dumps({'error': 'Streaming error occurred'})}\n\n"

        return app.response_class(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )

    except Exception as exc:
        logger.error(f"Error in Pokedex streaming chat API: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An unexpected error occurred. Please try again.'}), 500


@app.route('/xsoar')
@log_web_activity
def xsoar_dashboard():
    """XSOAR incident dashboard"""
    return render_template('xsoar_dashboard.html')


@app.route('/api/xsoar/incidents')
@log_web_activity
def api_xsoar_incidents():
    """API to get XSOAR incidents with search and pagination"""
    query = request.args.get('query', '')
    period = request.args.get('period')
    size = int(request.args.get('size', 50))

    try:
        incidents = xsoar_dashboard_handler.get_xsoar_incidents(prod_ticket_handler, query, period, size)
        return jsonify({'success': True, 'incidents': incidents})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/xsoar/incident/<incident_id>')
@log_web_activity
def api_xsoar_incident_detail(incident_id):
    """API to get XSOAR incident details"""
    try:
        incident, entries = xsoar_dashboard_handler.get_xsoar_incident_detail(prod_ticket_handler, incident_id)
        return jsonify({'success': True, 'incident': incident, 'entries': entries})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/xsoar/incident/<incident_id>')
@log_web_activity
def xsoar_incident_detail(incident_id):
    """XSOAR incident detail view"""
    try:
        incident, entries = xsoar_dashboard_handler.get_xsoar_incident_detail(prod_ticket_handler, incident_id)
        return render_template('xsoar_incident_detail.html', incident=incident, entries=entries)
    except Exception as exc:
        return f"Error loading incident {incident_id}: {str(exc)}", 500


@app.route('/api/xsoar/incident/<incident_id>/entries')
@log_web_activity
def api_xsoar_incident_entries(incident_id):
    """API to get incident entries/comments"""
    try:
        entries = xsoar_dashboard_handler.get_xsoar_incident_entries(prod_ticket_handler, incident_id)
        return jsonify({'success': True, 'entries': entries})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/xsoar/incident/<incident_id>/link', methods=['POST'])
@log_web_activity
def api_xsoar_link_incident(incident_id):
    """API to link incidents"""
    link_incident_id = request.json.get('link_incident_id')
    try:
        result = xsoar_dashboard_handler.link_xsoar_incidents(prod_ticket_handler, incident_id, link_incident_id)
        return jsonify({'success': True, 'result': result})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/xsoar/incident/<incident_id>/participant', methods=['POST'])
@log_web_activity
def api_xsoar_add_participant(incident_id):
    """API to add participant to incident"""
    email = request.json.get('email')
    try:
        result = xsoar_dashboard_handler.add_participant_to_incident(prod_ticket_handler, incident_id, email)
        return jsonify({'success': True, 'result': result})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/shift-performance')
@log_web_activity
def shift_performance_dashboard():
    """Display shift performance page - loads instantly with empty structure"""
    return render_template(
        'shift_performance.html',
        xsoar_prod_ui_base=getattr(CONFIG, 'xsoar_prod_ui_base_url', 'https://msoar.crtx.us.paloaltonetworks.com')
    )


@app.route('/api/shift-list')
@log_web_activity
def get_shift_list():
    """Single source of truth for shift performance data."""
    try:
        shift_data = shift_performance_handler.get_shift_list_data(prod_ticket_handler, eastern)
        return jsonify({'success': True, 'data': shift_data})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/clear-cache', methods=['POST'])
@log_web_activity
def clear_shift_cache():
    """No-op endpoint for compatibility with frontend cache clearing."""
    return jsonify({'success': True, 'message': 'No backend cache (frontend-only caching)'})


@app.route('/meaningful-metrics')
@log_web_activity
def meaningful_metrics():
    """Meaningful Metrics Dashboard"""
    return render_template('meaningful_metrics.html')


@app.route('/api/meaningful-metrics/data')
@log_web_activity
def api_meaningful_metrics_data():
    """API to get cached security incident data for dashboard."""
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        result = meaningful_metrics_handler.get_meaningful_metrics_data(base_dir, eastern)
        return jsonify(result)
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Cache file not found'}), 404
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/meaningful-metrics/export', methods=['POST'])
@log_web_activity
def api_meaningful_metrics_export():
    """Server-side Excel export with professional formatting."""
    try:
        data = request.get_json()
        if not data or 'filters' not in data:
            return jsonify({'success': False, 'error': 'No filters provided'}), 400

        base_dir = os.path.dirname(os.path.abspath(__file__))
        temp_path = meaningful_metrics_handler.export_meaningful_metrics(
            base_dir,
            eastern,
            data['filters'],
            data.get('visible_columns', []),
            data.get('column_labels', {}),
            data.get('include_notes', False)
        )

        return send_file(
            temp_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='security_incidents.xlsx'
        )

    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Cache file not found'}), 404
    except ValueError as val_err:
        return jsonify({'success': False, 'error': str(val_err)}), 400
    except Exception as exc:
        logger.error(f"Error exporting meaningful metrics: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/meaningful-metrics/export-async/start', methods=['POST'])
@log_web_activity
def api_meaningful_metrics_export_async_start():
    """Start an async export job and return job ID immediately."""
    try:
        data = request.get_json()
        if not data or 'filters' not in data:
            return jsonify({'success': False, 'error': 'No filters provided'}), 400

        # Create export job
        export_manager = get_export_manager()
        job_id = export_manager.create_job()

        # Start export in background thread
        base_dir = os.path.dirname(os.path.abspath(__file__))

        def export_wrapper(progress_callback):
            """Wrapper to call export_meaningful_metrics with progress."""
            return meaningful_metrics_handler.export_meaningful_metrics_async(
                base_dir,
                eastern,
                data['filters'],
                data.get('visible_columns', []),
                data.get('column_labels', {}),
                data.get('include_notes', False),
                progress_callback=progress_callback
            )

        export_manager.start_export_thread(
            job_id,
            export_wrapper
        )

        return jsonify({
            'success': True,
            'job_id': job_id,
            'status': 'queued'
        })

    except Exception as exc:
        logger.error(f"Error starting async export: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/meaningful-metrics/export-async/status/<job_id>', methods=['GET'])
@log_web_activity
def api_meaningful_metrics_export_async_status(job_id):
    """Get status of an async export job."""
    try:
        export_manager = get_export_manager()
        job = export_manager.get_job(job_id)

        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404

        return jsonify({
            'success': True,
            **job.to_dict()
        })

    except Exception as exc:
        logger.error(f"Error getting export status: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/meaningful-metrics/export-async/download/<job_id>', methods=['GET'])
@log_web_activity
def api_meaningful_metrics_export_async_download(job_id):
    """Download completed export file."""
    try:
        export_manager = get_export_manager()
        job = export_manager.get_job(job_id)

        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404

        if job.status != 'complete':
            return jsonify({'success': False, 'error': f'Job status is {job.status}, not complete'}), 400

        if not job.file_path or not os.path.exists(job.file_path):
            return jsonify({'success': False, 'error': 'Export file not found'}), 404

        return send_file(
            job.file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='security_incidents.xlsx'
        )

    except Exception as exc:
        logger.error(f"Error downloading export: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route("/healthz")
def healthz():
    """Lightweight health probe endpoint for load balancers / monitoring."""
    try:
        health = health_handler.get_server_health(
            eastern,
            SERVER_START_TIME,
            getattr(CONFIG, 'team_name', 'unknown'),
            WEB_SERVER_PORT,
            request.environ
        )
        return jsonify(health), 200
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/api/config")
def api_public_config():
    """Return public config values for JavaScript clients."""
    return jsonify(PUBLIC_CONFIG)


@app.route('/toodles')
@log_web_activity
def toodles_chat():
    """Toodles chat interface - password protected"""
    return render_template('toodles_chat.html')


@app.route('/api/toodles/login', methods=['POST'])
def api_toodles_login():
    """API endpoint for Toodles authentication"""
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        email = data.get('email', '').strip()

        success, error = toodles_handler.authenticate_toodles(password, CONFIG.toodles_password)

        if success:
            session['toodles_authenticated'] = True
            session['toodles_user_email'] = email
            session.permanent = True
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            return jsonify({'success': False, 'error': error}), 401

    except Exception as exc:
        logger.error(f"Error in Toodles login: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/toodles/logout', methods=['POST'])
def api_toodles_logout():
    """API endpoint to logout from Toodles"""
    session.pop('toodles_authenticated', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app.route('/api/toodles/create-x-ticket', methods=['POST'])
@log_web_activity
def api_create_x_ticket():
    """API endpoint to create X ticket"""
    try:
        data = request.get_json()
        title = data.get('title', '').strip()
        details = data.get('details', '').strip()
        detection_source = data.get('detection_source', '').strip()
        user_email = data.get('user_email', '').strip()

        if not title or not details or not detection_source:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        message = toodles_handler.create_x_ticket(
            title,
            details,
            detection_source,
            user_email,
            request.remote_addr,
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating X ticket: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/toodles/approved-testing', methods=['POST'])
@log_web_activity
def api_approved_testing():
    """API endpoint to add approved testing entry"""
    try:
        data = request.get_json()

        try:
            message = approved_testing_handler.submit_toodles_approved_testing(
                data,
                prod_list_handler,
                CONFIG.team_name,
                eastern,
                request.remote_addr
            )
            return jsonify({'success': True, 'message': message})

        except ValueError as val_err:
            return jsonify({'success': False, 'error': str(val_err)}), 400

    except Exception as exc:
        logger.error(f"Error adding approved testing: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/toodles/ioc-hunt', methods=['POST'])
@log_web_activity
def api_ioc_hunt():
    """API endpoint to create IOC hunt"""
    try:
        data = request.get_json()
        ioc_title = data.get('ioc_title', '').strip()
        iocs = data.get('iocs', '').strip()
        user_email = data.get('user_email', '').strip()

        if not ioc_title or not iocs:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        message = toodles_handler.create_ioc_hunt(
            ioc_title,
            iocs,
            user_email,
            request.remote_addr,
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating IOC hunt: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/toodles/threat-hunt', methods=['POST'])
@log_web_activity
def api_threat_hunt():
    """API endpoint to create threat hunt"""
    try:
        data = request.get_json()
        threat_title = data.get('threat_title', '').strip()
        threat_description = data.get('threat_description', '').strip()
        user_email = data.get('user_email', '').strip()

        if not threat_title or not threat_description:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        message = toodles_handler.create_threat_hunt(
            threat_title,
            threat_description,
            user_email,
            request.remote_addr,
            prod_ticket_handler,
            CONFIG.xsoar_prod_ui_base_url
        )

        return jsonify({'success': True, 'message': message})

    except Exception as exc:
        logger.error(f"Error creating threat hunt: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/toodles/oncall', methods=['GET'])
@log_web_activity
def api_oncall():
    """API endpoint to get on-call information"""
    try:
        on_call_person = toodles_handler.get_oncall_info()
        return jsonify({'success': True, 'data': on_call_person})

    except Exception as exc:
        logger.error(f"Error getting on-call info: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/employee-reach-out')
@log_web_activity
def employee_reach_out_form():
    """Display employee reach out form"""
    ticket_id = request.args.get('case_id', '')
    task_id = employee_reach_out_handler.get_employee_reach_out_task_info(ticket_id, dev_ticket_handler)

    if task_id:
        return render_template('employee_reach_out_form.html', ticket_id=ticket_id)
    else:
        return render_template('employee_reach_out_already_completed.html')


@app.route('/submit-employee-response', methods=['POST'])
@log_web_activity
def submit_employee_response():
    """Handle employee reach out form submission"""
    try:
        data = request.form.to_dict()
        recognized = data.get('recognized')
        ticket_id = data.get('ticket_id', '')
        comments = data.get('comments', '').strip()
        file_data = request.files.get('file')

        if not ticket_id:
            return jsonify({
                'status': 'success',
                'message': 'Thank you for your response.'
            })

        success, message = employee_reach_out_handler.submit_employee_response(
            recognized,
            ticket_id,
            comments,
            file_data,
            dev_ticket_handler
        )

        if success:
            return jsonify({'status': 'success', 'message': message})
        else:
            return jsonify({'status': 'error', 'error': message}), 500

    except Exception as exc:
        logger.error(f"Error submitting employee reach out: {exc}")
        return jsonify({'status': 'error', 'error': str(exc)}), 500


@app.route('/api/countdown-timer')
def countdown_timer():
    """Generate an animated countdown timer GIF for emails."""
    try:
        deadline_str = request.args.get('deadline')
        if not deadline_str:
            return jsonify({'error': 'deadline parameter required'}), 400

        img_buffer = countdown_timer_handler.generate_countdown_timer(deadline_str)
        return send_file(img_buffer, mimetype='image/gif', as_attachment=False)

    except ValueError as val_err:
        logger.error(f"Invalid deadline format: {val_err}", exc_info=True)
        return jsonify({'error': str(val_err)}), 400
    except Exception as exc:
        logger.error(f"Error generating countdown timer: {exc}", exc_info=True)
        error_buffer = countdown_timer_handler.generate_error_timer()
        return send_file(error_buffer, mimetype='image/gif', as_attachment=False)


def _shutdown_handler(signum=None, frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 WEB SERVER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """Entry point for launching the web server."""

    # Register shutdown handlers for graceful logging
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Initialize Pokédex bot components
    try:
        if os.environ.get('SKIP_POKEDEX_WARMUP', '').lower() == 'true':
            print("⏭️ Skipping Pokedex initialization (SKIP_POKEDEX_WARMUP=true)")
        else:
            print("🤖 Initializing Pokedex chat components...")
            from my_bot.core.my_model import initialize_model_and_agent
            if initialize_model_and_agent():
                print("✅ Pokedex chat components initialized!")

                print("🔥 Warming up LLM (this will load the model into memory)...")
                state_manager = get_state_manager()
                if state_manager and hasattr(state_manager, 'fast_warmup') and state_manager.fast_warmup():
                    print("✅ LLM warmed up and ready! Model is now loaded in memory.")
                else:
                    print("⚠️ LLM warmup skipped or failed - model will load on first request")
            else:
                print("⚠️ Pokedex chat initialization failed - chat endpoint will return errors")
    except Exception as exc:
        print(f"⚠️ Failed to initialize Pokedex chat: {exc}")
        print("   Chat endpoint will be available but may return errors")

    charts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static/charts'))
    app.config['CHARTS_DIR'] = charts_dir

    host = '0.0.0.0'
    port = WEB_SERVER_PORT

    # Start proxy server if enabled
    if SHOULD_START_PROXY and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        proxy_thread = threading.Thread(target=proxy_server.start_proxy_server, args=(PROXY_PORT,), daemon=True)
        proxy_thread.start()
        print(f"High-performance proxy server thread started on port {PROXY_PORT}")
    elif not SHOULD_START_PROXY:
        print("Proxy server disabled (pass --proxy to enable)")

    print(f"Attempting to start web server on http://{host}:{WEB_SERVER_PORT}")

    if USE_DEBUG_MODE:
        print("Using Flask dev server with auto-reload (debug mode)")
        try:
            app.run(debug=True, host=host, port=WEB_SERVER_PORT, threaded=True, use_reloader=True)
        except OSError as exc:
            _handle_port_error(exc, WEB_SERVER_PORT, debug=True)
    else:
        try:
            from waitress import serve
            print("Using Waitress WSGI server for production deployment")
            try:
                serve(app, host=host, port=port, threads=20, channel_timeout=120)
            except OSError as excep:
                _handle_port_error(excep, port, debug=False)
        except ImportError:
            print("Waitress not available, falling back to Flask dev server")
            try:
                app.run(debug=True, host=host, port=port, threaded=True, use_reloader=True)
            except OSError as ex:
                _handle_port_error(ex, port, debug=True)


def _handle_port_error(exc, port, debug=False):
    """Handle port-related errors with helpful messages."""
    if port < 1024 and exc.errno == 13:
        fallback_port = 8080
        print(f"\n{'=' * 70}")
        print(f"❌ ERROR: Port {port} is LOCKED/UNAVAILABLE")
        print(f"{'=' * 70}")
        print(f"Port {port} requires elevated privileges (sudo/root).")
        print(f"This is typically because ports below 1024 are privileged ports.")
        print(f"\nTo fix this:")
        print(f"  1. Run with sudo: sudo python3 web/web_server.py")
        print(f"  2. Grant capability: sudo setcap 'cap_net_bind_service=+ep' $(which python3)")
        print(f"  3. Use a different port in .env: WEB_SERVER_PORT=8080")
        print(f"\nFalling back to port {fallback_port}...")
        print(f"{'=' * 70}\n")

        if debug:
            app.run(debug=True, host='0.0.0.0', port=fallback_port, threaded=True, use_reloader=True)
        else:
            from waitress import serve
            serve(app, host='0.0.0.0', port=fallback_port, threads=20, channel_timeout=120)

    elif exc.errno == 48 or exc.errno == 98:
        print(f"\n{'=' * 70}")
        print(f"❌ ERROR: Port {port} is LOCKED/IN USE")
        print(f"{'=' * 70}")
        print(f"Port {port} is already being used by another process.")
        print(f"\nTo fix this:")
        print(f"  1. Find the process: sudo lsof -i :{port}")
        print(f"  2. Stop the process using the port")
        print(f"  3. Or use a different port in .env: WEB_SERVER_PORT=8080")
        print(f"{'=' * 70}\n")
        raise
    else:
        raise


if __name__ == "__main__":
    main()
