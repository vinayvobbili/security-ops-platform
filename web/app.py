#!/usr/bin/python3
"""
Web App - Main entry point

This module sets up the Flask application, registers blueprints,
and handles server startup. Routes are organized into blueprints
in the web/routes/ package.
"""

# Standard library imports
import atexit
import logging
import os
import signal
import sys
import threading
from datetime import datetime
from functools import lru_cache

# Load .env file before any other imports that use environment variables
from dotenv import load_dotenv
_CURRENT_DIR = os.path.dirname(__file__)
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Load environment variables from data/transient/.env
load_dotenv(os.path.join(_PROJECT_ROOT, 'data', 'transient', '.env'))

# Third-party imports
from flask import Flask, abort, jsonify, request

# Local imports
from src.utils.logging_utils import is_scanner_request, setup_logging, get_client_ip
from web.config import (
    CONFIG,
    PUBLIC_CONFIG,
    EASTERN,
    SHOULD_START_PROXY,
    USE_DEBUG_MODE,
    PROXY_PORT,
    WEB_SERVER_PORT,
)
from web.extensions import limiter
from web.routes import register_all_blueprints
from src.components.web import proxy_server

# Configure logging
setup_logging(
    bot_name='web_server',
    log_level=logging.INFO,
    info_modules=['__main__', 'src.components.web.meaningful_metrics_handler'],
    rotate_on_startup=False
)

logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('waitress').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Log clear startup marker
logger.warning("=" * 100)
logger.warning(f"🚀 WEB SERVER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

# Initialize Flask app
app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
app.secret_key = CONFIG.flask_secret_key if hasattr(CONFIG, 'flask_secret_key') else 'your-secret-key-change-this'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB max request body (meeting recap uploads — Teams MP4s for ~2hr meetings)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Bind rate limiter to app
limiter.init_app(app)

# Store server start time
SERVER_START_TIME = datetime.now(EASTERN)
app.config['SERVER_START_TIME'] = SERVER_START_TIME

# Blocked IP ranges
blocked_ip_ranges = []


@app.context_processor
def inject_public_config():
    """Inject public config values into all templates for branding/customization."""
    return {'config': PUBLIC_CONFIG}


# --- Server detection utilities ---

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
            ipaddress.ip_network(get_client_ip()).subnet_of(ipaddress.ip_network(blocked_ip_range))
            for blocked_ip_range in blocked_ip_ranges
        ):
            abort(403)

    if is_scanner_request():
        return abort(404)


@app.before_request
def csrf_content_type_check():
    """Block cross-origin form POSTs to API routes by requiring JSON Content-Type."""
    if request.method in ('POST', 'PUT', 'DELETE') and request.path.startswith('/api/'):
        content_type = request.content_type or ''
        # Allow multipart/form-data for file upload endpoints
        if 'application/json' not in content_type and 'multipart/form-data' not in content_type:
            return jsonify({'error': 'Content-Type must be application/json'}), 415


@app.after_request
def set_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Pages that embed vendor sidecars in same-origin iframes need SAMEORIGIN
    # instead of DENY.
    if (request.path == '/ai-spm' or request.path.startswith('/ai-spm-app/')
            or request.path == '/db-security' or request.path.startswith('/db-sec-app/')
            or request.path == '/exposed-api-scanner' or request.path.startswith('/exposed-api-scanner-app/')
            or request.path == '/cyber-simulator' or request.path.startswith('/cyber-simulator-app/')
            or request.path == '/dspm' or request.path.startswith('/dspm-app/')
            or request.path == '/db-config' or request.path.startswith('/db-config-app/')):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    else:
        response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-XSS-Protection'] = '0'
    return response


@app.route('/favicon.ico')
def favicon():
    """Serve favicon from static icons folder."""
    return app.send_static_file('icons/favicon.ico')


# Register all route blueprints
register_all_blueprints(app)


# --- Server startup ---

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
            print("⏭️ Skipping the security assistant bot initialization (SKIP_POKEDEX_WARMUP=true)")
        else:
            print("🤖 Initializing the security assistant bot chat components...")
            from my_bot.core.my_model import initialize_model_and_agent
            from my_bot.core.state_manager import get_state_manager
            if initialize_model_and_agent():
                print("✅ the security assistant bot chat components initialized!")

                print("🔥 Warming up LLM (this will load the model into memory)...")
                state_manager = get_state_manager()
                if state_manager and hasattr(state_manager, 'fast_warmup') and state_manager.fast_warmup():
                    print("✅ LLM warmed up and ready! Model is now loaded in memory.")
                else:
                    print("⚠️ LLM warmup skipped or failed - model will load on first request")
            else:
                print("⚠️ the security assistant bot chat initialization failed - chat endpoint will return errors")
    except Exception as exc:
        print(f"⚠️ Failed to initialize the security assistant bot chat: {exc}")
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
            # exclude external/ so Werkzeug's reloader doesn't restart Flask
            # mid-request when the AISPM deploy portal extracts/swaps vendor code
            # under external/aispm{,_staging,_backups}/ (see web/routes/ai_spm.py).
            app.run(
                debug=True,
                host=host,
                port=WEB_SERVER_PORT,
                threaded=True,
                use_reloader=True,
                exclude_patterns=["*/external/*"],
            )
        except OSError as exc:
            _handle_port_error(exc, WEB_SERVER_PORT, debug=True)
    else:
        try:
            from waitress import serve
            print("Using Waitress WSGI server for production deployment")
            try:
                serve(app, host=host, port=port, threads=20, channel_timeout=600)
            except OSError as excep:
                _handle_port_error(excep, port, debug=False)
        except ImportError:
            print("Waitress not available, falling back to Flask dev server")
            try:
                app.run(debug=False, host=host, port=port, threaded=True, use_reloader=False)
            except OSError as ex:
                _handle_port_error(ex, port, debug=False)


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
        print(f"  1. Run with sudo: sudo python3 web/app.py")
        print(f"  2. Grant capability: sudo setcap 'cap_net_bind_service=+ep' $(which python3)")
        print(f"  3. Use a different port in .env: WEB_SERVER_PORT=8080")
        print(f"\nFalling back to port {fallback_port}...")
        print(f"{'=' * 70}\n")

        if debug:
            app.run(debug=True, host='0.0.0.0', port=fallback_port, threaded=True, use_reloader=True)
        else:
            from waitress import serve
            serve(app, host='0.0.0.0', port=fallback_port, threads=20, channel_timeout=600)

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
