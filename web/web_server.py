#!/usr/bin/python3
"""
Web Server - Main entry point

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

_CURRENT_DIR = os.path.dirname(__file__)
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Third-party imports
from flask import Flask, abort, request

# Local imports
from src.utils.logging_utils import is_scanner_request, setup_logging
from web.config import (
    CONFIG,
    PUBLIC_CONFIG,
    EASTERN,
    SHOULD_START_PROXY,
    USE_DEBUG_MODE,
    PROXY_PORT,
    WEB_SERVER_PORT,
)
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
            ipaddress.ip_network(request.remote_addr).subnet_of(ipaddress.ip_network(blocked_ip_range))
            for blocked_ip_range in blocked_ip_ranges
        ):
            abort(403)

    if is_scanner_request():
        return abort(404)


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
            print("⏭️ Skipping Pokedex initialization (SKIP_POKEDEX_WARMUP=true)")
        else:
            print("🤖 Initializing Pokedex chat components...")
            from my_bot.core.my_model import initialize_model_and_agent
            from my_bot.core.state_manager import get_state_manager
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
