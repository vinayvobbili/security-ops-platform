#!/usr/bin/env python3
"""
Bot Status API - REST API for monitoring and controlling IR bots
Provides endpoints for checking status and controlling bots (start/stop/restart)
"""

import os
import subprocess
import time
import csv
import threading
from functools import wraps
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

# Load .env from data/transient
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(_ROOT, 'data', 'transient', '.env'))

# Also load encrypted secrets so probe_auth_env entries (e.g. EMBEDS_API_KEY) resolve
try:
    import sys as _sys
    if _ROOT not in _sys.path:
        _sys.path.insert(0, _ROOT)
    from src.utils.env_encryption import load_encrypted_env
    load_encrypted_env(encrypted_path=os.path.join(_ROOT, 'data', 'transient', '.secrets.age'))
except Exception as _e:
    print(f"[bot_status_api] could not load encrypted secrets: {_e}")

app = Flask(__name__)
CORS(app)  # Allow CORS for the frontend

# Configuration
AUTH_USERNAME = os.environ['LOG_VIEWER_USERNAME']
AUTH_PASSWORD = os.environ['LOG_VIEWER_PASSWORD']
PROJECT_ROOT = os.environ.get('PROJECT_ROOT', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUDIT_LOG_FILE = os.path.join(PROJECT_ROOT, 'data/transient/logs/log_viewer_audit_log.csv')

# CPU utilization tracking (delta between /proc/stat reads)
_cpu_lock = threading.Lock()
_prev_cpu_idle = 0
_prev_cpu_total = 0
_prev_cpu_initialized = False


def _get_cpu_utilization():
    """Calculate real-time CPU utilization from /proc/stat delta between polls."""
    global _prev_cpu_idle, _prev_cpu_total, _prev_cpu_initialized

    try:
        with open('/proc/stat') as f:
            parts = f.readline().split()
        # fields: cpu user nice system idle iowait irq softirq steal
        idle = int(parts[4]) + int(parts[5])  # idle + iowait
        total = sum(int(p) for p in parts[1:])

        with _cpu_lock:
            if _prev_cpu_initialized:
                idle_delta = idle - _prev_cpu_idle
                total_delta = total - _prev_cpu_total
                cpu_pct = round((1.0 - idle_delta / total_delta) * 100, 1) if total_delta > 0 else 0.0
            else:
                cpu_pct = None  # First poll — no delta yet

            _prev_cpu_idle = idle
            _prev_cpu_total = total
            _prev_cpu_initialized = True

        return cpu_pct
    except Exception:
        return None


# Bot configuration mapping bot name to process pattern
BOTS = {
    'pokedex': {
        'name': 'Pokedex',
        'emoji': '🔮',
        'process_pattern': 'webex_bots/pokedex',
        'start_script': 'startup_scripts/start_pokedex.sh',
        'log_port': 8042,
        'systemd_service': 'ir-pokedex.service'
    },
    'toodles': {
        'name': 'Toodles',
        'emoji': '🎯',
        'process_pattern': 'webex_bots/toodles',
        'start_script': 'startup_scripts/start_toodles.sh',
        'log_port': 8032,
        'systemd_service': 'ir-toodles.service'
    },
    'msoar': {
        'name': 'MSOAR',
        'emoji': '🤖',
        'process_pattern': 'webex_bots/msoar',
        'start_script': 'startup_scripts/start_msoar.sh',
        'log_port': 8033,
        'systemd_service': 'ir-msoar.service'
    },
    'moneyball': {
        'name': 'MoneyBall',
        'emoji': '💰',
        'process_pattern': 'webex_bots/money_ball',
        'start_script': 'startup_scripts/start_money_ball.sh',
        'log_port': 8034,
        'systemd_service': 'ir-money-ball.service'
    },
    'jarvis': {
        'name': 'Jarvis',
        'emoji': '🛡️',
        'process_pattern': 'webex_bots/jarvis',
        'start_script': 'startup_scripts/start_jarvis.sh',
        'log_port': 8035,
        'systemd_service': 'ir-jarvis.service'
    },
    'barnacles': {
        'name': 'Barnacles',
        'emoji': '⚓',
        'process_pattern': 'webex_bots/barnacles',
        'start_script': 'startup_scripts/start_barnacles.sh',
        'log_port': 8036,
        'systemd_service': 'ir-barnacles.service'
    },
    'tars': {
        'name': 'TARS',
        'emoji': '☁️',
        'process_pattern': 'webex_bots/tars',
        'start_script': 'startup_scripts/start_tars.sh',
        'log_port': 8038,
        'systemd_service': 'ir-tars.service'
    },
    'case': {
        'name': 'CASE',
        'emoji': '🏢',
        'process_pattern': 'webex_bots/case',
        'start_script': 'startup_scripts/start_case.sh',
        'log_port': 8041,
        'systemd_service': 'ir-case.service'
    },
    'jobs': {
        'name': 'IR Scheduler',
        'emoji': '⏰',
        'process_pattern': 'src/ir_scheduler.py',
        'start_script': 'startup_scripts/start_scheduler.sh',
        'log_port': 8037,
        'systemd_service': 'ir-scheduler.service'
    },
    'epp': {
        'name': 'EPP Scheduler',
        'emoji': '🛡️',
        'process_pattern': 'src/epp_scheduler.py',
        'start_script': 'startup_scripts/start_epp_scheduler.sh',
        'log_port': 8044,
        'systemd_service': 'ir-epp-scheduler.service'
    },
    'ai': {
        'name': 'AI Scheduler',
        'emoji': '🧠',
        'process_pattern': 'src/ai_scheduler.py',
        'log_port': 8045,
        'systemd_service': 'ai-scheduler.service'
    },
    'de': {
        'name': 'DE Scheduler',
        'emoji': '🔍',
        'process_pattern': 'src/de_scheduler.py',
        'log_port': 8046,
        'systemd_service': 'de-scheduler.service'
    },
    'winai': {
        'name': 'Win.AI',
        'emoji': '📚',
        'process_pattern': 'webex_bots/win_ai',
        'log_port': 8043,
        'systemd_service': 'win-ai.service'
    },
    'webserver': {
        'name': 'Web App',
        'emoji': '🌐',
        'process_pattern': 'web/app',
        'start_script': 'startup_scripts/start_web_server.sh',
        'log_port': 8039,
        'systemd_service': 'ir-web-app.service'
    }
}


LLM_ENDPOINTS = [
    # Analysis / tool-calling: mac-m1 is the ONLY analysis LLM in the fleet.
    # Powers Pokedex, Win.AI, and any caller that needs tools.
    {'key': 'm1-analysis', 'label': 'M1 Analysis',   'port': 8015, 'model_size': '30 GB', 'remote': 'M1:8000'},
    {'key': 'm1-router',   'label': 'M1 Router',     'port': 8016, 'model_size': '4.3 GB', 'remote': 'M1:8001'},
    # Embeddings, reranker, transcription, TTS: all on studio1 since 2026-05-07.
    # mac-m3 retired (converted to a workstation) — its services migrated here.
    {'key': 'embed',       'label': 'S1 Embeddings', 'port': None, 'probe_url': 'http://studio1.lab:8004', 'probe_auth_env': 'EMBEDS_API_KEY', 'display_model': 'Qwen3-Embedding-8B-4bit-DWQ', 'model_size': '4.0 GB', 'health_timeout': 60, 'remote': 'Studio1:8004'},
    {'key': 's1-reranker', 'label': 'S1 Reranker',   'port': 8020, 'display_model': 'bge-reranker-v2-m3-finetuned', 'model_size': '2.2 GB', 'remote': 'Studio1:8020'},
    # Transcription: faster-whisper-large-v3-turbo + pyannote diarization on studio1.
    # Uses /health instead of /v1/models — health_path override below.
    {'key': 's1-transcription', 'label': 'S1 Transcription', 'port': 11437, 'display_model': 'whisper-large-v3-turbo + pyannote', 'model_size': '~3 GB', 'remote': 'Studio1:11437', 'health_path': '/health'},
    # TTS: kokoro-onnx for demo-video narration (and any other TTS caller).
    {'key': 's1-tts', 'label': 'S1 TTS', 'port': 8021, 'display_model': 'kokoro-onnx (54 voices)', 'model_size': '~80 MB', 'remote': 'Studio1:8021', 'health_path': '/health'},
    # Mac Studio 1 (M3 Ultra, 96GB) — large analysis model via Ollama.
    # OpenAI-compatible /v1/models is exposed by Ollama natively.
    {'key': 's1-laguna', 'label': 'S1 Laguna', 'port': 8022, 'display_model': 'laguna-xs.2:q8_0', 'model_size': '~33 GB', 'remote': 'Studio1:11434'},
    {'key': 's1-qwen', 'label': 'S1 Qwen3-32B', 'port': 8023, 'display_model': 'Qwen3-32B-8bit', 'model_size': '~33 GB', 'remote': 'Studio1:8000'},
]

# Track when each endpoint was first seen as "up" (reset on transition to down)
_llm_up_since: dict[str, float] = {}


def check_auth(username, password):
    """Check if username/password combination is valid."""
    return username == AUTH_USERNAME and password == AUTH_PASSWORD


def authenticate():
    """Send 401 response for authentication."""
    return Response(
        'Authentication required',
        401,
        {'WWW-Authenticate': 'Basic realm="Bot Status API"'}
    )


def requires_auth(f):
    """Decorator to require HTTP Basic Auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def log_audit_event(ip_address, action, bot_name, success, message=''):
    """Log control actions to SQLite audit log."""
    try:
        import sys
        sys.path.insert(0, PROJECT_ROOT)
        from src.utils.bot_logs_db import log_viewer_audit
        log_viewer_audit(
            timestamp=datetime.now().isoformat(),
            ip_address=ip_address,
            action=action,
            bot_name=bot_name,
            success=success,
            message=message,
        )
    except Exception as e:
        print(f"Warning: Failed to write audit log: {e}")


def get_bot_status(bot_key):
    """
    Get detailed status for a specific bot.
    Returns dict with status, pid, uptime, memory, etc.
    """
    bot_config = BOTS.get(bot_key)
    if not bot_config:
        return None

    try:
        # Get the main PID from systemd (avoids counting worker/child processes)
        service_name = bot_config.get('systemd_service')
        main_pid = None
        if service_name:
            pid_result = subprocess.run(
                ['systemctl', '--user', 'show', service_name, '--property=MainPID', '--value'],
                capture_output=True, text=True, timeout=5
            )
            if pid_result.returncode == 0 and pid_result.stdout.strip() not in ('', '0'):
                main_pid = int(pid_result.stdout.strip())

        # Fallback to pgrep if no systemd service or MainPID is 0
        if main_pid:
            pid_list = [main_pid]
        else:
            result = subprocess.run(
                ['pgrep', '-f', bot_config['process_pattern']],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                pid_list = [int(p) for p in pids if p.strip().isdigit()]
            else:
                pid_list = []

        if not pid_list:
            return {
                'status': 'stopped',
                'pids': [],
                'pid_count': 0,
                'pid': None,
                'uptime': None,
                'cpu_percent': 0,
                'memory_mb': 0,
                'memory_percent': 0
            }

        # Get process details for all PIDs using ps
        ps_result = subprocess.run(
            ['ps', '-p', ','.join(map(str, pid_list)), '-o', 'pid,etime,%cpu,%mem,rss', '--no-headers'],
            capture_output=True, text=True, timeout=5
        )

        if ps_result.returncode == 0:
            lines = ps_result.stdout.strip().split('\n')

            total_cpu = 0
            total_mem_mb = 0
            total_mem_percent = 0
            uptime = 'N/A'

            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    if uptime == 'N/A':
                        uptime = parts[1]
                    total_cpu += float(parts[2]) if parts[2].replace('.', '').isdigit() else 0
                    total_mem_percent += float(parts[3]) if parts[3].replace('.', '').isdigit() else 0
                    mem_kb = parts[4]
                    total_mem_mb += int(mem_kb) // 1024 if mem_kb.isdigit() else 0

            return {
                'status': 'running',
                'pids': pid_list,
                'pid_count': len(pid_list),
                'pid': pid_list[0],
                'uptime': uptime,
                'cpu_percent': total_cpu,
                'memory_mb': total_mem_mb,
                'memory_percent': total_mem_percent
            }

        # Process not running
        return {
            'status': 'stopped',
            'pids': [],
            'pid_count': 0,
            'pid': None,
            'uptime': None,
            'cpu_percent': 0,
            'memory_mb': 0,
            'memory_percent': 0
        }

    except Exception as e:
        print(f"Error getting status for {bot_key}: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'pids': [],
            'pid_count': 0,
            'pid': None,
            'uptime': None,
            'cpu_percent': 0,
            'memory_mb': 0,
            'memory_percent': 0
        }


@app.route('/api/status', methods=['GET'])
def get_all_status():
    """Get status of all bots."""
    status = {}
    running_count = 0
    total_count = len(BOTS)

    for bot_key, bot_config in BOTS.items():
        bot_status = get_bot_status(bot_key)
        if bot_status['status'] == 'running':
            running_count += 1

        status[bot_key] = {
            **bot_config,
            **bot_status,
            'key': bot_key
        }

    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'running': running_count,
            'stopped': total_count - running_count,
            'total': total_count
        },
        'bots': status
    })


@app.route('/api/status/<bot_key>', methods=['GET'])
def get_single_status(bot_key):
    """Get status of a specific bot."""
    if bot_key not in BOTS:
        return jsonify({'error': 'Bot not found'}), 404

    bot_config = BOTS[bot_key]
    bot_status = get_bot_status(bot_key)

    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'bot': {
            **bot_config,
            **bot_status,
            'key': bot_key
        }
    })


@app.route('/api/control/<bot_key>/<action>', methods=['POST'])
@requires_auth
def control_bot(bot_key, action):
    """
    Control a bot (start/stop/restart).
    Actions: start, stop, restart
    """
    # Get client IP address (handle proxy headers)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    if bot_key not in BOTS:
        return jsonify({'error': 'Bot not found'}), 404

    if action not in ['start', 'stop', 'restart']:
        return jsonify({'error': 'Invalid action. Use: start, stop, or restart'}), 400

    bot_config = BOTS[bot_key]

    try:
        if action == 'stop':
            # Use systemctl if bot has a systemd service, otherwise use pkill
            if 'systemd_service' in bot_config:
                # Stop via systemd (may take time for graceful shutdown)
                try:
                    result = subprocess.run(
                        ['systemctl', '--user', 'stop', bot_config['systemd_service']],
                        timeout=90,
                        capture_output=True
                    )
                except subprocess.TimeoutExpired:
                    # Systemd stop may take longer than timeout but still succeed
                    # The service will continue stopping in the background
                    pass
                time.sleep(2)  # Give systemd time to complete shutdown
            else:
                # Kill the bot process using pkill
                subprocess.run(
                    ['pkill', '-f', bot_config['process_pattern']],
                    timeout=10
                )

                # Wait for process to actually terminate (up to 10 seconds)
                max_wait = 10  # seconds
                wait_interval = 0.5  # seconds
                elapsed = 0

                while elapsed < max_wait:
                    time.sleep(wait_interval)
                    elapsed += wait_interval

                    # Check if process is still running
                    check_result = subprocess.run(
                        ['pgrep', '-f', bot_config['process_pattern']],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    # If pgrep returns non-zero, process is gone
                    if check_result.returncode != 0:
                        break
                else:
                    # Process still running after max_wait, force kill it
                    subprocess.run(
                        ['pkill', '-9', '-f', bot_config['process_pattern']],
                        timeout=10
                    )
                    time.sleep(1)  # Give force kill a moment

            message = f"{bot_config['name']} stopped"

        elif action == 'start':
            if 'systemd_service' in bot_config:
                subprocess.run(
                    ['systemctl', '--user', 'start', bot_config['systemd_service']],
                    timeout=30,
                    capture_output=True
                )
                time.sleep(2)
            else:
                script_path = os.path.join(PROJECT_ROOT, bot_config['start_script'])
                subprocess.Popen(
                    ['bash', script_path],
                    cwd=PROJECT_ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(2)
            message = f"{bot_config['name']} started"

        elif action == 'restart':
            # Use systemctl if bot has a systemd service, otherwise use pkill + script
            if 'systemd_service' in bot_config:
                # Restart via systemd (may take time for graceful shutdown + startup)
                try:
                    result = subprocess.run(
                        ['systemctl', '--user', 'restart', bot_config['systemd_service']],
                        timeout=120,
                        capture_output=True
                    )
                except subprocess.TimeoutExpired:
                    # Systemd restart may take longer than timeout but still succeed
                    pass
                time.sleep(3)  # Give systemd time to restart
                message = f"{bot_config['name']} restarted"
            else:
                # Stop then start (script runs in background and may take 30-60 seconds)
                subprocess.run(
                    ['pkill', '-f', bot_config['process_pattern']],
                    timeout=10
                )

                # Wait for process to actually terminate (up to 10 seconds)
                max_wait = 10  # seconds
                wait_interval = 0.5  # seconds
                elapsed = 0

                while elapsed < max_wait:
                    time.sleep(wait_interval)
                    elapsed += wait_interval

                    # Check if process is still running
                    check_result = subprocess.run(
                        ['pgrep', '-f', bot_config['process_pattern']],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    # If pgrep returns non-zero, process is gone
                    if check_result.returncode != 0:
                        break
                else:
                    # Process still running after max_wait, force kill it
                    subprocess.run(
                        ['pkill', '-9', '-f', bot_config['process_pattern']],
                        timeout=10
                    )
                    time.sleep(1)  # Give force kill a moment

                # Now start the bot
                script_path = os.path.join(PROJECT_ROOT, bot_config['start_script'])
                subprocess.Popen(
                    ['bash', script_path],
                    cwd=PROJECT_ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(2)
                message = f"{bot_config['name']} restart initiated (may take 30-60s to complete)"

        # Get updated status
        bot_status = get_bot_status(bot_key)

        # Log successful action
        log_audit_event(
            ip_address=client_ip,
            action=action,
            bot_name=bot_config['name'],
            success=True,
            message=message
        )

        return jsonify({
            'success': True,
            'message': message,
            'action': action,
            'bot': {
                **bot_config,
                **bot_status,
                'key': bot_key
            }
        })

    except Exception as e:
        error_msg = f"Failed to {action} {bot_config['name']}: {str(e)}"

        # Log failed action
        log_audit_event(
            ip_address=client_ip,
            action=action,
            bot_name=bot_config['name'],
            success=False,
            message=error_msg
        )

        return jsonify({
            'success': False,
            'error': str(e),
            'message': f"Failed to {action} {bot_config['name']}"
        }), 500


@app.route('/api/log-viewers/restart', methods=['POST'])
@requires_auth
def restart_log_viewers():
    """Restart all log viewer services."""
    # Get client IP address (handle proxy headers)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    try:
        # Stop all log viewers
        subprocess.run(
            ['pkill', '-f', 'deployment/log_viewer.py'],
            timeout=10,
            capture_output=True
        )
        time.sleep(2)

        # Start log viewers using the management script
        script_path = os.path.join(PROJECT_ROOT, 'deployment/manage_log_viewers.sh')
        result = subprocess.run(
            ['bash', script_path, 'start'],
            cwd=PROJECT_ROOT,
            timeout=30,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            message = "Log viewer services restarted successfully"
            success = True
        else:
            message = f"Log viewers restarted with warnings: {result.stderr}"
            success = True  # Still consider it success if script ran

        # Log the action
        log_audit_event(
            ip_address=client_ip,
            action='restart_log_viewers',
            bot_name='Log Viewers',
            success=success,
            message=message
        )

        return jsonify({
            'success': success,
            'message': message
        })

    except Exception as e:
        error_msg = f"Failed to restart log viewers: {str(e)}"

        log_audit_event(
            ip_address=client_ip,
            action='restart_log_viewers',
            bot_name='Log Viewers',
            success=False,
            message=error_msg
        )

        return jsonify({
            'success': False,
            'error': str(e),
            'message': "Failed to restart log viewers"
        }), 500


@app.route('/api/self-restart', methods=['POST'])
@requires_auth
def self_restart():
    """Restart the bot status API service itself."""
    # Get client IP address (handle proxy headers)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    try:
        # Log the action before restarting (since we won't be around after)
        log_audit_event(
            ip_address=client_ip,
            action='self_restart',
            bot_name='Bot Status API',
            success=True,
            message='Service restart initiated'
        )

        # Spawn the restart command in the background and return immediately
        # The service will restart after we respond
        subprocess.Popen(
            ['systemctl', '--user', 'restart', 'ir-bot-status-api.service'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        return jsonify({
            'success': True,
            'message': 'Service restart initiated. Please refresh the page in a few seconds.'
        })

    except Exception as e:
        error_msg = f"Failed to restart service: {str(e)}"

        log_audit_event(
            ip_address=client_ip,
            action='self_restart',
            bot_name='Bot Status API',
            success=False,
            message=error_msg
        )

        return jsonify({
            'success': False,
            'error': str(e),
            'message': "Failed to restart service"
        }), 500


@app.route('/api/git-pull', methods=['POST'])
@requires_auth
def git_pull():
    """Pull latest changes from git."""
    # Get client IP address (handle proxy headers)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    try:
        result = subprocess.run(
            ['git', 'pull', '--autostash'],
            cwd=PROJECT_ROOT,
            timeout=30,
            capture_output=True,
            text=True
        )

        output = result.stdout.strip() or result.stderr.strip()
        success = result.returncode == 0

        log_audit_event(
            ip_address=client_ip,
            action='git_pull',
            bot_name='Git',
            success=success,
            message=output[:200]  # Truncate for audit log
        )

        return jsonify({
            'success': success,
            'message': output,
            'return_code': result.returncode
        })

    except Exception as e:
        log_audit_event(
            ip_address=client_ip,
            action='git_pull',
            bot_name='Git',
            success=False,
            message=str(e)
        )

        return jsonify({
            'success': False,
            'error': str(e),
            'message': f"Failed to pull: {str(e)}"
        }), 500


@app.route('/api/system-status', methods=['GET'])
def system_status():
    """Get system resource usage."""
    try:
        # Get disk usage
        disk_result = subprocess.run(
            ['df', '-h', PROJECT_ROOT],
            capture_output=True,
            text=True,
            timeout=5
        )
        disk_lines = disk_result.stdout.strip().split('\n')
        disk_info = disk_lines[1].split() if len(disk_lines) > 1 else []

        # Get memory usage
        mem_result = subprocess.run(
            ['free', '-h'],
            capture_output=True,
            text=True,
            timeout=5
        )
        mem_lines = mem_result.stdout.strip().split('\n')
        mem_info = mem_lines[1].split() if len(mem_lines) > 1 else []

        # Get load average
        load_result = subprocess.run(
            ['cat', '/proc/loadavg'],
            capture_output=True,
            text=True,
            timeout=5
        )
        load_parts = load_result.stdout.strip().split()

        # Get CPU core count (server-side, not browser)
        nproc_result = subprocess.run(
            ['nproc'],
            capture_output=True,
            text=True,
            timeout=5
        )
        cpu_count = int(nproc_result.stdout.strip()) if nproc_result.returncode == 0 else None

        # Get real-time CPU utilization from /proc/stat delta
        cpu_percent = _get_cpu_utilization()

        # Get uptime
        uptime_result = subprocess.run(
            ['uptime', '-p'],
            capture_output=True,
            text=True,
            timeout=5
        )

        return jsonify({
            'success': True,
            'disk': {
                'filesystem': disk_info[0] if len(disk_info) > 0 else 'N/A',
                'size': disk_info[1] if len(disk_info) > 1 else 'N/A',
                'used': disk_info[2] if len(disk_info) > 2 else 'N/A',
                'available': disk_info[3] if len(disk_info) > 3 else 'N/A',
                'percent': disk_info[4] if len(disk_info) > 4 else 'N/A'
            },
            'memory': {
                'total': mem_info[1] if len(mem_info) > 1 else 'N/A',
                'used': mem_info[2] if len(mem_info) > 2 else 'N/A',
                'free': mem_info[3] if len(mem_info) > 3 else 'N/A',
                'available': mem_info[6] if len(mem_info) > 6 else 'N/A'
            },
            'load': {
                '1min': load_parts[0] if len(load_parts) > 0 else 'N/A',
                '5min': load_parts[1] if len(load_parts) > 1 else 'N/A',
                '15min': load_parts[2] if len(load_parts) > 2 else 'N/A'
            },
            'cpu_count': cpu_count,
            'cpu_percent': cpu_percent,
            'uptime': uptime_result.stdout.strip()
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# lab-vm2 status (SSH-based, cached) — same shape as /api/system-status
_lab_vm2_cache: dict = {}
_lab_vm2_cache_ts: float = 0.0
_LAB_VM2_TTL = 30  # seconds


@app.route('/api/lab-vm2-status', methods=['GET'])
def lab_vm2_status():
    """Get lab-vm2 system stats via SSH (cached)."""
    global _lab_vm2_cache, _lab_vm2_cache_ts
    now = time.time()
    if now - _lab_vm2_cache_ts < _LAB_VM2_TTL and _lab_vm2_cache:
        return jsonify(_lab_vm2_cache)

    cmd = [
        'ssh', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes', 'lab-vm2',
        "df -h $HOME;"
        " echo ---FREE---;"
        " free -h;"
        " echo ---LOADAVG---;"
        " cat /proc/loadavg;"
        " echo ---NPROC---;"
        " nproc;"
        " echo ---UPTIME---;"
        " uptime -p;"
        " echo ---CPU1---;"
        " grep '^cpu ' /proc/stat;"
        " sleep 1;"
        " echo ---CPU2---;"
        " grep '^cpu ' /proc/stat"
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'ssh timeout'}), 504
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)[:120]}), 500

    if r.returncode != 0:
        return jsonify({'success': False, 'error': (r.stderr.strip() or 'ssh failed')[:120]}), 502

    sections: dict[str, list[str]] = {'DF': []}
    current = 'DF'
    for line in r.stdout.split('\n'):
        if line.startswith('---') and line.endswith('---') and len(line) > 6:
            current = line.strip('-')
            sections[current] = []
        else:
            sections.setdefault(current, []).append(line)

    disk_lines = sections.get('DF', [])
    disk_info = disk_lines[1].split() if len(disk_lines) > 1 else []
    mem_lines = sections.get('FREE', [])
    mem_info = mem_lines[1].split() if len(mem_lines) > 1 else []
    load_parts = (sections.get('LOADAVG', [''])[0] or '').split()
    cpu_count_str = (sections.get('NPROC', [''])[0] or '').strip()
    cpu_count = int(cpu_count_str) if cpu_count_str.isdigit() else None
    uptime = (sections.get('UPTIME', [''])[0] or '').strip()
    if uptime and not uptime.startswith('up '):
        uptime = f'up {uptime}'

    cpu_percent = None
    try:
        p1 = (sections.get('CPU1', [''])[0] or '').split()
        p2 = (sections.get('CPU2', [''])[0] or '').split()
        if len(p1) >= 8 and len(p2) >= 8:
            idle1 = int(p1[4]) + int(p1[5])
            idle2 = int(p2[4]) + int(p2[5])
            total1 = sum(int(x) for x in p1[1:])
            total2 = sum(int(x) for x in p2[1:])
            idle_delta = idle2 - idle1
            total_delta = total2 - total1
            if total_delta > 0:
                cpu_percent = round((1.0 - idle_delta / total_delta) * 100, 1)
    except Exception:
        pass

    result = {
        'success': True,
        'disk': {
            'filesystem': disk_info[0] if len(disk_info) > 0 else 'N/A',
            'size': disk_info[1] if len(disk_info) > 1 else 'N/A',
            'used': disk_info[2] if len(disk_info) > 2 else 'N/A',
            'available': disk_info[3] if len(disk_info) > 3 else 'N/A',
            'percent': disk_info[4] if len(disk_info) > 4 else 'N/A',
        },
        'memory': {
            'total': mem_info[1] if len(mem_info) > 1 else 'N/A',
            'used': mem_info[2] if len(mem_info) > 2 else 'N/A',
            'free': mem_info[3] if len(mem_info) > 3 else 'N/A',
            'available': mem_info[6] if len(mem_info) > 6 else 'N/A',
        },
        'load': {
            '1min': load_parts[0] if len(load_parts) > 0 else 'N/A',
            '5min': load_parts[1] if len(load_parts) > 1 else 'N/A',
            '15min': load_parts[2] if len(load_parts) > 2 else 'N/A',
        },
        'cpu_count': cpu_count,
        'cpu_percent': cpu_percent,
        'uptime': uptime,
    }
    _lab_vm2_cache = result
    _lab_vm2_cache_ts = now
    return jsonify(result)


@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint (no auth required)."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/llm-health', methods=['GET'])
def llm_health():
    """Check health of all inference model endpoints via SSH reverse tunnels."""
    import requests as req
    import socket
    results = {}
    for ep in LLM_ENDPOINTS:
        probe_url = ep.get('probe_url')
        if probe_url is None and ep['port'] is None:
            results[ep['key']] = {'status': 'unknown', 'label': ep['label'], 'port': None, 'error': 'Endpoint not configured'}
            continue
        # Direct-dial endpoints skip the local tunnel check
        probe_headers = {}
        if ep.get('probe_auth_env'):
            token = os.environ.get(ep['probe_auth_env'])
            if token:
                probe_headers['Authorization'] = f"Bearer {token}"
        if probe_url:
            tunnel_status = 'direct'
            base_target = probe_url.rstrip('/')
        else:
            tunnel_status = 'down'
            try:
                sock = socket.create_connection(('localhost', ep['port']), timeout=3)
                sock.close()
                tunnel_status = 'up'
            except Exception:
                pass
            base_target = f"http://localhost:{ep['port']}"
        # HTTP model health check
        start = time.time()
        try:
            health_timeout = ep.get('health_timeout', 5)
            health_path = ep.get('health_path', '/v1/models')
            resp = req.get(f"{base_target}{health_path}", headers=probe_headers, timeout=health_timeout)
            latency_ms = int((time.time() - start) * 1000)
            if resp.ok:
                body = resp.json() if health_path == '/v1/models' else {}
                if health_path == '/v1/models':
                    models = [m['id'].split('/')[-1] for m in body.get('data', [])]
                else:
                    # Custom health endpoint (e.g. transcription server /health)
                    models = []
                if ep.get('display_model'):
                    models = [ep['display_model']]
                if ep['key'] not in _llm_up_since:
                    _llm_up_since[ep['key']] = time.time()
                uptime_s = int(time.time() - _llm_up_since[ep['key']])
                entry = {
                    'status': 'up',
                    'label': ep['label'],
                    'port': ep['port'],
                    'models': models,
                    'latency_ms': latency_ms,
                    'uptime_s': uptime_s,
                    'model_size': ep.get('model_size'),
                    'tunnel': tunnel_status,
                    'remote': ep.get('remote'),
                }
                results[ep['key']] = entry
            else:
                _llm_up_since.pop(ep['key'], None)
                results[ep['key']] = {
                    'status': 'down',
                    'label': ep['label'],
                    'port': ep['port'],
                    'error': f"HTTP {resp.status_code}",
                    'latency_ms': latency_ms,
                    'tunnel': tunnel_status,
                    'remote': ep.get('remote'),
                }
        except Exception as e:
            _llm_up_since.pop(ep['key'], None)
            results[ep['key']] = {
                'status': 'down',
                'label': ep['label'],
                'port': ep['port'],
                'error': str(e)[:80],
                'latency_ms': None,
                'tunnel': tunnel_status,
                'remote': ep.get('remote'),
            }
    return jsonify({'timestamp': datetime.now().isoformat(), 'endpoints': results})


# ---------- Mac hardware health (SSH-based, cached) ----------

MAC_HOSTS = [
    {'key': 'mac-m1', 'label': 'Mac M1', 'ssh_host': 'mac-m1', 'total_gb': 64},
    {'key': 'studio1', 'label': 'Studio 1', 'ssh_host': 'studio1', 'total_gb': 96},
]
_mac_cache: dict[str, dict] = {}
_mac_cache_ts: dict[str, float] = {}
_MAC_TTL = 30  # seconds


def _fetch_one_mac(host: dict) -> dict:
    """SSH into a Mac and return parsed system stats."""
    # Single command: vm_stat for memory, top for CPU, sysctl for cores, uptime
    cmd = [
        'ssh', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes',
        host['ssh_host'],
        "vm_stat;"
        " /usr/bin/top -l 1 -n 0 -s 0 2>/dev/null | grep 'CPU usage';"
        " sysctl -n hw.ncpu;"
        " echo CHIP:$(sysctl -n machdep.cpu.brand_string);"
        " echo MACOS:$(sw_vers -productVersion);"
        " echo PCORES:$(sysctl -n hw.perflevel0.logicalcpu 2>/dev/null || echo ?);"
        " echo ECORES:$(sysctl -n hw.perflevel1.logicalcpu 2>/dev/null || echo ?);"
        " echo DISK:$(df -k / | tail -1);"
        " uptime"
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return {'status': 'down', 'error': (r.stderr.strip() or 'ssh failed')[:80]}
    except subprocess.TimeoutExpired:
        return {'status': 'down', 'error': 'ssh timeout'}
    except Exception as e:
        return {'status': 'down', 'error': str(e)[:80]}

    import re
    lines = r.stdout.strip().split('\n')
    result: dict = {'status': 'up', 'label': host['label']}

    # Parse vm_stat output to compute app memory (wired + active + compressor).
    # Inactive/purgeable/speculative/free pages are reclaimable and excluded.
    page_size = 16384  # Apple Silicon default
    vm_pages: dict[str, int] = {}
    for line in lines:
        if 'page size of' in line:
            m = re.search(r'page size of (\d+) bytes', line)
            if m:
                page_size = int(m.group(1))
        for key in ('Pages active', 'Pages wired down', 'Pages occupied by compressor',
                     'Pages free', 'Pages inactive', 'Pages speculative', 'Pages purgeable'):
            if line.startswith(key):
                m = re.search(r':\s+(\d+)', line)
                if m:
                    vm_pages[key] = int(m.group(1))

    if vm_pages.get('Pages active') is not None:
        app_pages = (vm_pages.get('Pages active', 0)
                     + vm_pages.get('Pages wired down', 0)
                     + vm_pages.get('Pages occupied by compressor', 0))
        free_pages = (vm_pages.get('Pages free', 0)
                      + vm_pages.get('Pages inactive', 0)
                      + vm_pages.get('Pages speculative', 0)
                      + vm_pages.get('Pages purgeable', 0))
        total_gb = host['total_gb']
        app_gb = round(app_pages * page_size / (1024 ** 3), 1)
        free_gb = round(free_pages * page_size / (1024 ** 3), 1)
        result['mem_used_gb'] = app_gb
        result['mem_free_gb'] = free_gb
        result['mem_total_gb'] = total_gb
        result['mem_pct'] = round(app_gb / total_gb * 100, 1)

    for line in lines:
        # CPU usage: 5.55% user, 10.24% sys, 84.20% idle
        if 'CPU usage' in line:
            m = re.search(r'([\d.]+)%\s*idle', line)
            if m:
                result['cpu_pct'] = round(100 - float(m.group(1)), 1)

        # last line from uptime: "18:19  up 12 days,  3:45, 2 users, load averages: 1.23 0.98 0.87"
        elif 'load average' in line.lower():
            m = re.search(r'up\s+(.+?),\s+\d+\s+user', line)
            if m:
                result['uptime'] = m.group(1).strip().rstrip(',')
            m2 = re.search(r'load averages?:\s*([\d.]+)', line)
            if m2:
                result['load_1m'] = float(m2.group(1))

        # Tagged fields
        elif line.startswith('CHIP:'):
            result['chip'] = line[5:].strip()
        elif line.startswith('MACOS:'):
            result['macos'] = line[6:].strip()
        elif line.startswith('PCORES:'):
            v = line[7:].strip()
            if v.isdigit():
                result['pcores'] = int(v)
        elif line.startswith('ECORES:'):
            v = line[7:].strip()
            if v.isdigit():
                result['ecores'] = int(v)

        # df -k / output: filesystem 1K-blocks used avail capacity ... mountpoint
        # APFS shares space across volumes, so "true" used = size - avail.
        elif line.startswith('DISK:'):
            parts = line[5:].strip().split()
            if len(parts) >= 4:
                try:
                    size_kb = int(parts[1])
                    avail_kb = int(parts[3])
                    used_kb = size_kb - avail_kb
                    size_gb = round(size_kb / (1024 ** 2), 1)
                    used_gb = round(used_kb / (1024 ** 2), 1)
                    result['disk_size_gb'] = size_gb
                    result['disk_used_gb'] = used_gb
                    result['disk_pct'] = round(used_gb / size_gb * 100, 1) if size_gb > 0 else 0.0
                except (ValueError, ZeroDivisionError):
                    pass

        # sysctl -n hw.ncpu → plain integer
        elif line.strip().isdigit():
            result['ncpu'] = int(line.strip())

    return result


@app.route('/api/mac-health', methods=['GET'])
def mac_health():
    """Return cached hardware health for Mac inference hosts."""
    now = time.time()
    results = {}
    threads = []

    def _fetch_and_cache(host):
        key = host['key']
        if now - _mac_cache_ts.get(key, 0) < _MAC_TTL and key in _mac_cache:
            results[key] = _mac_cache[key]
            return
        data = _fetch_one_mac(host)
        _mac_cache[key] = data
        _mac_cache_ts[key] = now
        results[key] = data

    for h in MAC_HOSTS:
        t = threading.Thread(target=_fetch_and_cache, args=(h,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=20)

    return jsonify({'timestamp': datetime.now().isoformat(), 'hosts': results})


if __name__ == '__main__':
    print("Starting Bot Status API...")
    print(f"Auth: {AUTH_USERNAME} / {AUTH_PASSWORD}")
    app.run(
        host='0.0.0.0',
        port=8040,
        debug=False,
        threaded=True
    )
