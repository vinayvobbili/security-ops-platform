#!/usr/bin/env python3
"""
Bot Status API - REST API for monitoring and controlling IR bots
Provides endpoints for checking status and controlling bots (start/stop/restart)
"""

import os
import subprocess
import time
from functools import wraps
from datetime import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow CORS for the frontend

# Configuration
AUTH_USERNAME = os.getenv('LOG_VIEWER_USERNAME', 'admin')
AUTH_PASSWORD = os.getenv('LOG_VIEWER_PASSWORD', 'admin')
PROJECT_ROOT = '/opt/incident-response'

# Bot configuration mapping bot name to process pattern
BOTS = {
    'toodles': {
        'name': 'Toodles',
        'emoji': '🎯',
        'process_pattern': 'webex_bots/toodles',
        'start_script': 'startup_scripts/start_toodles.sh',
        'log_port': 8032
    },
    'msoar': {
        'name': 'MSOAR',
        'emoji': '🤖',
        'process_pattern': 'webex_bots/msoar',
        'start_script': 'startup_scripts/start_msoar.sh',
        'log_port': 8033
    },
    'moneyball': {
        'name': 'MoneyBall',
        'emoji': '💰',
        'process_pattern': 'webex_bots/money_ball',
        'start_script': 'startup_scripts/start_money_ball.sh',
        'log_port': 8034
    },
    'jarvis': {
        'name': 'Jarvis',
        'emoji': '🛡️',
        'process_pattern': 'webex_bots/jarvis',
        'start_script': 'startup_scripts/start_jarvis.sh',
        'log_port': 8035
    },
    'barnacles': {
        'name': 'Barnacles',
        'emoji': '⚓',
        'process_pattern': 'webex_bots/barnacles',
        'start_script': 'startup_scripts/start_barnacles.sh',
        'log_port': 8036
    },
    'tars': {
        'name': 'TARS',
        'emoji': '🤖',
        'process_pattern': 'webex_bots/tars',
        'start_script': 'startup_scripts/start_tars.sh',
        'log_port': 8038
    },
    'jobs': {
        'name': 'All Jobs',
        'emoji': '⏰',
        'process_pattern': 'src/all_jobs.py',
        'start_script': 'startup_scripts/start_all_jobs.sh',
        'log_port': 8037
    },
    'webserver': {
        'name': 'Web Server',
        'emoji': '🌐',
        'process_pattern': 'web/web_server',
        'start_script': 'startup_scripts/start_web_server.sh',
        'log_port': 8039
    }
}


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


def get_bot_status(bot_key):
    """
    Get detailed status for a specific bot.
    Returns dict with status, pid, uptime, memory, etc.
    """
    bot_config = BOTS.get(bot_key)
    if not bot_config:
        return None

    try:
        # Check if process is running using pgrep
        result = subprocess.run(
            ['pgrep', '-f', bot_config['process_pattern']],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout.strip():
            pid = result.stdout.strip().split('\n')[0]  # Get first PID if multiple

            # Get process details using ps
            ps_result = subprocess.run(
                ['ps', '-p', pid, '-o', 'pid,etime,%cpu,%mem,rss'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if ps_result.returncode == 0:
                lines = ps_result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    uptime = parts[1] if len(parts) > 1 else 'unknown'
                    cpu = parts[2] if len(parts) > 2 else '0'
                    mem_percent = parts[3] if len(parts) > 3 else '0'
                    mem_kb = parts[4] if len(parts) > 4 else '0'
                    mem_mb = int(mem_kb) // 1024 if mem_kb.isdigit() else 0

                    return {
                        'status': 'running',
                        'pid': int(pid),
                        'uptime': uptime,
                        'cpu_percent': float(cpu),
                        'memory_mb': mem_mb,
                        'memory_percent': float(mem_percent)
                    }

        # Process not running
        return {
            'status': 'stopped',
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
            'pid': None,
            'uptime': None,
            'cpu_percent': 0,
            'memory_mb': 0,
            'memory_percent': 0
        }


@app.route('/api/status', methods=['GET'])
@requires_auth
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
@requires_auth
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
    if bot_key not in BOTS:
        return jsonify({'error': 'Bot not found'}), 404

    if action not in ['start', 'stop', 'restart']:
        return jsonify({'error': 'Invalid action. Use: start, stop, or restart'}), 400

    bot_config = BOTS[bot_key]

    try:
        if action == 'stop':
            # Kill the bot process
            subprocess.run(
                ['pkill', '-f', bot_config['process_pattern']],
                timeout=10
            )
            time.sleep(1)
            message = f"{bot_config['name']} stopped"

        elif action == 'start':
            # Start the bot using its startup script
            script_path = os.path.join(PROJECT_ROOT, bot_config['start_script'])
            subprocess.Popen(
                ['bash', script_path],
                cwd=PROJECT_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)  # Give it time to start
            message = f"{bot_config['name']} started"

        elif action == 'restart':
            # Stop then start
            subprocess.run(
                ['pkill', '-f', bot_config['process_pattern']],
                timeout=10
            )
            time.sleep(1)
            script_path = os.path.join(PROJECT_ROOT, bot_config['start_script'])
            subprocess.Popen(
                ['bash', script_path],
                cwd=PROJECT_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)
            message = f"{bot_config['name']} restarted"

        # Get updated status
        bot_status = get_bot_status(bot_key)

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
        return jsonify({
            'success': False,
            'error': str(e),
            'message': f"Failed to {action} {bot_config['name']}"
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint (no auth required)."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("Starting Bot Status API...")
    print(f"Auth: {AUTH_USERNAME} / {AUTH_PASSWORD}")
    app.run(
        host='0.0.0.0',
        port=8040,
        debug=False,
        threaded=True
    )
