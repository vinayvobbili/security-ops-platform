#!/usr/bin/env python3
"""
Bot Status API - REST API for monitoring and controlling IR bots
Provides endpoints for checking status and controlling bots (start/stop/restart)
"""

import os
import subprocess
import time
import csv
from functools import wraps
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

# Load .env from project root
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

app = Flask(__name__)
CORS(app)  # Allow CORS for the frontend

# Configuration
AUTH_USERNAME = os.environ['LOG_VIEWER_USERNAME']
AUTH_PASSWORD = os.environ['LOG_VIEWER_PASSWORD']
PROJECT_ROOT = '/home/vinay/pub/IR'
AUDIT_LOG_FILE = os.path.join(PROJECT_ROOT, 'data/transient/logs/log_viewer_audit_log.csv')

# Bot configuration mapping bot name to process pattern
BOTS = {
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
        'name': 'All Jobs',
        'emoji': '⏰',
        'process_pattern': 'src/all_jobs.py',
        'start_script': 'startup_scripts/start_all_jobs.sh',
        'log_port': 8037,
        'systemd_service': 'ir-all-jobs.service'
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


def log_audit_event(ip_address, action, bot_name, success, message=''):
    """
    Log control actions to audit log CSV file.

    Args:
        ip_address: IP address of the requester
        action: Action performed (start/stop/restart)
        bot_name: Name of the bot
        success: Boolean indicating if action succeeded
        message: Optional message/error
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)

        # Check if file exists to determine if we need to write headers
        file_exists = os.path.exists(AUDIT_LOG_FILE)

        with open(AUDIT_LOG_FILE, 'a', newline='') as f:
            fieldnames = ['timestamp', 'ip_address', 'action', 'bot_name', 'success', 'message']
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            # Write headers if file is new
            if not file_exists:
                writer.writeheader()

            # Write audit event
            writer.writerow({
                'timestamp': datetime.now().isoformat(),
                'ip_address': ip_address,
                'action': action,
                'bot_name': bot_name,
                'success': success,
                'message': message
            })
    except Exception as e:
        # Don't fail the request if audit logging fails, just print error
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
        # Check if process is running using pgrep
        result = subprocess.run(
            ['pgrep', '-f', bot_config['process_pattern']],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split('\n')  # Get all PIDs
            pid_list = [int(p) for p in pids if p.strip().isdigit()]

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
                capture_output=True,
                text=True,
                timeout=5
            )

            if ps_result.returncode == 0:
                lines = ps_result.stdout.strip().split('\n')

                # Aggregate stats from all processes
                total_cpu = 0
                total_mem_mb = 0
                total_mem_percent = 0
                uptime = 'N/A'

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        if uptime == 'N/A':
                            uptime = parts[1]  # Use first process's uptime
                        total_cpu += float(parts[2]) if parts[2].replace('.', '').isdigit() else 0
                        total_mem_percent += float(parts[3]) if parts[3].replace('.', '').isdigit() else 0
                        mem_kb = parts[4]
                        total_mem_mb += int(mem_kb) // 1024 if mem_kb.isdigit() else 0

                return {
                    'status': 'running',
                    'pids': pid_list,
                    'pid_count': len(pid_list),
                    'pid': pid_list[0],  # Keep for backward compatibility
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
                        ['sudo', '-n', 'systemctl', 'stop', bot_config['systemd_service']],
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
            # Use systemctl if bot has a systemd service, otherwise use pkill + script
            if 'systemd_service' in bot_config:
                # Restart via systemd (may take time for graceful shutdown + startup)
                try:
                    result = subprocess.run(
                        ['sudo', '-n', 'systemctl', 'restart', bot_config['systemd_service']],
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
            ['sudo', '-n', 'systemctl', 'restart', 'ir-bot-status-api.service'],
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
            'uptime': uptime_result.stdout.strip()
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
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
