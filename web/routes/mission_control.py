"""Mission Control — admin-gated bot/system control console, merged into the web app.

Previously a standalone Flask service on :8040 with a separate nginx page on :8030,
gated only by a shared basic-auth password. It now lives inside the IR web app as an
``@admin_required`` blueprint, so it inherits the platform's real session-based admin
gate (AUTH_ADMIN_EMAILS / role=admin) — no separate credential, no CORS, same-origin
calls that carry the logged-in admin's session cookie automatically.

The heavy bot/system logic is reused as-is from :mod:`deployment.bot_status_api`,
imported as a library (its standalone Flask app and ``__main__`` are simply never run).
Five mutating endpoints there are wrapped in HTTP Basic auth; we call their
``.__wrapped__`` originals because the admin gate is already enforced here. The Webex
bot logic functions resolve Flask's ``request``/``jsonify`` against the active web-app
request context, so calling them from these routes works unchanged.

Feature switches (toggle a runtime env flag, then restart the unit that reads it) are
owned by this blueprint. The set of flags is whitelisted and values are coerced to a
bare true/false, so a request can never write an arbitrary key or value into the .env.
"""

from __future__ import annotations

import os
import re
import subprocess

from flask import Blueprint, jsonify, render_template, request

from web.auth.helpers import admin_required

mission_control_bp = Blueprint('mission_control', __name__)

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
ENV_FILE = os.path.join(_REPO_ROOT, 'data', 'transient', '.env')


def _bsa():
    """Lazily import the bot/system logic module (cached in sys.modules after the
    first call). Lazy so any problem importing it degrades only Mission Control rather
    than breaking web-app startup."""
    import deployment.bot_status_api as bsa
    return bsa


# --- Page --------------------------------------------------------------------

@mission_control_bp.route('/mission-control')
@admin_required
def mission_control_page():
    return render_template('mission_control.html')


# --- Bot + system status / control (reused from bot_status_api) --------------
# GET handlers there are unauthenticated already; the five mutating handlers are
# HTTP-Basic-wrapped, so we call ``.__wrapped__`` — the admin gate above is the gate.

@mission_control_bp.route('/mission-control/api/status', methods=['GET'])
@admin_required
def mc_status():
    return _bsa().get_all_status()


@mission_control_bp.route('/mission-control/api/status/<bot_key>', methods=['GET'])
@admin_required
def mc_single_status(bot_key):
    return _bsa().get_single_status(bot_key)


@mission_control_bp.route('/mission-control/api/control/<bot_key>/<action>', methods=['POST'])
@admin_required
def mc_control(bot_key, action):
    return _bsa().control_bot.__wrapped__(bot_key, action)


@mission_control_bp.route('/mission-control/api/log-viewers/restart', methods=['POST'])
@admin_required
def mc_restart_log_viewers():
    return _bsa().restart_log_viewers.__wrapped__()


@mission_control_bp.route('/mission-control/api/git-pull', methods=['POST'])
@admin_required
def mc_git_pull():
    return _bsa().git_pull.__wrapped__()


@mission_control_bp.route('/mission-control/api/system-status', methods=['GET'])
@admin_required
def mc_system_status():
    return _bsa().system_status()


@mission_control_bp.route('/mission-control/api/lab-vm2-status', methods=['GET'])
@admin_required
def mc_lab_vm2_status():
    return _bsa().lab_vm2_status()


@mission_control_bp.route('/mission-control/api/health', methods=['GET'])
@admin_required
def mc_health():
    return _bsa().health_check()


@mission_control_bp.route('/mission-control/api/llm-health', methods=['GET'])
@admin_required
def mc_llm_health():
    return _bsa().llm_health()


@mission_control_bp.route('/mission-control/api/mac-health', methods=['GET'])
@admin_required
def mc_mac_health():
    return _bsa().mac_health()


# --- Feature switches (owned here) -------------------------------------------

FEATURE_FLAGS = [
    {
        'key': 'ambient_enabled', 'env': 'POKEDEX_AMBIENT_ENABLED',
        'group': 'Pokedex Ambient', 'icon': '👁️', 'label': 'Ambient mode',
        'description': 'Master switch — proactively watch the SOC room and offer/auto-run help. '
                       'Off = fully reactive (mention-only).',
        'default': False, 'restart': ['de-scheduler.service'],
    },
    {
        'key': 'ambient_post', 'env': 'POKEDEX_AMBIENT_POST',
        'group': 'Pokedex Ambient', 'icon': '📣', 'label': 'Post to room (live)',
        'description': 'Off = dry-run: classify and log but never post. On = post answers and cards to the room.',
        'default': True, 'restart': ['de-scheduler.service'],
    },
    {
        'key': 'ambient_autorun', 'env': 'POKEDEX_AMBIENT_AUTORUN',
        'group': 'Pokedex Ambient', 'icon': '⚡', 'label': 'Auto-run read-only',
        'description': 'On = read-only asks (enrich, lookup, status) run automatically; destructive intent always '
                       'needs a click. Off = everything becomes a click-to-run card.',
        'default': True, 'restart': ['de-scheduler.service'],
    },
    {
        'key': 'ambient_post_as_oauth', 'env': 'POKEDEX_AMBIENT_POST_AS_OAUTH',
        'group': 'Pokedex Ambient', 'icon': '🧵', 'label': 'Threaded replies',
        'description': 'On = proactive answers thread under the question via the OAuth identity '
                       '("You via AI Assistant"). Off = standalone bot posts.',
        'default': False, 'restart': ['de-scheduler.service'],
    },
    {
        'key': 'ambient_gist', 'env': 'POKEDEX_AMBIENT_GIST',
        'group': 'Pokedex Ambient', 'icon': '🧠', 'label': 'Conversation gist (v2)',
        'description': 'On = respond to what the whole conversation is asking, consolidating an indicator with a '
                       'follow-up question across messages. Off = score each message independently (v1).',
        'default': False, 'restart': ['de-scheduler.service'],
    },
]

_FLAGS_BY_KEY = {f['key']: f for f in FEATURE_FLAGS}


def _read_env_flag(env_var, default):
    """Current on/off for an env flag, read from the .env FILE — the source of truth
    the target unit loads on restart, not a stale ``os.environ`` snapshot."""
    try:
        with open(ENV_FILE, 'r') as fh:
            for line in fh:
                s = line.strip()
                if s.startswith('#') or '=' not in s:
                    continue
                k, _, v = s.partition('=')
                if k.strip() == env_var:
                    return v.strip().strip('"\'').lower() in ('1', 'true', 'yes', 'on')
    except FileNotFoundError:
        pass
    return default


def _write_env_flag(env_var, enabled):
    """Set ``ENV_VAR=true|false`` in the .env file, preserving everything else —
    updating the line in place if present, appending it otherwise. Writes via a temp
    file + atomic replace so a crash mid-write can't truncate the env file."""
    value = 'true' if enabled else 'false'
    new_line = f'{env_var}={value}\n'
    try:
        with open(ENV_FILE, 'r') as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        lines = []
    pat = re.compile(rf'^\s*{re.escape(env_var)}\s*=')
    replaced = False
    for i, line in enumerate(lines):
        if pat.match(line):
            lines[i] = new_line
            replaced = True
            break
    if not replaced:
        if lines and not lines[-1].endswith('\n'):
            lines[-1] += '\n'
        lines.append(new_line)
    tmp = ENV_FILE + '.tmp'
    with open(tmp, 'w') as fh:
        fh.writelines(lines)
    os.replace(tmp, ENV_FILE)
    return value


def _audit(client_ip, action, name, success, message):
    """Mirror the action into the existing log-viewer audit trail (best-effort)."""
    try:
        _bsa().log_audit_event(client_ip, action, name, success, message)
    except Exception:
        pass


@mission_control_bp.route('/mission-control/api/feature-flags', methods=['GET'])
@admin_required
def mc_get_feature_flags():
    """List toggleable feature flags and their current state (read from the .env file)."""
    out = [{
        'key': f['key'], 'env': f['env'], 'label': f['label'],
        'group': f.get('group', ''), 'icon': f.get('icon', ''),
        'description': f.get('description', ''),
        'enabled': _read_env_flag(f['env'], f.get('default', False)),
    } for f in FEATURE_FLAGS]
    return jsonify({'flags': out})


@mission_control_bp.route('/mission-control/api/feature-flags/<key>', methods=['POST'])
@admin_required
def mc_set_feature_flag(key):
    """Toggle a whitelisted feature flag, then restart the unit(s) that read it."""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
    actor = (getattr(request, 'user', None) or {}).get('email', 'admin')

    flag = _FLAGS_BY_KEY.get(key)
    if not flag:
        return jsonify({'success': False, 'message': 'Unknown feature flag'}), 404

    body = request.get_json(silent=True) or {}
    enabled = bool(body.get('enabled'))
    state = 'on' if enabled else 'off'

    try:
        _write_env_flag(flag['env'], enabled)
    except Exception as e:
        _audit(client_ip, f'feature_flag:{key}:{state}', f"{flag['env']} by {actor}", False, str(e))
        return jsonify({'success': False, 'message': f'Failed to write flag: {e}'}), 500

    # Restart the unit(s) that read the flag so the change is live immediately.
    restart_errors = []
    for unit in flag.get('restart', []):
        try:
            r = subprocess.run(['systemctl', '--user', 'restart', unit],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                restart_errors.append(f'{unit}: {r.stderr.strip() or "restart failed"}')
        except subprocess.TimeoutExpired:
            pass  # systemd restart can outlast the timeout but still complete
        except Exception as e:
            restart_errors.append(f'{unit}: {e}')

    success = not restart_errors
    units = ', '.join(flag.get('restart', [])) or 'no restart needed'
    if success:
        message = f"{flag['label']} turned {state} — restarted {units}"
    else:
        message = f"Flag set {state} but restart had issues: {'; '.join(restart_errors)}"
    _audit(client_ip, f'feature_flag:{key}:{state}', f"{flag['env']} by {actor}", success, message)
    return jsonify({'success': success, 'message': message, 'enabled': enabled, 'key': key})
