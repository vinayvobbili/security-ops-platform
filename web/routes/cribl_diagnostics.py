"""Cribl Edge Diagnostics — self-service web workbench.

Upload a Cribl edge-nodes CSV, view the data, deduplicate, filter,
ping hosts, enrich with ServiceNow CMDB, and export to Excel.
"""

import json
import logging
import os
import platform
import shlex
import subprocess
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

import pandas as pd
from flask import (
    Blueprint, Response, jsonify, render_template, request, send_file,
)

from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)

cribl_diagnostics_bp = Blueprint('cribl_diagnostics', __name__)

# ── In-memory session store ─────────────────────────────────────────
# Each upload gets a UUID key; value is a dict with the DataFrame + metadata.
_sessions: dict = {}
_sessions_lock = Lock()
MAX_SESSIONS = 10  # evict oldest when exceeded

PING_DOMAIN_SUFFIX = ".internal.local"
MAX_WORKERS_PING = 100
REVERSE_SSH_PORT = 2222  # Reverse SSH tunnel to Mac for ping routing
REVERSE_SSH_USER = os.getenv("REVERSE_SSH_USER", "")  # Mac username for SSH tunnel
MAX_WORKERS_SNOW = 30
DECOMMISSIONED_STATUSES = {"retired", "decommissioned", "disposed"}


def _get_session(sid):
    with _sessions_lock:
        return _sessions.get(sid)


def _set_session(sid, data):
    with _sessions_lock:
        _sessions[sid] = data
        # Evict oldest sessions if limit exceeded
        if len(_sessions) > MAX_SESSIONS:
            oldest = sorted(_sessions, key=lambda k: _sessions[k].get('created', 0))
            for old_sid in oldest[:len(_sessions) - MAX_SESSIONS]:
                del _sessions[old_sid]


def _df_to_records(df, page=1, per_page=100):
    """Convert a DataFrame slice to JSON-serialisable records + pagination info."""
    total = len(df)
    start = (page - 1) * per_page
    end = start + per_page
    page_df = df.iloc[start:end]

    records = []
    for _, row in page_df.iterrows():
        rec = {}
        for col in df.columns:
            val = row[col]
            if pd.isna(val):
                rec[col] = None
            else:
                rec[col] = val
        records.append(rec)

    return {
        'records': records,
        'columns': list(df.columns),
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, -(-total // per_page)),  # ceil division
    }


def _summary(df):
    """Return summary stats for a DataFrame."""
    total = len(df)
    host_counts = df['Host'].value_counts()
    unique_hosts = len(host_counts)
    duplicates = int((host_counts > 1).sum())

    connected = int((df['Connection'] == 'Connected').sum())
    disconnected = int((df['Connection'] == 'Disconnected').sum())

    fleet_breakdown = df['Fleet'].value_counts().head(10).to_dict()

    return {
        'total_rows': total,
        'unique_hosts': unique_hosts,
        'duplicate_hosts': duplicates,
        'connected': connected,
        'disconnected': disconnected,
        'fleet_breakdown': {k: int(v) for k, v in fleet_breakdown.items()},
    }


def _epoch_ms_to_str(val):
    try:
        return datetime.fromtimestamp(int(val) / 1000, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (ValueError, TypeError, OSError):
        return ""


# ── Page route ──────────────────────────────────────────────────────

@cribl_diagnostics_bp.route('/cribl-diagnostics')
@log_web_activity
def cribl_diagnostics_page():
    return render_template('cribl_diagnostics.html')


# ── Upload CSV ──────────────────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/upload', methods=['POST'])
@log_web_activity
def api_cribl_upload():
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400

        df = pd.read_csv(file)
        required_cols = {'Connection', 'Host', 'Fleet', 'Connected at'}
        if not required_cols.issubset(set(df.columns)):
            missing = required_cols - set(df.columns)
            return jsonify({'success': False, 'error': f'Missing columns: {missing}'}), 400

        # Add human-readable timestamps
        df['Connected at (UTC)'] = df['Connected at'].apply(_epoch_ms_to_str)
        if 'Disconnected at' in df.columns:
            df['Disconnected at (UTC)'] = df['Disconnected at'].apply(_epoch_ms_to_str)
        if 'Last Heartbeat' in df.columns:
            df['Last Heartbeat (UTC)'] = df['Last Heartbeat'].apply(_epoch_ms_to_str)

        sid = str(uuid.uuid4())
        _set_session(sid, {
            'df': df,
            'original_df': df.copy(),
            'created': datetime.now(timezone.utc).timestamp(),
            'actions': ['Uploaded CSV'],
        })

        summary = _summary(df)
        table = _df_to_records(df, page=1)

        return jsonify({
            'success': True,
            'session_id': sid,
            'summary': summary,
            'table': table,
        })

    except Exception as exc:
        logger.error(f"Upload error: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


# ── Get page of data ────────────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/data')
@log_web_activity
def api_cribl_data():
    sid = request.args.get('session_id')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)

    session = _get_session(sid)
    if not session:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

    table = _df_to_records(session['df'], page=page, per_page=per_page)
    return jsonify({'success': True, 'table': table, 'summary': _summary(session['df'])})


# ── Deduplicate ─────────────────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/deduplicate', methods=['POST'])
@log_web_activity
def api_cribl_deduplicate():
    sid = request.get_json(silent=True, force=True).get('session_id') if request.is_json else request.form.get('session_id')
    session = _get_session(sid)
    if not session:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

    df = session['df']
    before = len(df)

    df = df.sort_values('Connected at', ascending=False)
    df = df.drop_duplicates(subset='Host', keep='first').reset_index(drop=True)

    session['df'] = df
    session['actions'].append(f'Deduplicated: {before} → {len(df)} rows')

    return jsonify({
        'success': True,
        'summary': _summary(df),
        'table': _df_to_records(df, page=1),
        'message': f'Deduplicated: {before:,} → {len(df):,} rows (kept latest per host)',
    })


# ── Filter disconnected ────────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/filter-disconnected', methods=['POST'])
@log_web_activity
def api_cribl_filter_disconnected():
    sid = request.get_json(silent=True, force=True).get('session_id') if request.is_json else request.form.get('session_id')
    session = _get_session(sid)
    if not session:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

    df = session['df']
    before = len(df)
    df = df[df['Connection'] == 'Disconnected'].reset_index(drop=True)

    session['df'] = df
    session['actions'].append(f'Filtered disconnected: {before} → {len(df)} rows')

    return jsonify({
        'success': True,
        'summary': _summary(df),
        'table': _df_to_records(df, page=1),
        'message': f'Filtered to disconnected only: {before:,} → {len(df):,} rows',
    })


# ── Reset to original ──────────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/reset', methods=['POST'])
@log_web_activity
def api_cribl_reset():
    sid = request.get_json(silent=True, force=True).get('session_id') if request.is_json else request.form.get('session_id')
    session = _get_session(sid)
    if not session:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

    session['df'] = session['original_df'].copy()
    # Remove any enrichment columns from a previous run
    enrichment_cols = ['Ping Reachable', 'Ping Latency (ms)', 'Ping Target',
                       'SNOW Status', 'SNOW Lifecycle', 'SNOW Environment',
                       'SNOW CI Class', 'SNOW OS', 'SNOW Country',
                       'Days Disconnected', 'Diagnosis']
    for col in enrichment_cols:
        if col in session['df'].columns:
            session['df'] = session['df'].drop(columns=[col])
    session['actions'] = ['Uploaded CSV', 'Reset to original']

    return jsonify({
        'success': True,
        'summary': _summary(session['df']),
        'table': _df_to_records(session['df'], page=1),
        'message': 'Reset to original uploaded data',
    })


# ── Ping hosts (SSE) ───────────────────────────────────────────────

def _ssh_ping_available():
    """Check if reverse SSH tunnel to Mac is available for remote pings."""
    try:
        result = subprocess.run(
            ["ssh", "-p", str(REVERSE_SSH_PORT), "-o", "BatchMode=yes",
             "-o", "ConnectTimeout=3", f"{REVERSE_SSH_USER}@localhost", "echo", "ok"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


@cribl_diagnostics_bp.route('/api/cribl-diagnostics/ping')
@log_web_activity
def api_cribl_ping():
    sid = request.args.get('session_id')
    session = _get_session(sid)
    if not session:
        return Response(
            f"data: {json.dumps({'status': 'error', 'error': 'Session not found'})}\n\n",
            mimetype='text/event-stream',
        )

    df = session['df']

    # Only ping unique hostnames
    unique_hosts = df['Host'].unique().tolist()
    use_ssh = _ssh_ping_available()

    def generate():
        yield f"data: {json.dumps({'status': 'started', 'total': len(unique_hosts)})}\n\n"

        results = {}  # hostname -> {reachable, latency, target}

        if use_ssh:
            # Route pings through Mac via reverse SSH tunnel.
            # Runs all pings in parallel on the Mac in a single SSH session,
            # streaming results back line-by-line for SSE progress.
            targets_map = {}  # FQDN target -> original hostname
            for h in unique_hosts:
                target = h if h.endswith(PING_DOMAIN_SUFFIX) else h + PING_DOMAIN_SUFFIX
                targets_map[target] = h

            target_args = ' '.join(shlex.quote(t) for t in targets_map)
            script = f'''
for host in {target_args}; do
    (
        if result=$(ping -c 1 -t 2 "$host" 2>/dev/null); then
            latency=$(echo "$result" | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2)
            printf '%s|OK|%s\\n' "$host" "$latency"
        else
            printf '%s|FAIL|\\n' "$host"
        fi
    ) &
done
wait
'''
            proc = subprocess.Popen(
                ["ssh", "-p", str(REVERSE_SSH_PORT), "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=5", f"{REVERSE_SSH_USER}@localhost", "bash"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            proc.stdin.write(script)
            proc.stdin.close()

            completed = 0
            for line in proc.stdout:
                line = line.strip()
                if not line or '|' not in line:
                    continue
                parts = line.split('|', 2)
                if len(parts) != 3:
                    continue
                target, status, latency_str = parts
                hostname = targets_map.get(target, target)
                latency = None
                if latency_str:
                    try:
                        latency = float(latency_str)
                    except ValueError:
                        pass
                results[hostname] = {
                    'reachable': status == 'OK', 'latency': latency, 'target': target
                }
                completed += 1
                if completed % 10 == 0 or completed == len(unique_hosts):
                    reachable_count = sum(1 for r in results.values() if r['reachable'])
                    yield f"data: {json.dumps({'status': 'progress', 'completed': completed, 'total': len(unique_hosts), 'reachable': reachable_count})}\n\n"

            proc.wait(timeout=10)

            # Fill in any hosts that didn't return a result (SSH died mid-run)
            for h in unique_hosts:
                if h not in results:
                    target = h if h.endswith(PING_DOMAIN_SUFFIX) else h + PING_DOMAIN_SUFFIX
                    results[h] = {'reachable': False, 'latency': None, 'target': target}
        else:
            # Local pings (fallback when SSH tunnel is unavailable)
            is_mac = platform.system() == "Darwin"
            timeout_flag = "-t" if is_mac else "-W"

            def ping_one(hostname):
                target = hostname if hostname.endswith(PING_DOMAIN_SUFFIX) else hostname + PING_DOMAIN_SUFFIX
                try:
                    result = subprocess.run(
                        ["ping", "-c", "1", timeout_flag, "2", target],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0:
                        latency = None
                        for ln in result.stdout.splitlines():
                            if "time=" in ln:
                                try:
                                    latency = float(ln.split("time=")[1].split()[0].rstrip("ms"))
                                except (ValueError, IndexError):
                                    pass
                                break
                        return hostname, True, latency, target
                    return hostname, False, None, target
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    return hostname, False, None, target

            completed = 0
            with ThreadPoolExecutor(max_workers=MAX_WORKERS_PING) as executor:
                futures = {executor.submit(ping_one, h): h for h in unique_hosts}
                for future in as_completed(futures):
                    hostname, reachable, latency, target = future.result()
                    results[hostname] = {
                        'reachable': reachable, 'latency': latency, 'target': target
                    }
                    completed += 1
                    if completed % 10 == 0 or completed == len(unique_hosts):
                        reachable_count = sum(1 for r in results.values() if r['reachable'])
                        yield f"data: {json.dumps({'status': 'progress', 'completed': completed, 'total': len(unique_hosts), 'reachable': reachable_count})}\n\n"

        # Apply results to the DataFrame
        df['Ping Target'] = df['Host'].map(lambda h: results.get(h, {}).get('target', ''))
        df['Ping Reachable'] = df['Host'].map(
            lambda h: 'Yes' if results.get(h, {}).get('reachable') else 'No'
        )
        df['Ping Latency (ms)'] = df['Host'].map(
            lambda h: results.get(h, {}).get('latency')
        )
        session['actions'].append(f'Pinged {len(unique_hosts)} hosts')

        reachable_count = sum(1 for r in results.values() if r['reachable'])
        yield f"data: {json.dumps({'status': 'complete', 'reachable': reachable_count, 'unreachable': len(unique_hosts) - reachable_count})}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


# ── SNOW enrichment (SSE) ──────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/enrich-snow')
@log_web_activity
def api_cribl_enrich_snow():
    sid = request.args.get('session_id')
    session = _get_session(sid)
    if not session:
        return Response(
            f"data: {json.dumps({'status': 'error', 'error': 'Session not found'})}\n\n",
            mimetype='text/event-stream',
        )

    df = session['df']
    unique_hosts = df['Host'].unique().tolist()

    def generate():
        yield f"data: {json.dumps({'status': 'started', 'total': len(unique_hosts)})}\n\n"

        try:
            from services.service_now import ServiceNowClient
            snow_client = ServiceNowClient(requests_per_second=30)
        except Exception as e:
            yield f"data: {json.dumps({'status': 'error', 'error': f'Failed to init ServiceNow client: {e}'})}\n\n"
            return

        results = {}

        def enrich_one(hostname):
            try:
                details = snow_client.get_host_details(hostname)
                if details.get("status") == "Not Found":
                    return hostname, {'snow_status': 'Not Found'}
                elif details.get("status") == "ServiceNow API Error":
                    return hostname, {'snow_status': f"Error: {details.get('error', 'Unknown')}"}
                else:
                    return hostname, {
                        'snow_status': 'Found',
                        'lifecycle': details.get('lifecycleStatus', ''),
                        'environment': details.get('environment', ''),
                        'ci_class': details.get('ciClass', ''),
                        'os': details.get('operatingSystem', ''),
                        'country': details.get('country', ''),
                    }
            except Exception as e:
                return hostname, {'snow_status': f'Error: {e}'}

        completed = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_SNOW) as executor:
            futures = {executor.submit(enrich_one, h): h for h in unique_hosts}
            for future in as_completed(futures):
                hostname, data = future.result()
                results[hostname] = data
                completed += 1
                if completed % 5 == 0 or completed == len(unique_hosts):
                    found = sum(1 for r in results.values() if r.get('snow_status') == 'Found')
                    yield f"data: {json.dumps({'status': 'progress', 'completed': completed, 'total': len(unique_hosts), 'found': found})}\n\n"

        # Apply to DataFrame
        df['SNOW Status'] = df['Host'].map(lambda h: results.get(h, {}).get('snow_status', ''))
        df['SNOW Lifecycle'] = df['Host'].map(lambda h: results.get(h, {}).get('lifecycle', ''))
        df['SNOW Environment'] = df['Host'].map(lambda h: results.get(h, {}).get('environment', ''))
        df['SNOW CI Class'] = df['Host'].map(lambda h: results.get(h, {}).get('ci_class', ''))
        df['SNOW OS'] = df['Host'].map(lambda h: results.get(h, {}).get('os', ''))
        df['SNOW Country'] = df['Host'].map(lambda h: results.get(h, {}).get('country', ''))
        session['actions'].append(f'Enriched {len(unique_hosts)} hosts with ServiceNow')

        found = sum(1 for r in results.values() if r.get('snow_status') == 'Found')
        yield f"data: {json.dumps({'status': 'complete', 'found': found, 'not_found': len(unique_hosts) - found})}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


# ── Diagnose ────────────────────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/diagnose', methods=['POST'])
@log_web_activity
def api_cribl_diagnose():
    sid = request.get_json(silent=True, force=True).get('session_id') if request.is_json else request.form.get('session_id')
    session = _get_session(sid)
    if not session:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

    df = session['df']

    # Calculate days disconnected
    now = datetime.now(timezone.utc)
    def calc_days(val):
        try:
            dt = datetime.fromtimestamp(int(val) / 1000, tz=timezone.utc)
            return (now - dt).days
        except (ValueError, TypeError, OSError):
            return None

    if 'Disconnected at' in df.columns:
        df['Days Disconnected'] = df['Disconnected at'].apply(calc_days)

    # Diagnose based on available data
    def diagnose_row(row):
        lifecycle = str(row.get('SNOW Lifecycle', '')).lower().strip()
        if lifecycle in DECOMMISSIONED_STATUSES:
            return 'Decommissioned'
        ping = str(row.get('Ping Reachable', '')).strip()
        if ping == 'Yes':
            return 'Agent Down (Host Reachable)'
        elif ping == 'No':
            return 'Host Down'
        # No ping data — check connection status
        if row.get('Connection') == 'Connected':
            return 'Online'
        return 'Unknown'

    df['Diagnosis'] = df.apply(diagnose_row, axis=1)
    session['actions'].append('Diagnosed nodes')

    # Build diagnosis summary
    diag_counts = df['Diagnosis'].value_counts().to_dict()

    return jsonify({
        'success': True,
        'summary': _summary(df),
        'table': _df_to_records(df, page=1),
        'diagnosis_counts': {k: int(v) for k, v in diag_counts.items()},
        'message': 'Diagnosis complete',
    })


# ── Export to Excel ─────────────────────────────────────────────────

@cribl_diagnostics_bp.route('/api/cribl-diagnostics/export')
@log_web_activity
def api_cribl_export():
    sid = request.args.get('session_id')
    session = _get_session(sid)
    if not session:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

    df = session['df']

    # Drop the raw epoch columns from the export (keep human-readable ones)
    drop_cols = []
    if 'Connected at (UTC)' in df.columns and 'Connected at' in df.columns:
        drop_cols.append('Connected at')
    if 'Disconnected at (UTC)' in df.columns and 'Disconnected at' in df.columns:
        drop_cols.append('Disconnected at')
    if 'Last Heartbeat (UTC)' in df.columns and 'Last Heartbeat' in df.columns:
        drop_cols.append('Last Heartbeat')

    export_df = df.drop(columns=drop_cols, errors='ignore')

    ROOT_DIR = Path(__file__).parent.parent.parent
    today = datetime.now().strftime('%m-%d-%Y')
    output_dir = ROOT_DIR / 'data' / 'transient' / 'cribl' / today
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    output_path = output_dir / f'Cribl_Edge_Diagnostics_{timestamp}.xlsx'
    export_df.to_excel(output_path, index=False, engine='openpyxl')

    try:
        from src.utils.excel_formatting import apply_professional_formatting
        apply_professional_formatting(output_path)
    except Exception as e:
        logger.warning(f"Formatting failed (export still works): {e}")

    return send_file(
        output_path,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'Cribl_Edge_Diagnostics_{timestamp}.xlsx',
    )
