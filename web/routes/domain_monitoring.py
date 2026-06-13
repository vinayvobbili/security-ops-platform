"""Domain monitoring routes."""

import json
import logging
import re
import tempfile
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file

from services.cert_transparency import (
    get_outstanding_threats,
    acknowledge_threat,
    acknowledge_all_threats,
)
from src.utils.logging_utils import log_web_activity
from web.auth.helpers import login_required, current_user
from web.auth.rbac import require_capability, SEND_EXTERNAL, MANAGE_DOMAIN_MONITORING_WATCHLIST

logger = logging.getLogger(__name__)
domain_monitoring_bp = Blueprint('domain_monitoring', __name__)

# Domain Monitoring Results Directory
MONITORING_RESULTS_DIR = Path(__file__).parent.parent.parent / "data" / "transient" / "domain_monitoring"


def _load_results_for(date_str=None):
    """Load a results.json (latest or a specific YYYY-MM-DD), or return None."""
    if date_str:
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
            return None
        filepath = MONITORING_RESULTS_DIR / date_str / 'results.json'
    else:
        filepath = MONITORING_RESULTS_DIR / 'latest.json'
    if not filepath.exists():
        return None
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def _xsoar_case_url(ticket_id):
    """Build the XSOAR PROD case URL for a ticket id, or '' if unavailable."""
    if not ticket_id:
        return ''
    from my_config import get_config
    base = (get_config().xsoar_prod_ui_base_url or '').rstrip('/')
    return f"{base}/Custom/caseinfoid/{ticket_id}" if base else ''


@domain_monitoring_bp.route('/domain-monitoring')
@domain_monitoring_bp.route('/domain-monitoring/<filename>')
@log_web_activity
def domain_monitoring_report(filename=None):
    """Display domain monitoring report page."""
    return render_template('domain_monitoring_report.html', filename=filename)


@domain_monitoring_bp.route('/api/domain-monitoring/results')
@domain_monitoring_bp.route('/api/domain-monitoring/results/<date_str>')
@log_web_activity
def api_domain_monitoring_results(date_str=None):
    """API endpoint to get monitoring results.

    Args:
        date_str: Optional date string (YYYY-MM-DD) for historical results.
                  Defaults to latest.json.
    """
    try:
        import re

        if date_str is None:
            # Load latest results
            filepath = MONITORING_RESULTS_DIR / 'latest.json'
        else:
            # Validate date format to prevent directory traversal
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
                return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

            # Load from date subdirectory
            filepath = MONITORING_RESULTS_DIR / date_str / 'results.json'

        if not filepath.exists():
            return jsonify({
                'success': False,
                'error': 'No monitoring results found. Run the daily monitoring job first.'
            }), 404

        with open(filepath, 'r') as f:
            results = json.load(f)

        return jsonify({'success': True, 'results': results, 'date': date_str})

    except Exception as exc:
        logger.error(f"Error fetching monitoring results: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/history')
@log_web_activity
def api_domain_monitoring_history():
    """API endpoint to list available monitoring result files."""
    try:
        if not MONITORING_RESULTS_DIR.exists():
            return jsonify({'success': True, 'files': []})

        files = []
        # Look for date subdirectories (YYYY-MM-DD format) containing results.json
        for date_dir in sorted(MONITORING_RESULTS_DIR.iterdir(), reverse=True):
            if date_dir.is_dir() and len(date_dir.name) == 10:  # YYYY-MM-DD is 10 chars
                results_file = date_dir / 'results.json'
                if results_file.exists():
                    stat = results_file.stat()
                    files.append({
                        'filename': date_dir.name,  # The date string
                        'date': date_dir.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })

        return jsonify({'success': True, 'files': files})

    except Exception as exc:
        logger.error(f"Error listing monitoring history: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/threats')
@log_web_activity
def api_outstanding_threats():
    """API endpoint to get outstanding (unacknowledged) threats."""
    try:
        threats = get_outstanding_threats()
        return jsonify({'success': True, 'threats': threats, 'count': len(threats)})
    except Exception as exc:
        logger.error(f"Error fetching outstanding threats: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/threats/acknowledge', methods=['POST'])
@login_required
@log_web_activity
def api_acknowledge_threat():
    """API endpoint to acknowledge a threat (remove from outstanding)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

        domain = data.get('domain')
        ack_all = data.get('all', False)

        if ack_all:
            count = acknowledge_all_threats()
            logger.info(f"Acknowledged all {count} outstanding threats")
            return jsonify({'success': True, 'message': f'Acknowledged {count} threats'})

        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        if acknowledge_threat(domain):
            logger.info(f"Acknowledged threat: {domain}")
            return jsonify({'success': True, 'message': f'Acknowledged {domain}'})
        else:
            return jsonify({'success': False, 'error': f'Threat not found: {domain}'}), 404

    except Exception as exc:
        logger.error(f"Error acknowledging threat: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── Takedown — create a PhishFort incident + notify the Domain Monitoring room ──
@domain_monitoring_bp.route('/api/domain-monitoring/takedown', methods=['POST'])
@login_required
@require_capability(SEND_EXTERNAL)
@log_web_activity
def api_submit_takedown():
    """Submit a takedown for a malicious domain.

    Creates a PhishFort incident (external write — hard-disabled on the dev
    instance) and posts a takedown-request notification to the Domain Monitoring
    Webex room. Gated on the send.external capability.
    """
    try:
        data = request.get_json(silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        user = current_user() or {}

        # Attach the stored weaponization assessment as takedown evidence, if any.
        evidence = None
        try:
            from src.components.domain_monitoring.findings_ledger import get_finding
            from src.components.domain_monitoring.weaponization import evidence_summary
            row = get_finding(domain)
            if row and row.get('weaponization_json'):
                import json as _json
                evidence = evidence_summary(_json.loads(row['weaponization_json'])) or None
        except Exception as ev_exc:
            logger.debug(f"No weaponization evidence for {domain}: {ev_exc}")

        from services.phish_fort import submit_takedown
        result = submit_takedown(
            domain=domain,
            url=data.get('url'),
            reason=data.get('reason'),
            submitted_by=user.get('email'),
            rf_risk_score=data.get('rf_risk_score'),
            evidence=evidence,
        )

        # Record the takedown (+ PhishFort incident id) into the findings ledger
        # so it shows up in the monthly report. Best-effort.
        try:
            from src.components.domain_monitoring.findings_ledger import record_takedown
            pf = result.get('phishfort')
            incident_id = pf.get('incident_id') if isinstance(pf, dict) else None
            record_takedown(domain, incident_id=incident_id, assignee=user.get('email'))
        except Exception as ledger_exc:
            logger.warning(f"Could not record takedown in ledger: {ledger_exc}")

        status = 200 if result.get('ok') else 502
        return jsonify({'success': result.get('ok', False), 'result': result}), status

    except Exception as exc:
        logger.error(f"Error submitting takedown: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── Block — proactively block a malicious domain via XSOAR (CIRT playbook) ──
@domain_monitoring_bp.route('/api/domain-monitoring/block', methods=['POST'])
@login_required
@require_capability(SEND_EXTERNAL)
@log_web_activity
def api_block_domain():
    """Block a malicious domain via XSOAR (fires the CIRT URL-block playbook).

    Containment that runs ahead of a takedown — protect users now, broker the
    takedown after. Gated on the send.external capability and HARD-disabled
    off-prod: the underlying TicketHandler is pinned to the PROD XSOAR tenant,
    so a dev-instance call would push a real production block.
    """
    try:
        data = request.get_json(silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        from my_config import get_config
        if not get_config().is_production:
            return jsonify({
                'success': False,
                'error': 'XSOAR block is disabled on the dev instance '
                         '(it would act on the production XSOAR tenant).',
            }), 403

        user = current_user() or {}
        reason = (data.get('reason') or '').strip() or \
            f"Domain Monitoring: malicious lookalike block requested by {user.get('email')}"

        from services.xsoar.url_block import block_url_via_xsoar
        result = block_url_via_xsoar(
            url=domain,
            reason=reason,
            owner=user.get('email'),
            xsoar_ticket_id=(data.get('xsoar_ticket_id') or '').strip(),
        )

        # Record the block (+ XSOAR ticket id) into the findings ledger so it
        # surfaces in the queue and monthly report. Best-effort.
        if result.get('success'):
            result['url'] = _xsoar_case_url(result.get('ticket_id'))
            try:
                from src.components.domain_monitoring.findings_ledger import record_block
                record_block(domain, xsoar_ticket_id=result.get('ticket_id'),
                             assignee=user.get('email'))
            except Exception as ledger_exc:
                logger.warning(f"Could not record block in ledger: {ledger_exc}")

        status = 200 if result.get('success') else 502
        return jsonify({'success': result.get('success', False), 'result': result}), status

    except Exception as exc:
        logger.error(f"Error blocking domain via XSOAR: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── Weaponization triage — is this lookalike actually a live phishing kit? ─────
@domain_monitoring_bp.route('/api/domain-monitoring/assess', methods=['POST'])
@login_required
@log_web_activity
def api_assess_domain():
    """Score a domain's weaponization (live page + DNS signals + LLM verdict) and
    persist it to the findings ledger. Read-only — fetches the suspect page and
    calls the LLM, takes no outbound action, so open to any verified user."""
    try:
        data = request.get_json(silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400
        from src.components.domain_monitoring.weaponization import score_and_record
        result = score_and_record(domain, brand=data.get('brand'))
        return jsonify({'success': True, 'result': result})
    except Exception as exc:
        logger.error(f"Error assessing domain: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── "Were we touched?" — async exposure hunt across DNS/proxy/EDR ──────────────
@domain_monitoring_bp.route('/api/domain-monitoring/exposure-hunt', methods=['POST'])
@login_required
@log_web_activity
def api_exposure_hunt():
    """Kick a background 'were we touched?' hunt for a domain. Returns immediately;
    poll the finding endpoint for exposure_status (running → done/error)."""
    try:
        data = request.get_json(silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400
        from src.components.domain_monitoring.exposure_hunt import start_exposure_hunt
        start_exposure_hunt(domain, tools=data.get('tools'))
        return jsonify({'success': True, 'domain': domain, 'status': 'running'})
    except Exception as exc:
        logger.error(f"Error starting exposure hunt: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── Finding detail — poll target for assess/hunt status + stored verdicts ──────
@domain_monitoring_bp.route('/api/domain-monitoring/finding/<path:domain>')
@login_required
@log_web_activity
def api_get_finding(domain):
    """Return a single ledger finding (used by the dashboard to poll assess/hunt
    progress and render stored weaponization + exposure results)."""
    try:
        from src.components.domain_monitoring.findings_ledger import get_finding
        row = get_finding((domain or '').strip().lower())
        if not row:
            return jsonify({'success': False, 'error': 'Finding not found'}), 404
        import json as _json
        for blob_key in ('weaponization_json', 'exposure_json'):
            if row.get(blob_key):
                try:
                    row[blob_key.replace('_json', '')] = _json.loads(row[blob_key])
                except (ValueError, TypeError):
                    pass
        return jsonify({'success': True, 'finding': row})
    except Exception as exc:
        logger.error(f"Error loading finding: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── Blocked domains map — one-shot hydration so blocked rows show their ticket ──
@domain_monitoring_bp.route('/api/domain-monitoring/blocked')
@login_required
@log_web_activity
def api_blocked_domains():
    """Return {domain: {ticket_id, url}} for every finding with an XSOAR block
    ticket, so the dashboard can render the ticket link in place of the Block
    button on page load (the block state survives reloads)."""
    try:
        from src.components.domain_monitoring.findings_ledger import list_findings
        blocked = {}
        for f in list_findings(limit=5000):
            tid = f.get('xsoar_id')
            if tid:
                blocked[f['domain']] = {'ticket_id': tid, 'url': _xsoar_case_url(tid)}
        return jsonify({'success': True, 'blocked': blocked})
    except Exception as exc:
        logger.error(f"Error loading blocked domains: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── Excel export of the current monitoring results ─────────────────────────────
@domain_monitoring_bp.route('/api/domain-monitoring/export')
@domain_monitoring_bp.route('/api/domain-monitoring/export/<date_str>')
@login_required
@log_web_activity
def api_export_results(date_str=None):
    """Export a monitoring report as a professionally formatted, multi-sheet xlsx."""
    results = _load_results_for(date_str)
    if results is None:
        return jsonify({'success': False, 'error': 'No monitoring results to export'}), 404

    try:
        from src.components.domain_monitoring.export import build_export_workbook
        report_date = date_str or 'latest'
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx', dir='/tmp')
        tmp_path = tmp.name
        tmp.close()
        build_export_workbook(results, tmp_path, report_date)
        download_name = f"domain_monitoring_{report_date}.xlsx"
        return send_file(tmp_path, as_attachment=True, download_name=download_name,
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as exc:
        logger.error(f"Error exporting monitoring results: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to build export'}), 500


# ── Watchlist management — view + edit the monitored lists ─────────────────────
@domain_monitoring_bp.route('/api/domain-monitoring/watchlist')
@login_required
@log_web_activity
def api_get_watchlist_config():
    """Return the editable monitoring lists for the management panel (read-only
    for any verified user; edits require the manage.domain_monitoring_watchlist
    capability)."""
    try:
        from src.components.domain_monitoring.config import load_full_config, EDITABLE_LISTS
        config = load_full_config()
        lists = {key: {'label': label, 'entries': config.get(key, [])}
                 for key, label in EDITABLE_LISTS.items()}
        return jsonify({'success': True, 'lists': lists})
    except Exception as exc:
        logger.error(f"Error loading watchlist config: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/watchlist', methods=['POST'])
@login_required
@require_capability(MANAGE_DOMAIN_MONITORING_WATCHLIST)
@log_web_activity
def api_edit_watchlist_config():
    """Add or remove a domain/keyword on an editable monitoring list."""
    try:
        data = request.get_json(silent=True) or {}
        key = data.get('key')
        action = data.get('action')
        value = data.get('value')
        if not all([key, action, value]):
            return jsonify({'success': False, 'error': 'key, action and value are required'}), 400

        from src.components.domain_monitoring.config import edit_config_list
        result = edit_config_list(key, action, value)
        return jsonify({'success': result.get('ok', False), **result}), (200 if result.get('ok') else 400)
    except Exception as exc:
        logger.error(f"Error editing watchlist config: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# ── Monthly Brand-Protection report ────────────────────────────────────────────
@domain_monitoring_bp.route('/domain-monitoring/reports')
@login_required
@log_web_activity
def domain_monitoring_reports():
    """Leadership-facing monthly Domain Monitoring & Brand Protection report."""
    return render_template('domain_monitoring_reports.html')


@domain_monitoring_bp.route('/api/domain-monitoring/reports/months')
@login_required
@log_web_activity
def api_report_months():
    """List months that have findings (for the month picker)."""
    try:
        from src.components.domain_monitoring.findings_ledger import available_months
        return jsonify({'success': True, 'months': available_months()})
    except Exception as exc:
        logger.error(f"Error listing report months: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/reports/<month>')
@login_required
@log_web_activity
def api_report_rollup(month):
    """Return the monthly rollup (YYYY-MM) for the report page."""
    if not re.match(r'^\d{4}-\d{2}$', month):
        return jsonify({'success': False, 'error': 'Invalid month. Use YYYY-MM.'}), 400
    try:
        from src.components.domain_monitoring.findings_ledger import monthly_rollup
        return jsonify({'success': True, 'rollup': monthly_rollup(month)})
    except Exception as exc:
        logger.error(f"Error building monthly rollup: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/reports/sync-statuses', methods=['POST'])
@login_required
@log_web_activity
def api_sync_takedown_statuses():
    """Pull current PhishFort incident statuses into the ledger so the SLA tiles
    reflect live takedown progress. Read-only against PhishFort (no incidents are
    created), so open to any verified user; no-ops without an API key."""
    try:
        from services.phish_fort import sync_phishfort_statuses
        return jsonify({'success': True, 'result': sync_phishfort_statuses()})
    except Exception as exc:
        logger.error(f"Error syncing takedown statuses: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/reports/<month>/export')
@login_required
@log_web_activity
def api_report_export(month):
    """Download the monthly report as a formatted xlsx."""
    if not re.match(r'^\d{4}-\d{2}$', month):
        return jsonify({'success': False, 'error': 'Invalid month. Use YYYY-MM.'}), 400
    try:
        from src.components.domain_monitoring.findings_ledger import monthly_rollup
        from src.components.domain_monitoring.export import build_monthly_report_workbook
        rollup = monthly_rollup(month)
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx', dir='/tmp')
        tmp_path = tmp.name
        tmp.close()
        build_monthly_report_workbook(rollup, tmp_path, month)
        return send_file(tmp_path, as_attachment=True,
                         download_name=f"brand_protection_report_{month}.xlsx",
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as exc:
        logger.error(f"Error exporting monthly report: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to build report'}), 500


@domain_monitoring_bp.route('/api/domain-monitoring/findings/triage', methods=['POST'])
@login_required
@require_capability(MANAGE_DOMAIN_MONITORING_WATCHLIST)
@log_web_activity
def api_triage_finding():
    """Apply analyst triage (status / brand / assignee / notes / xsoar id)."""
    try:
        data = request.get_json(silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        if not domain:
            return jsonify({'success': False, 'error': 'domain is required'}), 400
        from src.components.domain_monitoring.findings_ledger import set_triage
        result = set_triage(
            domain=domain,
            status=data.get('status'),
            brand=data.get('brand'),
            assignee=data.get('assignee'),
            notes=data.get('notes'),
            xsoar_id=data.get('xsoar_id'),
        )
        return jsonify({'success': result.get('ok', False), **result}), (200 if result.get('ok') else 400)
    except Exception as exc:
        logger.error(f"Error applying triage: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500
