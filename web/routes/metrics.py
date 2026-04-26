"""Metrics routes: shift performance, meaningful metrics, EPP tagging, threat intel, defense pulse."""

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from queue import Queue

from flask import Blueprint, jsonify, render_template, request, send_file, Response

from src.utils.logging_utils import get_client_ip, log_web_activity
from src.components.web import shift_performance_handler, meaningful_metrics_handler, epp_tagging_handler, threat_intel_dashboard_handler
from src.components.web.async_export_manager import get_export_manager, hash_export_request
from web.config import CONFIG, EASTERN, prod_ticket_handler

logger = logging.getLogger(__name__)
metrics_bp = Blueprint('metrics', __name__)


# --- Shift Performance ---

@metrics_bp.route('/shift-performance')
@log_web_activity
def shift_performance_dashboard():
    """Display shift performance page - loads instantly with empty structure"""
    return render_template(
        'shift_performance.html',
        xsoar_prod_ui_base=getattr(CONFIG, 'xsoar_prod_ui_base_url', 'https://msoar.crtx.us.paloaltonetworks.com')
    )


@metrics_bp.route('/api/shift-list')
@log_web_activity
def get_shift_list():
    """Single source of truth for shift performance data."""
    try:
        shift_data = shift_performance_handler.get_shift_list_data(prod_ticket_handler, EASTERN)
        return jsonify({'success': True, 'data': shift_data})
    except Exception as exc:
        logger.error(f"Error fetching shift list: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/clear-cache', methods=['POST'])
@log_web_activity
def clear_shift_cache():
    """No-op endpoint for compatibility with frontend cache clearing."""
    return jsonify({'success': True, 'message': 'No backend cache (frontend-only caching)'})


# --- Meaningful Metrics ---

@metrics_bp.route('/meaningful-metrics')
@log_web_activity
def meaningful_metrics():
    """Meaningful Metrics Dashboard"""
    return render_template('meaningful_metrics.html')


@metrics_bp.route('/api/meaningful-metrics/data')
@log_web_activity
def api_meaningful_metrics_data():
    """API to get cached security incident data for dashboard."""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = meaningful_metrics_handler.get_meaningful_metrics_data(base_dir, EASTERN)
        return jsonify(result)
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Cache file not found'}), 404
    except Exception as exc:
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/meaningful-metrics/data/range')
@log_web_activity
def api_meaningful_metrics_data_range():
    """Fetch XSOAR tickets on-demand for an arbitrary date range."""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    if not start_date or not end_date:
        return jsonify({'success': False, 'error': 'start_date and end_date are required'}), 400
    try:
        from src.components.ticket_cache import TicketCache
        tickets = TicketCache.fetch_for_range(start_date, end_date)
        return jsonify({
            'success': True,
            'data': tickets,
            'total_count': len(tickets),
            'data_generated_at': datetime.now(EASTERN).isoformat(),
        })
    except Exception as exc:
        logger.error(f"Error fetching metrics for range {start_date} to {end_date}: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/meaningful-metrics/data/range/stream')
@log_web_activity
def api_meaningful_metrics_data_range_stream():
    """SSE endpoint: fetch XSOAR tickets for a date range with progress updates."""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    if not start_date or not end_date:
        def err():
            yield f"data: {json.dumps({'status': 'error', 'error': 'start_date and end_date are required'})}\n\n"
        return Response(err(), mimetype='text/event-stream')

    def generate():
        q = Queue()

        def on_page(page, page_count, total):
            q.put({'status': 'fetching', 'page': page, 'page_count': page_count, 'total': total})

        def worker():
            try:
                from src.components.ticket_cache import TicketCache
                q.put({'status': 'started'})
                tickets = TicketCache.fetch_for_range(start_date, end_date, progress_callback=on_page)
                q.put({'status': 'processing', 'total': len(tickets)})
                q.put({
                    'status': 'complete',
                    'data': tickets,
                    'total_count': len(tickets),
                    'data_generated_at': datetime.now(EASTERN).isoformat(),
                })
            except Exception as exc:
                logger.error(f"SSE range fetch error: {exc}", exc_info=True)
                q.put({'status': 'error', 'error': str(exc)})

        t = threading.Thread(target=worker, daemon=True)
        t.start()

        while True:
            msg = q.get()
            yield f"data: {json.dumps(msg, default=str)}\n\n"
            if msg['status'] in ('complete', 'error'):
                break

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


@metrics_bp.route('/api/meaningful-metrics/export', methods=['POST'])
@log_web_activity
def api_meaningful_metrics_export():
    """Server-side Excel export with professional formatting."""
    try:
        data = request.get_json()
        if not data or 'filters' not in data:
            return jsonify({'success': False, 'error': 'No filters provided'}), 400

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        temp_path = meaningful_metrics_handler.export_meaningful_metrics(
            base_dir,
            EASTERN,
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
        logger.warning(f"Validation error exporting meaningful metrics: {val_err}")
        return jsonify({'success': False, 'error': 'Invalid export parameters'}), 400
    except Exception as exc:
        logger.error(f"Error exporting meaningful metrics: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/meaningful-metrics/export-async/start', methods=['POST'])
@log_web_activity
def api_meaningful_metrics_export_async_start():
    """Start an async export job and return job ID immediately.

    Concurrency guards:
    - Identical requests (same filters/columns/include_notes) collapse to a
      single underlying job via request-hash dedup.
    - Notes-enabled exports run one-at-a-time globally; subsequent requests
      sit in 'queued' state with a queue_message until the lock frees.
    """
    try:
        data = request.get_json()
        if not data or 'filters' not in data:
            return jsonify({'success': False, 'error': 'No filters provided'}), 400

        filters = data['filters']
        visible_columns = data.get('visible_columns', [])
        column_labels = data.get('column_labels', {})
        include_notes = data.get('include_notes', False)

        # Dedup identical requests (same person double-clicking, same query
        # from two browser tabs, two analysts running the same export, etc.)
        request_hash = hash_export_request(filters, visible_columns, include_notes)
        client_ip = get_client_ip()

        export_manager = get_export_manager()
        job_id, deduped = export_manager.create_or_get_job(
            request_hash=request_hash,
            requested_by=client_ip,
        )

        if deduped:
            # Identical export already in flight — hand back its job_id and let
            # the client latch onto its progress instead of spawning a duplicate.
            return jsonify({
                'success': True,
                'job_id': job_id,
                'status': 'queued',
                'deduped': True,
                'message': 'An identical export is already running; tracking that one.',
            })

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        def export_wrapper(progress_callback, warning_callback):
            """Wrapper to call export_meaningful_metrics with progress + warnings."""
            return meaningful_metrics_handler.export_meaningful_metrics_async(
                base_dir,
                EASTERN,
                filters,
                visible_columns,
                column_labels,
                include_notes,
                progress_callback=progress_callback,
                warning_callback=warning_callback,
            )

        export_manager.start_export_thread(
            job_id,
            export_wrapper,
            serialize_with_notes_lock=bool(include_notes),
        )

        return jsonify({
            'success': True,
            'job_id': job_id,
            'status': 'queued',
            'deduped': False,
        })

    except Exception as exc:
        logger.error(f"Error starting async export: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/meaningful-metrics/export-async/status/<job_id>', methods=['GET'])
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
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/meaningful-metrics/export-async/download/<job_id>', methods=['GET'])
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
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# --- EPP Device Tagging Metrics ---

@metrics_bp.route('/epp-tagging-metrics')
@log_web_activity
def epp_tagging_metrics():
    """EPP Device Tagging Metrics Dashboard"""
    return render_template('epp_tagging_metrics.html')


@metrics_bp.route('/api/epp-tagging/data')
@log_web_activity
def api_epp_tagging_data():
    """API endpoint to get EPP tagging metrics data."""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        platform = request.args.get('platform')

        result = epp_tagging_handler.get_dashboard_data(start_date, end_date, platform)
        return jsonify(result)

    except Exception as exc:
        logger.error(f"Error fetching EPP tagging data: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/epp-tagging/chart/country')
@log_web_activity
def api_epp_tagging_chart_country():
    """API endpoint for country chart data."""
    limit = request.args.get('limit', 20, type=int)
    return jsonify(epp_tagging_handler.get_chart_data_by_country(limit))


@metrics_bp.route('/api/epp-tagging/chart/monthly')
@log_web_activity
def api_epp_tagging_chart_monthly():
    """API endpoint for monthly chart data."""
    return jsonify(epp_tagging_handler.get_chart_data_by_month())


@metrics_bp.route('/api/epp-tagging/chart/platform')
@log_web_activity
def api_epp_tagging_chart_platform():
    """API endpoint for platform chart data."""
    return jsonify(epp_tagging_handler.get_chart_data_by_platform())


@metrics_bp.route('/api/epp-tagging/chart/daily')
@log_web_activity
def api_epp_tagging_chart_daily():
    """API endpoint for daily chart data."""
    days = request.args.get('days', 90, type=int)
    return jsonify(epp_tagging_handler.get_chart_data_daily(days))


# --- Threat Intel Dashboard ---

@metrics_bp.route('/threat-intel-dashboard')
@log_web_activity
def threat_intel_dashboard():
    """Threat Intel Dashboard"""
    return render_template('threat_intel_dashboard.html')


@metrics_bp.route('/api/threat-intel/data')
@log_web_activity
def api_threat_intel_data():
    """API endpoint to get threat intel dashboard data from SQLite."""
    try:
        start_date = request.args.get('start_date')  # YYYY-MM-DD or None
        end_date = request.args.get('end_date')       # YYYY-MM-DD or None
        result = threat_intel_dashboard_handler.get_dashboard_data(start_date=start_date, end_date=end_date)
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching threat intel data: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500



@metrics_bp.route('/api/threat-intel/attack-matrix')
@log_web_activity
def api_threat_intel_attack_matrix():
    """API endpoint to get ATT&CK matrix heatmap data."""
    try:
        actors = [a for a in request.args.get('actor', '').split(',') if a] or None
        tipper_titles = [t for t in request.args.get('tipper_title', '').split(',') if t] or None
        tipper_ids = [int(i) for i in request.args.get('tipper_id', '').split(',') if i.isdigit()] or None
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        result = threat_intel_dashboard_handler.get_attack_matrix_data(actors=actors, tipper_titles=tipper_titles, tipper_ids=tipper_ids, start_date=start_date, end_date=end_date)
        status_code = 200 if result.get('success') else 500
        return jsonify(result), status_code
    except Exception as exc:
        logger.error(f"Error fetching ATT&CK matrix data: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/atlas-matrix')
@log_web_activity
def api_threat_intel_atlas_matrix():
    """API endpoint to get ATLAS matrix heatmap data."""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        result = threat_intel_dashboard_handler.get_atlas_matrix_data(start_date=start_date, end_date=end_date)
        status_code = 200 if result.get('success') else 500
        return jsonify(result), status_code
    except Exception as exc:
        logger.error(f"Error fetching ATLAS matrix data: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/actors')
@log_web_activity
def api_threat_intel_actors():
    """API endpoint to get all distinct threat actor names for filter dropdowns."""
    try:
        from services.threat_intel_db import get_distinct_threat_actors
        actors = get_distinct_threat_actors()
        return jsonify({'success': True, 'actors': actors})
    except Exception as exc:
        logger.error(f"Error fetching threat actors: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/tipper-titles')
@log_web_activity
def api_threat_intel_tipper_titles():
    """API endpoint to get distinct tipper titles for filter dropdowns."""
    try:
        from services.threat_intel_db import get_distinct_tipper_titles
        titles = get_distinct_tipper_titles()
        return jsonify({'success': True, 'titles': titles})
    except Exception as exc:
        logger.error(f"Error fetching tipper titles: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/tipper-ids')
@log_web_activity
def api_threat_intel_tipper_ids():
    """API endpoint to get tipper ID/title pairs for filter dropdowns."""
    try:
        from services.threat_intel_db import get_tipper_id_title_pairs
        tippers = get_tipper_id_title_pairs()
        return jsonify({'success': True, 'tippers': tippers})
    except Exception as exc:
        logger.error(f"Error fetching tipper IDs: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/navigator-layer')
@log_web_activity
def api_threat_intel_navigator_layer():
    """Download ATT&CK Navigator layer JSON file."""
    try:
        import json
        import tempfile
        actors = [a for a in request.args.get('actor', '').split(',') if a] or None
        tipper_titles = [t for t in request.args.get('tipper_title', '').split(',') if t] or None
        tipper_ids = [int(i) for i in request.args.get('tipper_id', '').split(',') if i.isdigit()] or None
        result = threat_intel_dashboard_handler.export_navigator_layer(actors=actors, tipper_titles=tipper_titles, tipper_ids=tipper_ids)
        if not result.get('success'):
            return jsonify(result), 500

        from datetime import datetime
        timestamp = datetime.now(EASTERN).strftime('%Y%m%d_%H%M%S')
        tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        tmp.write(json.dumps(result['layer'], indent=2).encode())
        tmp.close()

        return send_file(
            tmp.name,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'attack_navigator_layer_{timestamp}.json',
        )
    except Exception as exc:
        logger.error(f"Error exporting Navigator layer: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/search')
@log_web_activity
def api_threat_intel_search():
    """Search all entities of a given tab type matching a query string."""
    try:
        tab = request.args.get('tab', '')
        query = request.args.get('q', '').strip()
        if not tab or not query:
            return jsonify({'success': False, 'error': 'Missing tab or q parameter'}), 400
        if tab not in ('domains', 'ips', 'hashes', 'cves', 'malware', 'actors', 'ttps', 'redteam'):
            return jsonify({'success': False, 'error': f'Invalid tab: {tab}'}), 400
        result = threat_intel_dashboard_handler.search_entities(tab, query)
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error searching threat intel: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/export')
@log_web_activity
def api_threat_intel_export():
    """Export a threat intel table tab as a professionally formatted Excel file."""
    try:
        tab = request.args.get('tab', '')
        query = request.args.get('q', '').strip()
        if not tab:
            return jsonify({'success': False, 'error': 'Missing tab parameter'}), 400
        if tab not in ('domains', 'ips', 'hashes', 'cves', 'malware', 'actors', 'ttps', 'redteam'):
            return jsonify({'success': False, 'error': f'Invalid tab: {tab}'}), 400

        file_path = threat_intel_dashboard_handler.export_table(tab, query)
        from datetime import datetime
        timestamp = datetime.now(EASTERN).strftime('%Y%m%d_%H%M%S')
        return send_file(
            file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'threat_intel_{tab}_{timestamp}.xlsx',
        )
    except Exception as exc:
        logger.error(f"Error exporting threat intel tab: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/tippers-for-entity')
@log_web_activity
def api_threat_intel_tippers_for_entity():
    """Get source tippers for a specific entity (drilldown from occurrence count)."""
    try:
        entity_type = request.args.get('type', '')
        entity_value = request.args.get('value', '')
        if not entity_type or not entity_value:
            return jsonify({'success': False, 'error': 'Missing type or value parameter'}), 400
        result = threat_intel_dashboard_handler.get_tippers_for_entity(entity_type, entity_value)
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching tippers for entity: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/enrich', methods=['POST'])
@log_web_activity
def api_threat_intel_enrich():
    """Trigger IOC enrichment with VT and RF data."""
    try:
        vt_limit = request.args.get('vt_limit', 50, type=int)
        rf_limit = request.args.get('rf_limit', 200, type=int)
        result = threat_intel_dashboard_handler.enrich_iocs(vt_limit=vt_limit, rf_limit=rf_limit)
        status_code = 200 if result.get('success') else 500
        return jsonify(result), status_code
    except Exception as exc:
        logger.error(f"Error enriching threat intel IOCs: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/sync-status')
@log_web_activity
def api_threat_intel_sync_status():
    """Get sync status for the threat intel dashboard."""
    try:
        result = threat_intel_dashboard_handler.get_sync_status()
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching sync status: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# --- AttackIQ BAS ---

@metrics_bp.route('/api/threat-intel/attackiq/status')
@log_web_activity
def api_attackiq_status():
    """Get AttackIQ configuration status and assessment counts."""
    try:
        result = threat_intel_dashboard_handler.get_attackiq_status()
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching AttackIQ status: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/attackiq/create/<int:tipper_id>', methods=['POST'])
@log_web_activity
def api_attackiq_create_assessment(tipper_id):
    """Manually create an AttackIQ assessment for a single tipper."""
    try:
        result = threat_intel_dashboard_handler.create_attackiq_assessment_for_tipper(tipper_id)
        status_code = 200 if result.get('success') else 400
        return jsonify(result), status_code
    except Exception as exc:
        logger.error(f"Error creating AttackIQ assessment for tipper {tipper_id}: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# --- Visual Insights ---

@metrics_bp.route('/api/threat-intel/actor-technique-map')
@log_web_activity
def api_actor_technique_map():
    """Get actor-to-technique relationship map for visual insights diagrams."""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        result = threat_intel_dashboard_handler.get_actor_technique_map(start_date, end_date)
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching actor-technique map: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/threat-intel/malware-actor-map')
@log_web_activity
def api_malware_actor_map():
    """Get malware-to-actor relationship map for visual insights diagrams."""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        result = threat_intel_dashboard_handler.get_malware_actor_map(start_date, end_date)
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching malware-actor map: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# --- XSOAR Ticket Timeline ---

@metrics_bp.route('/api/xsoar/timeline')
@log_web_activity
def api_xsoar_timeline():
    """API endpoint to get XSOAR ticket timeline data for bar chart race."""
    try:
        from src.components.web import xsoar_timeline_handler
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        granularity = request.args.get('granularity', 'monthly')
        if granularity not in ('monthly', 'weekly'):
            granularity = 'monthly'
        result = xsoar_timeline_handler.get_timeline_data(start_date=start_date, end_date=end_date, granularity=granularity)
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching XSOAR timeline data: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/xsoar/timeline/status')
@log_web_activity
def api_xsoar_timeline_status():
    """API endpoint to get XSOAR timeline sync status."""
    try:
        from src.components.web import xsoar_timeline_handler
        result = xsoar_timeline_handler.get_sync_status()
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error fetching XSOAR timeline status: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


# --- control-efficacy analytics ---

@metrics_bp.route('/defense-pulse')
@log_web_activity
def defense_pulse():
    """control-efficacy analytics — systemic security gap analysis dashboard."""
    return render_template('defense_pulse.html')


@metrics_bp.route('/api/defense-pulse/filter')
@log_web_activity
def api_defense_pulse_filter():
    """Return re-computed control-efficacy analytics data filtered by a single dimension."""
    try:
        category = request.args.get('category')
        impact = request.args.get('impact')
        source = request.args.get('source')
        vector = request.args.get('vector')
        root_cause = request.args.get('root_cause')

        if not any([category, impact, source, vector, root_cause]):
            return jsonify({'success': False, 'error': 'No filter specified'}), 400

        from src.charts.defense_pulse import (
            load_tickets, _compute_chart_data, _disposition_stats,
            _short_type, _cost_stats, _attack_vector_stats,
            _identity_stats, _repeat_offender_stats,
        )
        import pandas as pd

        tickets = load_tickets()

        if category:
            tickets = [t for t in tickets if t.get('security_category') == category]
        if impact:
            tickets = [t for t in tickets if t.get('impact') == impact]
        if source:
            tickets = [t for t in tickets if _short_type(t.get('type', '')) == source]
        if vector:
            tickets = [t for t in tickets if t.get('attack_vector') == vector]
        if root_cause:
            tickets = [t for t in tickets if t.get('root_cause') == root_cause]

        if not tickets:
            return jsonify({'success': True, 'data': {'total_incidents': 0, 'chart_data': {}}})

        df = pd.DataFrame(tickets)
        ds = _disposition_stats(df)

        from my_config import get_config
        config = get_config()

        return jsonify({
            'success': True,
            'data': {
                'total_incidents': len(tickets),
                'blocked_count': ds['blocked'],
                'escalated_count': ds['escalated'],
                'blocked_pct': round(ds['blocked_pct'], 0),
                'mtp_count': ds['mtp'],
                'mtp_pct': round(ds['mtp_pct'], 1),
                'cost': _cost_stats(df, config.analyst_hourly_cost),
                'attack_vectors': _attack_vector_stats(df),
                'identity': _identity_stats(df),
                'repeat_offenders': _repeat_offender_stats(df),
                'chart_data': _compute_chart_data(tickets),
            }
        })
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Ticket data not found'}), 404
    except Exception as exc:
        logger.error(f"Error filtering control-efficacy analytics data: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@metrics_bp.route('/api/defense-pulse/data')
@log_web_activity
def api_defense_pulse_data():
    """API to get control-efficacy analytics chart paths and report markdown."""
    try:
        web_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        charts_root = web_dir / 'static' / 'charts'

        # Find the latest dated folder that contains control-efficacy analytics charts
        chart_date = None
        for folder in sorted(charts_root.iterdir(), reverse=True):
            if folder.is_dir() and (folder / 'control-efficacy analytics - Dashboard.png').exists():
                chart_date = folder.name
                break

        if not chart_date:
            return jsonify({'success': False, 'error': 'No control-efficacy analytics charts found. Run: python src/charts/defense_pulse.py'}), 404

        chart_dir = charts_root / chart_date

        # Read the markdown report
        report_path = chart_dir / 'control-efficacy analytics - Strategic Report.md'
        report_md = report_path.read_text(encoding='utf-8') if report_path.exists() else ''

        # Get generated timestamp from report first line
        generated_at = ''
        for line in report_md.splitlines():
            if line.startswith('*Generated:'):
                generated_at = line.strip('* ')
                break

        # Get chart file modification time as "last refreshed" timestamp
        dashboard_path = chart_dir / 'control-efficacy analytics - Dashboard.png'
        last_refreshed = datetime.fromtimestamp(
            dashboard_path.stat().st_mtime, tz=EASTERN
        ).strftime('%B %d, %Y %I:%M %p %Z') if dashboard_path.exists() else ''

        # Read KPI summary if available
        import json as _json
        kpi_path = chart_dir / 'control-efficacy analytics - KPIs.json'
        kpis = _json.loads(kpi_path.read_text(encoding='utf-8')) if kpi_path.exists() else {}

        return jsonify({
            'success': True,
            'data': {
                'chart_date': chart_date,
                'generated_at': generated_at,
                'last_refreshed': last_refreshed,
                'next_refresh': 'Biweekly Monday at 06:00 AM ET',
                'kpis': kpis,
                'charts': {
                    'heatmap': 'control-efficacy analytics - Category Impact Heatmap.png',
                    'dashboard': 'control-efficacy analytics - Dashboard.png',
                    'root_cause': 'control-efficacy analytics - Root Cause Detection Source.png',
                    'awareness': 'control-efficacy analytics - Awareness Trends.png',
                    'repeat_offenders': 'control-efficacy analytics - Repeat Offenders.png',
                },
                'report_markdown': report_md,
            }
        })
    except Exception as exc:
        logger.error(f"Error loading control-efficacy analytics data: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500
