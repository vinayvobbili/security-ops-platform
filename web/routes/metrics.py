"""Metrics routes: shift performance, meaningful metrics, EPP tagging."""

import logging
import os

from flask import Blueprint, jsonify, render_template, request, send_file

from src.utils.logging_utils import log_web_activity
from src.components.web import shift_performance_handler, meaningful_metrics_handler, epp_tagging_handler
from src.components.web.async_export_manager import get_export_manager
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
        return jsonify({'success': False, 'error': str(exc)}), 500


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
        return jsonify({'success': False, 'error': str(exc)}), 500


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
        return jsonify({'success': False, 'error': str(val_err)}), 400
    except Exception as exc:
        logger.error(f"Error exporting meaningful metrics: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@metrics_bp.route('/api/meaningful-metrics/export-async/start', methods=['POST'])
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
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        def export_wrapper(progress_callback):
            """Wrapper to call export_meaningful_metrics with progress."""
            return meaningful_metrics_handler.export_meaningful_metrics_async(
                base_dir,
                EASTERN,
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
        return jsonify({'success': False, 'error': str(exc)}), 500


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
        return jsonify({'success': False, 'error': str(exc)}), 500


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
        return jsonify({'success': False, 'error': str(exc)}), 500


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
