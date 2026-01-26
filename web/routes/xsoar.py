"""XSOAR routes: dashboard, incidents, ticket import."""

import logging

from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity
from src.components.web import xsoar_import_handler, xsoar_dashboard_handler
from web.config import CONFIG, prod_ticket_handler, dev_ticket_handler

logger = logging.getLogger(__name__)
xsoar_bp = Blueprint('xsoar', __name__)


# --- XSOAR Ticket Import ---

@xsoar_bp.route('/xsoar-ticket-import-form', methods=['GET'])
@log_web_activity
def xsoar_ticket_import_form():
    return render_template('xsoar-ticket-import-form.html')


@xsoar_bp.route("/import-xsoar-ticket", methods=['POST'])
@log_web_activity
def import_xsoar_ticket():
    source_ticket_number = request.form.get('source_ticket_number')
    file_data = request.files.get('file')
    destination_ticket_number, destination_ticket_link = xsoar_import_handler.import_ticket(
        source_ticket_number,
        file_data,
        dev_ticket_handler
    )
    return jsonify({
        'source_ticket_number': source_ticket_number,
        'destination_ticket_number': destination_ticket_number,
        'destination_ticket_link': destination_ticket_link
    })


# --- XSOAR Dashboard ---

@xsoar_bp.route('/xsoar')
@log_web_activity
def xsoar_dashboard():
    """XSOAR incident dashboard"""
    return render_template('xsoar_dashboard.html')


@xsoar_bp.route('/api/xsoar/incidents')
@log_web_activity
def api_xsoar_incidents():
    """API to get XSOAR incidents with search and pagination"""
    query = request.args.get('query', '')
    period = request.args.get('period')
    size = int(request.args.get('size', 50))

    try:
        incidents = xsoar_dashboard_handler.get_xsoar_incidents(prod_ticket_handler, query, period, size)
        return jsonify({'success': True, 'incidents': incidents})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@xsoar_bp.route('/api/xsoar/incident/<incident_id>')
@log_web_activity
def api_xsoar_incident_detail(incident_id):
    """API to get XSOAR incident details"""
    try:
        incident, entries = xsoar_dashboard_handler.get_xsoar_incident_detail(prod_ticket_handler, incident_id)
        return jsonify({'success': True, 'incident': incident, 'entries': entries})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@xsoar_bp.route('/xsoar/incident/<incident_id>')
@log_web_activity
def xsoar_incident_detail(incident_id):
    """XSOAR incident detail view"""
    try:
        incident, entries = xsoar_dashboard_handler.get_xsoar_incident_detail(prod_ticket_handler, incident_id)
        return render_template('xsoar_incident_detail.html', incident=incident, entries=entries)
    except Exception as exc:
        return f"Error loading incident {incident_id}: {str(exc)}", 500


@xsoar_bp.route('/api/xsoar/incident/<incident_id>/entries')
@log_web_activity
def api_xsoar_incident_entries(incident_id):
    """API to get incident entries/comments"""
    try:
        entries = xsoar_dashboard_handler.get_xsoar_incident_entries(prod_ticket_handler, incident_id)
        return jsonify({'success': True, 'entries': entries})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@xsoar_bp.route('/api/xsoar/incident/<incident_id>/link', methods=['POST'])
@log_web_activity
def api_xsoar_link_incident(incident_id):
    """API to link incidents"""
    link_incident_id = request.json.get('link_incident_id')
    try:
        result = xsoar_dashboard_handler.link_xsoar_incidents(prod_ticket_handler, incident_id, link_incident_id)
        return jsonify({'success': True, 'result': result})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@xsoar_bp.route('/api/xsoar/incident/<incident_id>/participant', methods=['POST'])
@log_web_activity
def api_xsoar_add_participant(incident_id):
    """API to add participant to incident"""
    email = request.json.get('email')
    try:
        result = xsoar_dashboard_handler.add_participant_to_incident(prod_ticket_handler, incident_id, email)
        return jsonify({'success': True, 'result': result})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500
