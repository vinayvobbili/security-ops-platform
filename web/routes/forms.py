"""Form routes: MSOC, Speak Up, Travel, Red Team Testing, Employee Reach Out."""

import logging
from datetime import date, datetime, timedelta

from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity
from src.components.web import (
    msoc_form_handler,
    speak_up_handler,
    approved_testing_handler,
    travel_handler,
    employee_reach_out_handler,
)
from web.config import (
    CONFIG,
    EASTERN,
    COMPANY_EMAIL_DOMAIN,
    prod_list_handler,
    prod_ticket_handler,
    dev_ticket_handler,
)

logger = logging.getLogger(__name__)
forms_bp = Blueprint('forms', __name__)


# --- MSOC Form ---

@forms_bp.route("/msoc-form")
@log_web_activity
def display_msoc_form():
    """Displays the MSOC form."""
    return render_template("msoc_form.html", show_burger=False)


@forms_bp.route("/submit-msoc-form", methods=['POST'])
@log_web_activity
def handle_msoc_form_submission():
    """Handles MSOC form submissions and processes the data."""
    result = msoc_form_handler.handle_msoc_form_submission(
        request.form,
        prod_ticket_handler,
        CONFIG.xsoar_dev_ui_base_url
    )
    return jsonify(result)


# --- Speak Up Form ---

@forms_bp.route("/speak-up-form")
@log_web_activity
def display_speak_up_form():
    """Displays the Speak Up form."""
    return render_template("speak_up_form.html")


@forms_bp.route("/submit-speak-up-form", methods=['POST'])
@log_web_activity
def handle_speak_up_form_submission():
    """Handles the Speak Up form submissions and processes the data."""
    result = speak_up_handler.handle_speak_up_form_submission(
        request.form,
        prod_ticket_handler,
        CONFIG.xsoar_dev_ui_base_url,
        CONFIG.team_name
    )
    return jsonify(result)


# --- Approved Testing ---

@forms_bp.route("/get-approved-testing-entries", methods=['GET'])
@log_web_activity
def get_approved_testing_entries():
    """Fetches approved testing records and displays them in separate HTML tables."""
    records = approved_testing_handler.get_approved_testing_entries(prod_list_handler, CONFIG.team_name)

    if not records:
        return "<h2>No Approved Testing Records Found</h2>"

    return render_template(
        'approved_testing.html',
        ENDPOINTS=records.get("ENDPOINTS", []),
        USERNAMES=records.get("USERNAMES", []),
        IP_ADDRESSES=records.get("IP_ADDRESSES", []),
        CIDR_BLOCKS=records.get("CIDR_BLOCKS", [])
    )


@forms_bp.route("/red-team-testing-form")
@log_web_activity
def display_red_team_testing_form():
    """Displays the Red Team Testing form."""
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    return render_template("red_team_testing_form.html", tomorrow=tomorrow)


@forms_bp.route("/submit-red-team-testing-form", methods=['POST'])
@log_web_activity
def handle_red_team_testing_form_submission():
    """Handles the Red Team Testing form submissions and processes the data."""
    try:
        approved_testing_handler.submit_red_team_testing_form(
            request.form,
            prod_list_handler,
            CONFIG.team_name,
            COMPANY_EMAIL_DOMAIN,
            EASTERN,
            request.remote_addr
        )
        return jsonify({'status': 'success'})
    except ValueError as val_err:
        return jsonify({'status': 'error', 'message': str(val_err)}), 400


# --- Travel Form ---

@forms_bp.route("/get-current-upcoming-travel-records", methods=['GET'])
@log_web_activity
def get_upcoming_travel():
    """Fetches upcoming travel records and displays them."""
    records = travel_handler.get_current_upcoming_travel_records(prod_list_handler)
    return render_template('upcoming_travel.html', travel_records=records)


@forms_bp.route("/travel-form")
@log_web_activity
def display_travel_form():
    """Displays the Upcoming Travel Notification form."""
    today = date.today().isoformat()
    return render_template("upcoming_travel_notification_form.html", today=today)


@forms_bp.route("/submit-travel-form", methods=['POST'])
@log_web_activity
def handle_travel_form_submission():
    """Handles the Upcoming Travel Notification form submissions and processes the data."""
    response = travel_handler.submit_travel_form(
        request.form,
        prod_list_handler,
        EASTERN,
        request.remote_addr
    )
    return jsonify({'status': 'success', 'response': response})


# --- Employee Reach Out ---

@forms_bp.route('/employee-reach-out')
@log_web_activity
def employee_reach_out_form():
    """Display employee reach out form"""
    ticket_id = request.args.get('case_id', '')
    task_id = employee_reach_out_handler.get_employee_reach_out_task_info(ticket_id, dev_ticket_handler)

    if task_id:
        return render_template('employee_reach_out_form.html', ticket_id=ticket_id)
    else:
        return render_template('employee_reach_out_already_completed.html')


@forms_bp.route('/submit-employee-response', methods=['POST'])
@log_web_activity
def submit_employee_response():
    """Handle employee reach out form submission"""
    try:
        data = request.form.to_dict()
        recognized = data.get('recognized')
        ticket_id = data.get('ticket_id', '')
        comments = data.get('comments', '').strip()
        file_data = request.files.get('file')

        if not ticket_id:
            return jsonify({
                'status': 'success',
                'message': 'Thank you for your response.'
            })

        success, message = employee_reach_out_handler.submit_employee_response(
            recognized,
            ticket_id,
            comments,
            file_data,
            dev_ticket_handler
        )

        if success:
            return jsonify({'status': 'success', 'message': message})
        else:
            return jsonify({'status': 'error', 'error': message}), 500

    except Exception as exc:
        logger.error(f"Error submitting employee reach out: {exc}")
        return jsonify({'status': 'error', 'error': str(exc)}), 500
