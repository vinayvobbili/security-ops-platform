"""Form routes: MSOC, Speak Up, Travel, Red Team Testing, Employee Reach Out, AI Intake, RUAI Screening, Ticket Cannon."""

import json
import logging
from datetime import date, datetime, timedelta

from flask import Blueprint, abort, jsonify, render_template, request, send_file

from src.utils.logging_utils import log_web_activity, get_client_ip
from web.auth.helpers import login_required, current_user
from web.auth.rbac import require_capability, MANAGE_SILENCER
from src.components.web import (
    msoc_form_handler,
    speak_up_handler,
    approved_testing_handler,
    travel_handler,
    employee_reach_out_handler,
    ai_intake_handler,
    ruai_handler,
    ruai_docs_handler,
    ruai_prompts_handler,
    ticket_cannon_handler,
)
from web.config import (
    CONFIG,
    EASTERN,
    COMPANY_EMAIL_DOMAIN,
    prod_list_handler,
    dev_list_handler,
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
        CONFIG.team_name,
        file_data=request.files.get('file'),
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
@login_required
@log_web_activity
def display_red_team_testing_form():
    """Displays the Red Team Testing form."""
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    return render_template("red_team_testing_form.html", tomorrow=tomorrow)


@forms_bp.route("/submit-red-team-testing-form", methods=['POST'])
@login_required
@log_web_activity
def handle_red_team_testing_form_submission():
    """Handles the Red Team Testing form submissions and processes the data."""
    try:
        approved_testing_handler.submit_red_team_testing_form(
            request.form,
            prod_list_handler,
            CONFIG.team_name,
            current_user()['email'],
            EASTERN,
            get_client_ip()
        )
        return jsonify({'status': 'success'})
    except ValueError as val_err:
        logger.warning(f"Validation error in red team testing form: {val_err}")
        return jsonify({'status': 'error', 'message': 'Invalid form data'}), 400


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
        get_client_ip()
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
        logger.error(f"Error submitting employee reach out: {exc}", exc_info=True)
        return jsonify({'status': 'error', 'error': 'An internal error occurred'}), 500


# --- AI Project Intake ---

@forms_bp.route("/ai-intake")
@log_web_activity
def display_ai_intake_form():
    """Displays the AI Project Intake form."""
    return render_template("ai_intake_form.html", email_domain=COMPANY_EMAIL_DOMAIN)


@forms_bp.route("/submit-ai-intake", methods=['POST'])
@login_required
@log_web_activity
def handle_ai_intake_submission():
    """Handles AI Project Intake form submissions."""
    result = ai_intake_handler.handle_ai_intake_submission(request.form, request.files.getlist('documents'))
    return jsonify(result)


@forms_bp.route("/ai-intake-submissions")
@log_web_activity
def view_ai_intake_submissions():
    """Displays all AI Project Intake submissions."""
    submissions = ai_intake_handler.get_all_submissions()
    return render_template("ai_intake_submissions.html", submissions=submissions)


@forms_bp.route("/ai-intake-submissions/<int:submission_id>")
@log_web_activity
def view_ai_intake_submission(submission_id):
    """Displays a single AI Project Intake submission."""
    submission = ai_intake_handler.get_submission(submission_id)
    if not submission:
        return "Submission not found", 404
    comments = ai_intake_handler.get_comments(submission_id)
    return render_template("ai_intake_submission_detail.html", s=submission, comments=comments)


@forms_bp.route("/ai-intake-submissions/<int:submission_id>/comments", methods=["POST"])
@login_required
@log_web_activity
def add_ai_intake_comment(submission_id):
    """Append a comment to an AI Intake submission and fire a Webex notification."""
    payload = request.get_json(silent=True) or request.form
    result = ai_intake_handler.add_comment(
        submission_id,
        payload.get("author_name", ""),
        payload.get("author_email", ""),
        payload.get("body", ""),
    )
    status_code = 200 if result.get("status") == "success" else 400
    return jsonify(result), status_code


@forms_bp.route("/ai-intake-submissions/<int:submission_id>/edit", methods=["GET"])
@log_web_activity
def edit_ai_intake_submission_form(submission_id):
    """Displays the edit form prefilled with the current submission values."""
    submission = ai_intake_handler.get_submission(submission_id)
    if not submission:
        return "Submission not found", 404
    return render_template(
        "ai_intake_submission_edit.html",
        s=submission,
        email_domain=COMPANY_EMAIL_DOMAIN,
    )


@forms_bp.route("/ai-intake-submissions/<int:submission_id>/edit", methods=["POST"])
@login_required
@log_web_activity
def update_ai_intake_submission(submission_id):
    """Updates an existing AI Intake submission and appends any new uploaded documents."""
    result = ai_intake_handler.update_submission(
        submission_id,
        request.form,
        request.files.getlist('documents'),
    )
    return jsonify(result)


@forms_bp.route("/ai-intake-submissions/<int:submission_id>/download/<path:filename>")
@log_web_activity
def download_ai_intake_document(submission_id, filename):
    """Download an uploaded document attached to an AI Intake submission."""
    fpath = ai_intake_handler.get_document_path(submission_id, filename)
    if not fpath:
        abort(404)
    return send_file(str(fpath), as_attachment=True)


@forms_bp.route("/ai-intake-submissions/<int:submission_id>", methods=["DELETE"])
@login_required
@log_web_activity
def delete_ai_intake_submission(submission_id):
    """Deletes an AI Project Intake submission (password-protected)."""
    password = request.json.get("password", "") if request.is_json else ""
    if password != "aiintake123":
        return jsonify({"status": "error", "message": "Incorrect password"}), 403
    deleted = ai_intake_handler.delete_submission(submission_id)
    if not deleted:
        return jsonify({"status": "error", "message": "Submission not found"}), 404
    return jsonify({"status": "success", "message": "Submission deleted"})


# --- RUAI Screening ---

@forms_bp.route("/ruai-screening")
@log_web_activity
def display_ruai_screening_form():
    """Displays the RUAI Screening submission form."""
    return render_template("ruai_screening_form.html")


@forms_bp.route("/api/ruai/form-config")
@log_web_activity
def get_ruai_form_config():
    """Returns the screening form configuration as JSON for the frontend rules engine."""
    return jsonify(ruai_handler.get_form_config())


@forms_bp.route("/api/ruai/upload-screening", methods=['POST'])
@login_required
@log_web_activity
def handle_ruai_upload_submission():
    """Creates an RUAI case from uploaded intake documents (XLSX survey + supporting docs)."""
    files = request.files.getlist('documents')
    result = ruai_handler.handle_upload_submission(files)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


@forms_bp.route("/submit-ruai-screening", methods=['POST'])
@login_required
@log_web_activity
def handle_ruai_screening_submission():
    """Handles RUAI screening form submissions."""
    try:
        form_data = json.loads(request.form.get('form_data', '{}'))
    except (json.JSONDecodeError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid form data'}), 400

    files = request.files.getlist('documents')
    result = ruai_handler.handle_submission(form_data, files)
    return jsonify(result)


@forms_bp.route("/ruai-screening/<int:submission_id>")
@log_web_activity
def ruai_submitter_view(submission_id):
    """Submitter view: see AI feedback, revise, and send to review."""
    submission = ruai_handler.get_submission(submission_id)
    if not submission:
        return "Submission not found", 404
    form_config = ruai_handler.get_form_config()
    return render_template("ruai_submitter_view.html", s=submission, form_config=form_config)


@forms_bp.route("/api/ruai/<int:submission_id>/update", methods=['POST'])
@login_required
@log_web_activity
def ruai_update_submission(submission_id):
    """Submitter updates their answers after seeing AI feedback."""
    try:
        form_data = json.loads(request.form.get('form_data', '{}'))
    except (json.JSONDecodeError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid form data'}), 400

    files = request.files.getlist('documents')
    result = ruai_handler.update_submission(submission_id, form_data, files)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


@forms_bp.route("/api/ruai/<int:submission_id>/send-for-review", methods=['POST'])
@login_required
@log_web_activity
def ruai_send_for_review(submission_id):
    """Submitter confirms they're done — promote to reviewer queue."""
    result = ruai_handler.submit_for_review(submission_id)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


@forms_bp.route("/ruai-dashboard")
@log_web_activity
def ruai_dashboard():
    """Displays the RUAI reviewer dashboard."""
    submissions = ruai_handler.get_all_submissions()
    analytics = ruai_handler.get_dashboard_analytics()
    return render_template("ruai_dashboard.html", submissions=submissions, analytics=analytics)


@forms_bp.route("/ruai-dashboard/<int:submission_id>")
@log_web_activity
def ruai_review_detail(submission_id):
    """Displays a single RUAI submission with AI review and reviewer actions."""
    submission = ruai_handler.get_submission(submission_id)
    if not submission:
        return "Submission not found", 404
    form_config = ruai_handler.get_form_config()
    return render_template("ruai_review_detail.html", s=submission, form_config=form_config)


@forms_bp.route("/api/ruai/<int:submission_id>/action", methods=['POST'])
@login_required
@log_web_activity
def ruai_reviewer_action(submission_id):
    """Handles reviewer actions (approve, reject, request changes, comment)."""
    data = request.get_json(silent=True) or {}
    reviewer_name = data.get('reviewer_name', '').strip()
    action = data.get('action', '').strip()
    notes = data.get('notes', '').strip()

    if not reviewer_name:
        return jsonify({'status': 'error', 'message': 'Reviewer name is required'}), 400
    if not action:
        return jsonify({'status': 'error', 'message': 'Action is required'}), 400

    result = ruai_handler.add_reviewer_action(submission_id, reviewer_name, action, notes)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


@forms_bp.route("/api/ruai/<int:submission_id>/status")
def ruai_submission_status(submission_id):
    """Returns lightweight status for polling (used by the progress tracker)."""
    submission = ruai_handler.get_submission(submission_id)
    if not submission:
        return jsonify({'status': 'error', 'message': 'Not found'}), 404
    phase = ruai_handler.get_review_phase(submission_id)
    resp = {
        'status': submission['status'],
        'has_ai_review': submission.get('ai_review') is not None,
        'phase': phase,
    }
    if phase in ('done', 'saving_results'):
        stats = ruai_handler.get_review_stats(submission_id)
        if stats:
            resp['stats'] = stats
    return jsonify(resp)


@forms_bp.route("/api/ruai/<int:submission_id>/rerun-review", methods=['POST'])
@login_required
@log_web_activity
def ruai_rerun_review(submission_id):
    """Re-triggers the AI review for a submission."""
    result = ruai_handler.rerun_ai_review(submission_id)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


@forms_bp.route("/api/ruai/<int:submission_id>/checklist", methods=['GET'])
@log_web_activity
def ruai_get_checklist(submission_id):
    """Returns the reviewer checklist for a submission."""
    reviewer_name = request.args.get('reviewer', '').strip()
    if not reviewer_name:
        return jsonify({'status': 'error', 'message': 'reviewer parameter required'}), 400
    result = ruai_handler.get_checklist(submission_id, reviewer_name)
    return jsonify(result)


@forms_bp.route("/api/ruai/<int:submission_id>/checklist", methods=['POST'])
@login_required
@log_web_activity
def ruai_save_checklist(submission_id):
    """Saves the reviewer checklist for a submission."""
    data = request.get_json(silent=True) or {}
    reviewer_name = data.get('reviewer_name', '').strip()
    items = data.get('items', {})
    if not reviewer_name:
        return jsonify({'status': 'error', 'message': 'reviewer_name required'}), 400
    result = ruai_handler.save_checklist(submission_id, reviewer_name, items)
    return jsonify(result)


@forms_bp.route("/api/ruai/<int:submission_id>/similar")
@log_web_activity
def ruai_similar_submissions(submission_id):
    """Returns similar past submissions using BM25 similarity."""
    results = ruai_handler.find_similar_submissions(submission_id)
    return jsonify(results)


@forms_bp.route("/api/ruai/<int:submission_id>/documents/<filename>")
@log_web_activity
def ruai_serve_document(submission_id, filename):
    """Serves an uploaded document for inline preview."""
    file_path = ruai_handler.get_upload_file_path(submission_id, filename)
    if not file_path:
        abort(404)
    return send_file(file_path)


@forms_bp.route("/api/ruai/<int:submission_id>/reviews")
@log_web_activity
def ruai_all_reviews(submission_id):
    """Returns all AI reviews for a submission (for comparison)."""
    reviews = ruai_handler.get_all_ai_reviews(submission_id)
    return jsonify(reviews)


@forms_bp.route("/api/ruai/<int:submission_id>/assign", methods=['POST'])
@login_required
@log_web_activity
def ruai_assign_reviewer(submission_id):
    """Assigns a reviewer to a submission."""
    data = request.get_json(silent=True) or {}
    reviewer_name = data.get('reviewer_name', '').strip()
    assigned_by = data.get('assigned_by', '').strip()
    if not reviewer_name or not assigned_by:
        return jsonify({'status': 'error', 'message': 'reviewer_name and assigned_by required'}), 400
    result = ruai_handler.assign_reviewer(submission_id, reviewer_name, assigned_by)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


@forms_bp.route("/api/ruai/<int:submission_id>/unassign", methods=['POST'])
@login_required
@log_web_activity
def ruai_unassign_reviewer(submission_id):
    """Removes a reviewer assignment from a submission."""
    data = request.get_json(silent=True) or {}
    reviewer_name = data.get('reviewer_name', '').strip()
    if not reviewer_name:
        return jsonify({'status': 'error', 'message': 'reviewer_name required'}), 400
    result = ruai_handler.remove_reviewer_assignment(submission_id, reviewer_name)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


# --- RUAI Docs ---

@forms_bp.route("/ruai-docs")
@log_web_activity
def ruai_docs():
    """RUAI reference documents — upload, delete, and embed."""
    docs = ruai_docs_handler.list_docs()
    stats = ruai_docs_handler.get_chroma_stats()
    return render_template("ruai_docs.html", docs=docs, stats=stats)


@forms_bp.route("/api/ruai-docs/upload", methods=['POST'])
@login_required
@log_web_activity
def ruai_docs_upload():
    """Upload a document to the RUAI reference library."""
    files = request.files.getlist('documents')
    if not files or not files[0].filename:
        return jsonify({'status': 'error', 'message': 'No file provided'}), 400
    results = []
    for f in files:
        try:
            meta = ruai_docs_handler.save_uploaded_file(f)
            results.append(meta)
        except ValueError as e:
            return jsonify({'status': 'error', 'message': str(e)}), 400
    return jsonify({'status': 'success', 'files': results})


@forms_bp.route("/api/ruai-docs/delete", methods=['POST'])
@login_required
@log_web_activity
def ruai_docs_delete():
    """Delete a document from the RUAI reference library."""
    data = request.get_json(silent=True) or {}
    filename = data.get('filename', '').strip()
    if not filename:
        return jsonify({'status': 'error', 'message': 'filename required'}), 400
    if ruai_docs_handler.delete_doc(filename):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'File not found'}), 404


@forms_bp.route("/api/ruai-docs/rebuild", methods=['POST'])
@login_required
@log_web_activity
def ruai_docs_rebuild():
    """Rebuild the RUAI docs vector store from all uploaded documents."""
    result = ruai_docs_handler.rebuild_vector_store()
    status_code = 200 if result.get('success') else 500
    return jsonify(result), status_code


@forms_bp.route("/api/ruai-docs/download/<filename>")
@log_web_activity
def ruai_docs_download(filename):
    """Download a RUAI reference document."""
    from werkzeug.utils import secure_filename as sf
    safe = sf(filename)
    fpath = ruai_docs_handler.DOCS_DIR / safe
    if not fpath.is_file():
        abort(404)
    return send_file(str(fpath), as_attachment=True)


# --- RUAI LLM Prompts management ---

@forms_bp.route("/ruai-prompts")
@log_web_activity
def ruai_prompts_page():
    """Manage versioned LLM prompts used by RUAI screening reviews."""
    prompts = ruai_prompts_handler.list_prompts()
    if not prompts:
        abort(404)
    requested = request.args.get('key') or prompts[0]['key']
    selected = ruai_prompts_handler.get_prompt(requested) or ruai_prompts_handler.get_prompt(prompts[0]['key'])
    return render_template("ruai_prompts.html", prompts=prompts, selected=selected)


@forms_bp.route("/api/ruai-prompts/<key>/versions", methods=['POST'])
@login_required
@log_web_activity
def ruai_prompts_create_version(key):
    """Append a new version of a prompt. Optionally sets it active."""
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    if not isinstance(content, str) or not content.strip():
        return jsonify({'status': 'error', 'message': 'content required'}), 400
    note = data.get('note', '') or ''
    set_active = bool(data.get('set_active', True))
    try:
        rec = ruai_prompts_handler.create_version(key, content, note=note, set_active=set_active)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    return jsonify({'status': 'success', 'version': rec['version'], 'active': set_active})


@forms_bp.route("/api/ruai-prompts/<key>/active", methods=['POST'])
@login_required
@log_web_activity
def ruai_prompts_set_active(key):
    """Point the prompt at a specific existing version."""
    data = request.get_json(silent=True) or {}
    try:
        version = int(data.get('version'))
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'version (int) required'}), 400
    if ruai_prompts_handler.set_active_version(key, version):
        return jsonify({'status': 'success', 'active_version': version})
    return jsonify({'status': 'error', 'message': 'Unknown prompt or version'}), 404


@forms_bp.route("/api/ruai-prompts/<key>/versions/<int:version>", methods=['DELETE'])
@login_required
@log_web_activity
def ruai_prompts_delete_version(key, version):
    """Delete a non-active version of a prompt."""
    if ruai_prompts_handler.delete_version(key, version):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Cannot delete (not found or currently active)'}), 400


# --- Ticket Cannon Silencer ---

@forms_bp.route("/ticket-cannon")
@log_web_activity
def display_ticket_cannon():
    """Displays the Silencers and Suppressors page."""
    data = ticket_cannon_handler.get_silencers_for_display(prod_list_handler, CONFIG.team_name)
    return render_template(
        'ticket_cannon.html',
        categories=data["categories"],
        fields=data["fields"],
        field_options=data["field_options"],
    )


@forms_bp.route("/api/ticket-cannon/create", methods=['POST'])
@require_capability(MANAGE_SILENCER)
@log_web_activity
def handle_create_silencer():
    """Creates a new silencer or suppressor entry."""
    data = request.get_json(silent=True) or {}
    try:
        entry = ticket_cannon_handler.handle_create_silencer(
            data,
            prod_list_handler,
            CONFIG.team_name,
            submitter_email=current_user()["email"],
        )
        return jsonify({'status': 'success', 'silencer': entry})
    except ValueError as val_err:
        logger.warning(f"Validation error creating entry: {val_err}")
        return jsonify({'status': 'error', 'message': str(val_err)}), 400


@forms_bp.route("/api/ticket-cannon/<silencer_id>/toggle", methods=['PUT'])
@require_capability(MANAGE_SILENCER)
@log_web_activity
def handle_toggle_silencer(silencer_id):
    """Activates or deactivates an entry."""
    data = request.get_json(silent=True) or {}
    active = data.get('active', False)
    category = data.get('category', '')
    result = ticket_cannon_handler.handle_toggle_silencer(
        silencer_id,
        active,
        category,
        prod_list_handler,
        CONFIG.team_name,
        toggled_by=current_user()["email"],
    )
    if result is None:
        return jsonify({'status': 'error', 'message': 'Entry not found'}), 404
    return jsonify({'status': 'success', 'silencer': result})
