"""Meeting Minutes QA routes."""

from flask import Blueprint, render_template, request, jsonify

from src.components.web.meeting_qa_handler import analyze_meeting_notes
from src.utils.logging_utils import log_web_activity

meeting_qa_bp = Blueprint('meeting_qa', __name__)


@meeting_qa_bp.route('/meeting-qa')
@log_web_activity
def meeting_qa():
    return render_template('meeting_qa.html')


@meeting_qa_bp.route('/api/meeting-qa/analyze', methods=['POST'])
@log_web_activity
def api_meeting_qa_analyze():
    data = request.get_json(silent=True) or {}
    human_notes = data.get('human_notes', '')
    copilot_notes = data.get('copilot_notes', '')
    result = analyze_meeting_notes(human_notes, copilot_notes)
    return jsonify(result)
