"""Regulatory Acceleration Matrix — page + API for AI intake submission #7.

v1: a crosswalk of GDPR / CCPA / HIPAA against NIST CSF 2.0 control families with
real evidence pulled from CrowdStrike + ServiceNow on a handful of cells. See
``src/components/web/regulatory_matrix_handler.py`` for the data model and the
v2 questions panel that the stakeholder should answer to drive the next iteration.
"""

from flask import Blueprint, jsonify, render_template, request

from src.components.web import regulatory_matrix_handler
from src.utils.logging_utils import log_web_activity

regulatory_matrix_bp = Blueprint("regulatory_matrix", __name__)


@regulatory_matrix_bp.route("/regulatory-acceleration-matrix")
@log_web_activity
def display_regulatory_matrix():
    return render_template("regulatory_acceleration_matrix.html")


@regulatory_matrix_bp.route("/api/regulatory-acceleration-matrix/data")
@log_web_activity
def api_regulatory_matrix_data():
    data = regulatory_matrix_handler.get_matrix_data()
    data["pulse"] = regulatory_matrix_handler.get_pulse_feed()
    data["pulse_impacts"] = regulatory_matrix_handler.get_pulse_impacts()
    data["v2_questions"] = regulatory_matrix_handler.get_v2_questions()
    return jsonify(data)


@regulatory_matrix_bp.route("/api/regulatory-acceleration-matrix/impacts")
@log_web_activity
def api_regulatory_matrix_impacts():
    """Lightweight poll endpoint: returns the impact cache snapshot only."""
    return jsonify(regulatory_matrix_handler.get_pulse_impacts())


@regulatory_matrix_bp.route("/api/regulatory-acceleration-matrix/impact/<pulse_id>", methods=["POST"])
@log_web_activity
def api_regulatory_matrix_impact(pulse_id):
    force = request.args.get("force", "").lower() in ("1", "true", "yes")
    return jsonify(regulatory_matrix_handler.analyze_pulse_impact(pulse_id, force=force))
