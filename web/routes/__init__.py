"""Web server route blueprints.

This package contains Flask blueprints for organizing routes by feature area.
"""

from .utilities import utilities_bp
from .forms import forms_bp
from .xsoar import xsoar_bp
from .metrics import metrics_bp
from .security_tools import security_tools_bp
from .chat import chat_bp
from .domain_monitoring import domain_monitoring_bp
from .detection_rules import detection_rules_bp
from .connectors import connectors_bp
from .cribl_diagnostics import cribl_diagnostics_bp
from .oe_detection import oe_detection_bp
from .escalation_contacts import escalation_contacts_bp
from .favorite_urls import favorite_urls_bp
from .s3_scanner import s3_scanner_bp
from .oncall import oncall_bp
from .roster import roster_bp
from .docs_library import docs_library_bp
from .meeting_qa import meeting_qa_bp
from .powerbi import powerbi_bp
from .recap import recap_bp
from .traffic_logs import traffic_logs_bp
from .auth_routes import auth_bp
from .pir import pir_bp
from .qradar import qradar_bp
from .qradar_chat import qradar_chat_bp
from .db_security import db_security_bp
from .wiki import wiki_bp
from .llm_usage import llm_usage_bp
from .customer_assurance import customer_assurance_bp
from .ai_drt import ai_drt_bp
from .exposed_api_scanner import exposed_api_scanner_bp
from .cyber_simulator import cyber_simulator_bp
from .dspm import dspm_bp
from .db_config import db_config_bp
from .cyber_tool_inventory import cyber_tool_inventory_bp
from .claude_code_setup import claude_code_setup_bp
from .gitlab_onboarding import gitlab_onboarding_bp
from .vibe_coding import vibe_coding_bp
from .regulatory_matrix import regulatory_matrix_bp
from .tipper_automation import tipper_automation_bp
from .person_of_interest import person_of_interest_bp
from .bench_local import bench_local_bp
from .soc_timeline import soc_timeline_bp
from .soc_in_a_box import soc_in_a_box_bp
from .github_advisories import github_advisories_bp
from .vulnerability_deep_dive import vuln_deep_dive_bp
from .app_logs import app_logs_bp
from .markdown_viewer import markdown_viewer_bp
from .phish_sentiment import phish_sentiment_bp
from .hunt_workbench import hunt_workbench_bp
from .detection_as_code import detection_as_code_bp
from .code_security import code_security_bp
from .third_party_risk import third_party_risk_bp
from .lessons import lessons_bp
from .admin_lessons import admin_lessons_bp

__all__ = [
    'utilities_bp',
    'forms_bp',
    'xsoar_bp',
    'metrics_bp',
    'security_tools_bp',
    'chat_bp',
    'domain_monitoring_bp',
    'detection_rules_bp',
    'connectors_bp',
    'cribl_diagnostics_bp',
    'oe_detection_bp',
    'escalation_contacts_bp',
    'favorite_urls_bp',
    's3_scanner_bp',
    'oncall_bp',
    'roster_bp',
    'docs_library_bp',
    'meeting_qa_bp',
    'powerbi_bp',
    'recap_bp',
    'traffic_logs_bp',
    'pir_bp',
    'qradar_bp',
    'qradar_chat_bp',
    'db_security_bp',
    'wiki_bp',
    'llm_usage_bp',
    'customer_assurance_bp',
    'ai_drt_bp',
    'exposed_api_scanner_bp',
    'cyber_simulator_bp',
    'dspm_bp',
    'db_config_bp',
    'cyber_tool_inventory_bp',
    'claude_code_setup_bp',
    'gitlab_onboarding_bp',
    'vibe_coding_bp',
    'regulatory_matrix_bp',
    'tipper_automation_bp',
    'person_of_interest_bp',
    'bench_local_bp',
    'soc_timeline_bp',
    'soc_in_a_box_bp',
    'github_advisories_bp',
    'vuln_deep_dive_bp',
    'app_logs_bp',
    'markdown_viewer_bp',
    'phish_sentiment_bp',
    'hunt_workbench_bp',
    'detection_as_code_bp',
    'code_security_bp',
    'third_party_risk_bp',
    'lessons_bp',
    'admin_lessons_bp',
]


def register_all_blueprints(app):
    """Register all route blueprints with the Flask app.

    Args:
        app: Flask application instance
    """
    app.register_blueprint(utilities_bp)
    app.register_blueprint(forms_bp)
    app.register_blueprint(xsoar_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(security_tools_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(domain_monitoring_bp)
    app.register_blueprint(detection_rules_bp)
    app.register_blueprint(connectors_bp)
    app.register_blueprint(cribl_diagnostics_bp)
    app.register_blueprint(oe_detection_bp)
    app.register_blueprint(escalation_contacts_bp)
    app.register_blueprint(favorite_urls_bp)
    app.register_blueprint(s3_scanner_bp)
    app.register_blueprint(oncall_bp)
    app.register_blueprint(roster_bp)
    app.register_blueprint(docs_library_bp)
    app.register_blueprint(meeting_qa_bp)
    app.register_blueprint(powerbi_bp)
    app.register_blueprint(recap_bp)
    app.register_blueprint(traffic_logs_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(pir_bp)
    app.register_blueprint(qradar_bp)
    app.register_blueprint(qradar_chat_bp)
    app.register_blueprint(db_security_bp)
    app.register_blueprint(wiki_bp)
    app.register_blueprint(llm_usage_bp)
    app.register_blueprint(customer_assurance_bp)
    app.register_blueprint(ai_drt_bp)
    app.register_blueprint(exposed_api_scanner_bp)
    app.register_blueprint(cyber_simulator_bp)
    app.register_blueprint(dspm_bp)
    app.register_blueprint(db_config_bp)
    app.register_blueprint(cyber_tool_inventory_bp)
    app.register_blueprint(claude_code_setup_bp)
    app.register_blueprint(gitlab_onboarding_bp)
    app.register_blueprint(vibe_coding_bp)
    app.register_blueprint(regulatory_matrix_bp)
    app.register_blueprint(tipper_automation_bp)
    app.register_blueprint(person_of_interest_bp)
    app.register_blueprint(bench_local_bp)
    app.register_blueprint(soc_timeline_bp)
    app.register_blueprint(soc_in_a_box_bp)
    app.register_blueprint(github_advisories_bp)
    app.register_blueprint(vuln_deep_dive_bp)
    app.register_blueprint(app_logs_bp)
    app.register_blueprint(markdown_viewer_bp)
    app.register_blueprint(phish_sentiment_bp)
    app.register_blueprint(hunt_workbench_bp)
    app.register_blueprint(detection_as_code_bp)
    app.register_blueprint(code_security_bp)
    app.register_blueprint(third_party_risk_bp)
    app.register_blueprint(lessons_bp)
    app.register_blueprint(admin_lessons_bp)
