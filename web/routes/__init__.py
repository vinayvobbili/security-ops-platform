"""Web server route blueprints.

This package contains Flask blueprints for organizing routes by feature area.
"""

from .utilities import utilities_bp
from .forms import forms_bp
from .xsoar import xsoar_bp
from .metrics import metrics_bp
from .security_tools import security_tools_bp
from .chat import chat_bp
from .monitoring import monitoring_bp
from .detection_rules import detection_rules_bp

__all__ = [
    'utilities_bp',
    'forms_bp',
    'xsoar_bp',
    'metrics_bp',
    'security_tools_bp',
    'chat_bp',
    'monitoring_bp',
    'detection_rules_bp',
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
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(detection_rules_bp)
