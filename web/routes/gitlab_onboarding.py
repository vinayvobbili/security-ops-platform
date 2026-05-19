"""GitLab self-serve onboarding page."""

from flask import Blueprint, render_template

from src.utils.logging_utils import log_web_activity

gitlab_onboarding_bp = Blueprint("gitlab_onboarding", __name__)


@gitlab_onboarding_bp.route("/gitlab")
@log_web_activity
def display_gitlab_onboarding():
    return render_template("gitlab_onboarding.html")
