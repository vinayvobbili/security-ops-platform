"""Vibe Coding — 15-minute Claude Code CLI workshop walkthrough."""

from flask import Blueprint, render_template

from src.utils.logging_utils import log_web_activity

vibe_coding_bp = Blueprint("vibe_coding", __name__)


@vibe_coding_bp.route("/vibe-coding")
@log_web_activity
def display_vibe_coding():
    return render_template("vibe_coding.html")
