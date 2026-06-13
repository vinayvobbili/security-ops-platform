"""Markdown Viewer — paste/drop/open a .md file and read it rendered.

Built for teammates who can't install a browser extension (no admin rights on
Edge/Chrome). Rendering is 100% client-side: marked + DOMPurify run in the
browser, so the markdown never leaves the user's machine.
"""

from flask import Blueprint, render_template

from src.utils.logging_utils import log_web_activity

markdown_viewer_bp = Blueprint("markdown_viewer", __name__)


@markdown_viewer_bp.route("/markdown-viewer")
@markdown_viewer_bp.route("/md")
@log_web_activity
def display_markdown_viewer():
    return render_template("markdown_viewer.html")
