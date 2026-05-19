"""Claude Code Local Setup — interactive guide page with help chat."""

import json
from pathlib import Path

from flask import Blueprint, abort, redirect, render_template, request, send_from_directory

from my_config import get_config
from src.utils.logging_utils import log_web_activity

claude_code_setup_bp = Blueprint("claude_code_setup", __name__)

_MIRROR_DIR = Path(__file__).resolve().parents[2] / "data" / "transient" / "cc_mirror"


def _load_manifest() -> dict:
    """Return mirror manifest, or empty dict if not yet populated."""
    manifest_path = _MIRROR_DIR / "manifest.json"
    if not manifest_path.exists():
        return {}
    try:
        return json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


@claude_code_setup_bp.route("/claude-code-with-local-models")
@log_web_activity
def display_claude_code_setup():
    """Render the Claude Code local-LLM setup guide."""
    config = get_config()
    return render_template(
        "claude_code_setup.html",
        local_llm_public_url=config.local_llm_public_url or "https://<your-llm-host>/local-llm",
    )


# Old URL — "setup" alone was ambiguous (could mean stock Claude Code install).
# Permanent redirect so external bookmarks still land on the page.
@claude_code_setup_bp.route("/claude-code-setup")
def redirect_legacy_claude_code_setup():
    return redirect("/claude-code-with-local-models", code=301)


# --- Trusted internal mirror — reverted 2026-05-16 ---
# UI was pulled because (a) raw archives aren't double-clickable so the install
# step still needed shell commands, and (b) the corp CA bundle distribution
# would have needed AppSec sign-off. Plumbing kept on disk for revival:
#   - scripts/refresh_cc_mirror.py  (10 artifacts → data/transient/cc_mirror/)
#   - data/transient/cc_mirror/manifest.json
# To revive: uncomment the mirror-related Jinja block in claude_code_setup.html,
# the mirror_* kwargs above, and the route below.
#
# @claude_code_setup_bp.route("/downloads/<path:filename>")
# @log_web_activity
# def serve_mirror_file(filename):
#     """Serve a file from the trusted internal mirror.
#
#     send_from_directory blocks path traversal; only files actually present in
#     the mirror dir are reachable.
#     """
#     if not _MIRROR_DIR.exists():
#         abort(404)
#     return send_from_directory(_MIRROR_DIR, filename, as_attachment=True)
