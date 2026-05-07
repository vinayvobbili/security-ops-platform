"""Claude Code Local Setup — interactive guide page with help chat."""

from flask import Blueprint, render_template

from my_config import get_config
from src.utils.logging_utils import log_web_activity

claude_code_setup_bp = Blueprint("claude_code_setup", __name__)


@claude_code_setup_bp.route("/claude-code-setup")
@log_web_activity
def display_claude_code_setup():
    """Render the Claude Code local-LLM setup guide."""
    config = get_config()
    return render_template(
        "claude_code_setup.html",
        local_llm_public_url=config.local_llm_public_url or "https://<your-llm-host>/local-llm",
    )
