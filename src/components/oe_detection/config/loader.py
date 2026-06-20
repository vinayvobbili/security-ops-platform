"""Configuration loader for OE Detection Framework.

Reads settings.yaml and resolves ${ENV_VAR} references.
Merges with IR get_config() for shared secrets (Webex bot token, etc.).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import yaml

logger = logging.getLogger("oe_detector")

_CONFIG_DIR = Path(__file__).parent
_SETTINGS_PATH = _CONFIG_DIR / "settings.yaml"

_ENV_RE = re.compile(r"\$\{([^}]+)\}")


def _resolve_env_vars(obj):
    """Recursively resolve ${ENV_VAR} references in config values."""
    if isinstance(obj, str):
        def _replace(m):
            return os.environ.get(m.group(1), "")
        return _ENV_RE.sub(_replace, obj)
    elif isinstance(obj, dict):
        return {k: _resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_resolve_env_vars(item) for item in obj]
    return obj


def load_oe_config(settings_path: str | Path | None = None) -> dict:
    """Load OE detection configuration.

    Reads settings.yaml, resolves environment variable references,
    and merges shared secrets from the IR config system.

    Args:
        settings_path: Override path to settings.yaml (defaults to bundled file)

    Returns:
        Fully resolved configuration dict
    """
    path = Path(settings_path) if settings_path else _SETTINGS_PATH

    if not path.exists():
        logger.error(f"OE config not found: {path}")
        raise FileNotFoundError(f"OE config not found: {path}")

    with open(path) as f:
        config = yaml.safe_load(f)

    # Merge shared secrets from IR config (Webex bot token, Ollama URL, etc.)
    try:
        from my_config import get_config
        ir_config = get_config()

        # Inject Webex bot token if not already set via env var
        alerts_webex = config.get("alerts", {}).get("webex", {})
        if not os.environ.get("WEBEX_BOT_ACCESS_TOKEN_SLEUTH"):
            bot_token = getattr(ir_config, "webex_bot_access_token_sleuth", "")
            if bot_token:
                os.environ["WEBEX_BOT_ACCESS_TOKEN_SLEUTH"] = bot_token
                logger.debug("Injected Webex bot token from IR config")
    except Exception as e:
        logger.debug(f"Could not merge IR config (standalone mode): {e}")

    config = _resolve_env_vars(config)

    logger.info(
        f"OE config loaded: {len(config.get('rules', {}))} rules, "
        f"{len(config.get('mcp_servers', {}))} MCP servers"
    )

    return config
