"""Configuration and constants for domain monitoring.

This module centralizes all configuration, constants, and client initialization
for the domain monitoring component.
"""

import json
import logging
from pathlib import Path
from zoneinfo import ZoneInfo

from webexteamssdk import WebexTeamsAPI

from my_config import get_config
from services.virustotal import VirusTotalClient
from src.utils.webex_pool_config import configure_webex_api_session

logger = logging.getLogger(__name__)

CONFIG = get_config()
EASTERN_TZ = ZoneInfo("America/New_York")

# Webex room configuration
# Default to test space for development; 8 AM job passes prod room
ALERT_ROOM_ID_TEST = CONFIG.webex_room_id_vinay_test_space
ALERT_ROOM_ID_PROD = CONFIG.webex_room_id_domain_monitoring

# Module-level active room ID, set by run_daily_monitoring
_active_room_id = ALERT_ROOM_ID_TEST

# Results storage - in transient data directory (git ignored)
RESULTS_DIR = Path(__file__).parent.parent.parent.parent / "data" / "transient" / "domain_monitoring"
CONFIG_FILE = RESULTS_DIR / "config.json"

# Web base URL for report links
WEB_BASE_URL = CONFIG.web_server_url if hasattr(CONFIG, 'web_server_url') else "https://your-server.com"


def get_active_room_id() -> str:
    """Get the currently active Webex room ID."""
    return _active_room_id


def set_active_room_id(room_id: str) -> None:
    """Set the active Webex room ID for alerts."""
    global _active_room_id
    _active_room_id = room_id


def load_monitored_domains() -> list[str]:
    """Load monitored domains from config file."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                return config.get("monitored_domains", [])
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading domain config: {e}")
    logger.warning(f"Config file not found at {CONFIG_FILE}, no domains to monitor")
    return []


def get_webex_api() -> WebexTeamsAPI:
    """Get configured Webex API instance with connection pooling."""
    return configure_webex_api_session(
        WebexTeamsAPI(
            access_token=CONFIG.webex_bot_access_token_toodles,
            single_request_timeout=120,
        ),
        pool_connections=10,
        pool_maxsize=10,
        max_retries=3
    )


# VirusTotal client singleton
_vt_client: VirusTotalClient | None = None


def get_vt_client() -> VirusTotalClient | None:
    """Get VirusTotal client if configured."""
    global _vt_client
    if _vt_client is None:
        _vt_client = VirusTotalClient()
        if not _vt_client.is_configured():
            logger.warning("VirusTotal not configured - domain reputation checks disabled")
            return None
        logger.info("VirusTotal client initialized for domain reputation checks")
    return _vt_client if _vt_client.is_configured() else None
