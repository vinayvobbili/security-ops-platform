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
ALERT_ROOM_ID_TEST = CONFIG.webex_room_id_dev_test_space
ALERT_ROOM_ID_PROD = CONFIG.webex_room_id_domain_monitoring

# Module-level active room ID, set by run_daily_monitoring
_active_room_id = ALERT_ROOM_ID_PROD

# Results storage - in transient data directory (git ignored)
RESULTS_DIR = Path(__file__).parent.parent.parent.parent / "data" / "transient" / "domain_monitoring"
CONFIG_FILE = RESULTS_DIR / "config.json"

# Web base URL for report links
WEB_BASE_URL = CONFIG.web_server_url

# Feature flags — toggle monitoring modules on/off
ENABLE_DARK_WEB = False       # Dark web monitoring (search_dark_web)
ENABLE_INTELX = False         # IntelligenceX dark web search (Tor/I2P)
ENABLE_CT_LOGS = True         # Certificate Transparency monitoring
ENABLE_WHOIS = True           # WHOIS change detection
ENABLE_VT = True              # VirusTotal bulk scan
ENABLE_HIBP = True            # HaveIBeenPwned breach check
ENABLE_SHODAN = True          # Shodan infrastructure exposure
ENABLE_ABUSECH = True         # abuse.ch malware/C2 check
ENABLE_ABUSEIPDB = True       # AbuseIPDB malicious IP check
ENABLE_BRAND_CT = True        # Brand impersonation via crt.sh CT search
ENABLE_WATCHLIST = True       # Watchlist semantic impersonation domains
ENABLE_REALTIME_WATCHLIST = True  # 5-min lightweight DNS/HTTP/SSL poller


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


def load_watchlist(domain: str) -> list[str]:
    """Load watchlist domains for a monitored domain.

    Watchlist contains suspicious domains (e.g., acme-loan.com) that dnstwist
    can't detect because they use semantic attacks (brand + keyword combinations).
    These are checked daily in CT logs for new certificates.

    Args:
        domain: The monitored domain to get watchlist for

    Returns:
        List of suspicious domains to monitor
    """
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                watchlist = config.get("watchlist", {})
                return watchlist.get(domain, [])
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading watchlist config: {e}")
    return []


def load_defensive_domains(domain: str) -> list[str]:
    """Load defensive domain registrations for a monitored domain.

    Defensive domains are known legitimate domains owned by the company to
    protect the brand. These are excluded from impersonation alerts.

    Args:
        domain: The monitored domain to get defensive domains for

    Returns:
        List of legitimate defensive domains (includes the monitored domain itself)
    """
    legitimate = [domain]  # Always include the monitored domain
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                defensive = config.get("defensive_domains", {})
                legitimate.extend(defensive.get(domain, []))
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading defensive domains config: {e}")
    return legitimate


def load_known_good_buckets(domain: str) -> list[str]:
    """Load known-good S3 buckets for a monitored domain."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                return config.get("known_good_buckets", {}).get(domain, [])
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading known-good buckets config: {e}")
    return []


def load_full_config() -> dict:
    """Load the entire monitoring config (for the management UI)."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading full config: {e}")
    return {}


# Lists an analyst may edit from the management UI. Maps the editable key to a
# human label; anything not in here is read-only (or structured/nested).
EDITABLE_LISTS = {
    "monitored_domains": "Monitored Domains (full dnstwist + threat-intel pipeline)",
    "rf_watchlist": "Recorded Future Watchlist (brand-keyword domains)",
    "brand_keywords": "Brand Keywords (widen the CT impersonation sweep)",
}

_DOMAIN_RE = __import__("re").compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*\.[a-z]{2,}$")


def _normalize_entry(key: str, value: str) -> str:
    """Normalize and validate a single list entry; raises ValueError if invalid."""
    v = (value or "").strip().lower()
    if not v:
        raise ValueError("empty value")
    if key == "brand_keywords":
        if not v.isascii() or " " in v or "." in v:
            raise ValueError(f"'{value}' is not a valid brand keyword")
        return v
    # domain-shaped lists
    if v.startswith("idn:"):
        v = v[4:]
    if not _DOMAIN_RE.match(v):
        raise ValueError(f"'{value}' is not a valid domain")
    return v


def edit_config_list(key: str, action: str, value: str) -> dict:
    """Add or remove a single entry on an editable config list.

    Args:
        key: one of EDITABLE_LISTS.
        action: 'add' or 'remove'.
        value: the domain / keyword.

    Returns:
        {'ok': bool, 'key', 'count', 'entries'} or {'ok': False, 'error'}.
    """
    if key not in EDITABLE_LISTS:
        return {"ok": False, "error": f"'{key}' is not an editable list"}
    if action not in ("add", "remove"):
        return {"ok": False, "error": "action must be 'add' or 'remove'"}

    config = load_full_config()
    current = list(config.get(key, []))

    try:
        entry = _normalize_entry(key, value)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    if action == "add":
        if entry not in current:
            current.append(entry)
            current.sort()
    else:  # remove
        if entry not in current:
            return {"ok": False, "error": f"'{entry}' is not on the {key} list"}
        current.remove(entry)

    config[key] = current
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
    except IOError as e:
        logger.error(f"Failed to save config after edit: {e}")
        return {"ok": False, "error": "could not save config"}

    logger.info(f"Config edit: {action} '{entry}' on {key} (now {len(current)} entries)")
    return {"ok": True, "key": key, "count": len(current), "entries": current}


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
