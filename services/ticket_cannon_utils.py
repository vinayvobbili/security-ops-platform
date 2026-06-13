"""Ticket Cannon Silencer & Noise Suppression utilities.

Manages filter entries stored in separate XSOAR lists:
  - {team}_Ticket_Cannon_Silencer  (for ticket cannon barrages)
  - {team}_Noise_Suppressor        (for chronic noisy rules)

All mutations go through the web app so that every create/activate/deactivate
triggers a Webex notification — no silent edits.
"""

import logging
import re
import time
import uuid
from datetime import datetime, timedelta

from pytz import timezone
from webexteamssdk import WebexTeamsAPI

from my_config import get_config

logger = logging.getLogger(__name__)
CONFIG = get_config()

# Field name → human-readable label. This is the *fallback* map used when the
# live XSOAR incident-field list can't be fetched; the web form normally builds
# its picker from XSOAR directly (see get_field_options) so every option is a
# guaranteed-valid API key. Keep this in sync with COMMON_FIELD_KEYS.
SILENCER_FIELDS = {
    "name": "Ticket Name",
    "type": "Ticket Type",
    "severity": "Severity",
    "detectionsource": "Detection Source",
    "securitycategory": "Security Category",
    "hostname": "Host name",
    "username": "Username",
    # Legacy labels — kept so any pre-existing entries keyed on these still
    # render a friendly label. They are NOT real XSOAR incident fields (the
    # registered ones are `hostname`/`username`), so they're not offered in the
    # picker; don't add them back to COMMON_FIELD_KEYS.
    "affectedhostname": "Hostname (legacy)",
    "affectedusername": "Username (legacy)",
    "sourceip": "Source IP",
    "correlationrule": "Correlation Rule",
    "alertname": "Alert Name",
    "filename": "File Name",
    "filepath": "File Path",
    "commandline": "Command Line",
    "parentcmdline": "Parent CMD line",
    "sha256": "SHA256",
}

# Curated high-signal fields, pinned to the top of the web picker — but only
# when the tenant actually has them (we intersect against the live cliNames so
# we never offer a key that would silently never match). Order = display order.
COMMON_FIELD_KEYS = [
    "name", "type", "severity", "detectionsource", "securitycategory",
    "hostname", "username", "sourceip", "correlationrule",
    "alertname", "filename", "filepath", "commandline", "parentcmdline",
    "sha256",
]

# Sample values shown as placeholder/helper text so analysts paste the right
# *format*. Illustrative only — the actual value must be copied from the ticket.
FIELD_EXAMPLES = {
    "name": "GitHub blocklisted repo accessed",
    "type": "CrowdStrike Detection",
    "severity": "Low",
    "detectionsource": "CrowdStrike",
    "securitycategory": "Execution",
    "hostname": "LAPTOP-AB12CD",
    "username": "jdoe",
    "sourceip": "<internal-host>",
    "correlationrule": "Suspicious PowerShell Encoded Command",
    "alertname": "Encoded PowerShell",
    "filename": "rundll32.exe",
    "filepath": "C:\\Users\\Public\\update.exe",
    "commandline": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
    "parentcmdline": "cmd.exe /c \"\"",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

# Incident-field types that the silencer script can't string-match — hide them
# from the picker so analysts don't pick an unmatchable field.
_NON_MATCHABLE_FIELD_TYPES = {
    "grid", "internal", "timer", "attachments", "role", "html", "markdown",
    "tagsSelect", "button",
}

# In-process cache for the XSOAR field list (one fetch per hour per worker).
_FIELDS_CACHE: dict = {"ts": 0.0, "options": None}
_FIELDS_TTL_SECONDS = 3600

# XSOAR custom-field API keys are always lowercase alphanumerics + underscores.
# Reject anything else so analysts can't enter display labels like "File Name"
# that will silently never match.
_VALID_FIELD_KEY = re.compile(r"^[a-z0-9_]+$")


def get_field_options(list_handler, *, force: bool = False) -> dict:
    """Return the field-picker model for the silencer web form:

        {"common": [{"key", "label", "example"}, ...],
         "all":    [{"key", "label", "type"}, ...],
         "source": "xsoar" | "fallback"}

    ``common`` are the curated high-signal fields (only those the tenant
    actually has, in COMMON_FIELD_KEYS order); ``all`` is every string-matchable
    incident field sorted by label. Built live from XSOAR's /incidentfields so
    each option is a real ``cliName`` (API key) — picking from it removes the
    display-label-vs-API-key trap entirely. Cached for an hour; on any XSOAR
    error we fall back to the static SILENCER_FIELDS map so the form always
    renders.
    """
    now = time.time()
    cached = _FIELDS_CACHE.get("options")
    if not force and cached is not None and now - _FIELDS_CACHE["ts"] < _FIELDS_TTL_SECONDS:
        return cached

    options = _build_field_options(list_handler)
    _FIELDS_CACHE["options"] = options
    _FIELDS_CACHE["ts"] = now
    return options


def _fallback_field_options() -> dict:
    """The static picker model used when XSOAR can't be reached."""
    common = [
        {"key": k, "label": SILENCER_FIELDS[k], "example": FIELD_EXAMPLES.get(k, "")}
        for k in COMMON_FIELD_KEYS if k in SILENCER_FIELDS
    ]
    all_opts = sorted(
        ({"key": k, "label": v, "type": ""} for k, v in SILENCER_FIELDS.items()),
        key=lambda o: o["label"].lower(),
    )
    return {"common": common, "all": all_opts, "source": "fallback"}


def _build_field_options(list_handler) -> dict:
    """Fetch /incidentfields from XSOAR and shape it into the picker model."""
    try:
        from services.xsoar._utils import _parse_generic_response
        resp = list_handler.client.generic_request(path="/incidentfields", method="GET")
        raw = _parse_generic_response(resp)
        if not isinstance(raw, list) or not raw:
            raise ValueError("empty or non-list /incidentfields response")
    except Exception as e:
        logger.warning(f"Could not load XSOAR incident fields, using static fallback: {e}")
        return _fallback_field_options()

    by_key: dict[str, dict] = {}
    for f in raw:
        if not isinstance(f, dict):
            continue
        if f.get("group", 0) != 0:  # group 0 = incident fields (1=evidence, 4=indicator)
            continue
        key = (f.get("cliName") or "").strip()
        if not key or not _VALID_FIELD_KEY.match(key):
            continue
        if f.get("type") in _NON_MATCHABLE_FIELD_TYPES:
            continue
        label = (f.get("name") or "").strip() or SILENCER_FIELDS.get(key, key)
        by_key.setdefault(key, {"key": key, "label": label, "type": f.get("type", "")})

    # Top-level system fields the matcher supports but that may not surface as
    # group-0 fields on every tenant — always make them pickable.
    for key in ("name", "type", "severity"):
        by_key.setdefault(key, {"key": key, "label": SILENCER_FIELDS.get(key, key), "type": "shortText"})

    all_opts = sorted(by_key.values(), key=lambda o: o["label"].lower())
    common = [
        {"key": k, "label": by_key[k]["label"], "example": FIELD_EXAMPLES.get(k, "")}
        for k in COMMON_FIELD_KEYS if k in by_key
    ]
    return {"common": common, "all": all_opts, "source": "xsoar"}

# Silencers expire at this hour (ET) on their chosen date (`expires_on`). Mirrors
# the approved-testing form so analysts only see one expiry pattern across tools.
EXPIRY_HOUR_ET = 17

# Storage shape (two-field bug-bypass for the un-upgraded XSOAR script):
#   "expires_on":  user's chosen date — source of truth for our code (display, cleanup)
#   "expiry_date": expires_on + 1 day — fed to the deployed XSOAR script ONLY
#
# The deployed script has an off-by-one bug (`fromisoformat(expiry_date) <= now()`
# skips silencers at midnight server-TZ on their expiry day). Storing +1 means the
# deployed script sees the silencer as active until midnight on the day AFTER
# user's expiry, which is comfortably after our 5 PM ET cleanup removes it from
# the list. Cleanup is the real cutoff; +1 is the safety net if cleanup fails.


def parse_expires_at(entry: dict) -> datetime | None:
    """Return the tz-aware expiry datetime (5 PM ET on `expires_on`), or None."""
    eastern = timezone('US/Eastern')
    raw = entry.get("expires_on")
    if raw:
        try:
            d = datetime.fromisoformat(raw).date()
            return eastern.localize(datetime.combine(d, datetime.min.time())).replace(hour=EXPIRY_HOUR_ET)
        except ValueError:
            pass
    # Legacy entries pre-dating `expires_on`: `expiry_date` was the user's date
    # directly (no +1 trick), so interpret it the same way.
    raw = entry.get("expiry_date")
    if raw:
        try:
            d = datetime.fromisoformat(raw).date()
            return eastern.localize(datetime.combine(d, datetime.min.time())).replace(hour=EXPIRY_HOUR_ET)
        except ValueError:
            pass
    # Backward compat for the brief window where entries had `expires_at` only
    # (UTC ISO timestamp from the duration-based iteration).
    raw = entry.get("expires_at")
    if raw:
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return None


def format_expires_at_et(entry: dict) -> str:
    """Render expiry as `YYYY-MM-DD 5 PM ET` for display."""
    exp = parse_expires_at(entry)
    if exp is None:
        return "N/A"
    return exp.astimezone(timezone('US/Eastern')).strftime("%Y-%m-%d 5 PM ET")

# Top-level incident fields (not under CustomFields in XSOAR)
TOP_LEVEL_FIELDS = {"name", "type", "severity"}

# Category key → (display label, XSOAR list suffix)
CATEGORIES = {
    "ticket_cannon": {"label": "Ticket Cannon Silencers", "list_suffix": "Ticket_Cannon_Silencer"},
    "noise_suppression": {"label": "Noisy Rules Suppressors", "list_suffix": "Noise_Suppressor"},
}


def _list_name(team_name: str, category: str) -> str:
    suffix = CATEGORIES[category]["list_suffix"]
    return f"{team_name}_{suffix}"


def get_entries(list_handler, team_name: str, category: str) -> list:
    """Fetch all entries from a category's XSOAR list."""
    data = list_handler.get_list_data_by_name(_list_name(team_name, category))
    if not data or not isinstance(data, list):
        return []
    return data


def save_entries(list_handler, team_name: str, category: str, entries: list) -> None:
    """Persist entries back to a category's XSOAR list."""
    list_handler.save(_list_name(team_name, category), entries)


def create_entry(
    list_handler,
    team_name: str,
    category: str,
    description: str,
    fields: dict,
    expiry_date: str,
    created_by: str,
) -> dict:
    """Create a new silencer/suppressor entry and announce it.

    Args:
        list_handler: XSOAR ListHandler instance
        team_name: e.g. 'DnR'
        category: 'ticket_cannon' or 'noise_suppression'
        description: human-readable description
        fields: dict of field_name → exact value
        expiry_date: ISO date string `YYYY-MM-DD`; silencer dies at 5pm ET on that day
        created_by: submitter email

    Returns:
        The newly created entry dict.
    """
    if not fields:
        raise ValueError("At least one field is required.")
    if not description.strip():
        raise ValueError("Description is required.")
    if category not in CATEGORIES:
        raise ValueError(f"Invalid category: {category}")

    bad_keys = [k for k in fields if not _VALID_FIELD_KEY.match(k)]
    if bad_keys:
        raise ValueError(
            f"Invalid field key(s): {', '.join(repr(k) for k in bad_keys)}. "
            f"XSOAR field keys must be lowercase letters/digits/underscores — "
            f"use the API key (e.g. 'filename'), not the display label (e.g. 'File Name')."
        )

    eastern = timezone('US/Eastern')
    now_et = datetime.now(eastern)
    try:
        exp_date = datetime.fromisoformat(expiry_date).date()
    except (TypeError, ValueError):
        raise ValueError(f"Invalid expiry date: {expiry_date!r} (expected YYYY-MM-DD).")
    if exp_date < now_et.date():
        raise ValueError(f"Expiry date {expiry_date} is in the past.")

    entry = {
        "id": uuid.uuid4().hex[:8],
        "description": description.strip(),
        "fields": fields,
        "active": True,
        "created_by": created_by,
        "created_at": now_et.strftime("%Y-%m-%dT%H:%M:%S"),
        "expires_on": exp_date.isoformat(),
        "expiry_date": (exp_date + timedelta(days=1)).isoformat(),
        "match_count": 0,
    }

    entries = get_entries(list_handler, team_name, category)
    entries.append(entry)
    save_entries(list_handler, team_name, category, entries)

    announce_change(entry, "created", category)
    return entry


def toggle_entry(
    list_handler,
    team_name: str,
    category: str,
    entry_id: str,
    active: bool,
    toggled_by: str,
) -> dict | None:
    """Activate or deactivate an entry.

    Returns the updated entry, or None if not found.
    """
    entries = get_entries(list_handler, team_name, category)
    target = None
    for e in entries:
        if e["id"] == entry_id:
            e["active"] = active
            if active:
                eastern = timezone('US/Eastern')
                tomorrow = (datetime.now(eastern) + timedelta(days=1)).date()
                e["expires_on"] = tomorrow.isoformat()
                e["expiry_date"] = (tomorrow + timedelta(days=1)).isoformat()
                e.pop("expires_at", None)
            target = e
            break

    if target is None:
        return None

    save_entries(list_handler, team_name, category, entries)
    action = "activated" if active else "deactivated"
    announce_change(target, action, category, toggled_by=toggled_by)
    return target


def remove_expired_entries() -> None:
    """Remove expired entries from both XSOAR lists. Runs on schedule."""
    from services.xsoar import ListHandler, XsoarEnvironment
    list_handler = ListHandler(XsoarEnvironment.PROD)
    team_name = CONFIG.team_name
    now_et = datetime.now(timezone('US/Eastern'))

    for category in CATEGORIES:
        try:
            entries = get_entries(list_handler, team_name, category)
            valid = []
            removed_count = 0
            for e in entries:
                expiry = parse_expires_at(e)
                if expiry is None:
                    logger.error(f"Entry has no parseable expiry, keeping: {e.get('id')}")
                    valid.append(e)
                    continue
                if now_et < expiry:
                    valid.append(e)
                else:
                    removed_count += 1
            if removed_count > 0:
                save_entries(list_handler, team_name, category, valid)
                logger.info(f"Removed {removed_count} expired {category} entries")
        except Exception as e:
            logger.error(f"Error cleaning expired {category} entries: {e}")


def announce_change(entry: dict, action: str, category: str, toggled_by: str = "") -> None:
    """Send an Adaptive Card to Webex when an entry changes.

    Args:
        entry: the entry dict
        action: 'created', 'activated', or 'deactivated'
        category: 'ticket_cannon' or 'noise_suppression'
        toggled_by: email of person who toggled (for activate/deactivate)
    """
    category_label = CATEGORIES.get(category, {}).get("label", "Unknown")
    actor = toggled_by or entry.get("created_by", "Unknown")

    action_emoji = {"created": "🆕", "activated": "✅", "deactivated": "⏸️"}.get(action, "🔔")

    # Build field facts for the card
    field_facts = []
    fields = entry.get("fields", {})
    for field_key, field_val in fields.items():
        label = SILENCER_FIELDS.get(field_key, field_key)
        field_facts.append({"title": label, "value": field_val})

    payload = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "Container",
                "style": "emphasis",
                "bleed": True,
                "items": [
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "auto",
                                "items": [{"type": "TextBlock", "text": "🔇", "size": "Medium"}],
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "verticalContentAlignment": "center",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": f"{action_emoji} {category_label} — {action}",
                                        "size": "Medium",
                                        "weight": "Bolder",
                                        "color": "Light",
                                    },
                                ],
                            },
                        ],
                    }
                ],
            },
            {
                "type": "TextBlock",
                "text": f"**{entry.get('description', 'No description')}**",
                "spacing": "Medium",
                "wrap": True,
            },
            {
                "type": "FactSet",
                "spacing": "Small",
                "facts": [
                    {"title": "By", "value": actor},
                    {"title": "Expires", "value": format_expires_at_et(entry)},
                    {"title": "Matches so far", "value": str(entry.get("match_count", 0))},
                ],
            },
            {
                "type": "TextBlock",
                "text": "🎯 **Filter fields**",
                "separator": True,
                "spacing": "Medium",
                "color": "Accent",
            },
            {
                "type": "FactSet",
                "spacing": "Small",
                "facts": field_facts if field_facts else [{"title": "None", "value": "—"}],
            },
        ],
        "actions": [
            {
                "type": "Action.OpenUrl",
                "title": "🌐 View all silencers on web dashboard",
                "url": f"https://gdnr.{CONFIG.my_web_domain}/ticket-cannon",
            },
        ],
    }

    try:
        webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_toodles)
        webex_api.messages.create(
            roomId=CONFIG.webex_room_id_threatcon_collab,
            text=f"{category_label} {action}: {entry.get('description', '')}",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": payload}],
        )
    except Exception as e:
        logger.error(f"Failed to announce change: {e}")
