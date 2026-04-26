"""Ticket Cannon Silencer & Noise Suppression utilities.

Manages filter entries stored in separate XSOAR lists:
  - {team}_Ticket_Cannon_Silencer  (for ticket cannon barrages)
  - {team}_Noise_Suppressor        (for chronic noisy rules)

All mutations go through the web app so that every create/activate/deactivate
triggers a Webex notification — no silent edits.
"""

import logging
import uuid
from datetime import datetime, timedelta

from pytz import timezone
from webexteamssdk import WebexTeamsAPI

from my_config import get_config

logger = logging.getLogger(__name__)
CONFIG = get_config()

# Field name → human-readable label for the dropdown
SILENCER_FIELDS = {
    "name": "Ticket Name",
    "type": "Ticket Type",
    "severity": "Severity",
    "detectionsource": "Detection Source",
    "securitycategory": "Security Category",
    "affectedhostname": "Hostname",
    "affectedusername": "Username",
    "sourceip": "Source IP",
    "correlationrule": "Correlation Rule",
    "alertname": "Alert Name",
}

# Top-level incident fields (not under CustomFields in XSOAR)
TOP_LEVEL_FIELDS = {"name", "type", "severity"}

EXPIRY_OPTIONS = [
    {"label": "1 day", "days": 1},
    {"label": "3 days", "days": 3},
    {"label": "7 days", "days": 7},
    {"label": "14 days", "days": 14},
    {"label": "30 days", "days": 30},
    {"label": "90 days", "days": 90},
]

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
    expiry_days: int,
    created_by: str,
) -> dict:
    """Create a new silencer/suppressor entry and announce it.

    Args:
        list_handler: XSOAR ListHandler instance
        team_name: e.g. 'DnR'
        category: 'ticket_cannon' or 'noise_suppression'
        description: human-readable description
        fields: dict of field_name → exact value
        expiry_days: number of days until expiry
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

    eastern = timezone('US/Eastern')
    now = datetime.now(eastern)
    expiry_date = (now + timedelta(days=expiry_days)).strftime("%Y-%m-%d")

    entry = {
        "id": uuid.uuid4().hex[:8],
        "description": description.strip(),
        "fields": fields,
        "active": True,
        "created_by": created_by,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%S"),
        "expiry_date": expiry_date,
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
                e["expiry_date"] = (datetime.now(eastern) + timedelta(days=1)).strftime("%Y-%m-%d")
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
    today = datetime.now()

    for category in CATEGORIES:
        try:
            entries = get_entries(list_handler, team_name, category)
            valid = []
            removed_count = 0
            for e in entries:
                try:
                    expiry = datetime.fromisoformat(e["expiry_date"])
                    if expiry > today:
                        valid.append(e)
                    else:
                        removed_count += 1
                except (ValueError, KeyError) as err:
                    logger.error(f"Invalid entry '{e}': {err}")
                    continue
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
                    {"title": "Expires", "value": entry.get("expiry_date", "N/A")},
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
                "url": "http://gdnr.the company.com/ticket-cannon",
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
