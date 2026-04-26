"""Ticket Cannon Silencer & Noise Suppression Handler for Web Dashboard."""

import logging
from typing import Any, Dict

from services.xsoar import ListHandler
from services.ticket_cannon_utils import (
    SILENCER_FIELDS,
    EXPIRY_OPTIONS,
    CATEGORIES,
    get_entries,
    create_entry,
    toggle_entry,
)

logger = logging.getLogger(__name__)


def get_silencers_for_display(list_handler: ListHandler, team_name: str) -> Dict[str, Any]:
    """Fetch entries for all categories, split into active/inactive.

    Returns:
        {
            "categories": {key: {"label": ..., "active": [...], "inactive": [...]}, ...},
            "fields": {api_name: label, ...},
            "expiry_options": [...],
        }
    """
    categories = {}
    for cat_key, cat_info in CATEGORIES.items():
        entries = get_entries(list_handler, team_name, cat_key)

        # Attach human-readable field labels for display
        for e in entries:
            e["field_labels"] = {
                SILENCER_FIELDS.get(k, k): v for k, v in e.get("fields", {}).items()
            }

        categories[cat_key] = {
            "label": cat_info["label"],
            "active": [e for e in entries if e.get("active", False)],
            "inactive": [e for e in entries if not e.get("active", False)],
        }

    return {
        "categories": categories,
        "fields": SILENCER_FIELDS,
        "expiry_options": EXPIRY_OPTIONS,
    }


def handle_create_silencer(
    form_data: Dict[str, Any],
    list_handler: ListHandler,
    team_name: str,
    submitter_email: str,
) -> dict:
    """Validate form data and create a new entry.

    Returns:
        The newly created entry dict.

    Raises:
        ValueError: If validation fails.
    """
    category = form_data.get("category", "").strip()
    description = form_data.get("description", "").strip()
    fields = form_data.get("fields", {})
    expiry_days = form_data.get("expiry_days", 1)

    if not isinstance(fields, dict) or not fields:
        raise ValueError("At least one filter field is required.")
    if not description:
        raise ValueError("Description is required.")

    try:
        expiry_days = int(expiry_days)
    except (TypeError, ValueError):
        expiry_days = 1

    return create_entry(
        list_handler=list_handler,
        team_name=team_name,
        category=category,
        description=description,
        fields=fields,
        expiry_days=expiry_days,
        created_by=submitter_email,
    )


def handle_toggle_silencer(
    silencer_id: str,
    active: bool,
    category: str,
    list_handler: ListHandler,
    team_name: str,
    toggled_by: str,
) -> dict | None:
    """Toggle an entry's active state.

    Returns:
        The updated entry dict, or None if not found.
    """
    return toggle_entry(
        list_handler=list_handler,
        team_name=team_name,
        category=category,
        entry_id=silencer_id,
        active=active,
        toggled_by=toggled_by,
    )
