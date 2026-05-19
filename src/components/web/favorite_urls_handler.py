"""Favorite URLs Handler — JSON-based CRUD for team URLs and phone numbers."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "favorite_urls"
JSON_PATH = DATA_DIR / "favorite_urls.json"
SEED_PATH = PROJECT_ROOT / "data" / "favorite_urls_seed.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# The runtime store is gitignored and user-mutable (CRUD via /favorite-urls UI).
# On first run, hydrate it from the tracked seed file; fall back to empty list.
if not JSON_PATH.exists():
    if SEED_PATH.exists():
        JSON_PATH.write_text(SEED_PATH.read_text())
    else:
        JSON_PATH.write_text("[]")


def load_urls() -> List[Dict[str, Any]]:
    """Read the JSON file and return the list of URL entries."""
    try:
        return json.loads(JSON_PATH.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        logger.warning("Could not read %s, returning empty list", JSON_PATH)
        return []


def save_urls(data: List[Dict[str, Any]]) -> None:
    """Write the list of URL entries to the JSON file."""
    tmp = JSON_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(JSON_PATH)


def get_all_urls() -> Dict[str, List[Dict[str, Any]]]:
    """Return URLs grouped by category (dict of category -> list of items)."""
    items = load_urls()
    items.sort(key=lambda x: (x.get("category", "General"), x.get("sort_order", 0), x.get("name", "")))
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        cat = item.get("category", "General")
        grouped.setdefault(cat, []).append(item)
    return grouped


def get_url(url_id: int) -> Optional[Dict[str, Any]]:
    """Return a single item by id, or None."""
    for item in load_urls():
        if item.get("id") == url_id:
            return item
    return None


def create_url(name: str, url: str = "", phone_number: str = "",
               category: str = "General") -> Dict[str, Any]:
    """Create a new entry, auto-assign id and sort_order, return the new item."""
    data = load_urls()
    max_id = max((item.get("id", 0) for item in data), default=0)
    max_sort = max((item.get("sort_order", 0) for item in data if item.get("category") == category), default=-1)
    new_item: Dict[str, Any] = {
        "id": max_id + 1,
        "name": name,
        "category": category,
        "sort_order": max_sort + 1,
    }
    if url:
        new_item["url"] = url
    if phone_number:
        new_item["phone_number"] = phone_number
    data.append(new_item)
    save_urls(data)
    return new_item


def update_url(url_id: int, **fields) -> Optional[Dict[str, Any]]:
    """Update allowed fields on an entry. Returns updated item or None."""
    allowed = {"name", "url", "phone_number", "category"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return None
    data = load_urls()
    for item in data:
        if item.get("id") == url_id:
            item.update(updates)
            # If switching between url and phone_number, clear the other
            if "url" in updates and updates["url"]:
                item.pop("phone_number", None)
            if "phone_number" in updates and updates["phone_number"]:
                item.pop("url", None)
            save_urls(data)
            return item
    return None


def delete_url(url_id: int) -> bool:
    """Remove an entry by id. Returns True if found and deleted."""
    data = load_urls()
    new_data = [item for item in data if item.get("id") != url_id]
    if len(new_data) == len(data):
        return False
    save_urls(new_data)
    return True


def url_count() -> int:
    """Return total number of entries."""
    return len(load_urls())


def get_categories() -> List[str]:
    """Return sorted list of distinct categories."""
    cats = {item.get("category", "General") for item in load_urls()}
    return sorted(cats)
