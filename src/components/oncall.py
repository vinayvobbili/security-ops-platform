"""
On-Call Schedule Management

Local JSON-based on-call rotation management with auto-extend.
Migrated from XSOAR list-based storage to local file.

Data file: data/transient/oncall.json
Schema: {"analysts": [...], "rotation": [...]}
"""

import json
import logging
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)

EASTERN_TZ = ZoneInfo("America/New_York")
DATA_FILE = Path(__file__).parent.parent.parent / "data" / "transient" / "oncall.json"
AUTO_EXTEND_DAYS = 90


# --- File I/O ---

def _ensure_data_file():
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text(json.dumps({"analysts": [], "rotation": []}, indent=2))
        logger.info(f"Created new on-call data file: {DATA_FILE}")


def load_data() -> Dict:
    _ensure_data_file()
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading on-call data: {e}")
        return {"analysts": [], "rotation": []}


def save_data(data: Dict):
    _ensure_data_file()
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)


# --- Auto-extend ---

def auto_extend_rotation(data: Dict) -> bool:
    """Ensure rotation covers at least AUTO_EXTEND_DAYS from today via round-robin.
    Returns True if new entries were added."""
    analysts = data.get("analysts", [])
    rotation = data.get("rotation", [])

    if not analysts:
        return False

    today = date.today()
    target_date = today + timedelta(days=AUTO_EXTEND_DAYS)

    existing_mondays = set()
    last_monday = None
    last_analyst_name = None
    for entry in rotation:
        try:
            monday = date.fromisoformat(entry["Monday_date"])
            existing_mondays.add(entry["Monday_date"])
            if last_monday is None or monday > last_monday:
                last_monday = monday
                last_analyst_name = entry.get("analyst_name")
        except (ValueError, KeyError):
            continue

    if last_monday is None:
        # No entries yet: start from this week's Monday
        last_monday = today - timedelta(days=today.weekday()) - timedelta(weeks=1)
        last_analyst_name = None

    if last_monday >= target_date:
        return False

    analyst_names = [a["name"] for a in analysts]
    if last_analyst_name and last_analyst_name in analyst_names:
        idx = (analyst_names.index(last_analyst_name) + 1) % len(analyst_names)
    else:
        idx = 0

    extended = False
    current_monday = last_monday + timedelta(weeks=1)
    while current_monday <= target_date:
        monday_str = current_monday.isoformat()
        if monday_str not in existing_mondays:
            rotation.append({"Monday_date": monday_str, "analyst_name": analyst_names[idx]})
            idx = (idx + 1) % len(analyst_names)
            extended = True
        current_monday += timedelta(weeks=1)

    if extended:
        rotation.sort(key=lambda w: w.get("Monday_date", ""))
        data["rotation"] = rotation
        logger.info(f"Auto-extended rotation to {target_date.isoformat()}")

    return extended


def _load_and_extend() -> Dict:
    """Load data and auto-extend if needed."""
    data = load_data()
    if auto_extend_rotation(data):
        save_data(data)
    return data


# --- Public API (unchanged interface) ---

def get_on_call_person() -> Dict[str, str]:
    """Get current on-call person.
    Returns: {'name': str, 'email_address': str, 'phone_number': str} or {}
    """
    try:
        today = datetime.now(EASTERN_TZ).date()
        last_monday_str = (today - timedelta(days=today.weekday())).isoformat()

        data = _load_and_extend()
        analysts = {a["name"]: a for a in data.get("analysts", [])}

        for entry in data.get("rotation", []):
            if entry.get("Monday_date") == last_monday_str:
                name = entry["analyst_name"]
                analyst = analysts.get(name, {})
                return {
                    "name": name,
                    "email_address": analyst.get("email_address", ""),
                    "phone_number": analyst.get("phone_number", ""),
                }

        logger.error(f"No rotation entry for week of {last_monday_str}")
        return {}
    except Exception as e:
        logger.error(f"Error in get_on_call_person: {e}", exc_info=True)
        return {}


def get_rotation() -> List[Dict]:
    """Get rotation schedule from previous week onward (for bot commands)."""
    try:
        data = _load_and_extend()
        today = date.today()
        start_date = today - timedelta(days=today.weekday() + 7)

        weeks = []
        for entry in data.get("rotation", []):
            try:
                if date.fromisoformat(entry["Monday_date"]) >= start_date:
                    weeks.append(entry)
            except (ValueError, KeyError):
                continue

        weeks.sort(key=lambda w: w.get("Monday_date", ""))
        return weeks
    except Exception as e:
        logger.error(f"Error getting rotation: {e}", exc_info=True)
        return []


def alert_change():
    """Send Webex notification about next week's on-call person (scheduled Friday)."""
    try:
        from my_config import get_config
        from webexpythonsdk import WebexAPI

        config = get_config()
        webex_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)

        today = date.today()
        days_until_monday = (7 - today.weekday()) % 7
        if days_until_monday == 0:
            days_until_monday = 7
        coming_monday_str = (today + timedelta(days=days_until_monday)).isoformat()

        data = _load_and_extend()
        analysts = {a["name"]: a for a in data.get("analysts", [])}

        on_call = None
        for entry in data.get("rotation", []):
            if entry.get("Monday_date") == coming_monday_str:
                name = entry["analyst_name"]
                a = analysts.get(name, {})
                on_call = {"name": name, "email_address": a.get("email_address", "")}
                break

        if not on_call:
            message = f"Warning: Could not determine next week's ({coming_monday_str}) On-call person."
            logger.error(message)
        else:
            message = (f"Next week's On-call person ({coming_monday_str}) is "
                       f"**{on_call['name']}** ({on_call['email_address']})")

        for room_id in [config.webex_room_id_response_engineering, config.webex_room_id_dev_test_space]:
            if not room_id:
                continue
            try:
                webex_api.messages.create(roomId=room_id, markdown=message)
                logger.info(f"Sent on-call alert to room {room_id}")
            except Exception as e:
                logger.error(f"Failed to send to room {room_id}: {e}")
    except Exception as e:
        logger.error(f"Failed to send on-call alert: {e}", exc_info=True)


def announce_change(room_id: Optional[str] = None):
    """Send Webex notification about current on-call person (scheduled Monday)."""
    try:
        from my_config import get_config
        from webexpythonsdk import WebexAPI

        config = get_config()
        if room_id is None:
            room_id = config.webex_room_id_threatcon_collab
        if not room_id:
            logger.error("No room_id for announce_change")
            return

        webex_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)
        on_call = get_on_call_person()

        if not on_call or "name" not in on_call:
            message = "Error: Could not determine the current on-call person."
        else:
            name = on_call["name"]
            email = on_call.get("email_address", "unknown")
            phone = on_call.get("phone_number", "unknown")
            message = f"On-call person now is **{name}** (<{email}>) Phone: [{phone}](tel:{phone})"

        try:
            webex_api.messages.create(roomId=room_id, markdown=message)
            logger.info(f"Sent on-call announcement to room {room_id}")
        except Exception as e:
            logger.error(f"Failed to send announcement: {e}")
    except Exception as e:
        logger.error(f"Failed to announce on-call change: {e}", exc_info=True)


# --- CRUD for web UI ---

def get_all_data() -> Dict:
    """Get full on-call data (analysts + rotation), auto-extending if needed."""
    return _load_and_extend()


def add_analyst(name: str, email_address: str, phone_number: str) -> bool:
    data = load_data()
    for a in data["analysts"]:
        if a["name"].lower() == name.lower():
            return False
    data["analysts"].append({
        "name": name,
        "email_address": email_address,
        "phone_number": phone_number,
    })
    auto_extend_rotation(data)
    save_data(data)
    return True


def update_analyst(original_name: str, name: str, email_address: str, phone_number: str) -> bool:
    data = load_data()
    for a in data["analysts"]:
        if a["name"] == original_name:
            if original_name != name:
                for entry in data["rotation"]:
                    if entry["analyst_name"] == original_name:
                        entry["analyst_name"] = name
            a["name"] = name
            a["email_address"] = email_address
            a["phone_number"] = phone_number
            save_data(data)
            return True
    return False


def remove_analyst(name: str) -> bool:
    """Remove an analyst from the pool. Existing rotation entries are kept."""
    data = load_data()
    before = len(data["analysts"])
    data["analysts"] = [a for a in data["analysts"] if a["name"] != name]
    if len(data["analysts"]) < before:
        save_data(data)
        return True
    return False


def assign_week(monday_date: str, analyst_name: str) -> bool:
    data = load_data()
    for entry in data["rotation"]:
        if entry["Monday_date"] == monday_date:
            entry["analyst_name"] = analyst_name
            save_data(data)
            return True
    data["rotation"].append({"Monday_date": monday_date, "analyst_name": analyst_name})
    data["rotation"].sort(key=lambda w: w.get("Monday_date", ""))
    save_data(data)
    return True


def swap_weeks(monday_date_1: str, monday_date_2: str) -> bool:
    data = load_data()
    e1 = e2 = None
    for entry in data["rotation"]:
        if entry["Monday_date"] == monday_date_1:
            e1 = entry
        elif entry["Monday_date"] == monday_date_2:
            e2 = entry
    if e1 and e2:
        e1["analyst_name"], e2["analyst_name"] = e2["analyst_name"], e1["analyst_name"]
        save_data(data)
        return True
    return False


# --- One-time seed from XSOAR ---

def seed_from_xsoar():
    """Pull current data from XSOAR Spear_OnCall list and save locally."""
    try:
        from services.xsoar import ListHandler, XsoarEnvironment
        handler = ListHandler(XsoarEnvironment.PROD)
        xsoar_data = handler.get_list_data_by_name('Spear_OnCall')

        if not xsoar_data or not isinstance(xsoar_data, dict):
            logger.error("Could not fetch Spear_OnCall from XSOAR")
            return False

        data = {
            "analysts": xsoar_data.get("analysts", []),
            "rotation": xsoar_data.get("rotation", []),
        }
        auto_extend_rotation(data)
        save_data(data)
        logger.info(f"Seeded on-call data: {len(data['analysts'])} analysts, {len(data['rotation'])} rotation entries")
        return True
    except Exception as e:
        logger.error(f"Error seeding from XSOAR: {e}", exc_info=True)
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Seeding on-call data from XSOAR...")
    if seed_from_xsoar():
        data = load_data()
        print(f"Done! {len(data['analysts'])} analysts, {len(data['rotation'])} rotation entries")
        print(f"Saved to {DATA_FILE}")
    else:
        print("Failed to seed data. Check logs.")
