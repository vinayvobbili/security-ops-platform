"""SecOps Daily Roster Management - JSON-backed, replaces Excel staffing sheets.

Data model:
- team_members: list of analyst names
- periods: keyed by "YYYY-MM" of start month (bimonthly: Jan-Feb, Mar-Apr, etc.)
  Each period has a weekly schedule: day -> shift -> team -> [4 slots]
  The first senior_analysts slot is the Shift Lead.
"""

import calendar
import json
import logging
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DATA_FILE = Path(__file__).parent.parent.parent / "data" / "transient" / "roster.json"

DAYS_OF_WEEK = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
SHIFTS = ["shift1", "shift2", "shift3", "shift4"]
TEAMS = ["monitoring_analysts", "response_analysts", "senior_analysts"]
SLOTS_PER_TEAM = 4

SHIFT_TIMINGS = {
    "shift1": "7:30 PM - 4:30 AM ET",
    "shift2": "3:30 AM - 12:30 PM ET",
    "shift3": "6:30 AM - 3:30 PM ET",
    "shift4": "11:30 AM - 8:30 PM ET",
}

# Map legacy 3-shift names (from get_current_shift()) to roster shift IDs
LEGACY_TO_ROSTER = {"night": "shift1", "morning": "shift2", "afternoon": "shift4"}
ROSTER_TO_LEGACY = {"shift1": "night", "shift2": "morning", "shift4": "afternoon"}

# Bimonthly period boundaries: (start_month, end_month)
PERIOD_MONTHS = [(1, 2), (3, 4), (5, 6), (7, 8), (9, 10), (11, 12)]


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _empty_shift() -> Dict[str, List[str]]:
    return {team: [""] * SLOTS_PER_TEAM for team in TEAMS}


def _empty_schedule() -> Dict:
    return {
        day: {shift: _empty_shift() for shift in SHIFTS}
        for day in DAYS_OF_WEEK
    }


def _default_data() -> Dict:
    return {"team_members": [], "periods": {}}


def load_data() -> Dict:
    try:
        if DATA_FILE.exists():
            return json.loads(DATA_FILE.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Error loading roster data: {e}")
    return _default_data()


def save_data(data: Dict):
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Period helpers
# ---------------------------------------------------------------------------

def _period_range(month: int) -> Tuple[int, int]:
    """Return (start_month, end_month) for the bimonthly period containing month."""
    for start_m, end_m in PERIOD_MONTHS:
        if month in (start_m, end_m):
            return start_m, end_m
    return month, month


def period_id_for(year: int, month: int) -> str:
    start_m, _ = _period_range(month)
    return f"{year}-{start_m:02d}"


def period_label(period_id: str) -> str:
    year, month = int(period_id[:4]), int(period_id[5:])
    start_m, end_m = _period_range(month)
    return f"{calendar.month_name[start_m]} - {calendar.month_name[end_m]} {year}"


def get_current_period_id() -> str:
    today = date.today()
    return period_id_for(today.year, today.month)


def get_adjacent_period_id(period_id: str, direction: int) -> str:
    """Get next (+1) or previous (-1) period ID."""
    year, month = int(period_id[:4]), int(period_id[5:])
    idx = next((i for i, (s, _) in enumerate(PERIOD_MONTHS) if s == month), 0)
    idx += direction
    if idx >= len(PERIOD_MONTHS):
        return f"{year + 1}-{PERIOD_MONTHS[0][0]:02d}"
    elif idx < 0:
        return f"{year - 1}-{PERIOD_MONTHS[-1][0]:02d}"
    return f"{year}-{PERIOD_MONTHS[idx][0]:02d}"


def get_all_periods(data: Dict = None) -> List[Dict]:
    if data is None:
        data = load_data()
    return [{"id": pid, "label": period_label(pid)} for pid in sorted(data.get("periods", {}).keys())]


def ensure_period(data: Dict, period_id: str) -> Dict:
    """Ensure a period exists, creating it if necessary. Returns the period dict."""
    if period_id not in data.setdefault("periods", {}):
        data["periods"][period_id] = {
            "label": period_label(period_id),
            "schedule": _empty_schedule(),
        }
        save_data(data)
    return data["periods"][period_id]


# ---------------------------------------------------------------------------
# Team members
# ---------------------------------------------------------------------------

def get_team_members(data: Dict = None) -> List[str]:
    if data is None:
        data = load_data()
    return data.get("team_members", [])


def get_members_by_role(schedule: Optional[Dict], data: Optional[Dict] = None) -> Dict[str, List[str]]:
    """Derive each member's primary role from schedule cell frequency.

    Falls back to stored role in team_member_details for members not in the schedule.
    Returns {team_key: sorted list of names} for the three teams.
    """
    counts: Dict[str, Dict[str, int]] = {}  # name -> {team -> count}
    if schedule:
        for day_data in schedule.values():
            for shift_data in day_data.values():
                for team in TEAMS:
                    for name in shift_data.get(team, []):
                        if name and name.strip():
                            counts.setdefault(name, {})
                            counts[name][team] = counts[name].get(team, 0) + 1

    result = {team: [] for team in TEAMS}
    assigned = set()
    for name, team_counts in counts.items():
        primary = max(team_counts, key=team_counts.get)
        result[primary].append(name)
        assigned.add(name)

    # Use stored role as fallback for members not in the schedule
    if data is None:
        data = load_data()
    details = data.get("team_member_details", {})
    for name in data.get("team_members", []):
        if name not in assigned:
            role = details.get(name, {}).get("role", "")
            if role and role in TEAMS:
                result[role].append(name)

    for team in TEAMS:
        result[team].sort()
    return result


def get_team_member_details(data: Dict = None) -> Dict[str, Dict]:
    """Return {name: {first_name, last_name, email}} for all members."""
    if data is None:
        data = load_data()
    return data.get("team_member_details", {})


def add_team_member(name: str, email: str = "", role: str = "") -> bool:
    data = load_data()
    members = data.setdefault("team_members", [])
    if name in members:
        return False
    members.append(name)
    members.sort()

    # Store details if provided
    if email or role:
        parts = name.split(" ", 1)
        details = data.setdefault("team_member_details", {})
        details[name] = {
            "first_name": parts[0],
            "last_name": parts[1] if len(parts) > 1 else "",
            "email": email,
            "role": role,
        }

    save_data(data)
    return True


def remove_team_member(name: str) -> bool:
    data = load_data()
    members = data.get("team_members", [])
    if name not in members:
        return False
    members.remove(name)
    # Also remove details entry
    details = data.get("team_member_details", {})
    details.pop(name, None)
    save_data(data)
    return True


def update_team_member(old_name: str, first_name: str, last_name: str, email: str) -> Dict[str, Any]:
    """Update a team member's details and optionally rename them.

    Returns {"success": True/False, "error": "...", "new_name": "..."}.
    """
    data = load_data()
    members = data.get("team_members", [])
    if old_name not in members:
        return {"success": False, "error": "Member not found"}

    new_name = f"{first_name} {last_name}".strip()
    if not new_name:
        return {"success": False, "error": "Name cannot be empty"}

    # Check for duplicate if name changed
    if new_name != old_name and new_name in members:
        return {"success": False, "error": "A member with that name already exists"}

    # Update name in team_members list
    if new_name != old_name:
        idx = members.index(old_name)
        members[idx] = new_name
        members.sort()

        # Rename in all schedule cells
        for period in data.get("periods", {}).values():
            schedule = period.get("schedule", {})
            for day_data in schedule.values():
                for shift_data in day_data.values():
                    for team in TEAMS:
                        slots = shift_data.get(team, [])
                        for i, slot_name in enumerate(slots):
                            if slot_name == old_name:
                                slots[i] = new_name

    # Update details
    details = data.setdefault("team_member_details", {})
    if new_name != old_name:
        details.pop(old_name, None)
    existing = details.get(old_name, {}) if new_name == old_name else details.get(new_name, {})
    details[new_name] = {"first_name": first_name, "last_name": last_name, "email": email, "role": existing.get("role", "")}

    save_data(data)
    return {"success": True, "new_name": new_name}


# ---------------------------------------------------------------------------
# Schedule CRUD
# ---------------------------------------------------------------------------

def update_slot(period_id: str, day: str, shift: str, team: str, slot: int, name: str) -> bool:
    if day not in DAYS_OF_WEEK or shift not in SHIFTS or team not in TEAMS:
        return False
    if not (0 <= slot < SLOTS_PER_TEAM):
        return False

    data = load_data()
    ensure_period(data, period_id)
    data["periods"][period_id]["schedule"][day][shift][team][slot] = name
    save_data(data)
    return True


# ---------------------------------------------------------------------------
# Compatibility layer (same interface as old Excel reader)
# ---------------------------------------------------------------------------

def get_staffing_for_day(day_name: str = None, shift_name: str = None) -> Dict[str, List[str]]:
    """Return staffing in the same format as the old ExcelStaffingReader.

    Returns: {'monitoring_analysts': [...], 'response_analysts': [...],
              'senior_analysts': [...], 'On-Call': [...]}
    """
    import pytz
    from src.secops.shift_utils import get_current_shift

    if day_name is None:
        day_name = datetime.now(pytz.timezone('US/Eastern')).strftime('%A')
    if shift_name is None:
        shift_name = get_current_shift()

    # Accept legacy names (morning/afternoon/night) and map to roster IDs
    roster_shift = LEGACY_TO_ROSTER.get(shift_name, shift_name)

    data = load_data()
    period_id = get_current_period_id()
    period = data.get("periods", {}).get(period_id)

    if not period:
        return {team: [] for team in TEAMS}

    shift_schedule = period.get("schedule", {}).get(day_name, {}).get(roster_shift, {})

    result = {}
    for team in TEAMS:
        result[team] = [m for m in shift_schedule.get(team, []) if m.strip()]

    # Append on-call info (separate system)
    from src.components import oncall
    try:
        person = oncall.get_on_call_person()
        result['On-Call'] = [f"{person['name']} ({person['phone_number']})"]
    except Exception:
        result['On-Call'] = ['N/A']

    return result


def get_shift_lead_name(day_name: str = None, shift_name: str = None) -> str:
    staffing = get_staffing_for_day(day_name, shift_name)
    seniors = staffing.get('senior_analysts', [])
    return seniors[0] if seniors else "No Lead Assigned"


# ---------------------------------------------------------------------------
# Seed from Excel (one-time migration)
# ---------------------------------------------------------------------------

def seed_from_excel() -> bool:
    """Read current Excel staffing sheet and populate roster JSON."""
    try:
        from openpyxl import load_workbook
        from src.secops.constants import EXCEL_PATH, cell_names_by_shift, config
    except ImportError as e:
        logger.error(f"Cannot import dependencies for seed: {e}")
        return False

    if not EXCEL_PATH or not EXCEL_PATH.exists():
        logger.error(f"Excel file not found: {EXCEL_PATH}")
        return False

    wb = load_workbook(EXCEL_PATH)
    sheet = wb[config.secops_shift_staffing_sheet_name]

    data = load_data()
    period_id = get_current_period_id()
    all_members = set()
    schedule = _empty_schedule()

    for day in DAYS_OF_WEEK:
        if day not in cell_names_by_shift:
            continue
        for shift in SHIFTS:
            if shift not in cell_names_by_shift[day]:
                continue
            shift_cells = cell_names_by_shift[day][shift]
            for team in TEAMS:
                if team not in shift_cells:
                    continue
                for i, cell_ref in enumerate(shift_cells[team][:SLOTS_PER_TEAM]):
                    cell = sheet[cell_ref]
                    value = getattr(cell, 'value', None)
                    if value and str(value).strip() and str(value).strip() != '\xa0':
                        name = str(value).strip()
                        schedule[day][shift][team][i] = name
                        all_members.add(name)

    data["team_members"] = sorted(all_members)
    data.setdefault("periods", {})[period_id] = {
        "label": period_label(period_id),
        "schedule": schedule,
    }
    save_data(data)
    print(f"Seeded {len(all_members)} team members into period {period_id}")
    return True


if __name__ == "__main__":
    print("Seeding roster from Excel...")
    if seed_from_excel():
        data = load_data()
        print(f"Team members: {data['team_members']}")
        print(f"Periods: {list(data['periods'].keys())}")
    else:
        print("Seed failed - check logs")
