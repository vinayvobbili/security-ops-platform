"""
SecOps Staffing Data

Reads staffing data from the local JSON roster (migrated from Excel).
Preserves the same public API so all consumers work unchanged.
"""
import logging
from typing import Any, Dict, List, Optional

from src.components import oncall
from src.components.roster import (
    get_staffing_for_day,
    get_shift_lead_name,
    LEGACY_TO_ROSTER,
    SHIFT_TIMINGS,
)
from .shift_utils import get_current_shift

logger = logging.getLogger(__name__)


def get_staffing_data(day_name: Optional[str] = None,
                      shift_name: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Get staffing data for a specific day and shift.

    Args:
        day_name: Day of week (e.g., 'Monday'). Defaults to current day.
        shift_name: Shift name ('morning', 'afternoon', 'night'). Defaults to current shift.

    Returns:
        Dictionary mapping team names to lists of staff members.
    """
    return get_staffing_for_day(day_name, shift_name)


def get_shift_lead(day_name: str, shift_name: str) -> str:
    """
    Get the shift lead for a specific day and shift.

    Args:
        day_name: Day of week (e.g., 'Monday')
        shift_name: Shift name ('morning', 'afternoon', 'night')

    Returns:
        Name of the shift lead or error message.
    """
    return get_shift_lead_name(day_name, shift_name)


def get_basic_shift_staffing(day_name: str, shift_name: str) -> Dict[str, Any]:
    """
    Get basic staffing count for a shift without detailed data.

    Args:
        day_name: Day of week (e.g., 'Monday')
        shift_name: Shift name ('morning', 'afternoon', 'night')

    Returns:
        Dictionary with 'total_staff' count and 'teams' breakdown.
    """
    staffing = get_staffing_for_day(day_name, shift_name)
    teams = {}
    for team, members in staffing.items():
        if team != 'On-Call':
            teams[team] = len(members)
    return {'total_staff': sum(teams.values()), 'teams': teams}


def get_shift_timings(shift_name: str) -> str:
    """
    Get shift timing information.

    Args:
        shift_name: Shift name ('morning', 'afternoon', 'night')

    Returns:
        Shift timings string.
    """
    roster_key = LEGACY_TO_ROSTER.get(shift_name, shift_name)
    return SHIFT_TIMINGS.get(roster_key, "N/A")


# --- Legacy stubs (exported by src/secops/__init__.py) ---

class ExcelStaffingReader:
    """Legacy class kept for backward compatibility — staffing now reads from JSON."""

    @staticmethod
    def get_oncall_info() -> str:
        person = oncall.get_on_call_person()
        return f"{person['name']} ({person['phone_number']})"

    @staticmethod
    def get_fallback_data() -> Dict[str, List[str]]:
        return {
            'senior_analysts': ['N/A (roster unavailable)'],
            'On-Call': [ExcelStaffingReader.get_oncall_info()]
        }

    @staticmethod
    def get_error_data() -> Dict[str, List[str]]:
        return {
            'senior_analysts': ['N/A (error)'],
            'On-Call': ['N/A (error)']
        }

    @staticmethod
    def is_valid_cell_value(value: Any) -> bool:
        return (value is not None and
                str(value).strip() != '' and
                value != '\xa0')

    @staticmethod
    def read_team_staffing(sheet: Any, cell_names: List[str]) -> List[str]:
        return []


def get_excel_sheet():
    """Legacy stub — Excel no longer used for staffing."""
    return None, False
