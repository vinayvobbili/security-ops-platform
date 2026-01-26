"""
SecOps Staffing Data

Handles reading staffing data from Excel sheets and on-call information.
"""
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pytz
from openpyxl import load_workbook

from src.components import oncall
from .constants import (
    EXCEL_PATH,
    ShiftConstants,
    cell_names_by_shift,
    config,
)
from .shift_utils import get_current_shift

logger = logging.getLogger(__name__)


def get_excel_sheet() -> Tuple[Any, bool]:
    """
    Load and return the Excel workbook sheet at runtime.

    Returns:
        Tuple of (sheet, is_available) where sheet is the openpyxl worksheet object
        and is_available is a boolean indicating if the file was loaded successfully.
    """
    try:
        wb = load_workbook(EXCEL_PATH)
        sheet = wb[config.secops_shift_staffing_sheet_name]
        return sheet, True
    except FileNotFoundError:
        logger.warning(f"Excel file not found: {EXCEL_PATH}. Staffing data will be unavailable.")
        return None, False
    except Exception as e:
        logger.error(f"Error loading Excel file: {e}. Staffing data will be unavailable.")
        return None, False


class ExcelStaffingReader:
    """Handles reading staffing data from Excel sheet."""

    @staticmethod
    def get_oncall_info() -> str:
        """Get formatted on-call person info."""
        person = oncall.get_on_call_person()
        return f"{person['name']} ({person['phone_number']})"

    @staticmethod
    def get_fallback_data() -> Dict[str, List[str]]:
        """Get fallback staffing data when Excel is unavailable."""
        return {
            'senior_analysts': ['N/A (Excel file missing)'],
            'On-Call': [ExcelStaffingReader.get_oncall_info()]
        }

    @staticmethod
    def get_error_data() -> Dict[str, List[str]]:
        """Get error fallback staffing data."""
        return {
            'senior_analysts': ['N/A (Error occurred)'],
            'On-Call': ['N/A (Error occurred)']
        }

    @staticmethod
    def is_valid_cell_value(value: Any) -> bool:
        """Check if cell value is valid and not empty."""
        return (value is not None and
                str(value).strip() != '' and
                value != '\xa0')

    @staticmethod
    def read_team_staffing(sheet: Any, cell_names: List[str]) -> List[str]:
        """Read staffing data for a specific team."""
        team_staff = []
        for cell_name in cell_names:
            cell = sheet[cell_name] if sheet else None
            if cell is not None:
                value = getattr(cell, 'value', None)
                if ExcelStaffingReader.is_valid_cell_value(value):
                    team_staff.append(value)
        return team_staff


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
    if day_name is None:
        day_name = datetime.now(pytz.timezone(ShiftConstants.EASTERN_TZ)).strftime('%A')
    if shift_name is None:
        shift_name = get_current_shift()

    try:
        sheet, is_available = get_excel_sheet()
        if not is_available or sheet is None:
            logger.warning("Excel file not available, returning minimal staffing data")
            return ExcelStaffingReader.get_fallback_data()

        shift_cell_names = cell_names_by_shift[day_name][shift_name]
        staffing_data = {}

        for team, cell_names in shift_cell_names.items():
            staffing_data[team] = ExcelStaffingReader.read_team_staffing(sheet, cell_names)

        staffing_data['On-Call'] = [ExcelStaffingReader.get_oncall_info()]
        return staffing_data

    except Exception as e:
        logger.error(f"Error in get_staffing_data: {e}")
        return ExcelStaffingReader.get_error_data()


def get_shift_lead(day_name: str, shift_name: str) -> str:
    """
    Get the shift lead for a specific day and shift.

    Args:
        day_name: Day of week (e.g., 'Monday')
        shift_name: Shift name ('morning', 'afternoon', 'night')

    Returns:
        Name of the shift lead or error message.
    """
    sheet, is_available = get_excel_sheet()
    if not is_available or sheet is None:
        return "N/A (Excel file missing)"

    try:
        shift_cell_names = cell_names_by_shift[day_name][shift_name]
        if 'Lead' not in shift_cell_names:
            return "No Lead Assigned"

        for cell_name in shift_cell_names['Lead']:
            cell = sheet[cell_name]
            if cell is not None:
                value = getattr(cell, 'value', None)
                if ExcelStaffingReader.is_valid_cell_value(value):
                    return str(value)

        return "No Lead Assigned"
    except (KeyError, IndexError, AttributeError) as e:
        logger.error(f"Error getting shift lead: {e}")
        return "N/A"


def get_basic_shift_staffing(day_name: str, shift_name: str) -> Dict[str, Any]:
    """
    Get basic staffing count for a shift without detailed data.

    Args:
        day_name: Day of week (e.g., 'Monday')
        shift_name: Shift name ('morning', 'afternoon', 'night')

    Returns:
        Dictionary with 'total_staff' count and 'teams' breakdown.
    """
    sheet, is_available = get_excel_sheet()
    if not is_available or sheet is None:
        return {'total_staff': 0, 'teams': {}}

    try:
        shift_cell_names = cell_names_by_shift[day_name][shift_name]
        teams = {}

        for team, cell_names in shift_cell_names.items():
            team_count = sum(
                1 for cell_name in cell_names
                if sheet[cell_name] is not None and
                ExcelStaffingReader.is_valid_cell_value(getattr(sheet[cell_name], 'value', None))
            )
            teams[team] = team_count

        total_staff = sum(teams.values())
        return {'total_staff': total_staff, 'teams': teams}

    except (KeyError, IndexError, AttributeError) as e:
        logger.error(f"Error getting basic staffing: {e}")
        return {'total_staff': 0, 'teams': {}}


def get_shift_timings(shift_name: str) -> str:
    """
    Get shift timing information from Excel.

    Args:
        shift_name: Shift name ('morning', 'afternoon', 'night')

    Returns:
        Shift timings string or error message.
    """
    sheet, is_available = get_excel_sheet()
    if not is_available or sheet is None:
        return "N/A (Excel file missing)"

    try:
        cell = sheet[cell_names_by_shift['shift_timings'][shift_name]]
        return getattr(cell, 'value', "N/A (Excel cell missing)") if cell else "N/A (Excel cell missing)"
    except (KeyError, TypeError):
        return "N/A (Excel file issue)"
