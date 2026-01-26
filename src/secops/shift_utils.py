"""
SecOps Shift Utilities

Utilities for shift determination, datetime parsing, and timing calculations.
"""
import logging
from datetime import datetime

import pytz

from .constants import ShiftConstants

logger = logging.getLogger(__name__)


def get_current_shift() -> str:
    """
    Determine current shift based on Eastern time.

    Returns:
        Shift name: 'morning', 'afternoon', or 'night'
    """
    try:
        eastern = pytz.timezone(ShiftConstants.EASTERN_TZ)
        now = datetime.now(eastern)
        total_minutes = now.hour * 60 + now.minute

        if ShiftConstants.MORNING_START <= total_minutes < ShiftConstants.AFTERNOON_START:
            return 'morning'
        elif ShiftConstants.AFTERNOON_START <= total_minutes < ShiftConstants.NIGHT_START:
            return 'afternoon'
        else:
            return 'night'
    except Exception as e:
        logger.error(f"Error in get_current_shift: {e}")
        # Default to morning if there's an error
        return 'morning'


def safe_parse_datetime(dt_string: str) -> datetime | None:
    """
    Parse datetime string safely, ensuring it's timezone naive.

    Handles the format: "09/16/2024 06:34:17 PM EDT"
    The timezone suffix (EDT, EST, etc.) is ignored since we return naive datetime.

    Args:
        dt_string: Datetime string to parse

    Returns:
        Parsed datetime object or None if parsing fails
    """
    if not dt_string:
        return None

    try:
        # Remove timezone suffix (EDT, EST, etc.) and parse
        # Format: "MM/DD/YYYY HH:MM:SS AM/PM TZ"
        dt_without_tz = dt_string.rsplit(' ', 1)[0]  # Remove last space-separated token (timezone)
        dt = datetime.strptime(dt_without_tz, '%m/%d/%Y %I:%M:%S %p')
        return dt
    except Exception as e:
        logger.error(f"Error parsing datetime {dt_string}: {e}")
        return None


def get_shift_start_hour(shift_name: str) -> float:
    """
    Get the start hour for a shift in decimal format.

    Args:
        shift_name: 'morning', 'afternoon', or 'night'

    Returns:
        Start hour in decimal format (e.g., 4.5 for 4:30 AM)
    """
    return ShiftConstants.SHIFT_START_HOURS.get(shift_name, 4.5)


def get_previous_shift_info(current_shift: str) -> tuple[str, int]:
    """
    Get information about the previous shift.

    Args:
        current_shift: Current shift name

    Returns:
        Tuple of (previous_shift_name, days_back)
    """
    previous_shift_mapping = {
        'morning': ('night', 1),  # Previous night (yesterday)
        'afternoon': ('morning', 0),  # This morning
        'night': ('afternoon', 0),  # This afternoon
    }
    return previous_shift_mapping.get(current_shift, ('morning', 0))


def get_eastern_timezone():
    """Get the Eastern timezone object."""
    return pytz.timezone(ShiftConstants.EASTERN_TZ)
