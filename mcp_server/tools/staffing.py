"""SOC shift staffing and scheduling tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)


@mcp.tool(tags={"readonly"})
def staffing_current_shift() -> str:
    """Get the current SOC shift name and time boundaries.

    Returns the active shift (morning/afternoon/night), current Eastern time,
    and the shift's start/end hours.
    """
    from src.secops import get_current_shift
    from datetime import datetime
    import pytz

    current_shift = get_current_shift()
    eastern_time = datetime.now(pytz.timezone('US/Eastern'))
    shift_times = {
        'morning': '04:30 - 12:29',
        'afternoon': '12:30 - 20:29',
        'night': '20:30 - 04:29',
    }
    return (
        f"Current shift: {current_shift.title()}\n"
        f"Time (Eastern): {eastern_time.strftime('%H:%M')}\n"
        f"Shift hours: {shift_times.get(current_shift, 'unknown')}\n"
        f"Day: {eastern_time.strftime('%A, %B %d, %Y')}"
    )


@mcp.tool(tags={"readonly"})
def staffing_get_staff(day_name: str = None, shift_name: str = None) -> str:
    """Get the staffing roster for a shift.

    Returns analyst names, roles, and assignments for the given shift.
    Defaults to the current shift if no parameters are provided.

    Args:
        day_name: Day of week (e.g. 'Monday'). Defaults to today.
        shift_name: Shift name ('morning', 'afternoon', 'night'). Defaults to current.
    """
    from src.secops import get_basic_shift_staffing
    return get_basic_shift_staffing(day_name=day_name, shift_name=shift_name)


@mcp.tool(tags={"readonly"})
def staffing_get_shift_lead(day_name: str = None, shift_name: str = None) -> str:
    """Get the shift lead for a specific shift.

    Returns the name and contact details of the shift lead.
    Defaults to the current shift if no parameters are provided.

    Args:
        day_name: Day of week (e.g. 'Monday'). Defaults to today.
        shift_name: Shift name ('morning', 'afternoon', 'night'). Defaults to current.
    """
    from src.secops import get_shift_lead
    return get_shift_lead(day_name=day_name, shift_name=shift_name)


@mcp.tool(tags={"readonly"})
def staffing_get_metrics(days_back: int = 0, shift_name: str = None) -> str:
    """Get shift performance metrics including ticket counts and resolution times.

    Args:
        days_back: How many days back to report (0 = current/most recent shift)
        shift_name: Specific shift to report on. Defaults to current.
    """
    from src.secops import get_shift_ticket_metrics
    return get_shift_ticket_metrics(days_back=days_back, shift_name=shift_name)
