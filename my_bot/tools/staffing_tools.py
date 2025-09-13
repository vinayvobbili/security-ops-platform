# /my_bot/tools/staffing_tools.py
"""
Shift Information Tools

This module provides shift timing tools for the security operations bot.
"""

import logging
import json
from datetime import datetime
import pytz
from langchain_core.tools import tool

# Import the essential staffing functions from secops
from src.secops import (
    get_current_shift,
    get_staffing_data,
    get_shift_lead,
    get_basic_shift_staffing,
    get_shift_ticket_metrics,
    get_shift_security_actions
)


@tool
def get_current_shift_info() -> str:
    """Get current shift information including shift name and time boundaries."""
    try:
        current_shift = get_current_shift()
        eastern_time = datetime.now(pytz.timezone('US/Eastern'))

        # Define shift time boundaries
        shift_times = {
            'morning': '04:30 - 12:29',
            'afternoon': '12:30 - 20:29',
            'night': '20:30 - 04:29'
        }

        result = [
            f"Current shift: {current_shift.title()}",
            f"Time (Eastern): {eastern_time.strftime('%H:%M')}",
            f"Shift hours: {shift_times[current_shift]}",
            f"Day: {eastern_time.strftime('%A, %B %d, %Y')}"
        ]

        return "\n".join(result)

    except Exception as e:
        logging.error(f"Error getting current shift info: {e}")
        return f"Unable to retrieve current shift information: {str(e)}"


@tool
def get_current_staffing() -> str:
    """Get current shift staffing information."""
    try:
        staffing_data = get_staffing_data()
        current_shift = get_current_shift()
        eastern_time = datetime.now(pytz.timezone('US/Eastern'))
        
        # Clean up the staffing data
        teams = {}
        for team, members in staffing_data.items():
            if members:
                clean_members = [member for member in members if member and member.strip()]
                if clean_members:
                    teams[team] = clean_members

        # Create simple structured data
        result = {
            "shift": current_shift,
            "day": eastern_time.strftime('%A'),
            "time": eastern_time.strftime('%H:%M EST'),
            "date": eastern_time.strftime('%Y-%m-%d'),
            "teams": teams
        }

        return json.dumps(result)

    except Exception as e:
        logging.error(f"Error getting current staffing: {e}")
        return f"Unable to retrieve current staffing information: {str(e)}"


@tool
def get_shift_lead_info(day_name: str = None, shift_name: str = None) -> str:
    """
    Get the shift lead for a specific day and shift.

    Args:
        day_name: Day of the week (e.g., 'Monday'). Defaults to current day.
        shift_name: Shift name ('morning', 'afternoon', 'night'). Defaults to current shift.

    Returns:
        JSON string with shift lead information.
    """
    try:
        if day_name is None:
            day_name = datetime.now(pytz.timezone('US/Eastern')).strftime('%A')
        if shift_name is None:
            shift_name = get_current_shift()

        shift_lead = get_shift_lead(day_name, shift_name.lower())

        result = {
            "day": day_name,
            "shift": shift_name,
            "shift_lead": shift_lead,
            "status": "success"
        }

        return json.dumps(result)

    except Exception as e:
        logging.error(f"Error getting shift lead info: {e}")
        return json.dumps({
            "error": str(e),
            "status": "error"
        })


@tool
def get_basic_staffing_summary(day_name: str = None, shift_name: str = None) -> str:
    """
    Get basic staffing summary with team counts for a specific shift.

    Args:
        day_name: Day of the week (e.g., 'Monday'). Defaults to current day.
        shift_name: Shift name ('morning', 'afternoon', 'night'). Defaults to current shift.

    Returns:
        JSON string with basic staffing data including total staff and team breakdowns.
    """
    try:
        if day_name is None:
            day_name = datetime.now(pytz.timezone('US/Eastern')).strftime('%A')
        if shift_name is None:
            shift_name = get_current_shift()

        basic_staffing = get_basic_shift_staffing(day_name, shift_name.lower())
        shift_lead = get_shift_lead(day_name, shift_name.lower())

        result = {
            "day": day_name,
            "shift": shift_name,
            "total_staff": basic_staffing['total_staff'],
            "teams": basic_staffing['teams'],
            "shift_lead": shift_lead,
            "status": "success"
        }

        return json.dumps(result)

    except Exception as e:
        logging.error(f"Error getting basic staffing summary: {e}")
        return json.dumps({
            "error": str(e),
            "status": "error"
        })


@tool
def get_shift_performance_metrics(days_back: int = 0, shift_name: str = None) -> str:
    """
    Get performance metrics for a specific shift including ticket data and response times.

    Args:
        days_back: Number of days back from today (0 = today, 1 = yesterday, etc.)
        shift_name: Shift name ('morning', 'afternoon', 'night'). Defaults to current shift.

    Returns:
        JSON string with ticket metrics and performance data.
    """
    try:
        if shift_name is None:
            shift_name = get_current_shift()

        # Map shift names to start hours
        shift_hour_map = {
            'morning': 4.5,
            'afternoon': 12.5,
            'night': 20.5
        }

        shift_start_hour = shift_hour_map.get(shift_name.lower(), 4.5)

        # Get ticket metrics
        ticket_metrics = get_shift_ticket_metrics(days_back, shift_start_hour)

        # Get security actions
        security_actions = get_shift_security_actions(days_back, shift_start_hour)

        result = {
            "days_back": days_back,
            "shift": shift_name,
            "ticket_metrics": ticket_metrics,
            "security_actions": security_actions,
            "status": "success"
        }

        return json.dumps(result)

    except Exception as e:
        logging.error(f"Error getting shift performance metrics: {e}")
        return json.dumps({
            "error": str(e),
            "status": "error"
        })


@tool
def get_comprehensive_shift_data(day_name: str = None, shift_name: str = None, days_back: int = 0) -> str:
    """
    Get comprehensive shift data combining staffing, leadership, and performance metrics.

    Args:
        day_name: Day of the week (e.g., 'Monday'). Defaults to current day.
        shift_name: Shift name ('morning', 'afternoon', 'night'). Defaults to current shift.
        days_back: Number of days back from today (0 = today, 1 = yesterday, etc.)

    Returns:
        JSON string with complete shift information including staff, lead, and performance data.
    """
    try:
        if day_name is None:
            day_name = datetime.now(pytz.timezone('US/Eastern')).strftime('%A')
        if shift_name is None:
            shift_name = get_current_shift()

        # Get all data components
        basic_staffing = get_basic_shift_staffing(day_name, shift_name.lower())
        shift_lead = get_shift_lead(day_name, shift_name.lower())
        detailed_staffing = get_staffing_data(day_name, shift_name.lower())

        # Get performance metrics if days_back is provided
        performance_data = None
        if days_back >= 0:
            try:
                shift_hour_map = {
                    'morning': 4.5,
                    'afternoon': 12.5,
                    'night': 20.5
                }
                shift_start_hour = shift_hour_map.get(shift_name.lower(), 4.5)

                ticket_metrics = get_shift_ticket_metrics(days_back, shift_start_hour)
                security_actions = get_shift_security_actions(days_back, shift_start_hour)

                performance_data = {
                    "ticket_metrics": ticket_metrics,
                    "security_actions": security_actions
                }
            except Exception as perf_error:
                logging.warning(f"Could not get performance data: {perf_error}")

        result = {
            "day": day_name,
            "shift": shift_name,
            "days_back": days_back,
            "shift_lead": shift_lead,
            "basic_staffing": basic_staffing,
            "detailed_staffing": detailed_staffing,
            "performance_data": performance_data,
            "status": "success"
        }

        return json.dumps(result)

    except Exception as e:
        logging.error(f"Error getting comprehensive shift data: {e}")
        return json.dumps({
            "error": str(e),
            "status": "error"
        })


if __name__ == "__main__":
    # Simple test calls
    print("Testing get_current_shift_info()")
    print(get_current_shift_info.invoke(""))

    print("\nTesting get_current_staffing()")
    print(get_current_staffing.invoke(""))

    print("\nTesting get_shift_lead_info()")
    print(get_shift_lead_info.invoke({}))

    print("\nTesting get_basic_staffing_summary()")
    print(get_basic_staffing_summary.invoke({}))

    print("\nTesting get_shift_performance_metrics()")
    print(get_shift_performance_metrics.invoke({"days_back": 0}))

    print("\nTesting get_comprehensive_shift_data()")
    print(get_comprehensive_shift_data.invoke({}))
