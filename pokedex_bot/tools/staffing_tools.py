# /pokedex_bot/tools/staffing_tools.py
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
from src.secops import get_current_shift, get_staffing_data


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


if __name__ == "__main__":
    # Simple test calls
    print("Testing get_current_shift_info()")
    print(get_current_shift_info.invoke(""))
    print("\nTesting get_current_staffing()")
    print(get_current_staffing.invoke(""))
