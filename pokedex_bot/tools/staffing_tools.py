# /pokedex_bot/tools/staffing_tools.py
"""
Shift Information Tools

This module provides shift timing tools for the security operations bot.
Staffing data is now handled via RAG search of the Excel schedule file.
"""

import logging
import json
from datetime import datetime
import pytz
from langchain_core.tools import tool
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    AdaptiveCard, HorizontalAlignment, FactSet, Fact
)

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
        day_name = eastern_time.strftime('%A')
        time_str = eastern_time.strftime('%H:%M EST')

        # Create facts for each team
        facts = []
        team_emojis = {
            'MA': '🔍',  # Monitoring Analysts
            'RA': '🛡️',  # Response Analysts  
            'SA': '👨‍💼',  # Senior Analysts
            'On-Call': '📞'  # On-Call person
        }

        for team, members in staffing_data.items():
            if members:
                clean_members = [member for member in members if member and member.strip()]
                if clean_members:
                    emoji = team_emojis.get(team, '👤')
                    facts.append(
                        Fact(
                            title=f"{emoji} {team} Team",
                            value=', '.join(clean_members)
                        )
                    )

        # Determine shift status color
        shift_colors = {
            'morning': Colors.GOOD,
            'afternoon': Colors.WARNING,
            'night': Colors.ATTENTION
        }
        shift_color = shift_colors.get(current_shift.lower(), Colors.DEFAULT)

        # Create the adaptive card
        card = AdaptiveCard(
            body=[
                TextBlock(
                    text="🏢 SOC Staffing Status",
                    weight=FontWeight.BOLDER,
                    color=Colors.ACCENT,
                    size=FontSize.LARGE,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text=f"{current_shift.title()} Shift • {day_name} • {time_str}",
                    weight=FontWeight.LIGHTER,
                    color=shift_color,
                    size=FontSize.MEDIUM,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text="Current Team Members",
                    weight=FontWeight.BOLDER,
                    size=FontSize.MEDIUM,
                    color=Colors.DEFAULT
                ),
                FactSet(facts=facts)
            ]
        )

        return card.to_json()

    except Exception as e:
        logging.error(f"Error getting current staffing: {e}")
        return f"Unable to retrieve current staffing information: {str(e)}"
