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
    AdaptiveCard, HorizontalAlignment, FactSet, Fact, ColumnSet, Column
)

# Import the essential staffing functions from secops
from src.secops import get_current_shift, get_staffing_data


class StaffingToolsManager:
    """Manager for staffing and shift timing tools"""
    
    def __init__(self):
        self.eastern_tz = pytz.timezone('US/Eastern')
    
    def get_tools(self) -> list:
        """Get list of available staffing tools"""
        return [
            get_current_shift_tool(),
            get_current_staffing_tool()
        ]
    
    def is_available(self) -> bool:
        """Check if shift tools are available"""
        return True


def get_current_shift_tool():
    """Factory function to create current shift tool"""
    @tool
    def get_current_shift_info() -> str:
        """Get information about the current shift including name and time boundaries."""
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
    
    return get_current_shift_info


def get_current_staffing_tool():
    """Factory function to create current staffing tool"""
    @tool
    def get_current_staffing() -> str:
        """Get the current shift's staffing information including all team members and on-call personnel. Use this for queries like 'Who is working right now?'"""
        try:
            staffing_data = get_staffing_data()
            current_shift = get_current_shift()
            eastern_time = datetime.now(pytz.timezone('US/Eastern'))
            day_name = eastern_time.strftime('%A')
            time_str = eastern_time.strftime('%H:%M EST')
            
            # Return structured data that Webex bot can detect and convert to cards
            result = f"🏢 **SOC STAFFING STATUS** 🏢\n"
            result += f"📅 **{current_shift.title()} Shift** • {day_name} • {time_str}\n\n"
            result += f"👥 **Current Team Members:**\n\n"
            
            # Add team emojis for card detection
            team_emojis = {
                'MA': '🔍',  # Malware Analysis
                'RA': '🛡️',   # Response Analysis  
                'SA': '👨‍💼',   # Security Analyst
                'On-Call': '📞'  # On-Call
            }
            
            for team, members in staffing_data.items():
                if members:
                    clean_members = [member for member in members if member and member.strip()]
                    if clean_members:
                        emoji = team_emojis.get(team, '👤')
                        result += f"{emoji} **{team} Team:** {', '.join(clean_members)}\n"
            
            # Add special marker for Webex bot to detect staffing responses
            result += f"\n<!-- STAFFING_RESPONSE:{current_shift}:{day_name}:{time_str} -->"
            
            return result
            
        except Exception as e:
            logging.error(f"Error getting current staffing: {e}")
            return f"Unable to retrieve current staffing information: {str(e)}"
    
    return get_current_staffing


def _create_staffing_adaptive_card(staffing_data, current_shift, day_name, time_str):
    """Create a beautiful Adaptive Card for staffing information"""
    
    # Create facts for each team
    facts = []
    team_emojis = {
        'MA': '🔍',  # Malware Analysis
        'RA': '🛡️',   # Response Analysis  
        'SA': '👨‍💼',   # Security Analyst
        'On-Call': '📞'  # On-Call
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
                text=f"🏢 SOC Staffing Status",
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
    
    return card