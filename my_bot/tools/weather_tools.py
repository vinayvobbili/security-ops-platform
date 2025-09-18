"""
Weather Tools Module

Simple weather tool that makes API calls and returns raw responses.
"""

import requests
from langchain_core.tools import tool

# Import tool logging decorator
from src.utils.tool_decorator import log_tool_call


@tool
@log_tool_call
def get_weather_info(city: str) -> str:
    """Get current weather information for a specific city."""
    try:
        from my_config import get_config
        config = get_config()
        api_key = config.open_weather_map_api_key
        
        if not api_key:
            return "Error: Weather API key not configured"
            
        response = requests.get(
            "http://api.openweathermap.org/data/2.5/weather",
            params={
                'q': city,
                'appid': api_key,
                'units': 'imperial'
            },
            timeout=10
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        return f"Error fetching weather data: {str(e)}"