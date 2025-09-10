"""
Weather Tools Module

Simple weather tool that makes API calls and returns raw responses.
"""

import requests
from langchain_core.tools import tool


def get_weather_info_tool(api_key: str):
    """Factory function to create weather tool with API key configuration"""

    @tool
    def get_weather_info(city: str) -> str:
        """Get current weather information for a specific city."""
        try:
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

    return get_weather_info
