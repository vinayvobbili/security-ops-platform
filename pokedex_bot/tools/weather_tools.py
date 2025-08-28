# /services/weather_tools.py
"""
Weather Tools Module

This module provides weather-related tools for the security operations bot,
including OpenWeatherMap API integration with fallback mock data.
"""

import requests
import logging
from typing import Dict
from langchain_core.tools import tool


class WeatherToolsManager:
    """Manager for weather-related tools and API configuration"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "http://api.openweathermap.org/data/2.5/weather"
        self.timeout = 10
        
    def get_tools(self) -> list:
        """Get list of available weather tools"""
        return [get_weather_info_tool(self.api_key)]
    
    def update_api_key(self, api_key: str):
        """Update API key configuration"""
        self.api_key = api_key


def get_weather_info_tool(api_key: str):
    """Factory function to create weather tool with API key configuration"""
    @tool
    def get_weather_info(city: str) -> str:
        """
        Get current weather information for a specific city using OpenWeatherMap free API.
        Use this tool when asked about weather conditions.
        """
        return _get_weather_data(city, api_key)
    
    return get_weather_info


def _get_weather_data(city: str, api_key: str) -> str:
    """Get weather data from OpenWeatherMap API with fallback"""
    base_url = "http://api.openweathermap.org/data/2.5/weather"
    
    try:
        # Make API request
        params = {
            'q': city,
            'appid': api_key,
            'units': 'imperial'  # For Fahrenheit, use 'metric' for Celsius
        }
        
        response = requests.get(base_url, params=params, timeout=10)
        
        if response.status_code == 401:
            # Fallback to mock data if no API key is configured
            return _get_mock_weather(city)
            
        response.raise_for_status()
        data = response.json()
        
        # Extract and format weather information
        return _format_weather_data(data)
        
    except requests.exceptions.HTTPError as e:
        if hasattr(e, 'response') and e.response.status_code == 404:
            return f"Weather data not available for '{city}'. Please check the city name and try again."
        else:
            return _get_mock_weather(city)
    except requests.exceptions.RequestException as e:
        # Fallback to mock data on network error
        return _get_mock_weather(city)
    except KeyError as e:
        return _get_mock_weather(city)
    except Exception as e:
        return _get_mock_weather(city)


def _format_weather_data(data: Dict) -> str:
    """Format weather data from API response"""
    try:
        location = data['name']
        country = data['sys']['country']
        weather = data['weather'][0]
        main = data['main']
        wind = data.get('wind', {})
        
        # Format the weather information
        weather_info = f"Current weather in {location}, {country}: "
        weather_info += f"{weather['description'].title()}, "
        weather_info += f"{main['temp']:.0f}°F "
        
        if 'feels_like' in main:
            weather_info += f"(feels like {main['feels_like']:.0f}°F), "
            
        weather_info += f"humidity {main['humidity']}%"
        
        if wind.get('speed'):
            # Convert m/s to mph and add wind direction
            wind_mph = wind['speed'] * 2.237
            wind_dir = wind.get('deg', 0)
            direction = _get_wind_direction(wind_dir)
            weather_info += f", wind {wind_mph:.0f} mph {direction}"
            
        return weather_info
        
    except KeyError as e:
        logging.error(f"Error formatting weather data: {e}")
        return "Error formatting weather data"


def _get_wind_direction(degrees: float) -> str:
    """Convert wind direction in degrees to cardinal direction"""
    directions = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
                  "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
    dir_index = int((degrees + 11.25) / 22.5) % 16
    return directions[dir_index]


def _get_mock_weather(city: str) -> str:
    """Fallback mock weather data when API is not available"""
    mock_data = {
        "new york": "Cloudy, 45°F, humidity 70%, wind 8 mph NW",
        "london": "Rainy, 52°F, humidity 85%, wind 12 mph SW", 
        "tokyo": "Clear, 72°F, humidity 60%, wind 5 mph E",
        "paris": "Partly cloudy, 59°F, humidity 65%, wind 6 mph W",
        "sydney": "Sunny, 75°F, humidity 55%, wind 10 mph SE",
        "san francisco": "Sunny, 68°F, humidity 70%, wind 15 mph W",
        "berlin": "Overcast, 48°F, humidity 80%, wind 7 mph N"
    }
    
    city_lower = city.lower()
    if city_lower in mock_data:
        return f"Current weather in {city}: {mock_data[city_lower]} (Note: Using sample data - configure OpenWeatherMap API key for live data)"
    else:
        return f"Weather data not available for '{city}'. Supported sample cities: {', '.join(mock_data.keys())}"


def get_supported_mock_cities() -> list:
    """Get list of cities supported by mock weather data"""
    return ["New York", "London", "Tokyo", "Paris", "Sydney", "San Francisco", "Berlin"]


def validate_api_key(api_key: str) -> bool:
    """Validate OpenWeatherMap API key by making a test request"""
    if not api_key:
        return False
        
    try:
        params = {
            'q': 'London',
            'appid': api_key,
            'units': 'imperial'
        }
        
        response = requests.get(
            "http://api.openweathermap.org/data/2.5/weather",
            params=params,
            timeout=5
        )
        
        return response.status_code == 200
        
    except Exception as e:
        logging.error(f"Error validating API key: {e}")
        return False