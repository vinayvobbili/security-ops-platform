"""Weather information tools via OpenWeatherMap."""

import logging

import requests

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

WEATHER_API_URL = "http://api.openweathermap.org/data/2.5/weather"


@mcp.tool()
def weather_get(city: str) -> dict:
    """Get current weather information for a city.

    Returns temperature (°F), humidity, wind speed, weather description,
    and "feels like" temperature for the given city.

    Args:
        city: City name (e.g. 'New York', 'London', 'Tokyo')
    """
    try:
        from my_config import get_config
        config = get_config()
        api_key = config.open_weather_map_api_key

        if not api_key:
            return {"error": "OpenWeatherMap API key not configured"}

        resp = requests.get(
            WEATHER_API_URL,
            params={"q": city, "appid": api_key, "units": "imperial"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        return {
            "city": data.get("name"),
            "country": data.get("sys", {}).get("country"),
            "description": data.get("weather", [{}])[0].get("description", ""),
            "temperature_f": data.get("main", {}).get("temp"),
            "feels_like_f": data.get("main", {}).get("feels_like"),
            "humidity_pct": data.get("main", {}).get("humidity"),
            "wind_mph": data.get("wind", {}).get("speed"),
        }

    except requests.RequestException as e:
        logger.error(f"Weather lookup failed for {city}: {e}")
        return {"error": f"Weather API error: {e}"}
