import json
from pathlib import Path
from typing import Dict
from my_config import get_config

CONFIG = get_config()
DATA_DIR = Path(__file__).parent.parent.parent / "data"
COUNTRIES_FILE = DATA_DIR / "countries_by_code.json"

try:
    with open(COUNTRIES_FILE, 'r') as f:
        COUNTRY_NAMES_BY_ABBREVIATION = json.load(f)
except Exception:
    COUNTRY_NAMES_BY_ABBREVIATION = {}

def guess_country_from_hostname(computer) -> tuple[str, str]:
    """Guess country based on hostname patterns."""
    computer_name = computer.name
    computer_name_lower = computer_name.lower()
    if 'pmli' in computer_name_lower:
        return 'India PMLI', "Country guessed from 'pmli' in hostname"
    if computer_name_lower.startswith('vmvdi') or (hasattr(CONFIG, 'team_name') and computer_name_lower.startswith(CONFIG.team_name.lower())):
        return 'United States', f"Country guessed from VMVDI/{CONFIG.team_name if hasattr(CONFIG, 'team_name') else ''} in hostname"
    country_code = computer_name[:2].upper()
    country_name = COUNTRY_NAMES_BY_ABBREVIATION.get(country_code, '')
    if country_name:
        return country_name, f"Country guessed from first two letters of hostname: {country_code} -> {country_name}"
    if computer_name and computer_name[0].isdigit():
        return 'Korea', "Country guessed from leading digit in hostname"
    if computer_name_lower.startswith('vm'):
        for tag in getattr(computer, 'custom_tags', []):
            if 'US' in tag:
                return 'United States', "Country guessed from VM prefix and US tag"
    return '', ''

def get_region_from_country(country: str) -> str:
    """Determine the region based on country name."""
    if not country:
        return ''
    normalized_country = country.strip()
    if normalized_country.lower() in ('us', 'united states'):
        return 'US'
    if not hasattr(get_region_from_country, 'regions_by_country'):
        try:
            with open(DATA_DIR / "regions_by_country.json", 'r') as f:
                get_region_from_country.regions_by_country = json.load(f)
        except Exception:
            get_region_from_country.regions_by_country = {}
    for map_country, region in get_region_from_country.regions_by_country.items():
        if normalized_country.lower() == map_country.lower():
            return region
    return get_region_from_country.regions_by_country.get(country, '')
