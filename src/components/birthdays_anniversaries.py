#!/usr/bin/python3
"""
Birthday and Anniversary Management
Handles storing and checking employee birthdays and work anniversaries.
"""

import json
import logging
import random
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)

EASTERN_TZ = ZoneInfo("America/New_York")
DATA_FILE = Path(__file__).parent.parent.parent / "data" / "transient" / "birthdays_anniversaries.json"

# Fun birthday messages with emojis
BIRTHDAY_MESSAGES = [
    "🎂 Happy Birthday, **{name}**! May your day be filled with joy, laughter, and zero security incidents! 🎉",
    "🎈 Wishing you a fantastic birthday, **{name}**! Here's to another year of catching threats and living your best life! 🎊",
    "🎁 Happy Birthday to our amazing teammate **{name}**! May your year ahead be bug-free and full of wins! 🌟",
    "🎉 Celebrating you today, **{name}**! Happy Birthday! May your cake be sweet and your alerts be few! 🍰",
    "🎂 Happy Birthday, **{name}**! Another year wiser, another year more awesome! 🚀",
    "🎊 Cheers to **{name}** on your special day! May your birthday be as epic as your incident response skills! 🎯",
    "🎈 Happy Birthday, **{name}**! Time to party like it's a zero-day... but in a good way! 🎉",
    "🌟 Wishing the happiest of birthdays to **{name}**! May your day be filled with joy and your inbox be empty! 🎁",
]

# Anniversary messages with milestone recognition
ANNIVERSARY_MESSAGES = {
    1: [
        "🎊 Congratulations on your 1-year work anniversary, **{name}**! You've made it through your first year - here's to many more! 🎉",
        "🌟 Happy 1st work anniversary, **{name}**! What a year it's been! Thank you for being part of our team! 🚀",
    ],
    2: [
        "🎉 Two years already, **{name}**? Time flies when you're stopping threats! Happy 2nd work anniversary! 🎊",
        "🎈 Celebrating 2 amazing years with **{name}**! Thank you for your dedication and hard work! 🌟",
    ],
    3: [
        "🎊 Three cheers for **{name}**'s 3-year work anniversary! Hip hip hooray! 🎉",
        "🌟 Happy 3rd work anniversary, **{name}**! You're a vital part of our security family! 🚀",
    ],
    5: [
        "🏆 MILESTONE ALERT! **{name}** has been with us for 5 incredible years! Thank you for your dedication! 🎊",
        "🌟 5 years of excellence! Happy work anniversary, **{name}**! You're a true security veteran! 🎉",
    ],
    10: [
        "🏅 A DECADE of awesomeness! **{name}** celebrates 10 years with us today! What a journey! 🎊",
        "👑 10 YEARS! **{name}**, you're a legend! Thank you for a decade of outstanding contributions! 🌟",
    ],
    15: [
        "💎 15 years of brilliance! **{name}**, you're a cornerstone of our team! Happy anniversary! 🎉",
        "🌟 Celebrating 15 amazing years with **{name}**! Your expertise is invaluable! 🏆",
    ],
    20: [
        "🏆 TWO DECADES! **{name}** celebrates 20 years of excellence! You're a true institution! 🎊",
        "👑 20 YEARS! **{name}**, your legacy is inspiring! Thank you for everything! 💎",
    ],
    25: [
        "💎 QUARTER CENTURY! **{name}** has been with us for 25 incredible years! What an achievement! 🏆",
        "👑 25 YEARS of dedication! **{name}**, you're an absolute legend! Thank you! 🌟",
    ],
}

# Default anniversary message for years not specifically listed
DEFAULT_ANNIVERSARY_MESSAGES = [
    "🎉 Happy {years}-year work anniversary, **{name}**! Thank you for your continued dedication! 🎊",
    "🌟 Celebrating {years} years with **{name}**! You're a valued member of our team! 🚀",
    "🎊 {years} years and counting! Happy work anniversary, **{name}**! Here's to many more! 🎉",
    "🎈 Congratulations on {years} amazing years, **{name}**! We're lucky to have you! 🌟",
]


def ensure_data_file_exists():
    """Create the data file if it doesn't exist."""
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text(json.dumps({"employees": []}, indent=2))
        logger.info(f"Created new birthdays/anniversaries data file: {DATA_FILE}")


def load_data() -> Dict:
    """Load birthday and anniversary data from JSON file."""
    ensure_data_file_exists()
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading birthdays/anniversaries data: {e}")
        return {"employees": []}


def save_data(data: Dict):
    """Save birthday and anniversary data to JSON file."""
    try:
        ensure_data_file_exists()
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved birthdays/anniversaries data to {DATA_FILE}")
    except Exception as e:
        logger.error(f"Error saving birthdays/anniversaries data: {e}")
        raise


def add_or_update_employee(email: str, name: str, birthday: Optional[str], anniversary: Optional[str]) -> str:
    """
    Add or update an employee's birthday and anniversary information.

    Args:
        email: Employee email address
        name: Employee name
        birthday: Birthday in MM-DD format (optional)
        anniversary: Work anniversary in YYYY-MM-DD format (optional)

    Returns:
        Success message
    """
    data = load_data()

    # Find existing employee or create new entry
    employee = None
    for emp in data["employees"]:
        if emp["email"].lower() == email.lower():
            employee = emp
            break

    if employee is None:
        employee = {
            "email": email,
            "name": name,
            "birthday": None,
            "anniversary": None
        }
        data["employees"].append(employee)
        action = "added"
    else:
        action = "updated"

    # Update fields (only if provided)
    if birthday:
        employee["birthday"] = birthday
    if anniversary:
        employee["anniversary"] = anniversary

    save_data(data)

    msg_parts = []
    if birthday:
        msg_parts.append(f"birthday ({birthday})")
    if anniversary:
        msg_parts.append(f"work anniversary ({anniversary})")

    return f"Successfully {action} {name}'s {' and '.join(msg_parts)}!"


def get_today_celebrations() -> Dict[str, List[Dict]]:
    """
    Check for today's birthdays and anniversaries.

    Returns:
        Dict with 'birthdays' and 'anniversaries' lists containing employee info
    """
    today = datetime.now(EASTERN_TZ)
    today_mmdd = today.strftime("%m-%d")

    data = load_data()

    birthdays = []
    anniversaries = []

    for employee in data["employees"]:
        # Check birthday (MM-DD format)
        if employee.get("birthday") == today_mmdd:
            birthdays.append(employee)

        # Check anniversary (YYYY-MM-DD format)
        if employee.get("anniversary"):
            try:
                anniv_date = datetime.strptime(employee["anniversary"], "%Y-%m-%d")
                if anniv_date.strftime("%m-%d") == today_mmdd:
                    years = today.year - anniv_date.year
                    anniversaries.append({
                        **employee,
                        "years": years
                    })
            except ValueError:
                logger.warning(f"Invalid anniversary date format for {employee['email']}: {employee['anniversary']}")

    return {
        "birthdays": birthdays,
        "anniversaries": anniversaries
    }


def get_birthday_message(name: str) -> str:
    """Generate a random birthday wish message."""
    return random.choice(BIRTHDAY_MESSAGES).format(name=name)


def get_anniversary_message(name: str, years: int) -> str:
    """Generate an anniversary wish message based on milestone."""
    # Check for milestone messages
    if years in ANNIVERSARY_MESSAGES:
        return random.choice(ANNIVERSARY_MESSAGES[years]).format(name=name, years=years)

    # Use default message
    return random.choice(DEFAULT_ANNIVERSARY_MESSAGES).format(name=name, years=years)


def generate_celebration_card(birthdays: List[Dict], anniversaries: List[Dict]) -> Dict:
    """
    Generate an adaptive card for birthday and anniversary celebrations.

    Args:
        birthdays: List of employees with birthdays today
        anniversaries: List of employees with anniversaries today (includes 'years' field)

    Returns:
        Adaptive card dict
    """
    from webexpythonsdk.models.cards import TextBlock, FontWeight, Colors

    body = [
        {
            "type": "TextBlock",
            "text": "🎉 Today's Celebrations! 🎉",
            "size": "Large",
            "weight": "Bolder",
            "color": "Accent",
            "horizontalAlignment": "Center"
        }
    ]

    # Add birthday wishes
    if birthdays:
        body.append({
            "type": "TextBlock",
            "text": "🎂 Birthdays 🎂",
            "size": "Medium",
            "weight": "Bolder",
            "spacing": "Large"
        })

        for employee in birthdays:
            message = get_birthday_message(employee["name"])
            body.append({
                "type": "TextBlock",
                "text": message,
                "wrap": True,
                "spacing": "Medium"
            })

    # Add anniversary wishes
    if anniversaries:
        body.append({
            "type": "TextBlock",
            "text": "🏆 Work Anniversaries 🏆",
            "size": "Medium",
            "weight": "Bolder",
            "spacing": "Large"
        })

        for employee in anniversaries:
            message = get_anniversary_message(employee["name"], employee["years"])
            body.append({
                "type": "TextBlock",
                "text": message,
                "wrap": True,
                "spacing": "Medium"
            })

    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": body
    }


def send_celebrations_if_any(webex_api, room_id: str) -> bool:
    """
    Check for celebrations and send wishes if any.

    Args:
        webex_api: Configured WebexAPI instance
        room_id: Webex room ID to send message to

    Returns:
        True if celebrations were found and message sent, False otherwise
    """
    celebrations = get_today_celebrations()
    birthdays = celebrations["birthdays"]
    anniversaries = celebrations["anniversaries"]

    if not birthdays and not anniversaries:
        logger.info("No birthdays or anniversaries today")
        return False

    logger.info(f"Found {len(birthdays)} birthday(s) and {len(anniversaries)} anniversary(ies) today!")

    try:
        card = generate_celebration_card(birthdays, anniversaries)
        webex_api.messages.create(
            roomId=room_id,
            text="Today's Celebrations!",
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card
            }]
        )
        logger.info(f"Sent celebration message to room {room_id}")
        return True
    except Exception as e:
        logger.error(f"Error sending celebration message: {e}")
        return False


def get_employee_by_email(email: str) -> Optional[Dict]:
    """
    Get an employee's birthday and anniversary data by email.

    Args:
        email: Employee email address

    Returns:
        Employee dict with 'email', 'name', 'birthday', 'anniversary' keys, or None if not found
    """
    data = load_data()
    for employee in data["employees"]:
        if employee["email"].lower() == email.lower():
            return employee
    return None


def daily_celebration_check():
    """
    Daily job to check for birthdays/anniversaries and send celebration messages.

    This function is designed to be called by the scheduler.
    It instantiates the WebexAPI and determines the target room from config.
    """
    from my_config import get_config
    from webexpythonsdk import WebexAPI

    config = get_config()

    try:
        # Create Webex API instance
        webex_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)

        # Determine target room (fallback to SOC shift updates if celebrations room not configured)
        celebration_room_id = getattr(config, 'webex_room_id_celebrations', config.webex_room_id_celebrations)

        # Check and send celebrations
        send_celebrations_if_any(webex_api, celebration_room_id)

    except Exception as e:
        logger.error(f"Error in daily celebration check: {e}", exc_info=True)
