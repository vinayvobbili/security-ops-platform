import logging
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional, Any

from pytz import timezone
from webexteamssdk import WebexTeamsAPI, ApiError

from my_config import get_config
from services.xsoar import ListHandler

# --- Configuration and Initialization ---
CONFIG = get_config()

webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_toodles)

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

list_handler = ListHandler()


# --- Helper Function ---

def _find_first(iterable: List[Dict], condition: callable, default: Any = None) -> Optional[Dict]:
    """Helper to find the first dictionary item matching a condition."""
    try:
        return next(item for item in iterable if condition(item))
    except StopIteration:
        return default
    except TypeError:  # Handle case where iterable might not be as expected
        log.error(f"Error iterating in _find_first. Expected list of dicts, got: {type(iterable)}")
        return default


def _get_on_call_details_by_monday_date(monday_date_str: str) -> Optional[Dict[str, str]]:
    """
    Retrieves the on-call person's name and email for a given Monday date string.

    Args:
        monday_date_str: The Monday date in 'YYYY-MM-DD' format.

    Returns:
        A dictionary {'name': str, 'email': str} if found, otherwise None.
    """
    try:
        on_call_list_data = list_handler.get_list_data_by_name('Spear_OnCall')
        # Basic validation for expected structure
        if not isinstance(on_call_list_data, dict) or \
                'rotation' not in on_call_list_data or \
                'analysts' not in on_call_list_data or \
                not isinstance(on_call_list_data['rotation'], list) or \
                not isinstance(on_call_list_data['analysts'], list):
            log.error("XSOAR list 'Spear_OnCall' has unexpected structure or missing keys.")
            return None
        analysts = on_call_list_data['analysts']
        rotation = on_call_list_data['rotation']
    except Exception as e:  # Catch potential errors from list_handler or network issues
        log.error(f"Failed to get or parse 'Spear_OnCall' list: {e}", exc_info=True)
        return None

    # Find the rotation entry for the given Monday
    rotation_entry = _find_first(rotation, lambda x: isinstance(x, dict) and x.get('Monday_date') == monday_date_str)
    if not rotation_entry or 'analyst_name' not in rotation_entry:
        log.warning(f"No rotation entry found for Monday_date: {monday_date_str}")
        return None
    on_call_name = rotation_entry['analyst_name']

    # Find the analyst details using the name
    analyst_entry = _find_first(analysts, lambda x: isinstance(x, dict) and x.get('name') == on_call_name)
    if not analyst_entry or 'email_address' not in analyst_entry:
        log.warning(f"No analyst details found for name: {on_call_name}")
        return None
    on_call_email_address = analyst_entry['email_address']
    on_call_phone_number = analyst_entry['phone_number']

    return {'name': on_call_name, 'email_address': on_call_email_address, 'phone_number': on_call_phone_number}


# --- Core Functions ---

def get_on_call_person() -> dict[str, str]:
    """
    Gets the formatted string for the current on-call person from XSOAR lists.

    Returns:
        Formatted string "**Name** (email@example.com)" or {} on failure.
    """
    try:
        # Use IANA timezone database name for reliability with DST
        tz = timezone('America/New_York')
        today = datetime.now(tz)
        # Calculate the date of the most recent Monday (could be today)
        last_monday_date = today.date() - timedelta(days=today.weekday())
        last_monday_str = last_monday_date.strftime('%Y-%m-%d')

        on_call_details = _get_on_call_details_by_monday_date(last_monday_str)

        if on_call_details:
            return on_call_details
        else:
            log.error(f"Could not determine on-call person for week of {last_monday_str}")
            return {}
    except Exception as e:
        log.error(f"Unexpected error in get_on_call_person: {e}", exc_info=True)
        return {}


def alert_change():
    """Sends a Webex notification about the upcoming on-call person."""
    try:
        today = date.today()
        # Calculate the date of the *next* Monday
        days_until_next_monday = (7 - today.weekday()) % 7
        # Handle case where today is Monday - we want next week's Monday
        if days_until_next_monday == 0:
            days_until_next_monday = 7
        coming_monday_date = today + timedelta(days=days_until_next_monday)
        coming_monday_str = coming_monday_date.strftime('%Y-%m-%d')

        on_call_details = _get_on_call_details_by_monday_date(coming_monday_str)

        if not on_call_details:
            message = f"⚠️ **Warning:** Could not determine next week's ({coming_monday_str}) On-call person from XSOAR list 'Spear_OnCall'."
            log.error(message)
        else:
            message = f"Next week's On-call person ({coming_monday_str}) is **{on_call_details['name']}** ({on_call_details['email_address']})"

        # List of rooms to notify
        room_ids = [
            # CONFIG.webex_room_id_response_engineering,
            CONFIG.webex_room_id_vinay_test_space,
            # Add other relevant room IDs here
        ]

        for room_id in room_ids:
            if not room_id:
                log.warning("Skipping notification due to missing room ID in config.")
                continue
            try:
                webex_api.messages.create(roomId=room_id, markdown=message)  # Use markdown for **
                log.info(f"Sent on-call change alert to room ID: {room_id}")
            except ApiError as webex_e:
                log.error(f"Webex API error sending message to room {room_id}: {webex_e}")
            except Exception as webex_e:  # Catch other potential errors (network, etc.)
                log.error(f"Failed to send Webex message to room {room_id}: {webex_e}", exc_info=True)

    except Exception as e:
        # Log the specific error that occurred before this broad catch
        log.error(f'Failed to generate and send on-call change alert: {e}', exc_info=True)


def announce_change(room_id: Optional[str] = CONFIG.webex_room_id_threatcon_collab):
    """Sends a Webex notification about the current on-call person."""
    try:
        on_call_details = get_on_call_person()

        if not on_call_details or "name" not in on_call_details:
            message = "⚠️ **Error:** Could not determine the current on-call person."
            log.error("Failed to determine current on-call person for announcement.")
        else:
            name = on_call_details.get("name", "_unknown_")
            email = on_call_details.get("email_address", "_unknown_")
            phone = on_call_details.get("phone_number", "_unknown_")
            # Try multiple approaches for phone link - Webex may be picky about URL schemes
            message = f"On-call person now is **{name}** (<{email}>) Phone: [{phone}](tel:{phone})"

        if not room_id:
            log.error("Cannot announce change: webex_room_id_threatcon_collab not configured.")
            return

        try:
            webex_api.messages.create(roomId=room_id, markdown=message)  # Use markdown for **
            log.info(f"Sent current on-call announcement to room ID: {room_id}")
        except ApiError as webex_e:
            log.error(f"Webex API error sending announcement to room {room_id}: {webex_e}")
        except Exception as webex_e:  # Catch other potential errors
            log.error(f"Failed to send Webex announcement to room {room_id}: {webex_e}", exc_info=True)

    except Exception as e:
        log.error(f'Failed to announce on-call change: {e}', exc_info=True)


def get_rotation() -> List[Dict]:
    """
    Gets the on-call rotation schedule starting from the previous week.

    Returns:
        A list of rotation dictionaries, sorted by date, or an empty list on error.
    """
    try:
        on_call_list_data = list_handler.get_list_data_by_name('Spear_OnCall')
        if not isinstance(on_call_list_data, dict) or 'rotation' not in on_call_list_data or not isinstance(on_call_list_data['rotation'], list):
            log.error("XSOAR list 'Spear_OnCall' has unexpected structure or missing 'rotation' key.")
            return []
        rotation = on_call_list_data['rotation']
    except Exception as e:
        log.error(f"Failed to get or parse 'Spear_OnCall' rotation: {e}", exc_info=True)
        return []  # Return empty list on error

    today = date.today()
    # Calculate the date of the Monday of the *previous* week.
    # today.weekday(): Mon=0, Sun=6.
    # days_since_last_monday = today.weekday()
    # days_to_subtract_for_previous_monday = days_since_last_monday + 7
    start_date_cutoff = today - timedelta(days=today.weekday() + 7)

    future_weeks = []
    for week in rotation:
        if not isinstance(week, dict):
            log.warning(f"Skipping non-dictionary item in rotation list: {week}")
            continue

        monday_date_str = week.get('Monday_date')
        if not monday_date_str:
            log.warning(f"Skipping rotation entry with missing 'Monday_date': {week}")
            continue

        try:
            # Compare using date objects - simpler and avoids timezone issues if time isn't needed
            monday_dt = date.fromisoformat(monday_date_str)  # Handles 'YYYY-MM-DD'
            if monday_dt >= start_date_cutoff:  # Include the previous week's Monday onwards
                future_weeks.append(week)
        except ValueError:
            log.warning(f"Skipping rotation entry with invalid date format '{monday_date_str}'. Expected YYYY-MM-DD. Entry: {week}")
        except Exception as e:  # Catch other potential errors during processing
            log.error(f"Error processing rotation week {week}: {e}", exc_info=True)

    # Sort the results by date as the source list might not be ordered
    try:
        future_weeks.sort(key=lambda w: w.get('Monday_date', ''))
    except Exception as e:
        log.error(f"Failed to sort future weeks: {e}", exc_info=True)
        # Decide if you want to return the unsorted list or an empty one on sort failure
        # return []

    return future_weeks


# Example of how you might run these (e.g., for testing or a script)
if __name__ == "__main__":
    log.info("Running on-call functions...")

    current_oncall = get_on_call_person()
    log.info(f"Current On-Call: {current_oncall}")

    rotation_schedule = get_rotation()
    log.info(f"Upcoming Rotation (from last week): {rotation_schedule}")

    # Uncomment to actually send messages (use with caution)
    # log.info("Announcing current on-call...")
    # announce_change(room_id=CONFIG.webex_room_id_vinay_test_space)
    # log.info("Alerting about next week's on-call...")
    alert_change()

    log.info("On-call functions execution finished.")
