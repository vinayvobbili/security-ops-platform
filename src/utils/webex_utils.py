"""
Simple Webex utility functions with retry logic.

Keep it simple - just retry on transient errors.
"""

import logging
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Any
from zoneinfo import ZoneInfo

import requests
from webexteamssdk import WebexTeamsAPI

from my_config import get_config

# Load configuration
config = get_config()

logger = logging.getLogger(__name__)


def clear_stale_lock(lock_path) -> None:
    """Remove a lock file left behind by a SIGKILLed process.

    Tests if the file-level fcntl lock is held by anyone. If not, the lock
    file is stale and safe to delete.
    """
    import fcntl
    from pathlib import Path
    lock_path = Path(lock_path)
    if not lock_path.exists():
        return
    try:
        with open(lock_path, 'r') as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_path.unlink(missing_ok=True)
        logger.info(f"Removed stale lock file: {lock_path}")
    except (OSError, IOError):
        pass  # Lock is actively held — leave it


def format_eta(minutes: int) -> str:
    """Return ETA string in US-Eastern and IST, e.g. '10:43 AM EDT / 8:13 PM IST'."""
    eta_utc = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    et = eta_utc.astimezone(ZoneInfo("America/New_York")).strftime("%-I:%M %p %Z")
    ist = eta_utc.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%-I:%M %p IST")
    return f"{et} / {ist}"


def send_message_with_retry(webex_api, room_id: str, text: Optional[str] = None,
                            markdown: Optional[str] = None, files: Optional[List[str]] = None,
                            max_retries: int = 3, **kwargs) -> Optional[Any]:
    """
    Send Webex message with simple retry on transient errors.

    Args:
        webex_api: WebexTeamsAPI instance
        room_id: Webex room ID
        text: Plain text message
        markdown: Markdown formatted message
        files: List of file paths
        max_retries: Number of retry attempts (default: 3)
        **kwargs: Additional arguments

    Returns:
        Message object if successful, None otherwise
    """

    for attempt in range(1, max_retries + 1):
        try:
            return webex_api.messages.create(
                roomId=room_id,
                text=text,
                markdown=markdown,
                files=files,
                **kwargs
            )
        except Exception as e:
            error_str = str(e).lower()

            # Simple check: retry on SSL, timeout, 5xx errors
            is_retryable = any(x in error_str for x in ['ssl', 'timeout', '503', '502', '500', '429'])

            if is_retryable and attempt < max_retries:
                delay = 2 ** attempt  # 2s, 4s, 8s
                logger.warning(f"Webex API error (attempt {attempt}/{max_retries}): {e}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                logger.error(f"Failed to send message: {e}")
                # Send simple error notification to user
                try:
                    webex_api.messages.create(roomId=room_id,
                                              markdown=f"❌ Message delivery failed after {attempt} attempts. Error: {str(e)[:100]}")
                except (ConnectionError, TimeoutError, RuntimeError):
                    pass  # Best effort
                return None

    return None


@contextmanager
def periodic_progress_pinger(webex_api, room_id: str, interval_seconds: int = 1200,
                             label: str = "your request"):
    """Keep the room warm with a periodic "still working" ping during long jobs.

    Starts a daemon thread that sends one webex message every `interval_seconds`
    until the context exits. First ping fires at `interval_seconds`, so fast jobs
    that finish before the interval never send anything.

    Default 1200s (20 min) matches the typical hour-long runtime of these jobs
    without flooding the room. Exceptions inside the pinger thread are logged
    and swallowed so they can never break the wrapped job.
    """
    stop_event = threading.Event()
    started_monotonic = time.monotonic()

    def _loop():
        while not stop_event.wait(interval_seconds):
            elapsed_min = int((time.monotonic() - started_monotonic) / 60)
            try:
                send_message_with_retry(
                    webex_api, room_id=room_id,
                    markdown=f"⏳ Still working on {label} ({elapsed_min} min elapsed)..."
                )
            except Exception as e:
                logger.warning(f"periodic_progress_pinger send failed (non-fatal): {e}")

    thread = threading.Thread(target=_loop, name="webex-progress-pinger", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop_event.set()


def send_card_with_retry(webex_api, room_id: str, text: str, attachments: List[Any],
                         max_retries: int = 3, **kwargs) -> Optional[Any]:
    """Send adaptive card with simple retry."""
    for attempt in range(1, max_retries + 1):
        try:
            return webex_api.messages.create(roomId=room_id, text=text,
                                             attachments=attachments, **kwargs)
        except Exception as e:
            if attempt < max_retries and any(x in str(e).lower() for x in ['ssl', 'timeout', '503', '502']):
                time.sleep(2 ** attempt)
                logger.warning(f"Retry card send (attempt {attempt}): {e}")
            else:
                logger.error(f"Failed to send card: {e}")
                return None
    return None


def get_webex_bot_rooms(bot_access_token):
    """
    Retrieve the rooms (spaces) where the Webex bot is a member.

    :param bot_access_token: Webex API access token for the bot
    :return: List of rooms the bot is in
    """
    # Webex API endpoint for listing rooms
    url = "https://webexapis.com/v1/rooms"

    # Headers for API authentication
    headers = {
        "Authorization": f"Bearer {bot_access_token}",
        "Content-Type": "application/json"
    }

    try:
        # Make the API request
        response = requests.get(url, headers=headers, verify=False)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            rooms_data = response.json()

            # List to store room details
            bot_rooms = []

            # Iterate through rooms
            for room in rooms_data['items']:
                bot_rooms.append({
                    'room_id': room['id'],
                    'room_title': room['title'],
                    'room_type': room['type']
                })

            return bot_rooms
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            return []

    except requests.RequestException as e:
        print(f"Request error: {e}")
        return []


class InvalidRoomIDException(Exception):
    """Exception raised when the room ID is invalid."""
    pass


def get_room_name(room_id, bot_access_token):
    """
    Retrieve the room name for a given room ID.

    :param room_id: The ID of the room
    :param bot_access_token: The Webex API access token for the bot
    :return: The name of the room
    :raises InvalidRoomIDException: If the room ID is invalid
    """
    url = f"https://webexapis.com/v1/rooms/{room_id}"
    headers = {
        "Authorization": f"Bearer {bot_access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            room_data = response.json()
            return room_data['title']
        elif response.status_code == 404:
            raise InvalidRoomIDException(f"Room ID {room_id} is invalid.")
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None


def send_file_to_webex_room(room_id, file_path, message=None):
    """
    Sends a file to a specified Webex room.

    :param room_id: The ID of the Webex room
    :param file_path: The path to the file to be sent
    :param message: Optional message to accompany the file
    """
    try:
        if message is None:
            message = "Here's the file you requested."

        bot_access_token = config.webex_bot_access_token_soar

        # Initialize Webex API client
        webex_api = WebexTeamsAPI(access_token=bot_access_token)

        # SAMPLE FILEPATH = 'IR/web/static/charts/07-02-2025/CrowdStrike Detection Efficacy-Month.png'
        webex_api.messages.create(
            roomId=room_id,
            text=message,
            files=[file_path]
        )
        print(f"File sent to room {room_id} successfully.")
    except Exception as e:
        print(f"Failed to send file to room {room_id}: {e}")


# Usage example
def main():
    print(get_webex_bot_rooms(bot_access_token = config.webex_bot_access_token_aide))
    # send_file_to_webex_room(
    #     room_id=config.webex_room_id_epp_tanium_cloud_tagging,
    #     file_path='./data/transient/epp_device_tagging/11-21-2025/Tanium_Ring_Tags_Report.xlsx',
    #     message="Here's the list of Tanium hosts without a Ring Tag. Ring tags have also been generated for your review."
    # )


if __name__ == "__main__":
    main()
