"""
Webex Messaging Utilities with Retry Logic

Provides helper functions for sending Webex messages with automatic retry
on transient failures. All functions include retry logic and proper error handling.

Usage:
    from src.utils.webex_messaging import send_message, send_message_with_files

    # Simple text message
    send_message(webex_api, room_id, text="Hello World")

    # Markdown message
    send_message(webex_api, room_id, markdown="**Bold** text")

    # Message with file attachment
    send_message_with_files(webex_api, room_id, markdown="See attached", files=["chart.png"])
"""

import logging
import time
from typing import Optional, List, Dict, Any

from src.utils.retry_utils import with_webex_retry

logger = logging.getLogger(__name__)

# Connection health monitoring (optional - can be None if not initialized)
_health_monitor = None


def set_health_monitor(monitor):
    """Set the global health monitor for tracking connection metrics"""
    global _health_monitor
    _health_monitor = monitor


@with_webex_retry(max_attempts=3, initial_delay=2.0)
def send_message(
        webex_api,
        room_id: str,
        text: Optional[str] = None,
        markdown: Optional[str] = None,
        **kwargs
) -> Any:
    """
    Send a Webex message with automatic retry on failures

    Args:
        webex_api: WebexTeamsAPI instance
        room_id: Webex room ID
        text: Plain text message (optional)
        markdown: Markdown formatted message (optional)
        **kwargs: Additional parameters for messages.create()

    Returns:
        Message object from Webex API

    Example:
        send_message(webex_api, room_id, markdown="**Hello** World!")
    """
    start_time = time.time()
    try:
        params = {"roomId": room_id, **kwargs}

        if markdown:
            params["markdown"] = markdown
        if text:
            params["text"] = text

        result = webex_api.messages.create(**params)

        # Record success in health monitor
        if _health_monitor:
            duration = time.time() - start_time
            _health_monitor.record_request_success(duration)
            _health_monitor.log_periodic_summary()  # Log summary every 5 minutes

        return result
    except Exception as e:
        # Record failure in health monitor
        if _health_monitor:
            duration = time.time() - start_time
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                _health_monitor.record_request_timeout(duration)
            else:
                _health_monitor.record_connection_error(e)
        raise


@with_webex_retry(max_attempts=3, initial_delay=2.0)
def send_message_with_files(
        webex_api,
        room_id: str,
        files: List[str],
        text: Optional[str] = None,
        markdown: Optional[str] = None,
        **kwargs
) -> Any:
    """
    Send a Webex message with file attachments and automatic retry

    Args:
        webex_api: WebexTeamsAPI instance
        room_id: Webex room ID
        files: List of file paths to attach
        text: Plain text message (optional)
        markdown: Markdown formatted message (optional)
        **kwargs: Additional parameters for messages.create()

    Returns:
        Message object from Webex API

    Example:
        send_message_with_files(
            webex_api,
            room_id,
            files=["chart.png"],
            markdown="Here's your chart!"
        )
    """
    start_time = time.time()
    try:
        params = {"roomId": room_id, "files": files, **kwargs}

        if markdown:
            params["markdown"] = markdown
        if text:
            params["text"] = text

        result = webex_api.messages.create(**params)

        # Record success in health monitor
        if _health_monitor:
            duration = time.time() - start_time
            _health_monitor.record_request_success(duration)
            _health_monitor.log_periodic_summary()

        return result
    except Exception as e:
        # Record failure in health monitor
        if _health_monitor:
            duration = time.time() - start_time
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                _health_monitor.record_request_timeout(duration)
            else:
                _health_monitor.record_connection_error(e)
        raise


@with_webex_retry(max_attempts=3, initial_delay=2.0)
def send_card(
        webex_api,
        room_id: str,
        attachments: List[Dict[str, Any]],
        text: str = "Card",
        **kwargs
) -> Any:
    """
    Send an Adaptive Card to a Webex room with automatic retry

    Args:
        webex_api: WebexTeamsAPI instance
        room_id: Webex room ID
        attachments: List of adaptive card attachments
        text: Fallback text for card (default: "Card")
        **kwargs: Additional parameters for messages.create()

    Returns:
        Message object from Webex API

    Example:
        card = {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": adaptive_card.to_dict()
        }
        send_card(webex_api, room_id, attachments=[card])
    """
    return webex_api.messages.create(
        roomId=room_id,
        text=text,
        attachments=attachments,
        **kwargs
    )


def safe_send_message(
        webex_api,
        room_id: str,
        text: Optional[str] = None,
        markdown: Optional[str] = None,
        fallback_text: Optional[str] = None,
        **kwargs
) -> bool:
    """
    Safely send a Webex message with error handling and optional fallback

    This function catches all exceptions and returns a success/failure boolean.
    Useful when you want to attempt to send a message but don't want to fail
    if it doesn't work.

    Args:
        webex_api: WebexTeamsAPI instance
        room_id: Webex room ID
        text: Plain text message (optional)
        markdown: Markdown formatted message (optional)
        fallback_text: Fallback plain text if markdown fails (optional)
        **kwargs: Additional parameters for messages.create()

    Returns:
        True if message sent successfully, False otherwise

    Example:
        success = safe_send_message(
            webex_api,
            room_id,
            markdown="**Error occurred**",
            fallback_text="Error occurred"
        )
        if not success:
            logger.warning("Failed to notify user")
    """
    try:
        send_message(webex_api, room_id, text=text, markdown=markdown, **kwargs)
        return True
    except Exception as e:
        logger.error(f"Failed to send message to room {room_id}: {e}")

        # Try fallback text if provided
        if fallback_text and fallback_text != text:
            try:
                send_message(webex_api, room_id, text=fallback_text, **kwargs)
                logger.info("Sent fallback message successfully")
                return True
            except Exception as fallback_error:
                logger.error(f"Fallback message also failed: {fallback_error}")

        return False


def safe_send_message_with_files(
        webex_api,
        room_id: str,
        files: List[str],
        text: Optional[str] = None,
        markdown: Optional[str] = None,
        fallback_text: Optional[str] = None,
        **kwargs
) -> bool:
    """
    Safely send a Webex message with files and error handling

    Args:
        webex_api: WebexTeamsAPI instance
        room_id: Webex room ID
        files: List of file paths to attach
        text: Plain text message (optional)
        markdown: Markdown formatted message (optional)
        fallback_text: Fallback plain text if sending fails (optional)
        **kwargs: Additional parameters for messages.create()

    Returns:
        True if message sent successfully, False otherwise
    """
    try:
        send_message_with_files(webex_api, room_id, files, text=text, markdown=markdown, **kwargs)
        return True
    except Exception as e:
        logger.error(f"Failed to send message with files to room {room_id}: {e}")

        # Try sending just the message without files as fallback
        if fallback_text or text or markdown:
            logger.info("Attempting to send message without files as fallback")
            return safe_send_message(
                webex_api,
                room_id,
                text=text,
                markdown=markdown,
                fallback_text=fallback_text or "Failed to attach files",
                **kwargs
            )

        return False


# Convenience function for backward compatibility
def create_message_with_retry(webex_api, **kwargs):
    """
    Backward-compatible wrapper for send_message

    Args:
        webex_api: WebexTeamsAPI instance
        **kwargs: All parameters for messages.create()

    Returns:
        Message object from Webex API
    """
    room_id = kwargs.pop("roomId", None)
    if not room_id:
        raise ValueError("roomId is required")

    files = kwargs.pop("files", None)
    if files:
        return send_message_with_files(webex_api, room_id, files, **kwargs)
    else:
        return send_message(webex_api, room_id, **kwargs)
