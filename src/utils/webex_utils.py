"""
Simple Webex utility functions with retry logic.

Keep it simple - just retry on transient errors.
"""

import logging
import time
from typing import Optional, List, Any

logger = logging.getLogger(__name__)


def send_message_with_retry(webex_api, roomId: str, text: Optional[str] = None,
                            markdown: Optional[str] = None, files: Optional[List[str]] = None,
                            max_retries: int = 3, **kwargs) -> Optional[Any]:
    """
    Send Webex message with simple retry on transient errors.

    Args:
        webex_api: WebexTeamsAPI instance
        roomId: Webex room ID
        text: Plain text message
        markdown: Markdown formatted message
        files: List of file paths
        max_retries: Number of retry attempts (default: 3)
        **kwargs: Additional arguments

    Returns:
        Message object if successful, None otherwise
    """
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            return webex_api.messages.create(
                roomId=roomId,
                text=text,
                markdown=markdown,
                files=files,
                **kwargs
            )
        except Exception as e:
            last_error = e
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
                    webex_api.messages.create(roomId=roomId,
                        markdown=f"❌ Message delivery failed after {attempt} attempts. Error: {str(e)[:100]}")
                except:
                    pass  # Best effort
                return None

    return None


def send_card_with_retry(webex_api, roomId: str, text: str, attachments: List[Any],
                         max_retries: int = 3, **kwargs) -> Optional[Any]:
    """Send adaptive card with simple retry."""
    for attempt in range(1, max_retries + 1):
        try:
            return webex_api.messages.create(roomId=roomId, text=text,
                                            attachments=attachments, **kwargs)
        except Exception as e:
            if attempt < max_retries and any(x in str(e).lower() for x in ['ssl', 'timeout', '503', '502']):
                time.sleep(2 ** attempt)
                logger.warning(f"Retry card send (attempt {attempt}): {e}")
            else:
                logger.error(f"Failed to send card: {e}")
                return None
    return None
