"""Countdown Timer Handler for Web Dashboard."""

import logging
from typing import Any

from src.components import countdown_timer_generator_v2

logger = logging.getLogger(__name__)


def generate_countdown_timer(deadline_str: str) -> Any:
    """Generate an animated countdown timer GIF for emails.

    Creates a 60-second animated GIF that counts down in real-time.
    Each time the email is opened, a fresh GIF is generated from current time.

    Args:
        deadline_str: ISO 8601 timestamp (e.g., 2025-11-11T15:00:00-05:00)

    Returns:
        BytesIO buffer with GIF image

    Raises:
        ValueError: If deadline format is invalid
    """
    logger.info(f"Generating countdown timer for deadline: {deadline_str}")

    try:
        img_buffer = countdown_timer_generator_v2.generate_countdown_timer_gif(deadline_str)
        return img_buffer
    except ValueError as val_err:
        logger.error(f"Invalid deadline format: {val_err}", exc_info=True)
        raise


def generate_error_timer() -> Any:
    """Generate an error timer GIF.

    Returns:
        BytesIO buffer with error GIF image
    """
    logger.warning("Generating error timer GIF")
    return countdown_timer_generator_v2.generate_error_timer_gif()
