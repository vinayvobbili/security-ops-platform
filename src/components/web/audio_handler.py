"""Audio Handler for Web Dashboard."""

import logging
import os
import random
from typing import Optional

logger = logging.getLogger(__name__)


def get_random_audio_file(audio_dir: str) -> Optional[str]:
    """Return a random mp3 filename from the audio directory.

    Args:
        audio_dir: Path to the audio directory

    Returns:
        Random audio filename or None if no files found
    """
    logger.debug(f"Getting random audio file from {audio_dir}")

    if not os.path.exists(audio_dir):
        logger.warning(f"Audio directory does not exist: {audio_dir}")
        return None

    files = [f for f in os.listdir(audio_dir) if f.endswith('.mp3')]

    if not files:
        logger.warning(f"No audio files found in {audio_dir}")
        return None

    return random.choice(files)
