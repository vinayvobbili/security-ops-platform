"""Transcription service client.

Calls the inference Mac's transcription server (services/transcription_server.py)
over the existing SSH reverse tunnel — same plumbing pattern as the embedding server.

The remote server runs faster-whisper + pyannote.audio and returns a diarized
transcript. This module is just a thin HTTP client; all the heavy ML lives on
the inference Mac.
"""

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Default points at the local end of the always-on SSH tunnel from lab-vm to
# the inference Mac. Override via env var for dev/testing against a remote host.
TRANSCRIPTION_BASE_URL = os.environ.get("TRANSCRIPTION_BASE_URL", "http://127.0.0.1:11437")

# Long timeout — large meetings + cold model load can take a while. The server
# itself enforces no upper bound; we just need to wait it out.
TRANSCRIBE_TIMEOUT = 60 * 60  # 60 minutes
HEALTH_TIMEOUT = 5


def transcribe_audio(file_path: str) -> dict[str, Any]:
    """Send an audio (or video container) file to the transcription server.

    Args:
        file_path: Absolute path to the audio/video file on the local filesystem.

    Returns:
        Dict with keys:
            segments: list of {speaker, start, end, text}
            full_text: str
            duration_seconds: float
            num_speakers: int
            language: str

    Raises:
        FileNotFoundError: if file_path does not exist
        requests.RequestException: on transport / HTTP errors
        RuntimeError: if the server returned an error payload
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Audio file not found: {file_path}")

    url = f"{TRANSCRIPTION_BASE_URL}/transcribe"
    file_size = os.path.getsize(file_path)
    logger.info(f"POST {url} — uploading {os.path.basename(file_path)} ({file_size} bytes)")

    with open(file_path, "rb") as f:
        resp = requests.post(
            url,
            files={"file": (os.path.basename(file_path), f)},
            timeout=TRANSCRIBE_TIMEOUT,
        )

    if resp.status_code != 200:
        # Try to surface the server's error message
        try:
            err = resp.json().get("error", resp.text[:500])
        except ValueError:
            err = resp.text[:500]
        raise RuntimeError(f"Transcription server returned {resp.status_code}: {err}")

    result = resp.json()
    logger.info(
        f"Transcription complete: {result.get('num_speakers')} speakers, "
        f"{len(result.get('segments', []))} segments, "
        f"{result.get('duration_seconds', 0):.1f}s audio"
    )
    return result


def health_check() -> dict[str, Any]:
    """Ping the transcription server. Returns the health JSON or raises."""
    url = f"{TRANSCRIPTION_BASE_URL}/health"
    resp = requests.get(url, timeout=HEALTH_TIMEOUT)
    resp.raise_for_status()
    return resp.json()
