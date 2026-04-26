"""Kokoro TTS HTTP server — OpenAI-compatible /v1/audio/speech endpoint.

Runs on mac-m3, exposed to lab-vm via SSH reverse tunnel (port 8021).

Environment:
    KOKORO_MODEL_PATH  path to kokoro-v1.0.onnx  (default: ~/models/kokoro/kokoro-v1.0.onnx)
    KOKORO_VOICES_PATH path to voices-v1.0.bin   (default: ~/models/kokoro/voices-v1.0.bin)
    KOKORO_HOST        bind host (default 127.0.0.1)
    KOKORO_PORT        bind port (default 8021)
    KOKORO_DEFAULT_VOICE (default af_heart)
"""
from __future__ import annotations

import io
import os
import subprocess
import threading
from pathlib import Path
from typing import Optional

import numpy as np
import soundfile as sf
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from kokoro_onnx import Kokoro
from pydantic import BaseModel
import uvicorn

HOME = Path.home()
MODEL_PATH = os.environ.get("KOKORO_MODEL_PATH", str(HOME / "models/kokoro/kokoro-v1.0.onnx"))
VOICES_PATH = os.environ.get("KOKORO_VOICES_PATH", str(HOME / "models/kokoro/voices-v1.0.bin"))
HOST = os.environ.get("KOKORO_HOST", "127.0.0.1")
PORT = int(os.environ.get("KOKORO_PORT", "8021"))
DEFAULT_VOICE = os.environ.get("KOKORO_DEFAULT_VOICE", "af_heart")

app = FastAPI(title="Kokoro TTS", version="1.0")

_kokoro: Optional[Kokoro] = None
_lock = threading.Lock()


def get_kokoro() -> Kokoro:
    global _kokoro
    if _kokoro is None:
        with _lock:
            if _kokoro is None:
                _kokoro = Kokoro(MODEL_PATH, VOICES_PATH)
    return _kokoro


def encode_mp3(samples: np.ndarray, sample_rate: int) -> bytes:
    """Encode float samples → MP3 via ffmpeg (piped stdin/stdout)."""
    wav_buf = io.BytesIO()
    sf.write(wav_buf, samples, sample_rate, format="WAV", subtype="PCM_16")
    wav_buf.seek(0)
    r = subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error",
         "-f", "wav", "-i", "pipe:0",
         "-codec:a", "libmp3lame", "-b:a", "128k",
         "-f", "mp3", "pipe:1"],
        input=wav_buf.read(),
        capture_output=True,
        check=True,
    )
    return r.stdout


def encode_wav(samples: np.ndarray, sample_rate: int) -> bytes:
    buf = io.BytesIO()
    sf.write(buf, samples, sample_rate, format="WAV", subtype="PCM_16")
    buf.seek(0)
    return buf.read()


class SpeechRequest(BaseModel):
    """OpenAI-compatible TTS request body. Extra fields accepted but mostly ignored."""
    model: str = "kokoro"
    input: str
    voice: Optional[str] = None
    response_format: str = "mp3"
    speed: float = 1.0
    lang: str = "en-us"


@app.get("/health")
def health():
    try:
        k = get_kokoro()
        return {"status": "ok", "voices": len(list(k.get_voices()))}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/v1/voices")
def list_voices():
    k = get_kokoro()
    return {"voices": list(k.get_voices())}


@app.post("/v1/audio/speech")
def speech(req: SpeechRequest):
    if not req.input.strip():
        raise HTTPException(400, "input is empty")
    if len(req.input) > 20000:
        raise HTTPException(400, "input too long (>20k chars)")

    voice = req.voice or DEFAULT_VOICE
    k = get_kokoro()

    with _lock:  # kokoro-onnx is not thread-safe
        samples, sample_rate = k.create(
            req.input, voice=voice, speed=req.speed, lang=req.lang
        )

    fmt = req.response_format.lower()
    if fmt == "mp3":
        data = encode_mp3(samples, sample_rate)
        media_type = "audio/mpeg"
    elif fmt == "wav":
        data = encode_wav(samples, sample_rate)
        media_type = "audio/wav"
    else:
        raise HTTPException(400, f"unsupported response_format: {fmt} (use mp3 or wav)")

    return Response(content=data, media_type=media_type)


if __name__ == "__main__":
    # Warm up at startup so first request is fast
    print(f"Loading Kokoro from {MODEL_PATH}...")
    get_kokoro()
    print(f"Ready on {HOST}:{PORT}  (default voice: {DEFAULT_VOICE})")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
