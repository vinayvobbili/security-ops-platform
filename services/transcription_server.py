#!/usr/bin/env python3
"""
Transcription API Server

Lightweight HTTP server that transcribes meeting audio with speaker diarization.
Runs on the inference Mac and is accessed by lab-vm via the existing SSH reverse
tunnel infra (same pattern as services/embedding_server.py).

Usage:
    python3 services/transcription_server.py              # default port 11437
    python3 services/transcription_server.py --port 11437

Endpoints:
    POST /transcribe   multipart audio (field name 'file') ->
                       {"segments": [{speaker, start, end, text}, ...],
                        "full_text": "...",
                        "duration_seconds": float,
                        "num_speakers": int,
                        "language": str}
    GET  /health       -> {"status": "ok", "models_loaded": bool, "last_used": "..."}

One-time setup on the inference Mac:
    brew install ffmpeg
    pip install faster-whisper pyannote.audio
    # Accept the model terms (free) at:
    #   https://huggingface.co/pyannote/speaker-diarization-3.1
    #   https://huggingface.co/pyannote/segmentation-3.0
    # Ensure HUGGING_FACE_ACCESS_TOKEN is set in the environment.

Models lazy-load on first request and are released from RAM after 10 minutes
idle. Cold load adds ~30s to the first request after eviction; this is fine
for the meeting recap use case (~1 recording per week).
"""

import argparse
import gc
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Use macOS native trust store for SSL (avoids Zscaler / corp CA issues)
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

WHISPER_MODEL_NAME = os.environ.get("WHISPER_MODEL", "large-v3-turbo")
WHISPER_DEVICE = os.environ.get("WHISPER_DEVICE", "auto")          # auto / cpu / cuda
WHISPER_COMPUTE_TYPE = os.environ.get("WHISPER_COMPUTE_TYPE", "int8")  # int8 for CPU, float16 for GPU
DIARIZATION_MODEL = os.environ.get("DIARIZATION_MODEL", "pyannote/speaker-diarization-3.1")
IDLE_EVICTION_SECONDS = int(os.environ.get("IDLE_EVICTION_SECONDS", "600"))  # 10 min
HF_TOKEN_ENV = "HUGGING_FACE_ACCESS_TOKEN"


def create_app():
    from flask import Flask, request, jsonify

    app = Flask(__name__)

    _state = {
        "whisper": None,
        "diarization": None,
        "last_used": None,
        "lock": threading.Lock(),
        "active_requests": 0,
    }

    def _load_models():
        """Lazy-load faster-whisper and pyannote pipeline. Idempotent."""
        with _state["lock"]:
            # Inject system trust store so HuggingFace downloads succeed behind
            # the corporate SSL-inspection proxy (matches embedding_server.py).
            try:
                import truststore
                truststore.inject_into_ssl()
            except ImportError:
                pass

            if _state["whisper"] is None:
                from faster_whisper import WhisperModel
                logger.info(f"Loading faster-whisper model: {WHISPER_MODEL_NAME} (device={WHISPER_DEVICE}, compute={WHISPER_COMPUTE_TYPE})")
                _state["whisper"] = WhisperModel(
                    WHISPER_MODEL_NAME,
                    device=WHISPER_DEVICE,
                    compute_type=WHISPER_COMPUTE_TYPE,
                )
                logger.info(f"Whisper model loaded: {WHISPER_MODEL_NAME}")

            if _state["diarization"] is None:
                from pyannote.audio import Pipeline
                hf_token = os.environ.get(HF_TOKEN_ENV)
                if not hf_token:
                    raise RuntimeError(
                        f"Missing {HF_TOKEN_ENV} environment variable — required for "
                        f"pyannote.audio model download."
                    )
                logger.info(f"Loading diarization pipeline: {DIARIZATION_MODEL}")
                _state["diarization"] = Pipeline.from_pretrained(
                    DIARIZATION_MODEL,
                    token=hf_token,
                )
                logger.info(f"Diarization pipeline loaded: {DIARIZATION_MODEL}")

    def _evict_models():
        """Release models from RAM. Called by idle evictor thread."""
        with _state["lock"]:
            if _state["whisper"] is None and _state["diarization"] is None:
                return
            logger.info(f"Evicting models from RAM (idle for >={IDLE_EVICTION_SECONDS}s)")
            _state["whisper"] = None
            _state["diarization"] = None
            gc.collect()

    def _idle_evictor_loop():
        """Background thread: evict models if idle for IDLE_EVICTION_SECONDS."""
        while True:
            time.sleep(60)  # check every minute
            last = _state["last_used"]
            if last is None:
                continue
            if _state["whisper"] is None and _state["diarization"] is None:
                continue
            if _state["active_requests"] > 0:
                continue
            idle = (datetime.now() - last).total_seconds()
            if idle >= IDLE_EVICTION_SECONDS:
                _evict_models()

    threading.Thread(target=_idle_evictor_loop, daemon=True, name="idle-evictor").start()

    def _ensure_audio_wav(input_path: str) -> str:
        """Convert input to 16kHz mono WAV via ffmpeg.

        Handles video containers (MP4, MKV, etc.) by extracting audio, and
        normalizes compressed audio (mp3, m4a) for consistent diarization input.
        Returns the original path if it's already a WAV.
        """
        ext = Path(input_path).suffix.lower()
        if ext == ".wav":
            return input_path

        wav_path = input_path + ".wav"
        cmd = [
            "ffmpeg", "-y", "-i", input_path,
            "-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le",
            wav_path,
        ]
        logger.info(f"Converting to 16kHz mono WAV via ffmpeg: {Path(input_path).name}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ffmpeg failed: {result.stderr[-500:]}")
        return wav_path

    def _merge_diarization_with_segments(whisper_segments, diarization):
        """Assign each Whisper segment to the speaker with the most overlap.

        Whisper gives us segment-level timestamps + text. Pyannote gives us
        speaker turns. For each Whisper segment, find which speaker turn it
        overlaps with most and tag it. This is the standard merge approach
        and works well for ~95% of typical meeting audio.
        """
        speaker_turns = [
            (turn.start, turn.end, speaker)
            for turn, _, speaker in diarization.itertracks(yield_label=True)
        ]

        merged = []
        for seg in whisper_segments:
            best_speaker = "SPEAKER_00"
            best_overlap = 0.0
            for t_start, t_end, speaker in speaker_turns:
                overlap = max(0.0, min(seg.end, t_end) - max(seg.start, t_start))
                if overlap > best_overlap:
                    best_overlap = overlap
                    best_speaker = speaker
            merged.append({
                "speaker": best_speaker,
                "start": round(seg.start, 2),
                "end": round(seg.end, 2),
                "text": seg.text.strip(),
            })
        return merged

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "whisper_model": WHISPER_MODEL_NAME,
            "diarization_model": DIARIZATION_MODEL,
            "models_loaded": _state["whisper"] is not None and _state["diarization"] is not None,
            "last_used": _state["last_used"].isoformat() if _state["last_used"] else None,
            "idle_eviction_seconds": IDLE_EVICTION_SECONDS,
        })

    @app.route("/transcribe", methods=["POST"])
    def transcribe():
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded (expected multipart field 'file')"}), 400
        upload = request.files["file"]
        if not upload.filename:
            return jsonify({"error": "Empty filename"}), 400

        suffix = Path(upload.filename).suffix.lower() or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            upload.save(tmp.name)
            input_path = tmp.name

        wav_path = None
        _state["active_requests"] += 1
        try:
            _load_models()
            _state["last_used"] = datetime.now()
            wav_path = _ensure_audio_wav(input_path)

            logger.info(f"Transcribing: {upload.filename} ({os.path.getsize(wav_path)} bytes)")
            _state["last_used"] = datetime.now()
            segments_iter, info = _state["whisper"].transcribe(wav_path, beam_size=5)
            whisper_segments = list(segments_iter)
            logger.info(f"Whisper produced {len(whisper_segments)} segments ({info.duration:.1f}s audio, lang={info.language})")

            logger.info("Running speaker diarization")
            _state["last_used"] = datetime.now()
            diarize_output = _state["diarization"](wav_path)
            # pyannote 4.x returns DiarizeOutput; extract the Annotation
            annotation = getattr(diarize_output, 'speaker_diarization', diarize_output)
            num_speakers = len({speaker for _, _, speaker in annotation.itertracks(yield_label=True)})
            logger.info(f"Diarization found {num_speakers} speaker(s)")

            merged = _merge_diarization_with_segments(whisper_segments, annotation)
            full_text = " ".join(s["text"] for s in merged)

            _state["last_used"] = datetime.now()

            return jsonify({
                "segments": merged,
                "full_text": full_text,
                "duration_seconds": info.duration,
                "num_speakers": num_speakers,
                "language": info.language,
            })

        except Exception as e:
            logger.exception(f"Transcription failed: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            _state["active_requests"] = max(0, _state["active_requests"] - 1)
            _state["last_used"] = datetime.now()
            for p in (input_path, wav_path):
                if p and os.path.exists(p):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    return app


def main():
    parser = argparse.ArgumentParser(description="Transcription API Server")
    parser.add_argument("--port", type=int, default=11437)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    app = create_app()
    logger.info(f"Transcription server listening on {args.host}:{args.port}")
    logger.info(
        f"Models lazy-load on first request and evict after {IDLE_EVICTION_SECONDS}s idle "
        f"(whisper={WHISPER_MODEL_NAME}, diarization={DIARIZATION_MODEL})"
    )
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
