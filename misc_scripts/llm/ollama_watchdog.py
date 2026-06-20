#!/usr/bin/env python3
"""
Ollama Watchdog

Runs on Mac, periodically tests actual inference against Ollama.
If inference hangs or fails, restarts Ollama via brew services and reloads models.

The key problem this solves: Ollama can freeze where metadata endpoints (/api/tags)
still respond but all inference requests hang indefinitely. A simple health check
against /api/tags won't detect this — we must test real inference.

Usage:
  python3 ollama_watchdog.py          # manual
  launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ir.ollama-watchdog.plist
"""

import collections
import logging
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

import requests

# --- Configuration ---

OLLAMA_SERIALIZER_URL = "http://localhost:11433"  # Inference — serialized to prevent deadlocks
OLLAMA_DIRECT_URL = "http://localhost:11434"       # Process liveness checks only
CHECK_INTERVAL = 60        # 1 minute between checks
INFERENCE_TIMEOUT = 120    # seconds — generous to cover TTFT on large contexts
STARTUP_POLL_TIMEOUT = 60  # seconds to wait for Ollama after restart
RETRY_DELAY = 5            # seconds between first failure and retry
MAX_INFERENCE_SECS = 300   # if serializer lock held longer than this, Ollama is hung

# Thermal throttle detection
LATENCY_WINDOW = 20        # rolling window of recent inference latencies
THROTTLE_RATIO = 3.0       # current latency must exceed this × baseline median
MIN_BASELINE_SAMPLES = 5   # need this many samples before evaluating throttle
THROTTLE_CONSEC = 3        # consecutive throttled checks before alerting

LLM_MODEL = os.environ["OLLAMA_LLM_MODEL"]
EMBEDDING_MODEL = os.environ["OLLAMA_EMBEDDING_MODEL"]

WEBEX_BOT_TOKEN = os.getenv("WEBEX_BOT_ACCESS_TOKEN_ORACLE", "")
WEBEX_ROOM_ID = os.getenv("WEBEX_ROOM_ID_DEV_TEST_SPACE", "")

# --- Logging ---

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LOG_FILE = PROJECT_ROOT / "logs" / "ollama_watchdog.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

log = logging.getLogger("ollama_watchdog")
log.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

_fh = logging.FileHandler(LOG_FILE)
_fh.setFormatter(_fmt)
log.addHandler(_fh)

# Only add console handler when running interactively (avoids duplicate lines under launchd)
if sys.stderr.isatty():
    _sh = logging.StreamHandler()
    _sh.setFormatter(_fmt)
    log.addHandler(_sh)

# --- State ---
_restart_notified = False
_throttle_notified = False
_throttle_streak = 0
_latency_history: collections.deque = collections.deque(maxlen=LATENCY_WINDOW)


# --- Functions ---

def is_serializer_reachable() -> bool:
    """Quick check if the serializer proxy is responding."""
    try:
        resp = requests.get(f"{OLLAMA_SERIALIZER_URL}/api/tags", timeout=5)
        return resp.status_code == 200
    except (requests.RequestException, OSError):
        return False


def get_serializer_health() -> dict | None:
    """Check the serializer's /health endpoint (bypasses the inference lock)."""
    try:
        resp = requests.get(f"{OLLAMA_SERIALIZER_URL}/health", timeout=5)
        return resp.json()
    except (requests.RequestException, OSError, ValueError):
        return None


def check_inference() -> tuple[bool, float | None]:
    """Test actual Ollama inference. Returns (healthy, latency_secs).

    Routes the probe directly to Ollama (not through the serializer) so a
    legitimate long-running request doesn't cause a false-positive timeout.
    The probe is a single-token generation that completes in <2s when healthy.
    """
    try:
        t0 = time.monotonic()
        resp = requests.post(
            f"{OLLAMA_DIRECT_URL}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": "hi",
                "stream": False,
                "num_predict": 1,
            },
            timeout=INFERENCE_TIMEOUT,
        )
        elapsed = time.monotonic() - t0
        resp.raise_for_status()
        healthy = resp.json().get("done", False)
        return healthy, elapsed if healthy else None
    except requests.exceptions.Timeout:
        log.warning("Inference check timed out after %ds", INFERENCE_TIMEOUT)
        return False, None
    except Exception as e:
        log.warning("Inference check failed: %s", e)
        return False, None


def wait_for_ollama(timeout: int = STARTUP_POLL_TIMEOUT) -> bool:
    """Poll /api/tags until Ollama responds or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{OLLAMA_DIRECT_URL}/api/tags", timeout=5)
            if resp.status_code == 200:
                return True
        except (requests.RequestException, OSError):
            pass
        time.sleep(3)
    return False


def restart_ollama():
    """Restart Ollama via brew services."""
    log.info("Restarting Ollama via 'brew services restart ollama'...")
    result = subprocess.run(
        ["brew", "services", "restart", "ollama"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        log.error("brew services restart failed: %s", result.stderr.strip())
    else:
        log.info("brew services restart: %s", result.stdout.strip())


def restart_serializer():
    """Restart the Ollama serializer to clear stale lock state."""
    log.info("Restarting Ollama serializer...")
    serializer_script = PROJECT_ROOT / "misc_scripts" / "llm" / "ollama_serializer.py"
    # Kill existing
    result = subprocess.run(
        ["pkill", "-f", "ollama_serializer.py"],
        capture_output=True, text=True, check=False,
    )
    time.sleep(2)
    # Start new
    subprocess.Popen(
        [sys.executable, str(serializer_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Wait for it to come up
    for _ in range(10):
        time.sleep(1)
        try:
            resp = requests.get(f"{OLLAMA_SERIALIZER_URL}/health", timeout=3)
            if resp.status_code == 200:
                log.info("Serializer restarted successfully")
                return
        except (requests.RequestException, OSError):
            pass
    log.warning("Serializer may not have restarted cleanly")


def reload_models():
    """Preload models with keep_alive=-1 so they stay resident in memory."""
    # LLM model — use /api/generate
    log.info("Preloading LLM model %s with keep_alive=-1...", LLM_MODEL)
    try:
        resp = requests.post(
            f"{OLLAMA_SERIALIZER_URL}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": "hi",
                "stream": False,
                "num_predict": 1,
                "keep_alive": -1,
            },
            timeout=120,
        )
        if resp.status_code == 200 and resp.json().get("done"):
            log.info("Model %s loaded successfully", LLM_MODEL)
        else:
            log.warning("Model %s preload response: %s", LLM_MODEL, resp.text[:200])
    except Exception as e:
        log.error("Failed to preload model %s: %s", LLM_MODEL, e)

    # Embedding model — use /api/embed (doesn't support /api/generate)
    log.info("Preloading embedding model %s with keep_alive=-1...", EMBEDDING_MODEL)
    try:
        resp = requests.post(
            f"{OLLAMA_SERIALIZER_URL}/api/embed",
            json={
                "model": EMBEDDING_MODEL,
                "input": "hi",
                "keep_alive": -1,
            },
            timeout=120,
        )
        if resp.status_code == 200:
            log.info("Model %s loaded successfully", EMBEDDING_MODEL)
        else:
            log.warning("Model %s preload response: %s", EMBEDDING_MODEL, resp.text[:200])
    except Exception as e:
        log.error("Failed to preload model %s: %s", EMBEDDING_MODEL, e)


def get_thermal_pressure() -> str:
    """Read macOS thermal pressure level. Returns 'nominal', 'moderate', 'heavy', 'critical', or 'unknown'."""
    try:
        result = subprocess.run(
            ["pmset", "-g", "therm"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        output = result.stdout.lower()
        for level in ("critical", "heavy", "moderate", "nominal"):
            if level in output:
                return level
        # No thermal warning = nominal
        if "no thermal warning" in output:
            return "nominal"
        return "unknown"
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def evaluate_throttling(latency: float) -> dict | None:
    """Check if current latency indicates thermal throttling.

    Returns a dict with throttle info if throttling detected, else None.
    """
    if len(_latency_history) < MIN_BASELINE_SAMPLES:
        return None

    baseline = statistics.median(_latency_history)
    if baseline <= 0:
        return None

    ratio = latency / baseline
    if ratio >= THROTTLE_RATIO:
        return {
            "latency": latency,
            "baseline": baseline,
            "ratio": ratio,
            "thermal": get_thermal_pressure(),
        }
    return None


def send_webex_notification(message: str):
    """Send a Webex notification to the dev room."""
    if not WEBEX_BOT_TOKEN or not WEBEX_ROOM_ID:
        log.warning("Webex credentials not configured, skipping notification")
        return
    try:
        from webexpythonsdk import WebexAPI
        api = WebexAPI(access_token=WEBEX_BOT_TOKEN)
        api.messages.create(roomId=WEBEX_ROOM_ID, markdown=message)
        log.info("Webex notification sent")
    except Exception as e:
        log.error("Failed to send Webex notification: %s", e)


# --- Main loop ---

def run_watchdog():
    global _restart_notified, _throttle_notified, _throttle_streak

    log.info("=" * 50)
    log.info("Ollama Watchdog Started")
    log.info("Serializer URL: %s (health + model reload)", OLLAMA_SERIALIZER_URL)
    log.info("Direct URL: %s (liveness + inference probes)", OLLAMA_DIRECT_URL)
    log.info("LLM model: %s", LLM_MODEL)
    log.info("Embedding model: %s", EMBEDDING_MODEL)
    log.info("Check interval: %ds", CHECK_INTERVAL)
    log.info("Throttle detection: %.0fx baseline for %d consecutive checks", THROTTLE_RATIO, THROTTLE_CONSEC)
    log.info("=" * 50)

    # Signal handling — clean shutdown
    def handle_signal(signum, _frame):
        log.info("Received signal %s, shutting down...", signum)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while True:
        # Quick check: is the serializer itself healthy?
        health = get_serializer_health()
        if health:
            held = health.get("lock_held_secs", 0)
            depth = health.get("queue_depth", 0)

            if held > MAX_INFERENCE_SECS:
                # Lock held longer than max — Ollama is hung
                log.error(
                    "Serializer lock held %.0fs (max %ds) by %s — Ollama inference is hung",
                    held, MAX_INFERENCE_SECS, health.get("lock_held_by", "?"),
                )
                _latency_history.clear()
                restart_ollama()
                restart_serializer()
                log.info("Waiting up to %ds for Ollama to come back...", STARTUP_POLL_TIMEOUT)
                if wait_for_ollama():
                    log.info("Ollama is back up, reloading models...")
                    reload_models()
                    if not _restart_notified:
                        send_webex_notification(
                            "**Ollama Watchdog** detected inference hang "
                            f"(lock held {held:.0f}s) — restarted Ollama and serializer, "
                            f"reloaded models (`{LLM_MODEL}`, `{EMBEDDING_MODEL}`)."
                        )
                        _restart_notified = True
                else:
                    log.error("Ollama did not come back up after restart!")
                    if not _restart_notified:
                        send_webex_notification(
                            "**Ollama Watchdog** attempted to restart Ollama but it "
                            "did not come back up. Manual intervention required."
                        )
                        _restart_notified = True
                time.sleep(CHECK_INTERVAL)
                continue

            if held > 0 or depth > 0:
                log.info(
                    "Serializer busy (lock held %.0fs by %s, queue %d) — "
                    "skipping inference probe to avoid concurrent request",
                    held, health.get("lock_held_by", "?"), depth,
                )
                time.sleep(CHECK_INTERVAL)
                continue
            if health.get("circuit_open"):
                log.warning("Serializer circuit breaker is open — Ollama likely down")
                # Fall through to inference check which will trigger restart

        log.info("Checking Ollama inference health...")

        healthy, latency = check_inference()

        if healthy:
            log.info("Ollama is healthy (%.2fs)", latency)

            if _restart_notified:
                log.info("Ollama recovered after previous restart, resetting notification flag")
                send_webex_notification(
                    "**Ollama Watchdog** — Ollama is healthy again after restart."
                )
                _restart_notified = False

            # --- Throttle detection ---
            throttle_info = evaluate_throttling(latency)
            if throttle_info:
                _throttle_streak += 1
                log.warning(
                    "Possible thermal throttling: %.2fs vs %.2fs baseline (%.1fx), "
                    "thermal=%s, streak=%d/%d",
                    latency, throttle_info["baseline"], throttle_info["ratio"],
                    throttle_info["thermal"], _throttle_streak, THROTTLE_CONSEC,
                )
                if _throttle_streak >= THROTTLE_CONSEC and not _throttle_notified:
                    send_webex_notification(
                        f"**Ollama Watchdog** — Thermal throttling detected on Mac.\n"
                        f"- Inference latency: **{latency:.2f}s** "
                        f"(baseline: {throttle_info['baseline']:.2f}s, "
                        f"{throttle_info['ratio']:.1f}x slower)\n"
                        f"- macOS thermal pressure: **{throttle_info['thermal']}**\n"
                        f"- Sustained for {_throttle_streak} consecutive checks"
                    )
                    _throttle_notified = True
            else:
                if _throttle_notified:
                    log.info("Throttling resolved, latency back to normal")
                    send_webex_notification(
                        f"**Ollama Watchdog** — Thermal throttling resolved. "
                        f"Latency back to normal ({latency:.2f}s)."
                    )
                    _throttle_notified = False
                _throttle_streak = 0

            # Record latency after throttle evaluation so current sample
            # doesn't pollute the baseline it was just compared against.
            _latency_history.append(latency)

        else:
            # Reset throttle streak — can't measure throttling during outages
            _throttle_streak = 0

            log.warning("First check failed, retrying in %ds...", RETRY_DELAY)
            time.sleep(RETRY_DELAY)

            healthy, latency = check_inference()
            if healthy:
                log.info("Retry succeeded — transient blip (%.2fs)", latency)
                _latency_history.append(latency)
            else:
                # Before restarting Ollama, verify the serializer is up.
                # If the serializer is down, inference will fail regardless —
                # restarting Ollama would be the wrong fix.
                if not is_serializer_reachable():
                    log.warning(
                        "Serializer unreachable at %s — skipping Ollama restart "
                        "(fix the serializer first)", OLLAMA_SERIALIZER_URL
                    )
                    time.sleep(CHECK_INTERVAL)
                    continue

                log.error("Ollama inference is stuck — initiating restart")

                # Clear latency history — post-restart baseline will differ
                _latency_history.clear()

                restart_ollama()
                restart_serializer()

                log.info("Waiting up to %ds for Ollama to come back...", STARTUP_POLL_TIMEOUT)
                if wait_for_ollama():
                    log.info("Ollama is back up, reloading models...")
                    reload_models()

                    if not _restart_notified:
                        send_webex_notification(
                            "**Ollama Watchdog** restarted Ollama and serializer on Mac, "
                            f"reloaded models (`{LLM_MODEL}`, `{EMBEDDING_MODEL}`). "
                            "Inference was hung."
                        )
                        _restart_notified = True
                else:
                    log.error("Ollama did not come back up after restart!")
                    if not _restart_notified:
                        send_webex_notification(
                            "**Ollama Watchdog** attempted to restart Ollama on Mac but it "
                            "did not come back up. Manual intervention required."
                        )
                        _restart_notified = True

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    run_watchdog()
