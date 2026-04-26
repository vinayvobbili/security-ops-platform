#!/usr/bin/env python3
"""Serializing reverse proxy for Ollama.

Ensures only one inference request runs at a time, preventing the known
Ollama deadlock where concurrent requests cause the runner to hang while
metadata endpoints (/api/tags) keep responding.

Architecture:
  Lab-VM bots → SSH tunnel → :11433 (this) → :11434 (Ollama, NUM_PARALLEL=1)
  Proxy server →               :11433 (this) ↗
  Watchdog (inference/reload) → :11433 (this) ↗
  Watchdog (liveness only)   →               :11434 (Ollama) directly
  Preload plist + script     → :11433 (this) ↗
  State manager warmup       → :11433 (this) ↗

Non-inference requests pass through without queuing.
GET /health bypasses the lock for external monitoring (watchdog, dashboards).

Usage:
  python3 ollama_serializer.py
  launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ir.ollama-serializer.plist
"""

import http.client
import http.server
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

# --- Configuration ---

LISTEN_PORT = int(os.environ.get("OLLAMA_SERIALIZER_PORT", "11433"))
OLLAMA_HOST = "localhost"
OLLAMA_PORT = 11434

# Per-socket-operation timeout (connect + each read/write).
# Ollama streams tokens, so even a 5-minute response produces data well within
# this window.  This is the *gap* between chunks, not total request time.
CHUNK_TIMEOUT = 120  # seconds

# Max wall-clock time a single inference may hold the lock.
# The internal watchdog forcibly releases after this.
# Longest legitimate /api/chat seen in logs: ~200s, so 240s gives headroom.
MAX_INFERENCE_SECS = 240  # 4 min (was 300)

# Max time a queued request waits for the lock before returning 503.
LOCK_WAIT_TIMEOUT = MAX_INFERENCE_SECS + 60  # 660s

# After CIRCUIT_THRESHOLD consecutive Ollama connection failures, reject new
# inference requests for CIRCUIT_COOLDOWN seconds instead of queuing them.
CIRCUIT_THRESHOLD = 3
CIRCUIT_COOLDOWN = 30  # seconds

INFERENCE_PATHS = frozenset({"/api/generate", "/api/chat", "/api/embed", "/api/embeddings"})

# --- Logging ---

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LOG_FILE = PROJECT_ROOT / "logs" / "ollama_serializer.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

log = logging.getLogger("ollama_serializer")
log.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

_fh = logging.FileHandler(LOG_FILE)
_fh.setFormatter(_fmt)
log.addHandler(_fh)

if sys.stderr.isatty():
    _sh = logging.StreamHandler()
    _sh.setFormatter(_fmt)
    log.addHandler(_sh)

# --- Serialization state ---

_inference_lock = threading.Semaphore(1)
_queue_depth = 0
_queue_lock = threading.Lock()

# Lock-holder tracking (for watchdog + /health)
_holder_lock = threading.Lock()
_holder_since = 0.0      # monotonic timestamp; 0 = lock is free
_holder_path = ""
_holder_gen = 0           # bumped on every acquire / forced release
_holder_conn = None       # active http.client.HTTPConnection; closed on forced release

# --- Circuit breaker ---

_cb_lock = threading.Lock()
_cb_consecutive_failures = 0
_cb_open_until = 0.0      # monotonic timestamp; circuit open until this


def _circuit_record_success():
    global _cb_consecutive_failures
    with _cb_lock:
        _cb_consecutive_failures = 0


def _circuit_record_failure():
    global _cb_consecutive_failures, _cb_open_until
    with _cb_lock:
        _cb_consecutive_failures += 1
        if _cb_consecutive_failures >= CIRCUIT_THRESHOLD:
            _cb_open_until = time.monotonic() + CIRCUIT_COOLDOWN
            log.warning(
                "Circuit breaker OPEN after %d consecutive failures — "
                "rejecting inference for %ds",
                _cb_consecutive_failures, CIRCUIT_COOLDOWN,
            )


def _circuit_is_open() -> bool:
    with _cb_lock:
        return _cb_open_until > 0 and time.monotonic() < _cb_open_until


# --- Internal lock watchdog ---

def _lock_watchdog_loop():
    """Daemon thread: forcibly release the lock if held beyond MAX_INFERENCE_SECS."""
    global _holder_since, _holder_path, _holder_gen, _holder_conn
    while True:
        time.sleep(10)
        conn_to_close = None
        with _holder_lock:
            if _holder_since > 0:
                held = time.monotonic() - _holder_since
                if held > MAX_INFERENCE_SECS:
                    log.critical(
                        "Lock held %.0fs for %s — forcibly releasing!",
                        held, _holder_path,
                    )
                    conn_to_close = _holder_conn
                    _holder_gen += 1
                    _holder_since = 0.0
                    _holder_path = ""
                    _holder_conn = None
                    _inference_lock.release()
        # Close the stuck Ollama connection outside the lock to unblock resp.read()
        if conn_to_close is not None:
            try:
                conn_to_close.close()
            except Exception:
                pass


# --- Handler ---

class SerializingHandler(http.server.BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path in INFERENCE_PATHS:
            self._serialized_forward()
        else:
            self._forward()

    def do_GET(self):
        if self.path == "/health":
            self._health()
        else:
            self._forward()

    def do_DELETE(self):
        self._forward()

    # -- /health endpoint (bypasses lock) --

    def _health(self):
        """Lightweight status for the watchdog and dashboards."""
        with _queue_lock:
            depth = _queue_depth
        with _holder_lock:
            held = (time.monotonic() - _holder_since) if _holder_since else 0
            path = _holder_path
        circuit_open = _circuit_is_open()

        status = 503 if circuit_open else 200
        body = json.dumps({
            "status": "circuit_open" if circuit_open else "ok",
            "queue_depth": depth,
            "lock_held_secs": round(held, 1),
            "lock_held_by": path,
            "circuit_open": circuit_open,
        }).encode() + b"\n"

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- Serialized inference path --

    def _serialized_forward(self):
        global _queue_depth, _holder_since, _holder_path, _holder_gen, _holder_conn

        # Circuit breaker: fast-fail if Ollama is known to be down
        if _circuit_is_open():
            log.warning("Circuit open — rejecting %s", self.path)
            try:
                self.send_error(503, "Ollama temporarily unavailable (circuit breaker)")
            except Exception:
                pass
            return

        with _queue_lock:
            _queue_depth += 1
            depth = _queue_depth

        if depth > 1:
            log.info("Queued %s (position %d)", self.path, depth)

        wait_start = time.monotonic()
        acquired = _inference_lock.acquire(timeout=LOCK_WAIT_TIMEOUT)

        if not acquired:
            with _queue_lock:
                _queue_depth -= 1
            log.error("Lock wait timeout (%.0fs) for %s", LOCK_WAIT_TIMEOUT, self.path)
            try:
                self.send_error(503, "Inference queue timeout")
            except Exception:
                pass
            return

        # Record lock acquisition
        with _holder_lock:
            _holder_gen += 1
            my_gen = _holder_gen
            _holder_since = time.monotonic()
            _holder_path = self.path
            _holder_conn = None  # will be set by _forward via callback

        with _queue_lock:
            _queue_depth -= 1

        wait_secs = time.monotonic() - wait_start
        if wait_secs > 0.1:
            log.info("Acquired lock for %s after %.1fs wait", self.path, wait_secs)

        infer_start = time.monotonic()
        try:
            def _register_conn(conn):
                with _holder_lock:
                    if _holder_gen == my_gen:
                        _holder_conn = conn
            self._forward(conn_callback=_register_conn)
        finally:
            infer_secs = time.monotonic() - infer_start
            with _holder_lock:
                if _holder_gen == my_gen:
                    # Normal release
                    _holder_since = 0.0
                    _holder_path = ""
                    _holder_conn = None
                    _inference_lock.release()
                else:
                    # Watchdog already force-released; skip to avoid double-release
                    log.warning(
                        "Skipping release for %s — watchdog already freed lock",
                        self.path,
                    )
            log.info("Finished %s (%.1fs inference)", self.path, infer_secs)

    # -- Raw proxy --

    def _forward(self, conn_callback=None):
        """Proxy the request to Ollama and stream the response back.

        conn_callback: optional callable(conn) invoked after the connection is
        established, so the serialized-forward path can register it with the
        lock watchdog for forced abort on hang.
        """
        # Read request body
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else None

        conn = http.client.HTTPConnection(OLLAMA_HOST, OLLAMA_PORT, timeout=CHUNK_TIMEOUT)
        try:
            headers = {}
            for key in ("Content-Type", "Content-Length"):
                val = self.headers.get(key)
                if val:
                    headers[key] = val

            conn.request(self.command, self.path, body=body, headers=headers)
            if conn_callback is not None:
                conn_callback(conn)
            resp = conn.getresponse()

            self.send_response_only(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(key, val)
            self.end_headers()

            # Stream response chunks
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()

            _circuit_record_success()

        except (ConnectionRefusedError, OSError) as e:
            log.warning("Cannot reach Ollama: %s", e)
            _circuit_record_failure()
            try:
                self.send_error(502, "Ollama is unreachable")
            except Exception:
                pass
        except Exception as e:
            log.error("Proxy error: %s", e)
            _circuit_record_failure()
            try:
                self.send_error(502, str(e))
            except Exception:
                pass
        finally:
            conn.close()

    def log_message(self, fmt, *args):
        pass  # suppress default per-request access log


# --- Main ---

def main():
    log.info("=" * 50)
    log.info("Ollama Serializer Started")
    log.info("Listening on :%d → Ollama :%d", LISTEN_PORT, OLLAMA_PORT)
    log.info("Serialized paths: %s", ", ".join(sorted(INFERENCE_PATHS)))
    log.info(
        "Chunk timeout: %ds | Max inference: %ds | Lock wait: %ds",
        CHUNK_TIMEOUT, MAX_INFERENCE_SECS, LOCK_WAIT_TIMEOUT,
    )
    log.info(
        "Circuit breaker: %d failures → %ds cooldown",
        CIRCUIT_THRESHOLD, CIRCUIT_COOLDOWN,
    )
    log.info("=" * 50)

    # Start internal lock watchdog
    wd = threading.Thread(target=_lock_watchdog_loop, daemon=True)
    wd.start()

    def handle_signal(signum, _frame):
        log.info("Received signal %s, shutting down...", signum)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), SerializingHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
