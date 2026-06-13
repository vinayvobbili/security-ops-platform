#!/usr/bin/env python3
"""Periodic keepalive ping for the active vllm-mlx analysis LLM on studio1.

Pings port 8003 (Coder, the only active analysis model right now) and 8005 (small router model).
Sends a 1-token chat completion every 30s to keep the Apple Silicon GPU clocks + Metal kernel cache + VM page-activity hot,
so the first real request after an idle gap doesn't pay the cold-start tax (~1 tok/s vs warm ~35 tok/s).

HTTP_TIMEOUT_S must be larger than the cold-start latency of the biggest model being warmed,
including the WORST case: a deeply-idle overnight model whose 30 GB has been swapped out and Metal state torn down.
A daytime warm-ish cold ping is ~30-40s, but a fully deep-cold overnight first forward pass can exceed 90s.
If the timeout fires before that completes, the client disconnects and the server's disconnect_guard cancels the in-flight prefill,
so the model is never actually warmed — the next ping hits an equally-cold model and the loop never recovers (observed all night 2026-05-30).
180s clears even the deep-cold case with headroom; once one warm-up completes the 30s cadence keeps it hot and pings drop to <1s.

Install on studio1:
  cp deployment/vllm_keepalive.py /Users/labuser/vllm_keepalive.py
  cp deployment/com.ir.vllm-mlx-keepalive.plist \\
     /Users/labuser/Library/LaunchAgents/
  launchctl bootstrap gui/$(id -u) \\
     ~/Library/LaunchAgents/com.ir.vllm-mlx-keepalive.plist
"""
import sys
import time
import urllib.request
import urllib.error
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("keepalive")

API_KEY = "703ccba9163393f769228e0c3d1b809b6897fa9b4a50972d"
ANALYSIS_PORTS = [8003, 8005]  # 8003=Coder (30B, real analysis), 8005=Router (Qwen3-4B, tiny tool-routing model). 8002 GLM stood down 2026-05-07.
INTERVAL_S = 30
HTTP_TIMEOUT_S = 180  # Must clear a fully deep-cold overnight first forward pass (>90s observed), or disconnect_guard cancels the warm-up and the model never recovers. See module docstring.


def http_json(url, body=None, method="GET"):
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
        return json.loads(resp.read())


def discover_model(port):
    try:
        r = http_json(f"http://127.0.0.1:{port}/v1/models")
        items = r.get("data", [])
        if items:
            return items[0]["id"]
    except Exception:
        return None
    return None


def ping(port, model):
    try:
        body = {
            "model": model,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
            "temperature": 0,
        }
        http_json(f"http://127.0.0.1:{port}/v1/chat/completions", body=body, method="POST")
        return True
    except Exception as e:
        log.warning(f"ping :{port} failed: {e}")
        return False


def main():
    log.info(f"keepalive starting; interval={INTERVAL_S}s, ports={ANALYSIS_PORTS}")
    last_logged_state = None
    while True:
        active = []
        for p in ANALYSIS_PORTS:
            m = discover_model(p)
            if m:
                if ping(p, m):
                    active.append((p, m))
        state = tuple(active)
        if state != last_logged_state:
            if active:
                pretty = ", ".join(f":{p}={m}" for p, m in active)
                log.info(f"warming: {pretty}")
            else:
                log.info("warming: no analysis model up")
            last_logged_state = state
        time.sleep(INTERVAL_S)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
