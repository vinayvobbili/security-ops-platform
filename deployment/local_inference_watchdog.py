#!/usr/bin/env python3
"""Local inference watchdog — runs on the Mac hosting vllm-mlx.

Detects wedged model servers (respond to /v1/models but hang on completions)
and force-kills them so the LaunchAgent can auto-restart.

Usage: python3 local_inference_watchdog.py [--port 8000 8001]
"""

import argparse
import os
import signal
import subprocess
import sys
from datetime import datetime

import requests

LOG_PATH = os.path.expanduser("~/security-ops-platform/logs/inference_watchdog_local.log")
COMPLETION_TIMEOUT = 90  # generous — avoids false positives on large models (35B) during cold start


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} {msg}"
    print(line)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def get_model_name(port):
    """Return the first model name from /v1/models, or None if unreachable."""
    try:
        r = requests.get(f"http://localhost:{port}/v1/models", timeout=5)
        r.raise_for_status()
        data = r.json().get("data", [])
        return data[0]["id"] if data else None
    except Exception:
        return None


def is_completion_ok(port, model):
    try:
        r = requests.post(
            f"http://localhost:{port}/v1/chat/completions",
            json={
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 3,
                "stream": False,
            },
            timeout=COMPLETION_TIMEOUT,
        )
        r.raise_for_status()
        choices = r.json().get("choices", [])
        return bool(choices and choices[0].get("message", {}).get("content"))
    except Exception:
        return False


def find_vllm_pids(port):
    """Find vllm-mlx PIDs serving the given port."""
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", f"vllm_mlx.*--port {port}"],
            text=True,
        ).strip()
        return [int(p) for p in out.split("\n") if p]
    except subprocess.CalledProcessError:
        return []


def check_port(port):
    """Check a single port. Kill the process if wedged."""
    model = get_model_name(port)
    if not model:
        log(f"port {port} /v1/models unreachable — server is down, skipping (LaunchAgent will restart)")
        return

    if is_completion_ok(port, model):
        return

    # Models responds but completions hang — wedged
    pids = find_vllm_pids(port)
    if not pids:
        log(f"port {port} WEDGED but could not find vllm-mlx process to kill")
        return

    log(f"port {port} WEDGED — completions hung >{COMPLETION_TIMEOUT}s. Killing PIDs: {pids}")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
            log(f"  kill -9 {pid} sent")
        except ProcessLookupError:
            log(f"  PID {pid} already gone")
        except PermissionError:
            log(f"  PID {pid} permission denied")

    log(f"port {port} vllm-mlx killed — LaunchAgent should auto-restart it")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, nargs="+", default=[8000])
    args = parser.parse_args()

    for port in args.port:
        check_port(port)


if __name__ == "__main__":
    main()
