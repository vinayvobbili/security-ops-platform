#!/usr/bin/env python3
"""Inference server health watchdog. Checks all reverse tunnel ports, alerts to Webex if any are down or wedged."""

import sys
import os
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests

PORTS = {
    8015: "M1 Analysis",
    8016: "M1 Router",
    8019: "M3 Embeds",
    8020: "M3 Reranker",
}

# Analysis/router ports that should be tested with a real completion
COMPLETION_CHECK_PORTS = {8015, 8016}
COMPLETION_TIMEOUT = 30  # seconds — if no response in this time, model is wedged

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "inference_watchdog.log")
STATE_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", ".watchdog_state")


def check_completion(port):
    """Send a minimal completion request. Returns True if the model generates tokens."""
    try:
        r = requests.post(
            f"http://localhost:{port}/v1/chat/completions",
            json={
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 3,
                "stream": False,
            },
            timeout=COMPLETION_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        choices = data.get("choices", [])
        return bool(choices and choices[0].get("message", {}).get("content"))
    except Exception:
        return False


def check_ports():
    down = []
    wedged = []
    for port, name in PORTS.items():
        try:
            r = requests.get(f"http://localhost:{port}/v1/models", timeout=5)
            r.raise_for_status()
        except Exception:
            down.append(f"{name} (:{port})")
            continue
        # For analysis/router ports, also test completions
        if port in COMPLETION_CHECK_PORTS:
            if not check_completion(port):
                wedged.append(f"{name} (:{port})")
    return down, wedged


def was_already_alerted(down_key):
    """Avoid spamming — only alert on state change."""
    try:
        with open(STATE_PATH) as f:
            return f.read().strip() == down_key
    except FileNotFoundError:
        return False


def save_state(down_key):
    with open(STATE_PATH, "w") as f:
        f.write(down_key)


def send_webex_alert(message):
    from my_config import get_config
    cfg = get_config()
    token = cfg.webex_bot_access_token_pinger or cfg.webex_bot_access_token_jarvis or cfg.webex_bot_access_token_barnacles
    room_id = cfg.webex_room_id_dev_test_space
    if not token or not room_id:
        return
    try:
        requests.post(
            "https://webexapis.com/v1/messages",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"roomId": room_id, "markdown": message},
            timeout=10,
        )
    except Exception as e:
        print(f"Webex alert failed: {e}")


def main():
    down, wedged = check_ports()
    issues = sorted(down + [w + " WEDGED" for w in wedged])
    issue_key = ",".join(issues) if issues else ""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    if down or wedged:
        parts = []
        if down:
            parts.append(f"DOWN: {', '.join(down)}")
        if wedged:
            parts.append(f"WEDGED: {', '.join(wedged)}")
        msg = f"{now} {'; '.join(parts)}"
        with open(LOG_PATH, "a") as f:
            f.write(msg + "\n")

        if not was_already_alerted(issue_key):
            alert_parts = []
            if down:
                alert_parts.append(f"{', '.join(down)} — unreachable")
            if wedged:
                alert_parts.append(f"{', '.join(wedged)} — responding to /models but completions hung (>{COMPLETION_TIMEOUT}s)")
            send_webex_alert(f"⚠️ **Inference Server Alert**\n\n{chr(10).join(alert_parts)}\n\n`{now}`")
            save_state(issue_key)
    else:
        if was_already_alerted(""):
            pass  # already clear
        else:
            # State changed from down to all-clear
            if os.path.exists(STATE_PATH):
                send_webex_alert(f"✅ **All inference servers recovered**\n\n`{now}`")
            save_state("")


if __name__ == "__main__":
    main()
