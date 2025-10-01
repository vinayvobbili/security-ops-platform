#!/usr/bin/env python3
"""Print probable access URLs for the running IR web server.

Usage:
  python scripts/print_access_urls.py --port 8080

It will attempt to:
  1. Collect local IPv4 addresses
  2. Show curl examples for / and /healthz endpoints
  3. Suggest temporary /etc/hosts entry format

No external dependencies required.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
from typing import List


def get_ipv4_addrs() -> List[str]:
    addrs: List[str] = []
    # Try standard hostname -I (Linux) first
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True).strip()
        for token in out.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
                addrs.append(token)
    except Exception:
        pass

    # Fallback: use socket trick (non-routing) to infer primary IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary not in addrs:
            addrs.append(primary)
    except Exception:
        pass

    # Always add localhost
    if "127.0.0.1" not in addrs:
        addrs.append("127.0.0.1")

    # Deduplicate preserving order
    seen = set()
    deduped = []
    for a in addrs:
        if a not in seen:
            seen.add(a)
            deduped.append(a)
    return deduped


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEB_PORT", "8080")))
    parser.add_argument("--host-candidate", default="metcirt-lab-12.internal.company.com",
                        help="Hostname you expect to resolve (for /etc/hosts suggestion)")
    args = parser.parse_args()

    addrs = get_ipv4_addrs()
    print("Discovered IPv4 addresses:")
    for a in addrs:
        print(f"  - {a}")

    print("\nSuggested access URLs (if server bound to 0.0.0.0):")
    for a in addrs:
        print(f"  http://{a}:{args.port}/")
    print("\nHealth checks:")
    for a in addrs:
        print(f"  curl -s http://{a}:{args.port}/healthz | jq .  # (or cat if jq not installed)")

    print("\nIf DNS for the expected hostname is missing, you can add a temporary /etc/hosts entry:")
    primary = addrs[0]
    hosts_line = f"{primary} {args.host_candidate}"
    echo_cmd = f"echo '{hosts_line}' >> /etc/hosts"
    print(f"  sudo sh -c \"{echo_cmd}\"  # Then: curl http://{args.host_candidate}:{args.port}/healthz")

    print("\n(Remove the /etc/hosts line later to avoid stale overrides.)")


if __name__ == "__main__":
    main()
