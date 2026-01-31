#!/usr/bin/env python3
"""
Tanium On-Prem Tunnel Starter

Run this script on your Mac after connecting to VPN.
It creates a tunnel from the IR server to Tanium On-Prem via your Mac.

== SETUP (for a new Mac) ==

1. VPN Access
   - Ensure you have VPN access to reach Tanium On-Prem network

2. SSH Key
   - Generate a key if you don't have one: ssh-keygen -t ed25519
   - Copy to the IR server: ssh-copy-id <user>@<server>
   - Test connection: ssh <user>@<server>

3. Install socat
   - brew install socat

4. Get this script
   - Clone the repo or copy this file to your Mac

== USAGE ==

1. Connect to VPN
2. Run this script: python3 start_tanium_tunnel.py
   - Or right-click in PyCharm and select "Run"
3. Keep the terminal open while using the tunnel
4. Press Ctrl+C to stop
"""

import os
import signal
import socket
import subprocess
import sys
import time

from dotenv import load_dotenv

load_dotenv()


def resolve_tanium_ip() -> str:
    """Resolve Tanium hostname to IP, fall back to static IP."""
    hostname = os.getenv("TANIUM_ONPREM_HOSTNAME")
    static_ip = os.getenv("TANIUM_ONPREM_IP")

    if hostname:
        try:
            resolved_ip = socket.gethostbyname(hostname)
            print(f"  Resolved {hostname} -> {resolved_ip}")
            return resolved_ip
        except socket.gaierror:
            print(f"  Warning: Could not resolve {hostname}, falling back to static IP")

    if static_ip:
        return static_ip

    raise ValueError("Could not resolve Tanium IP. Set TANIUM_ONPREM_HOSTNAME or TANIUM_ONPREM_IP in .env")


# Configuration from .env
TANIUM_ONPREM_IP = resolve_tanium_ip()
LOCAL_SOCAT_PORT = int(os.getenv("TANIUM_TUNNEL_LOCAL_PORT"))
REMOTE_TUNNEL_PORT = int(os.getenv("TANIUM_TUNNEL_REMOTE_PORT"))
SSH_HOST = os.getenv("TANIUM_TUNNEL_SSH_HOST")


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def is_vpn_connected() -> bool:
    """Check if VPN is connected by pinging Tanium On-Prem."""
    result = run_cmd(["ping", "-c", "1", "-W", "2000", TANIUM_ONPREM_IP], check=False)
    return result.returncode == 0


def kill_existing():
    """Kill any existing tunnel processes (local and remote)."""
    # Kill local processes
    subprocess.run(["pkill", "-f", f"socat.*{LOCAL_SOCAT_PORT}"],
                   capture_output=True, check=False)
    subprocess.run(["pkill", "-f", f"ssh.*{REMOTE_TUNNEL_PORT}.*{SSH_HOST}"],
                   capture_output=True, check=False)

    # Kill orphaned SSH tunnel sessions on the remote server
    # fuser doesn't work on sshd-owned sockets, so we kill old sshd sessions directly
    cleanup_cmd = f"""
        # Get socket inode for port {REMOTE_TUNNEL_PORT}
        PORT_HEX=$(printf '%04X' {REMOTE_TUNNEL_PORT})
        INODE=$(cat /proc/net/tcp 2>/dev/null | grep ":$PORT_HEX" | awk '{{print $10}}' | head -1)
        if [ -n "$INODE" ] && [ "$INODE" != "0" ]; then
            # Find sshd processes that might own this (look for @notty sessions)
            for pid in $(pgrep -u $USER 'sshd'); do
                # Kill any old sshd session processes (not the current one)
                if [ "$pid" != "$$" ]; then
                    kill $pid 2>/dev/null || true
                fi
            done
            sleep 1
        fi
    """
    subprocess.run(["ssh", SSH_HOST, cleanup_cmd], capture_output=True, check=False)
    time.sleep(1)


def start_tunnel():
    """Start the tunnel components."""
    print("=" * 50)
    print("Tanium On-Prem Tunnel")
    print("=" * 50)

    # Check VPN
    print("\n[1/3] Checking VPN connection...")
    if not is_vpn_connected():
        print(f"  ERROR: Cannot reach {TANIUM_ONPREM_IP}")
        print("  Make sure VPN is connected!")
        input("\nPress Enter to exit...")
        sys.exit(1)
    print(f"  VPN connected - can reach Tanium On-Prem")

    # Kill existing
    print("\n[2/3] Cleaning up old processes...")
    kill_existing()
    print("  Done")

    # Start socat
    print(f"\n[3/3] Starting tunnel...")
    print(f"  Starting socat (localhost:{LOCAL_SOCAT_PORT} -> {TANIUM_ONPREM_IP}:443)...")

    socat_proc = subprocess.Popen(
        ["socat", f"TCP-LISTEN:{LOCAL_SOCAT_PORT},fork,reuseaddr", f"TCP:{TANIUM_ONPREM_IP}:443"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1)

    if socat_proc.poll() is not None:
        print("  ERROR: socat failed to start")
        input("\nPress Enter to exit...")
        sys.exit(1)
    print(f"  socat running (PID: {socat_proc.pid})")

    # Start SSH tunnel
    print(f"  Starting SSH tunnel (lab-server:{REMOTE_TUNNEL_PORT} -> localhost:{LOCAL_SOCAT_PORT})...")

    ssh_proc = subprocess.Popen(
        [
            "ssh",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-R", f"{REMOTE_TUNNEL_PORT}:localhost:{LOCAL_SOCAT_PORT}",
            "-N",
            SSH_HOST
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    time.sleep(3)

    if ssh_proc.poll() is not None:
        stderr = ssh_proc.stderr.read() if ssh_proc.stderr else ""
        print(f"  ERROR: SSH tunnel failed: {stderr}")
        socat_proc.terminate()
        input("\nPress Enter to exit...")
        sys.exit(1)
    print(f"  SSH tunnel running (PID: {ssh_proc.pid})")

    # Success
    print("\n" + "=" * 50)
    print("TUNNEL IS RUNNING")
    print("=" * 50)
    print(f"\nlab-server:localhost:{REMOTE_TUNNEL_PORT} --> Tanium On-Prem")
    print("\nKeep this window open to maintain the tunnel.")
    print("Press Ctrl+C to stop.\n")

    # Wait and handle Ctrl+C
    def cleanup(_signum, _frame):
        print("\n\nShutting down tunnel...")
        socat_proc.terminate()
        ssh_proc.terminate()
        print("Done.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Keep running and monitor
    try:
        while True:
            time.sleep(5)
            # Check if processes are still running
            if socat_proc.poll() is not None:
                print("\nWARNING: socat died, restarting...")
                socat_proc = subprocess.Popen(
                    ["socat", f"TCP-LISTEN:{LOCAL_SOCAT_PORT},fork,reuseaddr", f"TCP:{TANIUM_ONPREM_IP}:443"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            if ssh_proc.poll() is not None:
                print("\nWARNING: SSH tunnel died, restarting...")
                ssh_proc = subprocess.Popen(
                    [
                        "ssh",
                        "-o", "ServerAliveInterval=30",
                        "-o", "ServerAliveCountMax=3",
                        "-o", "ExitOnForwardFailure=yes",
                        "-R", f"{REMOTE_TUNNEL_PORT}:localhost:{LOCAL_SOCAT_PORT}",
                        "-N",
                        SSH_HOST
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE
                )
    except KeyboardInterrupt:
        cleanup(None, None)


if __name__ == "__main__":
    start_tunnel()
