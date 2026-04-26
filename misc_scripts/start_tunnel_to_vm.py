#!/usr/bin/env python3
"""
Mac-to-Lab-VM Tunnel Starter

Run on your Mac to create reverse SSH tunnels from the lab-vm to services
accessible via your Mac:
  - Tanium On-Prem (requires VPN + socat)
  - QRadar Cloud (requires socat, optional)
  - mlx-lm servers (configured via MLX_TUNNELS env var)

Setup:
  1. Network access to reach Tanium On-Prem
  2. SSH key copied to lab-vm: ssh-copy-id <user>@<server>
  3. brew install socat autossh
  4. mlx-lm servers running (LaunchAgents com.ir.mlx-lm-*)

Usage:
  python3 start_tunnel_to_vm.py          # manual
  launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ir.tunnel.plist
"""

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / "data" / "transient" / ".env")

# --- Configuration from .env ---

# MLX_TUNNELS: comma-separated remote:local port pairs for mlx-lm servers.
# Example: MLX_TUNNELS=8010:8000,8011:8001,8012:8002
_mlx_raw = os.getenv("MLX_TUNNELS", "")
MLX_FORWARDS = []
for pair in _mlx_raw.split(","):
    pair = pair.strip()
    if pair:
        remote, local = pair.split(":")
        MLX_FORWARDS.append((int(remote), int(local)))

REVERSE_SSH_PORT = int(os.getenv("REVERSE_SSH_PORT", "0"))
SSH_HOST = os.getenv("TANIUM_TUNNEL_SSH_HOST")
TANIUM_LOCAL_PORT = int(os.getenv("TANIUM_TUNNEL_LOCAL_PORT", "0"))
TANIUM_REMOTE_PORT = int(os.getenv("TANIUM_TUNNEL_REMOTE_PORT", "0"))
QRADAR_HOST = os.getenv("QRADAR_TUNNEL_HOST", "")
QRADAR_LOCAL_PORT = int(os.getenv("QRADAR_TUNNEL_LOCAL_PORT", "8444"))
QRADAR_REMOTE_PORT = int(os.getenv("QRADAR_TUNNEL_REMOTE_PORT", "8444"))


# --- Helpers ---

def check_port(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a TCP port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve_tanium_ip() -> str:
    """Resolve Tanium hostname to IP, fall back to static IP."""
    hostname = os.getenv("TANIUM_ONPREM_HOSTNAME")
    static_ip = os.getenv("TANIUM_ONPREM_IP")

    if hostname:
        try:
            resolved = socket.gethostbyname(hostname)
            print(f"  Resolved {hostname} -> {resolved}")
            return resolved
        except socket.gaierror:
            print(f"  Warning: Could not resolve {hostname}, falling back to static IP")

    if static_ip:
        return static_ip

    raise ValueError("Set TANIUM_ONPREM_HOSTNAME or TANIUM_ONPREM_IP in .env")


def start_socat(listen_port: int, target_host: str, target_port: int = 443) -> subprocess.Popen:
    """Start a socat TCP proxy."""
    return subprocess.Popen(
        ["socat", f"TCP-LISTEN:{listen_port},fork,reuseaddr", f"TCP:{target_host}:{target_port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def start_autossh(forwards: list[tuple[int, int]], host: str) -> subprocess.Popen:
    """Start an autossh reverse tunnel with the given port forwards."""
    cmd = [
        "autossh",
        "-M", "0",  # rely on SSH keepalives instead of monitoring port
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
    ]
    for remote_port, local_port in forwards:
        cmd += ["-R", f"{remote_port}:127.0.0.1:{local_port}"]
    cmd += ["-N", host]
    env = {**os.environ, "AUTOSSH_GATETIME": "0"}  # no initial grace period
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)


def kill_existing():
    """Kill old tunnel processes (local and remote)."""
    my_pid = os.getpid()

    # Kill old instances of this script first to prevent socat respawn race
    result = subprocess.run(
        ["pgrep", "-f", "start_tunnel_to_vm"], capture_output=True, text=True, check=False,
    )
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != my_pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    time.sleep(1)

    # Kill local socat and ssh processes
    kill_patterns = [f"autossh.*{SSH_HOST}"]
    if TANIUM_LOCAL_PORT:
        kill_patterns.append(f"socat.*{TANIUM_LOCAL_PORT}")
    if QRADAR_LOCAL_PORT:
        kill_patterns.append(f"socat.*{QRADAR_LOCAL_PORT}")
    for pattern in kill_patterns:
        subprocess.run(["pkill", "-f", pattern], capture_output=True, check=False)

    # Kill only remote sshd sessions holding our specific tunnel ports
    our_ports = [str(r) for r, _ in MLX_FORWARDS]
    if TANIUM_REMOTE_PORT:
        our_ports.append(str(TANIUM_REMOTE_PORT))
    if REVERSE_SSH_PORT:
        our_ports.append(str(REVERSE_SSH_PORT))
    port_pattern = "|".join(our_ports)
    cleanup_cmd = f"""
        for pid in $(sudo ss -tlnp | grep -E ':{port_pattern} ' | grep -oP 'pid=\\K[0-9]+' | sort -u); do
            kill $pid 2>/dev/null || true
        done
        sleep 1
    """
    subprocess.run(["ssh", SSH_HOST, cleanup_cmd], capture_output=True, check=False)
    time.sleep(1)


# --- Main ---

def start_tunnel():
    tanium_enabled = bool(TANIUM_REMOTE_PORT)
    qradar_enabled = bool(QRADAR_HOST)

    print("=" * 50)
    print("Mac-to-Lab-VM Tunnels")
    print("=" * 50)

    # Pre-flight checks
    steps = ["cleanup", "start"]
    if tanium_enabled:
        steps.insert(0, "tanium")
    if qradar_enabled:
        steps.insert(len(steps) - 2, "qradar")
    if MLX_FORWARDS:
        steps.insert(len(steps) - 2, "mlx")
    total = len(steps)
    step = 0

    tanium_ip = None
    if tanium_enabled:
        tanium_ip = resolve_tanium_ip()
        step += 1
        print(f"\n[{step}/{total}] Checking Tanium reachability...")
        tanium_reachable = check_port(tanium_ip, 443, timeout=2)
        print(f"  {'Reachable' if tanium_reachable else 'Not reachable - continuing anyway'} ({tanium_ip}:443)")

    if qradar_enabled:
        step += 1
        print(f"\n[{step}/{total}] Checking QRadar Cloud...")
        qradar_ok = check_port(QRADAR_HOST, 443, timeout=5)
        print(f"  {'Reachable' if qradar_ok else 'Not reachable - continuing anyway'} ({QRADAR_HOST})")

    if MLX_FORWARDS:
        step += 1
        print(f"\n[{step}/{total}] Checking mlx-lm servers...")
        for remote, local in MLX_FORWARDS:
            ok = check_port("localhost", local, timeout=2)
            print(f"  mlx-lm :{local}: {'Running' if ok else 'NOT RUNNING'} (tunnel -> lab-vm:{remote})")

    step += 1
    print(f"\n[{step}/{total}] Cleaning up old processes...")
    kill_existing()
    print("  Done")

    step += 1
    print(f"\n[{step}/{total}] Starting tunnels...")

    tanium_socat = None
    if tanium_enabled:
        print(f"  Tanium socat: localhost:{TANIUM_LOCAL_PORT} -> {tanium_ip}:443")
        tanium_socat = start_socat(TANIUM_LOCAL_PORT, tanium_ip)
        time.sleep(1)
        if tanium_socat.poll() is not None:
            print("  ERROR: Tanium socat failed to start")
            sys.exit(1)

    qradar_socat = None
    if qradar_enabled:
        print(f"  QRadar socat: localhost:{QRADAR_LOCAL_PORT} -> {QRADAR_HOST}:443")
        qradar_socat = start_socat(QRADAR_LOCAL_PORT, QRADAR_HOST)
        time.sleep(1)
        if qradar_socat.poll() is not None:
            print("  ERROR: QRadar socat failed to start")
            sys.exit(1)

    # Build SSH reverse forwards
    forwards = list(MLX_FORWARDS)
    if tanium_enabled:
        forwards.append((TANIUM_REMOTE_PORT, TANIUM_LOCAL_PORT))
    if REVERSE_SSH_PORT:
        forwards.append((REVERSE_SSH_PORT, 22))
    if qradar_enabled:
        forwards.append((QRADAR_REMOTE_PORT, QRADAR_LOCAL_PORT))

    print("  SSH reverse tunnels:")
    for remote, local in forwards:
        print(f"    lab-vm:{remote} -> localhost:{local}")

    ssh = start_autossh(forwards, SSH_HOST)
    time.sleep(3)
    if ssh.poll() is not None:
        stderr = ssh.stderr.read() if ssh.stderr else ""
        print(f"  ERROR: autossh tunnel failed: {stderr}")
        tanium_socat.terminate()
        if qradar_socat:
            qradar_socat.terminate()
        sys.exit(1)

    # Success
    print("\n" + "=" * 50)
    print("TUNNELS ARE RUNNING")
    print("=" * 50)
    print(f"\nActive tunnels on lab-vm:")
    if tanium_enabled:
        print(f"  localhost:{TANIUM_REMOTE_PORT} --> Tanium On-Prem")
    if qradar_enabled:
        print(f"  localhost:{QRADAR_REMOTE_PORT} --> QRadar Cloud ({QRADAR_HOST})")
    for remote, local in MLX_FORWARDS:
        print(f"  localhost:{remote} --> Mac mlx-lm (:{local})")
    if REVERSE_SSH_PORT:
        print(f"  localhost:{REVERSE_SSH_PORT} --> Mac SSH (ping routing)")
    print("\nPress Ctrl+C to stop.\n")

    # Signal handler
    procs = [p for p in [tanium_socat, qradar_socat, ssh] if p]

    def cleanup(_signum, _frame):
        print("\nShutting down tunnels...")
        for p in procs:
            p.terminate()
        print("Done.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Monitor loop — autossh handles SSH restarts, only socat needs monitoring
    while True:
        time.sleep(5)
        if tanium_socat and tanium_socat.poll() is not None:
            print("\nWARNING: Tanium socat died, restarting...")
            tanium_socat = start_socat(TANIUM_LOCAL_PORT, tanium_ip)
        if qradar_socat and qradar_socat.poll() is not None:
            print("\nWARNING: QRadar socat died, restarting...")
            qradar_socat = start_socat(QRADAR_LOCAL_PORT, QRADAR_HOST)


if __name__ == "__main__":
    start_tunnel()
