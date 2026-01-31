#!/bin/bash

# Tanium On-Prem Tunnel Script
#
# This script creates a tunnel from lab-server to Tanium On-Prem
# via this Mac's VPN connection.
#
# Flow: Linux:8443 --> SSH tunnel --> Mac:9443 --> socat --> VPN --> Tanium:443
#
# Usage:
#   ./tanium-onprem-tunnel.sh start   # Start the tunnel
#   ./tanium-onprem-tunnel.sh stop    # Stop the tunnel
#   ./tanium-onprem-tunnel.sh status  # Check tunnel status
#   ./tanium-onprem-tunnel.sh restart # Restart the tunnel

# Load config from project .env file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
    TANIUM_ONPREM_HOSTNAME=$(grep "^TANIUM_ONPREM_HOSTNAME=" "$ENV_FILE" | cut -d'=' -f2)
    TANIUM_ONPREM_IP=$(grep "^TANIUM_ONPREM_IP=" "$ENV_FILE" | cut -d'=' -f2)
    TANIUM_TUNNEL_SSH_HOST=$(grep "^TANIUM_TUNNEL_SSH_HOST=" "$ENV_FILE" | cut -d'=' -f2)
    TANIUM_TUNNEL_LOCAL_PORT=$(grep "^TANIUM_TUNNEL_LOCAL_PORT=" "$ENV_FILE" | cut -d'=' -f2)
    TANIUM_TUNNEL_REMOTE_PORT=$(grep "^TANIUM_TUNNEL_REMOTE_PORT=" "$ENV_FILE" | cut -d'=' -f2)
fi

# Resolve hostname to IP dynamically, fall back to static IP
resolve_tanium_ip() {
    if [[ -n "$TANIUM_ONPREM_HOSTNAME" ]]; then
        local resolved_ip
        resolved_ip=$(dig +short "$TANIUM_ONPREM_HOSTNAME" 2>/dev/null | tail -1)
        if [[ -n "$resolved_ip" && "$resolved_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$resolved_ip"
            return 0
        fi
    fi
    # Fall back to static IP
    if [[ -n "$TANIUM_ONPREM_IP" ]]; then
        echo "$TANIUM_ONPREM_IP"
        return 0
    fi
    return 1
}

TANIUM_ONPREM_IP=$(resolve_tanium_ip) || { echo "ERROR: Could not resolve Tanium IP. Set TANIUM_ONPREM_HOSTNAME or TANIUM_ONPREM_IP in $ENV_FILE"; exit 1; }
SSH_HOST="${TANIUM_TUNNEL_SSH_HOST:?TANIUM_TUNNEL_SSH_HOST not found in $ENV_FILE}"
LOCAL_SOCAT_PORT="${TANIUM_TUNNEL_LOCAL_PORT:-9443}"
REMOTE_TUNNEL_PORT="${TANIUM_TUNNEL_REMOTE_PORT:-8443}"

# PID files
PID_DIR="$HOME/.tanium-tunnel"
SOCAT_PID="$PID_DIR/socat.pid"
SSH_PID="$PID_DIR/ssh.pid"

mkdir -p "$PID_DIR"

check_vpn() {
    # Check if VPN is connected by testing TCP connectivity to Tanium (ping is blocked)
    if nc -z -w 2 "$TANIUM_ONPREM_IP" 443 &>/dev/null; then
        return 0
    else
        return 1
    fi
}

start_tunnel() {
    echo "Starting Tanium On-Prem tunnel..."
    echo "  Tanium IP: $TANIUM_ONPREM_IP (resolved from ${TANIUM_ONPREM_HOSTNAME:-static config})"

    # Check VPN
    if ! check_vpn; then
        echo "ERROR: Cannot reach Tanium On-Prem ($TANIUM_ONPREM_IP)"
        echo "       Make sure VPN is connected."
        exit 1
    fi
    echo "✓ VPN connected - can reach Tanium On-Prem ($TANIUM_ONPREM_IP)"

    # Kill any existing processes
    stop_tunnel 2>/dev/null

    # Start socat
    echo "Starting socat forwarder on port $LOCAL_SOCAT_PORT..."
    /opt/homebrew/bin/socat "TCP-LISTEN:${LOCAL_SOCAT_PORT},fork,reuseaddr" "TCP:${TANIUM_ONPREM_IP}:443" &
    echo "$!" > "$SOCAT_PID"
    sleep 1

    if ! kill -0 "$(cat "$SOCAT_PID")" 2>/dev/null; then
        echo "ERROR: Failed to start socat"
        exit 1
    fi
    echo "✓ socat running (PID: $(cat "$SOCAT_PID"))"

    # Start SSH tunnel (use autossh if available for auto-reconnect)
    echo "Starting SSH reverse tunnel..."
    if command -v autossh &>/dev/null; then
        AUTOSSH_PIDFILE="$SSH_PID" autossh -M 0 -f \
            -o "ServerAliveInterval=30" \
            -o "ServerAliveCountMax=3" \
            -o "ExitOnForwardFailure=yes" \
            -R "${REMOTE_TUNNEL_PORT}:localhost:${LOCAL_SOCAT_PORT}" \
            -N "$SSH_HOST"
        sleep 2
        # autossh writes its own PID file
    else
        ssh -f \
            -o "ServerAliveInterval=30" \
            -o "ServerAliveCountMax=3" \
            -o "ExitOnForwardFailure=yes" \
            -R "${REMOTE_TUNNEL_PORT}:localhost:${LOCAL_SOCAT_PORT}" \
            -N "$SSH_HOST"
        # Find the SSH PID
        pgrep -f "ssh.*${REMOTE_TUNNEL_PORT}.*${SSH_HOST}" > "$SSH_PID"
    fi

    if [[ -f "$SSH_PID" ]] && kill -0 "$(cat "$SSH_PID")" 2>/dev/null; then
        echo "✓ SSH tunnel running (PID: $(cat "$SSH_PID"))"
    else
        echo "ERROR: Failed to start SSH tunnel"
        stop_tunnel
        exit 1
    fi

    echo ""
    echo "Tunnel is running!"
    echo "  Linux localhost:$REMOTE_TUNNEL_PORT --> Tanium On-Prem:443"
}

stop_tunnel() {
    echo "Stopping Tanium On-Prem tunnel..."

    # Stop SSH tunnel
    if [[ -f "$SSH_PID" ]]; then
        kill "$(cat "$SSH_PID")" 2>/dev/null && echo "✓ SSH tunnel stopped"
        rm -f "$SSH_PID"
    fi

    # Also kill any lingering SSH processes for this tunnel
    pkill -f "ssh.*${REMOTE_TUNNEL_PORT}.*${SSH_HOST}" 2>/dev/null
    pkill -f "autossh.*${REMOTE_TUNNEL_PORT}.*${SSH_HOST}" 2>/dev/null

    # Stop socat
    if [[ -f "$SOCAT_PID" ]]; then
        kill "$(cat "$SOCAT_PID")" 2>/dev/null && echo "✓ socat stopped"
        rm -f "$SOCAT_PID"
    fi

    # Also kill any lingering socat processes for this port
    pkill -f "socat.*${LOCAL_SOCAT_PORT}.*${TANIUM_ONPREM_IP}" 2>/dev/null
}

status_tunnel() {
    echo "Tanium On-Prem Tunnel Status"
    echo "=============================="

    # Check VPN
    if check_vpn; then
        echo "VPN:        ✓ Connected (can reach $TANIUM_ONPREM_IP)"
    else
        echo "VPN:        ✗ Not connected"
    fi

    # Check socat
    if [[ -f "$SOCAT_PID" ]] && kill -0 "$(cat "$SOCAT_PID")" 2>/dev/null; then
        echo "socat:      ✓ Running (PID: $(cat "$SOCAT_PID"))"
    else
        echo "socat:      ✗ Not running"
    fi

    # Check SSH
    if [[ -f "$SSH_PID" ]] && kill -0 "$(cat "$SSH_PID")" 2>/dev/null; then
        echo "SSH tunnel: ✓ Running (PID: $(cat "$SSH_PID"))"
    else
        echo "SSH tunnel: ✗ Not running"
    fi

    # Check if port is listening on remote
    echo ""
    echo "Testing tunnel connectivity..."
    if ssh -o ConnectTimeout=5 "$SSH_HOST" "ss -tlnp | grep -q :${REMOTE_TUNNEL_PORT}" 2>/dev/null; then
        echo "Remote:     ✓ Port $REMOTE_TUNNEL_PORT listening on lab-server"
    else
        echo "Remote:     ✗ Port $REMOTE_TUNNEL_PORT not listening"
    fi
}

case "${1:-start}" in
    start)
        start_tunnel
        ;;
    stop)
        stop_tunnel
        ;;
    restart)
        stop_tunnel
        sleep 2
        start_tunnel
        ;;
    status)
        status_tunnel
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
