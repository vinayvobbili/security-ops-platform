#!/usr/bin/env bash
# Helper script to launch the IR web server on port 80 using the project's virtualenv.
# Usage:
#   sudo ./scripts/run_web_port80.sh            # runs with defaults (0.0.0.0:80)
#   sudo BIND_HOST=0.0.0.0 PORT=80 ./scripts/run_web_port80.sh
# Optional env vars:
#   BIND_HOST (default 0.0.0.0)
#   PORT (default 80)
#   EXTRA_ARGS (extra args to pass to web_server module)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
VENV_PY="$PROJECT_ROOT/.venv/bin/python"
MODULE="web.web_server"
BIND_HOST="${BIND_HOST:-0.0.0.0}"
PORT="${PORT:-80}"
EXTRA_ARGS=${EXTRA_ARGS:-}

if [[ ! -x "$VENV_PY" ]]; then
  echo "[ERROR] Virtualenv python not found at $VENV_PY" >&2
  echo "Create it with: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi

# Quick dependency presence check
if ! "$VENV_PY" -c 'import flask' 2>/dev/null; then
  echo "[ERROR] Flask not installed in virtualenv." >&2
  echo "Install with: source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 2
fi

# Warn if not root and port < 1024
if (( PORT < 1024 )) && [[ $EUID -ne 0 ]]; then
  echo "[WARN] Port $PORT is privileged; re-run with sudo or use setcap on the venv python." >&2
  echo "       Example: sudo setcap 'cap_net_bind_service=+ep' $VENV_PY" >&2
  exit 3
fi

# Ensure logs dir permissions are writable by future non-root runs (optional)
LOG_DIR="$PROJECT_ROOT/data/transient/logs"
mkdir -p "$LOG_DIR"
chmod 775 "$LOG_DIR" || true

echo "[INFO] Starting IR web server with: $VENV_PY -m $MODULE --host $BIND_HOST --port $PORT $EXTRA_ARGS"
exec "$VENV_PY" -m "$MODULE" --host "$BIND_HOST" --port "$PORT" $EXTRA_ARGS

