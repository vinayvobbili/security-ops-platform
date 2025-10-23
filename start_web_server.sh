#!/bin/bash

# Disable job control messages to prevent "Killed" messages from interfering with output
set +m 2>/dev/null || true

cd /home/vinay/pub/IR || { echo "Failed to enter project directory"; exit 1; }

echo "Stopping existing web server instances..."
EXISTING_PIDS=$(pgrep -f "web_server.py" || true)
if [ -n "$EXISTING_PIDS" ]; then
  echo "Sending SIGTERM..."
  sudo pkill -f "web_server.py" >/dev/null 2>&1 || true
  # Try up to 5 times (5 seconds) for graceful stop; loop variable unused intentionally
  for _ in {1..5}; do
    if ! pgrep -f "web_server.py" >/dev/null; then
      echo "Stopped gracefully."
      break
    fi
    sleep 1
  done
  if pgrep -f "web_server.py" >/dev/null; then
    echo "Force killing..."
    for PID in $(pgrep -f "web_server.py"); do
      sudo kill -9 "$PID" 2>/dev/null || true
    done
    sleep 1
    if pgrep -f "web_server.py" >/dev/null; then
      echo "⚠️  Warning: some processes may still be running"
    else
      echo "Terminated."
    fi
  fi
else
  echo "No existing instances found."
fi

echo ""

# Fresh log
: > web_server.log

echo "Starting web server on port 80..."
# shellcheck disable=SC2024
sudo /usr/bin/nohup /usr/bin/env PYTHONPATH=/home/vinay/pub/IR /home/vinay/pub/IR/.venv/bin/python /home/vinay/pub/IR/web/web_server.py >> /home/vinay/pub/IR/web_server.log 2>&1 &

sleep 2

echo "Initial log (last 10 lines):"
echo "-----------------------------------"
if [ -s web_server.log ]; then
  tail -10 web_server.log 2>/dev/null || echo "(unable to read log)"
else
  echo "(log empty so far)"
fi
echo "-----------------------------------"

echo ""
PYTHON_PID=$(pgrep -f "python.*web_server.py" | tail -1)
if [ -n "$PYTHON_PID" ]; then
  echo "✅ Web Server running (PID: $PYTHON_PID)"
  echo "Log: tail -f /home/vinay/pub/IR/web_server.log"
else
  echo "❌ Could not detect running server process. Check logs: tail -20 /home/vinay/pub/IR/web_server.log"
fi

echo ""
