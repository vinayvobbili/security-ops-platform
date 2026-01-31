#!/bin/bash
# the security assistant bot SOC Bot - Standalone Launcher
# Run this script directly instead of through PyCharm for better resource management

# Get project root (parent of scripts directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Kill any existing instances
pkill -f "webex_bots.pokedex" 2>/dev/null && echo "Stopped existing the security assistant bot instance(s)" && sleep 1

cd "$PROJECT_ROOT" || exit 1
source .venv/bin/activate
exec python -m webex_bots.pokedex