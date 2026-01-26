#!/bin/bash
# Restart the security assistant bot with optimizations

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🔄 Restarting Optimized the security assistant bot..."

# Kill existing processes
"$SCRIPT_DIR/kill_pokedex.sh"

# Wait a moment for cleanup
sleep 3

# Start optimized version
"$SCRIPT_DIR/run_pokedex.sh"