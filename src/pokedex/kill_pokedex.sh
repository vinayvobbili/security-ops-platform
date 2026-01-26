#!/bin/bash
# Kill the security assistant bot processes

echo "🛑 Stopping the security assistant bot..."

# Kill by process name (ignore errors if no processes found)
pkill -9 -f "pokedex.py" 2>/dev/null || true
pkill -9 -f "webex_bots.pokedex" 2>/dev/null || true

# Brief pause for process cleanup
sleep 1

echo "✅ the security assistant bot processes terminated"

# Show remaining ollama processes
echo "📊 Current Ollama status:"
ollama ps