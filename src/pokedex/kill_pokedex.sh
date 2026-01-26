#!/bin/bash
# Kill Pokedex processes

echo "🛑 Stopping Pokedex..."

# Kill by process name (ignore errors if no processes found)
pkill -9 -f "pokedex.py" 2>/dev/null || true
pkill -9 -f "webex_bots.pokedex" 2>/dev/null || true

# Brief pause for process cleanup
sleep 1

echo "✅ Pokedex processes terminated"

# Show remaining ollama processes
echo "📊 Current Ollama status:"
ollama ps