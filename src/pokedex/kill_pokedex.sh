#!/bin/bash
# Kill the security assistant bot processes

echo "🛑 Stopping the security assistant bot..."

# Kill by process name
pkill -f "pokedex.py"

# Kill by keyword search for more thorough cleanup
ps aux | grep -i pokedex | grep -v grep | awk '{print $2}' | xargs -r kill -9

# Also kill any lingering python processes running webex bot
ps aux | grep -E "(webex_bots|pokedex)" | grep -v grep | awk '{print $2}' | xargs -r kill -9

echo "✅ the security assistant bot processes terminated"

# Show remaining ollama processes
echo "📊 Current Ollama status:"
ollama ps