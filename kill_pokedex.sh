#!/bin/bash
# Emergency Pokedex Bot Killer Script

echo "🔥 Force killing Pokedex bot..."

# Kill by process name
pkill -f "python.*pokedex.py" && echo "✅ Pokedex process killed" || echo "⚠️ No Pokedex process found"

# Also kill any hanging Python processes related to the bot
pkill -f "webex_bots/pokedex.py" && echo "✅ Additional processes killed"

echo "🧹 Cleanup complete"