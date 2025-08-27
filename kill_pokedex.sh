#!/bin/bash
# Emergency the security assistant bot Bot Killer Script

echo "🔥 Force killing the security assistant bot bot..."

# Kill by process name
pkill -f "python.*pokedex.py" && echo "✅ the security assistant bot process killed" || echo "⚠️ No the security assistant bot process found"

# Also kill any hanging Python processes related to the bot
pkill -f "webex_bots/pokedex.py" && echo "✅ Additional processes killed"

echo "🧹 Cleanup complete"