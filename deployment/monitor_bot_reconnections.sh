#!/bin/bash
# Monitor the notification service bot reconnections and health

echo "📊 the notification service Bot Reconnection Monitor"
echo "===================================="
echo ""

# Check if bot is running
if ssh lab-lab "pgrep -f 'python.*webex_bots/toodles.py'" > /dev/null; then
    PID=$(ssh lab-lab "pgrep -f 'python.*webex_bots/toodles.py'")
    UPTIME=$(ssh lab-lab "ps -p $PID -o etime=" | tr -d ' ')
    echo "✅ Bot Status: RUNNING"
    echo "   PID: $PID"
    echo "   Uptime: $UPTIME"
else
    echo "❌ Bot Status: NOT RUNNING"
    exit 1
fi

echo ""
echo "📈 Recent Activity (last 20 lines):"
echo "------------------------------------"
ssh lab-lab "tail -20 ~/pub/IR/logs/toodles.log" | grep -v "WARNING.*deprecated"

echo ""
echo "🔄 Reconnection Events (last 10):"
echo "----------------------------------"
ssh lab-lab "grep -E '(Triggering.*reconnection|Bot instance cleared|Bot thread|Reconnection requested|up and running)' ~/pub/IR/logs/toodles.log | tail -15"

echo ""
echo "⚠️  Connection Errors (last 5):"
echo "--------------------------------"
ssh lab-lab "grep -E '(Connection.*error|timed out|Connection aborted|Remote.*closed)' ~/pub/IR/logs/toodles.log | tail -5"

echo ""
echo "✅ Expected behavior with fix:"
echo "   1. 'Triggering reconnection' message appears"
echo "   2. 'Bot instance cleared' message appears"
echo "   3. 'up and running' message appears within 30s"
echo "   4. No long gaps (>1 min) between steps 1-3"
echo ""
echo "❌ Old broken behavior:"
echo "   1. 'Triggering reconnection' appears"
echo "   2. 'Bot instance cleared' appears"
echo "   3. Long silence (hours) - bot stuck, no restart"
