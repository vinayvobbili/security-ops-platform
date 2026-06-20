#!/bin/bash
# Kill ALL bot instances (use before restart to clean up multiple instances)

BOTS=("aide" "relay" "oracle" "orchestrator")

echo "🛑 Killing ALL bot instances..."
echo "=================================================="
echo ""

for bot in "${BOTS[@]}"; do
    echo "🛑 Killing all $bot instances..."

    # Count instances before killing
    count=$(pgrep -f "python.*webex_bots/${bot}.py" | wc -l)
    if [ "$count" -gt 0 ]; then
        echo "   Found $count instance(s)"

        # Try graceful shutdown first
        pkill -f "python.*webex_bots/${bot}.py" 2>/dev/null
        sleep 2

        # Force kill any remaining
        if pgrep -f "python.*webex_bots/${bot}.py" > /dev/null; then
            echo "   Force killing remaining instances..."
            pkill -9 -f "python.*webex_bots/${bot}.py" 2>/dev/null
            sleep 1
        fi

        # Verify all dead
        remaining=$(pgrep -f "python.*webex_bots/${bot}.py" | wc -l)
        if [ "$remaining" -eq 0 ]; then
            echo "   ✅ All $bot instances killed"
        else
            echo "   ⚠️  Warning: $remaining instance(s) still running"
        fi
    else
        echo "   No instances running"
    fi
    echo ""
done

echo "=================================================="
echo "✅ All bots killed"
echo ""
echo "📊 Verify no bots running:"
echo "   pgrep -f 'python.*webex_bots' | wc -l"
echo ""
echo "🔄 Now restart with:"
echo "   ./restart_all_bots"
