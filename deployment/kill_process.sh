#!/bin/bash

# Utility function to gracefully kill a process with fallback to force kill
# Usage: kill_process_gracefully "process_pattern" "Process Name"
# Example: kill_process_gracefully "webex_bots/tars" "TARS"

kill_process_gracefully() {
    local process_pattern="$1"
    local process_name="${2:-Process}"

    if ! pgrep -f "$process_pattern" > /dev/null; then
        echo "No existing $process_name instances found"
        return 0
    fi

    # Try graceful shutdown first
    pkill -f "$process_pattern"

    # Wait up to 5 seconds for graceful shutdown
    for i in {1..5}; do
        if ! pgrep -f "$process_pattern" > /dev/null; then
            echo "✅ $process_name stopped gracefully"
            return 0
        fi
        sleep 1
    done

    # If still running, force kill
    if pgrep -f "$process_pattern" > /dev/null; then
        echo "⚠️  Graceful shutdown failed, force killing..."
        pkill -9 -f "$process_pattern"
        sleep 1

        if pgrep -f "$process_pattern" > /dev/null; then
            echo "❌ Error: Could not stop $process_name process"
            return 1
        fi
        echo "✅ $process_name force stopped"
    fi

    return 0
}

# If script is executed directly (not sourced), run the function with arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    kill_process_gracefully "$@"
fi
