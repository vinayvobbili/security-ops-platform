#!/bin/bash
# Simple Pokedex SOC Bot Runner Script

# Save current directory
ORIGINAL_DIR=$(pwd)

# Get project directory (3 levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Change to project directory
cd "$PROJECT_DIR" || exit 1

echo "🚀 Starting Pokedex SOC Bot..."

# Check if ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo "⚠️  Ollama not running. Starting ollama serve..."
    ollama serve &
    sleep 3
fi

# Just check if model is available, don't pre-load
echo "🔍 Checking qwen2.5:32b model availability..."
if ollama list | grep -q "qwen2.5:32b"; then
    echo "✅ Model is available"
else
    echo "❌ Model not found. Please run: ollama pull qwen2.5:32b"
    exit 1
fi

# Activate virtual environment and run bot
echo "🤖 Starting Pokedex bot..."
source .venv/bin/activate
export PYTHONPATH="$PROJECT_DIR:$PYTHONPATH"
python webex_bots/pokedex.py

# Return to original directory
cd "$ORIGINAL_DIR" || exit 1