#!/bin/bash
# Simple the security assistant bot SOC Bot Runner Script

# Save current directory
ORIGINAL_DIR=$(pwd)

# Change to project directory
cd /Users/<redacted-email>/PycharmProjects/IR || exit 1

echo "🚀 Starting the security assistant bot SOC Bot..."

# Check if ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo "⚠️  Ollama not running. Starting ollama serve..."
    ollama serve &
    sleep 3
fi

# Just check if model is available, don't pre-load
echo "🔍 Checking llama3.1:70b model availability..."
if ollama list | grep -q "llama3.1:70b"; then
    echo "✅ Model is available"
else
    echo "❌ Model not found. Please run: ollama pull llama3.1:70b"
    exit 1
fi

# Activate virtual environment and run bot
echo "🤖 Starting the security assistant bot bot..."
source .venv/bin/activate
export PYTHONPATH="/Users/<redacted-email>/PycharmProjects/IR:$PYTHONPATH"
python webex_bots/pokedex.py

# Return to original directory
cd "$ORIGINAL_DIR" || exit 1