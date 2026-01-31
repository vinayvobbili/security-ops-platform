#!/bin/bash
# Simple the security assistant bot SOC Bot Runner Script

# Save current directory
ORIGINAL_DIR=$(pwd)

# Get project directory (3 levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Change to project directory
cd "$PROJECT_DIR" || exit 1

echo "🚀 Starting the security assistant bot SOC Bot..."

# Check if ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo "⚠️  Ollama not running. Starting ollama serve..."
    ollama serve &
    sleep 3
fi

# Load environment variables from .env if it exists
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Get model from environment, default to glm-4.7-flash
MODEL="${OLLAMA_LLM_MODEL:-glm-4.7-flash}"

# Just check if model is available, don't pre-load
echo "🔍 Checking $MODEL model availability..."
if ollama list | grep -q "$MODEL"; then
    echo "✅ Model is available"
else
    echo "❌ Model not found. Please run: ollama pull $MODEL"
    exit 1
fi

# Activate virtual environment and run bot
echo "🤖 Starting the security assistant bot bot..."
source .venv/bin/activate
export PYTHONPATH="$PROJECT_DIR:$PYTHONPATH"
python webex_bots/pokedex.py

# Return to original directory
cd "$ORIGINAL_DIR" || exit 1