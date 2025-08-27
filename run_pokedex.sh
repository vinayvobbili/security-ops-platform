#!/bin/bash
# Optimized the security assistant bot SOC Bot Runner Script with performance enhancements

# Save current directory
ORIGINAL_DIR=$(pwd)

# Change to project directory
cd /Users/user/PycharmProjects/IR || exit 1

echo "🚀 Starting Optimized the security assistant bot SOC Bot..."

# Check if ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo "⚠️  Ollama not running. Starting ollama serve..."
    ollama serve &
    sleep 3
fi

# Pre-warm the model if not already loaded
echo "🔥 Pre-warming llama3.1:70b model..."
if ! ollama ps | grep -q "llama3.1:70b"; then
    echo "📥 Loading llama3.1:70b model into memory..."
    # Use a timeout to prevent hanging
    timeout 60 ollama run llama3.1:70b "ping" > /dev/null 2>&1 &
    OLLAMA_PID=$!
    
    # Wait for model to load with progress indicator
    echo -n "Loading model"
    for i in {1..30}; do
        if ollama ps | grep -q "llama3.1:70b"; then
            echo " ✅ Model loaded!"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    # Kill the ollama run process if still running
    kill $OLLAMA_PID 2>/dev/null || true
else
    echo "✅ Model already loaded in memory"
fi

# Activate virtual environment and run optimized bot
echo "🤖 Starting optimized the security assistant bot bot..."
source .venv/bin/activate
export PYTHONPATH="/Users/user/PycharmProjects/IR:$PYTHONPATH"
export POKEDEX_OPTIMIZED=1  # Flag to enable optimizations
python webex_bots/pokedex.py

# Return to original directory
cd "$ORIGINAL_DIR" || exit 1