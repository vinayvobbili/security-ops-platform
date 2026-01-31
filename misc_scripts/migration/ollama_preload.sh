#!/bin/bash
# Ollama Model Preloader
# Loads LLM model into Ollama memory at Mac startup with keep_alive=-1
# This ensures the model stays loaded even when Pokedex is not running

MODEL="${OLLAMA_LLM_MODEL:-qwen2.5:32b}"
LOG_FILE="$HOME/Library/Logs/ollama_preload.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

log "=== Ollama Preload Started ==="
log "Model: $MODEL"

# Wait for Ollama to be ready (max 60 seconds)
RETRIES=12
for i in $(seq 1 $RETRIES); do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        log "Ollama is ready"
        break
    fi
    log "Waiting for Ollama... ($i/$RETRIES)"
    sleep 5
done

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    log "ERROR: Ollama is not running. Please start Ollama first."
    exit 1
fi

# Check if model is available
if ! ollama list 2>/dev/null | grep -q "$MODEL"; then
    log "WARNING: Model $MODEL not found locally. Pulling..."
    ollama pull "$MODEL" >> "$LOG_FILE" 2>&1
fi

# Preload model with keep_alive=-1 (indefinite)
# This sends a minimal request that loads the model into memory
log "Preloading model $MODEL with keep_alive=-1..."

RESPONSE=$(curl -s -X POST http://localhost:11434/api/generate \
    -H "Content-Type: application/json" \
    -d "{
        \"model\": \"$MODEL\",
        \"prompt\": \"Hello\",
        \"stream\": false,
        \"keep_alive\": -1
    }" 2>&1)

if echo "$RESPONSE" | grep -q '"done":true'; then
    log "SUCCESS: Model $MODEL loaded and will stay in memory"
    log "Response preview: $(echo "$RESPONSE" | head -c 200)"
else
    log "ERROR: Failed to preload model"
    log "Response: $RESPONSE"
    exit 1
fi

log "=== Ollama Preload Complete ==="
