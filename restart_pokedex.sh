#!/bin/bash
# Restart Pokedex with optimizations

echo "🔄 Restarting Optimized Pokedex..."

# Kill existing processes
./kill_pokedex.sh

# Wait a moment for cleanup
sleep 3

# Start optimized version
./run_pokedex.sh