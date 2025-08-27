#!/bin/bash
# Restart the security assistant bot with optimizations

echo "🔄 Restarting Optimized the security assistant bot..."

# Kill existing processes
./kill_pokedex.sh

# Wait a moment for cleanup
sleep 3

# Start optimized version
./run_pokedex.sh