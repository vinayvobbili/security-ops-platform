#!/bin/bash
# Check the security assistant bot and Ollama Status

echo "🔍 the security assistant bot & Ollama Status Check"
echo "=" * 50

echo "📡 the security assistant bot Processes:"
ps aux | grep "pokedex\.py" | grep -v grep | while read line; do
    echo "  ✅ $line"
done

if ! ps aux | grep "pokedex\.py" | grep -v grep > /dev/null; then
    echo "  ❌ No the security assistant bot processes running"
fi

echo ""
echo "🤖 Ollama Service:"
if pgrep -x "ollama" > /dev/null; then
    echo "  ✅ Ollama service is running"
else
    echo "  ❌ Ollama service is not running"
fi

echo ""
echo "📊 Currently Loaded Models:"
ollama ps

echo ""
echo "💾 Available Models:"
ollama list

echo ""
echo "🖥️  System Resources:"
echo "  Memory Usage: $(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')" 2>/dev/null || echo "  Memory: $(vm_stat | grep 'Pages active' | awk '{print $3}' | sed 's/\.//')MB active"
echo "  CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')%" 2>/dev/null || echo "  CPU: $(top -l 1 -s 0 | grep 'CPU usage' | awk '{print $3}')" 

echo ""
echo "🚀 Quick Commands:"
echo "  Start the security assistant bot:   ./run_pokedex.sh"
echo "  Kill the security assistant bot:    ./kill_pokedex.sh"
echo "  Restart:         ./restart_pokedex.sh"
echo "  Switch model:    python switch_model.py [model]"
echo "  Benchmark:       python benchmark_startup.py"