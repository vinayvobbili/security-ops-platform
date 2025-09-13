# Extending ZScaler Monitoring to Other Bots

## Overview
The ZScaler monitoring system is designed to be easily extended to other bots when they need resilience against ZScaler connection kills.

## Current Implementation
- **Pokedex**: Fully implemented with configurable monitoring script
- **Other bots**: Ready to be extended when ZScaler affects them

## How to Extend to Another Bot (e.g., HAL9000)

### Step 1: Copy and Configure the Monitor Script
```bash
# Copy the configurable monitor script
cp src/pokedex/zscaler_bot_monitor.sh src/hal9000/zscaler_bot_monitor.sh

# Edit the bot configuration at the top of the file:
BOT_NAME="hal9000"                    # Change this
BOT_PROCESS_NAME="hal9000.py"         # Change this  
BOT_LOG_FILE="hal9000.log"            # Change this
BOT_RESTART_SCRIPT="restart_hal9000.sh"  # Change this
BOT_DISPLAY_NAME="HAL9000"            # Change this
```

### Step 2: Copy and Configure Management Script
```bash
# Copy the management script
cp src/pokedex/manage_pokedex_zscaler.sh src/hal9000/manage_hal9000_zscaler.sh

# Update the script variables:
- Change PLIST_FILE to use "com.hal9000.zscaler.monitor"
- Change SERVICE_NAME to "com.hal9000.zscaler.monitor"  
- Update log file references from "pokedex" to "hal9000"
- Update script references from "pokedex_zscaler_monitor.sh" to "hal9000_zscaler_monitor.sh"
```

### Step 3: Create LaunchAgent plist
```bash
# Copy the plist file
cp ~/Library/LaunchAgents/com.pokedex.zscaler.monitor.plist ~/Library/LaunchAgents/com.hal9000.zscaler.monitor.plist

# Update the plist:
- Change Label to "com.hal9000.zscaler.monitor"
- Update ProgramArguments path to use hal9000 script
- Update log file paths to use "hal9000" instead of "pokedex"
```

### Step 4: Make Scripts Executable and Test
```bash
chmod +x src/hal9000/zscaler_bot_monitor.sh
chmod +x src/hal9000/manage_hal9000_zscaler.sh

# Test the management interface
./src/hal9000/manage_hal9000_zscaler.sh status
./src/hal9000/manage_hal9000_zscaler.sh start
```

## Configuration Variables in Monitor Script

The monitor script uses these configurable variables that automatically generate all paths:

```bash
# Bot Configuration - MODIFY THESE FOR OTHER BOTS
BOT_NAME="pokedex"                    # Bot identifier (pokedex, hal9000, etc.)
BOT_PROCESS_NAME="pokedex.py"         # Process name to monitor
BOT_LOG_FILE="pokedex.log"            # Log file name
BOT_RESTART_SCRIPT="restart_pokedex.sh"  # Restart script name
BOT_DISPLAY_NAME="Pokedex"            # Display name for logs

# Derived paths - these auto-adjust based on bot name
PROJECT_DIR="/Users/user@company.com/PycharmProjects/IR"
LOG_FILE="$PROJECT_DIR/logs/$BOT_LOG_FILE"
RESTART_SCRIPT="$PROJECT_DIR/src/$BOT_NAME/$BOT_RESTART_SCRIPT"
MONITOR_LOG="$PROJECT_DIR/logs/${BOT_NAME}_zscaler_monitor.log"
LOCK_FILE="/tmp/${BOT_NAME}_zscaler_monitor.lock"
RESTART_COUNT_FILE="/tmp/${BOT_NAME}_restart_count"
```

## When to Enable ZScaler Monitoring

Only enable ZScaler monitoring for bots that:
1. Experience connection drops during MacBook sleep/wake cycles
2. Are affected by ZScaler proxy terminating long-running WebSocket connections
3. Run on machines with ZScaler 4.5.x or newer

## Current Bot Status
- **Pokedex**: ZScaler monitoring active (affected by ZScaler 4.5.0.198)
- **HAL9000**: Ready to enable when needed (older ZScaler version currently)
- **Other bots**: Template ready for extension