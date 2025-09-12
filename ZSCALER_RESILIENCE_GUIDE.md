# ZScaler Resilience Framework

This framework provides automatic WebSocket connection monitoring and recovery for bots affected by newer ZScaler versions (4.5.x+) that cause connection drops during Mac sleep/wake cycles.

## Current Status

- **Pokedex**: ✅ Using ZScaler resilience (affected by ZScaler 4.5.0.198)
- **HAL9000**: ⏸️ Using standard resilience (ZScaler 4.1.0.161 works fine)

## How to Enable for a Bot

When ZScaler gets upgraded on HAL's machine, simply change one setting:

### Option 1: Configuration File Update
Edit `/src/utils/zscaler_resilience.py`:
```python
"HAL9000": {
    "description": "Will need resilience when ZScaler gets upgraded",
    "needs_resilience": True  # Change from False to True
}
```

### Option 2: Code Update (Alternative)
Update HAL's main function in `/webex_bots/hal9000.py`:
```python
def main():
    """HAL9000 main - uses ZScaler resilience if needed"""
    from src.utils.zscaler_resilience import should_use_zscaler_resilience, ZScalerResilientBot
    from src.utils.bot_resilience import ResilientBot
    
    bot_name = "HAL9000"
    
    # Choose resilience framework based on ZScaler needs
    if should_use_zscaler_resilience(bot_name):
        logger.info("🛡️ Using ZScaler-aware resilience framework")
        resilient_runner = ZScalerResilientBot(...)
    else:
        logger.info("🔧 Using standard resilience framework")
        resilient_runner = ResilientBot(...)
    
    resilient_runner.run()
```

## Features

- **Automatic ZScaler Detection**: Detects ZScaler 4.5.x versions that cause issues
- **WebSocket Health Monitoring**: Checks connection health every 30 seconds
- **Smart Restart Logic**: Rate-limited restarts (max 10 per hour)
- **Zero Impact When Not Needed**: Falls back to standard resilience if ZScaler not detected

## Adding New Bots

To add any new bot to the framework:

1. Add to configuration in `zscaler_resilience.py`:
```python
"YourBotName": {
    "description": "Description of ZScaler status",
    "needs_resilience": True/False
}
```

2. Update bot's main function to check `should_use_zscaler_resilience(bot_name)`

That's it! The framework handles the rest automatically.