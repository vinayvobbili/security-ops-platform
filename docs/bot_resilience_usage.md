# Bot Resilience Framework Usage

This document shows how to convert existing bots to use the common resilience framework.

## Framework Features

The `src.utils.bot_resilience.BotResilient` class provides:

- ✅ **Automatic reconnection** with exponential backoff (30s → 60s → 120s → 240s → 300s)  
- ✅ **Health monitoring** with keepalive pings every 4 minutes
- ✅ **Graceful shutdown** on SIGINT/SIGTERM signals
- ✅ **Clean error handling** with detailed logging
- ✅ **Configurable retry limits** and timing

## Migration Pattern

### Before (Manual Resilience)
```python
def main():
    # Complex manual resilience logic
    max_retries = 5
    retry_delay = 30
    
    for attempt in range(max_retries):
        try:
            # Bot creation and initialization
            bot = create_bot()
            initialize_components() 
            bot.run()
        except Exception as e:
            # Manual retry logic...
```

### After (Common Framework)
```python
def bot_factory():
    """Factory function to create bot instance"""
    return create_bot()

def initialization():
    """Custom initialization logic"""
    return initialize_components()

def main():
    """Main entry point using resilience framework"""
    from src.utils.bot_resilience import BotResilient
    
    resilient_runner = BotResilient(
        bot_name="MyBot",
        bot_factory=bot_factory,
        initialization_func=initialization
    )
    resilient_runner.run()
```

## Example: Converting Toodles Bot

```python
# toodles.py - After conversion

def toodles_bot_factory():
    """Create Toodles bot instance"""
    return WebexBot(
        CONFIG.webex_bot_access_token_toodles,
        bot_name="🛠🤖 Toodles! 👋",
        approved_rooms=[...],
        log_level="ERROR",
        threads=True
    )

def toodles_initialization():
    """Initialize Toodles commands"""
    global bot_instance
    if bot_instance:
        # Add all commands
        bot_instance.add_command(GetApprovedTestingCard())
        bot_instance.add_command(Who())
        bot_instance.add_command(ContainmentStatusCS())
        # ... add all other commands
    return True

def main():
    """Toodles main with resilience"""
    from src.utils.bot_resilience import BotResilient
    
    resilient_runner = BotResilient(
        bot_name="Toodles",
        bot_factory=toodles_bot_factory,
        initialization_func=toodles_initialization,
        max_retries=5,
        initial_retry_delay=30,
        max_retry_delay=300
    )
    resilient_runner.run()

if __name__ == "__main__":
    main()
```

## Example: Converting Jarvais Bot

```python
# jarvais.py - After conversion

def jarvais_bot_factory():
    """Create Jarvais bot instance"""  
    return WebexBot(
        CONFIG.webex_bot_access_token_jarvais,
        bot_name="🤖 Jarvais",
        approved_rooms=[...],
    )

def jarvais_initialization():
    """Initialize Jarvais components"""
    # Custom Jarvais initialization
    return initialize_jarvais_components()

def main():
    """Jarvais main with resilience"""  
    from src.utils.bot_resilience import BotResilient
    
    resilient_runner = BotResilient(
        bot_name="Jarvais", 
        bot_factory=jarvais_bot_factory,
        initialization_func=jarvais_initialization
    )
    resilient_runner.run()
```

## Configuration Options

```python
BotResilient(
    bot_name="MyBot",                    # Bot name for logging
    bot_factory=create_bot,              # Function that returns bot instance
    initialization_func=init_bot,        # Optional initialization function
    max_retries=5,                       # Max restart attempts (default: 5)
    initial_retry_delay=30,              # Initial delay in seconds (default: 30)
    max_retry_delay=300,                 # Max delay in seconds (default: 300)
    keepalive_interval=240,              # Normal keepalive interval (default: 240s)
    max_keepalive_interval=1800          # Max keepalive interval (default: 1800s)
)
```

## Migration Benefits

1. **Consistency** - All bots use the same resilience patterns
2. **Maintainability** - One place to update resilience logic  
3. **Reduced Code** - Eliminates duplicate resilience code from each bot
4. **Testing** - Common framework can be tested once
5. **Features** - All bots get the same robust error handling

## Implementation Steps

1. **Create factory function** - Returns bot instance
2. **Create initialization function** - Handles custom setup (optional)  
3. **Replace main()** - Use BotResilient instead of manual logic
4. **Remove old resilience code** - Delete manual retry/keepalive logic
5. **Test** - Verify bot starts and recovers from failures

## Next Steps

Apply this pattern to all existing bots:
- [x] Pokedex ✅
- [x] Toodles ✅
- [x] Jarvais ✅
- [x] Barnacles ✅
- [x] HAL9000 ✅
- [x] MoneyBall ✅

This will provide enterprise-grade resilience across all bots with minimal code changes.