# /src/utils/simple_bot_resilience.py
"""
Simplified Bot Resilience Framework

Provides essential resilience patterns without over-engineering:
- Basic automatic reconnection (3 attempts max)
- Graceful shutdown on signals
- Simple factory pattern for bot creation

Removed complex features:
- Process competition detection/killing
- Exponential backoff keepalive pings
- Complex retry logic and timing
- Excessive logging and monitoring

Usage:
    from src.utils.simple_bot_resilience import SimpleBotRunner
    
    def create_my_bot():
        return WebexBot(...)
    
    def initialize_my_bot(bot_instance):
        # Add commands to bot_instance
        return True
    
    runner = SimpleBotRunner(
        bot_name="MyBot",
        bot_factory=create_my_bot,
        initialization_func=initialize_my_bot
    )
    runner.run()
"""

import signal
import sys
import logging
from typing import Callable, Optional, Any

logger = logging.getLogger(__name__)


class SimpleBotRunner:
    """
    Simplified resilient bot runner with essential features only:
    - Basic reconnection on failures (max 3 attempts)
    - Graceful shutdown on signals
    - Clean factory pattern
    """
    
    def __init__(self, 
                 bot_name: str,
                 bot_factory: Callable[[], Any],
                 initialization_func: Optional[Callable[[Any], bool]] = None):
        """
        Initialize simple bot runner
        
        Args:
            bot_name: Name of the bot for logging
            bot_factory: Function that creates and returns a bot instance
            initialization_func: Optional function for custom initialization
        """
        self.bot_name = bot_name
        self.bot_factory = bot_factory
        self.initialization_func = initialization_func
        self.bot_instance = None
        self.shutdown_requested = False
        
        # Setup signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, sig, _):
        """Handle shutdown signals gracefully"""
        logger.info(f"🛑 Signal {sig} received, shutting down {self.bot_name}...")
        self.shutdown_requested = True
        self._cleanup()
        sys.exit(0)
    
    def _cleanup(self):
        """Simple cleanup of bot instance"""
        if self.bot_instance:
            logger.info(f"🧹 Cleaning up {self.bot_name}...")
            try:
                # Try to stop the bot cleanly if it has a stop method
                if hasattr(self.bot_instance, 'stop'):
                    self.bot_instance.stop()
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")
            finally:
                self.bot_instance = None
    
    def run(self):
        """
        Main entry point - runs bot with basic resilience (max 3 attempts)
        """
        max_attempts = 3
        
        for attempt in range(max_attempts):
            if self.shutdown_requested:
                break
                
            try:
                logger.info(f"🚀 Starting {self.bot_name} (attempt {attempt + 1}/{max_attempts})")
                
                # Create bot instance
                self.bot_instance = self.bot_factory()
                logger.info(f"✅ {self.bot_name} created successfully")
                
                # Run custom initialization if provided
                if self.initialization_func:
                    if not self.initialization_func(self.bot_instance):
                        logger.error(f"❌ Failed to initialize {self.bot_name}. Retrying...")
                        continue
                
                logger.info(f"🚀 {self.bot_name} is running...")
                
                # Start the bot (this blocks until bot stops)
                self.bot_instance.run()
                
                # If we reach here, bot stopped normally
                logger.info(f"{self.bot_name} stopped normally")
                break
                
            except KeyboardInterrupt:
                logger.info(f"🛑 {self.bot_name} stopped by user")
                break
                
            except Exception as e:
                logger.error(f"❌ {self.bot_name} error: {e}")
                self._cleanup()
                
                if attempt < max_attempts - 1:
                    logger.info(f"🔄 Retrying {self.bot_name} in 10 seconds...")
                    import time
                    time.sleep(10)
                else:
                    logger.error(f"❌ Max attempts reached. {self.bot_name} will not restart.")
                    raise
        
        # Final cleanup
        self._cleanup()


def create_simple_main(bot_name: str, 
                      bot_factory: Callable[[], Any],
                      initialization_func: Optional[Callable[[Any], bool]] = None):
    """
    Convenience function to create a simple main() function
    
    Usage:
        def create_my_bot():
            return WebexBot(...)
        
        def initialize_my_bot(bot_instance):
            bot_instance.add_command(...)
            return True
        
        main = create_simple_main("MyBot", create_my_bot, initialize_my_bot)
        
        if __name__ == "__main__":
            main()
    """
    def main():
        runner = SimpleBotRunner(
            bot_name=bot_name,
            bot_factory=bot_factory,
            initialization_func=initialization_func
        )
        runner.run()
    
    return main