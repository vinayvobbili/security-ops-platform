# /src/utils/bot_resilience.py
"""
Bot Resilience Framework

Provides common resilience patterns for all Webex bots:
- Automatic reconnection with exponential backoff
- Health monitoring and keepalive functionality
- Graceful shutdown handling
- Signal handlers for clean exits

Usage:
    from src.utils.bot_resilience import BotResilient
    
    def create_my_bot():
        return WebexBot(...)
    
    def initialize_my_bot():
        # Custom initialization logic
        return True
    
    # Run with resilience
    resilient_runner = BotResilient(
        bot_name="MyBot",
        bot_factory=create_my_bot,
        initialization_func=initialize_my_bot
    )
    resilient_runner.run()
"""

import time
import signal
import sys
import threading
import logging
from datetime import datetime
from typing import Callable, Optional, Any

logger = logging.getLogger(__name__)


class BotResilient:
    """
    Resilient bot runner that handles:
    - Automatic reconnection on failures
    - Health monitoring with keepalive pings
    - Graceful shutdown on signals
    - Exponential backoff retry logic
    """
    
    def __init__(self, 
                 bot_name: str,
                 bot_factory: Callable[[], Any],
                 initialization_func: Optional[Callable[..., bool]] = None,
                 max_retries: int = 5,
                 initial_retry_delay: int = 30,
                 max_retry_delay: int = 300,
                 keepalive_interval: int = 240,
                 max_keepalive_interval: int = 1800):
        """
        Initialize resilient bot runner
        
        Args:
            bot_name: Name of the bot for logging
            bot_factory: Function that creates and returns a bot instance
            initialization_func: Optional function for custom initialization
            max_retries: Maximum number of restart attempts
            initial_retry_delay: Initial delay between retries (seconds)
            max_retry_delay: Maximum delay between retries (seconds)
            keepalive_interval: Normal keepalive ping interval (seconds)
            max_keepalive_interval: Maximum keepalive ping interval (seconds)
        """
        self.bot_name = bot_name
        self.bot_factory = bot_factory
        self.initialization_func = initialization_func
        self.max_retries = max_retries
        self.initial_retry_delay = initial_retry_delay
        self.max_retry_delay = max_retry_delay
        self.keepalive_interval = keepalive_interval
        self.max_keepalive_interval = max_keepalive_interval
        
        # Runtime state
        self.bot_instance = None
        self.shutdown_requested = False
        self.keepalive_thread = None
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(sig, _):
            logger.info(f"🛑 Signal {sig} received, shutting down {self.bot_name}...")
            self.shutdown_requested = True
            self._graceful_shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _keepalive_ping(self):
        """Keep connection alive with periodic health checks"""
        wait = 60  # Start with 1 minute
        
        while not self.shutdown_requested:
            try:
                if self.bot_instance and hasattr(self.bot_instance, 'teams'):
                    self.bot_instance.teams.people.me()  # Simple health check
                    wait = self.keepalive_interval  # Reset to normal interval
                time.sleep(wait)
            except Exception as e:
                if not self.shutdown_requested:
                    logger.warning(f"Keepalive ping failed for {self.bot_name}: {e}. Retrying in {wait}s.")
                    wait = min(wait * 2, self.max_keepalive_interval)  # Exponential backoff
                    time.sleep(wait)
    
    def _graceful_shutdown(self):
        """Perform graceful shutdown cleanup with proper WebSocket handling"""
        try:
            self.shutdown_requested = True
            logger.info(f"🛑 Performing graceful shutdown of {self.bot_name}...")
            
            # Stop keepalive thread
            if self.keepalive_thread and self.keepalive_thread.is_alive():
                logger.info("Stopping keepalive monitoring...")
            
            # Properly close bot instance and WebSocket connections
            if self.bot_instance:
                logger.info("Closing WebSocket connections...")
                try:
                    # Try multiple ways to close WebSocket properly
                    if hasattr(self.bot_instance, 'stop'):
                        self.bot_instance.stop()
                    elif hasattr(self.bot_instance, 'websocket_client') and self.bot_instance.websocket_client:
                        if hasattr(self.bot_instance.websocket_client, 'close'):
                            self.bot_instance.websocket_client.close()
                        if hasattr(self.bot_instance.websocket_client, 'websocket') and self.bot_instance.websocket_client.websocket:
                            import asyncio
                            try:
                                # Close WebSocket connection properly
                                if hasattr(self.bot_instance.websocket_client.websocket, 'close'):
                                    asyncio.run(self.bot_instance.websocket_client.websocket.close())
                            except Exception as ws_error:
                                logger.warning(f"WebSocket close error: {ws_error}")
                    
                    logger.info("WebSocket connections closed")
                except Exception as close_error:
                    logger.warning(f"Error closing WebSocket: {close_error}")
                
                # Clear bot instance
                logger.info("Clearing bot instance...")
                self.bot_instance = None
            
            logger.info(f"✅ {self.bot_name} shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during graceful shutdown of {self.bot_name}: {e}")
    
    def run_with_reconnection(self):
        """Run bot with automatic reconnection on failures"""
        retry_delay = self.initial_retry_delay
        
        for attempt in range(self.max_retries):
            if self.shutdown_requested:
                break
                
            try:
                logger.info(f"🚀 Starting {self.bot_name} (attempt {attempt + 1}/{self.max_retries})")
                
                # Longer delay to ensure previous WebSocket connections are fully closed
                if attempt > 0:
                    logger.info("⏳ Waiting for previous WebSocket connections to clean up...")
                    time.sleep(10)  # Increased from 5 to 10 seconds
                
                start_time = datetime.now()
                
                # Create bot instance
                logger.info(f"🌐 Creating {self.bot_name} connection...")
                self.bot_instance = self.bot_factory()
                logger.info(f"✅ {self.bot_name} created successfully")
                
                # Run custom initialization if provided
                if self.initialization_func:
                    logger.info(f"🧠 Initializing {self.bot_name} components...")
                    # Try to pass bot instance to initialization function
                    try:
                        import inspect
                        sig = inspect.signature(self.initialization_func)
                        if len(sig.parameters) > 0:
                            # Initialization function accepts parameters
                            if not self.initialization_func(self.bot_instance):
                                logger.error(f"❌ Failed to initialize {self.bot_name}. Retrying...")
                                continue
                        else:
                            # No parameters, call without arguments
                            if not self.initialization_func():
                                logger.error(f"❌ Failed to initialize {self.bot_name}. Retrying...")
                                continue
                    except Exception as init_error:
                        logger.error(f"❌ Initialization function failed: {init_error}")
                        continue
                
                # Calculate initialization time
                init_duration = (datetime.now() - start_time).total_seconds()
                logger.info(f"🚀 {self.bot_name} is up and running (startup in {init_duration:.1f}s)...")
                print(f"🚀 {self.bot_name} is up and running (startup in {init_duration:.1f}s)...")
                
                # Start the bot (this will block and run forever)
                self.bot_instance.run()
                
                # If we reach here, the bot stopped normally
                logger.info(f"{self.bot_name} stopped normally")
                break
                
            except KeyboardInterrupt:
                logger.info(f"🛑 {self.bot_name} stopped by user (Ctrl+C)")
                break
            except Exception as e:
                logger.error(f"❌ {self.bot_name} crashed with error: {e}", exc_info=True)
                
                # Enhanced cleanup before retry
                logger.info(f"🧹 Performing cleanup after {self.bot_name} crash...")
                try:
                    self._graceful_shutdown()
                    # Additional delay after cleanup to ensure connections are fully closed
                    time.sleep(3)
                except Exception as cleanup_error:
                    logger.warning(f"Cleanup error: {cleanup_error}")
                    # Even if cleanup fails, give time for connections to timeout
                    time.sleep(5)
                
                if attempt < self.max_retries - 1:
                    logger.info(f"🔄 Restarting {self.bot_name} in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, self.max_retry_delay)  # Exponential backoff
                else:
                    logger.error(f"❌ Max retries exceeded. {self.bot_name} will not restart.")
                    raise
    
    def _kill_competing_processes(self):
        """Find and kill any competing instances of this bot"""
        try:
            import subprocess
            import os
            import signal
            
            # Get current process info
            current_pid = os.getpid()
            bot_script = f"{self.bot_name.lower()}.py"
            
            # Check for other Python processes running the same bot script
            result = subprocess.run(
                ["ps", "aux"], 
                capture_output=True, 
                text=True
            )
            
            competing_processes = []
            for line in result.stdout.split('\n'):
                if f"python" in line and bot_script in line:
                    # Extract PID (usually the second column)
                    parts = line.split()
                    if len(parts) > 1:
                        try:
                            pid = int(parts[1])
                            if pid != current_pid:
                                competing_processes.append(pid)
                        except ValueError:
                            continue
            
            # Kill competing processes
            if competing_processes:
                logger.info(f"🔫 Found {len(competing_processes)} competing {self.bot_name} process(es). Terminating...")
                for pid in competing_processes:
                    try:
                        logger.info(f"Killing process {pid}...")
                        os.kill(pid, signal.SIGTERM)
                        time.sleep(1)  # Give process time to exit gracefully
                        
                        # Check if process is still running, force kill if needed
                        try:
                            os.kill(pid, 0)  # Check if process exists
                            logger.warning(f"Process {pid} still running, force killing...")
                            os.kill(pid, signal.SIGKILL)
                        except OSError:
                            # Process no longer exists, good
                            pass
                            
                        logger.info(f"✅ Successfully terminated process {pid}")
                    except OSError as e:
                        logger.warning(f"Could not kill process {pid}: {e}")
                
                # Wait a moment for WebSocket cleanup
                logger.info("⏳ Waiting 3s for WebSocket cleanup...")
                time.sleep(3)
            else:
                logger.info(f"✅ No competing {self.bot_name} processes detected")
            
            return len(competing_processes)
            
        except Exception as e:
            logger.warning(f"Could not check/kill competing processes: {e}")
            return 0

    def run(self):
        """
        Main entry point - starts bot with full resilience features
        """
        try:
            # Kill any competing processes automatically
            killed_count = self._kill_competing_processes()
            if killed_count > 0:
                logger.info(f"🧹 Cleaned up {killed_count} competing process(es). Starting {self.bot_name}...")
            
            # Start keepalive monitoring thread
            self.keepalive_thread = threading.Thread(target=self._keepalive_ping, daemon=True)
            self.keepalive_thread.start()
            logger.info(f"💓 Keepalive monitoring started for {self.bot_name}")
            
            # Run bot with reconnection logic
            self.run_with_reconnection()
            
        except Exception as e:
            logger.error(f"Fatal error in {self.bot_name}: {e}", exc_info=True)
            self._graceful_shutdown()
            sys.exit(1)


def create_resilient_main(bot_name: str, 
                         bot_factory: Callable[[], Any],
                         initialization_func: Optional[Callable[[], bool]] = None):
    """
    Convenience function to create a resilient main() function
    
    Usage:
        def create_my_bot():
            return WebexBot(...)
        
        def initialize_my_bot():
            return True
        
        main = create_resilient_main("MyBot", create_my_bot, initialize_my_bot)
        
        if __name__ == "__main__":
            main()
    """
    def main():
        resilient_runner = BotResilient(
            bot_name=bot_name,
            bot_factory=bot_factory, 
            initialization_func=initialization_func
        )
        resilient_runner.run()
    
    return main