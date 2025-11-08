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

import logging
import signal
import sys
import threading
import time
from datetime import datetime
from typing import Callable, Optional, Any

# Import connection-related exceptions
try:
    from requests.exceptions import ConnectionError as RequestsConnectionError
    from urllib3.exceptions import ProtocolError
except ImportError:
    RequestsConnectionError = ConnectionError
    ProtocolError = ConnectionError

# Import WebSocket configuration from enhanced_websocket_client
try:
    from src.utils.enhanced_websocket_client import WEBSOCKET_PING_INTERVAL, WEBSOCKET_PING_TIMEOUT
except ImportError:
    # Fallback values if import fails
    WEBSOCKET_PING_INTERVAL = 60
    WEBSOCKET_PING_TIMEOUT = 30

logger = logging.getLogger(__name__)


class ResilientBot:
    """
    Resilient bot runner that handles:
    - Automatic reconnection on failures
    - Health monitoring with keepalive pings
    - Graceful shutdown on signals
    - Exponential backoff retry logic
    """

    def __init__(self,
                 bot_factory: Callable[[], Any],
                 initialization_func: Optional[Callable[..., bool]] = None,
                 bot_name: Optional[str] = None,
                 max_retries: int = 5,
                 initial_retry_delay: int = 30,
                 max_retry_delay: int = 300,
                 keepalive_interval: int = 120,
                 max_keepalive_interval: int = 600,
                 max_keepalive_failures: int = 5):
        """
        Initialize resilient bot runner

        Args:
            bot_factory: Function that creates and returns a bot instance
            initialization_func: Optional function for custom initialization
            bot_name: Optional bot name (will be extracted from bot instance if not provided)
            max_retries: Maximum number of restart attempts
            initial_retry_delay: Initial delay between retries (seconds)
            max_retry_delay: Maximum delay between retries (seconds)
            keepalive_interval: Keepalive ping interval (seconds)
            max_keepalive_interval: Maximum keepalive ping interval (seconds)
            max_keepalive_failures: Max consecutive keepalive failures before reconnection
        """
        # Suppress noisy websocket logs for all bots
        # These INFO-level logs create excessive noise without adding value
        logging.getLogger('webex_bot.websockets.webex_websocket_client').setLevel(logging.WARNING)
        logging.getLogger('webex_bot.webex_bot').setLevel(logging.WARNING)
        logging.getLogger('webexpythonsdk').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.ERROR)
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)

        # Apply SDK timeout patch for all bots using this resilience framework
        # The WebSocket client makes HTTP calls to register/refresh devices, and the default 60s timeout
        # is too short for unreliable networks, causing "Read timed out" errors
        try:
            import webexpythonsdk.config
            webexpythonsdk.config.DEFAULT_SINGLE_REQUEST_TIMEOUT = 180
            logger.info("⏱️  Increased SDK HTTP timeout from 60s to 180s for device registration")
        except Exception as timeout_patch_error:
            logger.warning(f"⚠️  Could not patch SDK timeout: {timeout_patch_error}")

        # Apply WebSocket keepalive patch to prevent idle connection timeouts
        # Network middleboxes (firewalls, proxies, NAT) drop idle TCP connections
        # This patch configures aggressive ping/pong to keep connections alive
        try:
            import websockets

            # Store the original connect function
            original_connect = websockets.connect

            # Create a wrapper that adds keepalive parameters
            def connect_with_keepalive(*args, **kwargs):
                # Set aggressive ping interval (15 seconds) to keep connection alive
                # Default is 20 seconds which may not be frequent enough
                kwargs.setdefault('ping_interval', 15)
                kwargs.setdefault('ping_timeout', 10)
                return original_connect(*args, **kwargs)

            # Replace the connect function globally
            websockets.connect = connect_with_keepalive
            logger.info("🔧 Patched WebSocket to use 15s ping interval to prevent idle timeout")
        except Exception as websocket_patch_error:
            logger.warning(f"⚠️  Could not patch WebSocket keepalive: {websocket_patch_error}")

        self.bot_name = bot_name  # Will be set after bot creation if not provided
        self.bot_factory = bot_factory
        self.initialization_func = initialization_func
        self.max_retries = max_retries
        self.initial_retry_delay = initial_retry_delay
        self.max_retry_delay = max_retry_delay
        self.keepalive_interval = keepalive_interval
        self.max_keepalive_interval = max_keepalive_interval
        self.max_keepalive_failures = max_keepalive_failures

        # Runtime state
        self.bot_instance = None
        self.shutdown_requested = False
        self.keepalive_thread = None
        self.last_successful_ping = datetime.now()
        self.consecutive_failures = 0
        self._bot_start_time = None
        self._bot_running = False  # Track if bot is currently running

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

    def _log_connection_issue(self, reason):
        """Log a connection issue without triggering reconnection"""
        logger.warning(f"⚠️ Connection issue detected for {self.bot_name}: {reason}")
        logger.info(f"🔄 Bot will continue running - monitoring active")

    def _trigger_reconnection(self, reason):
        """Trigger bot reconnection by stopping the current instance"""
        logger.warning(f"🔄 Triggering reconnection for {self.bot_name}: {reason}")
        try:
            if self.bot_instance:
                # Try to stop the bot gracefully
                if hasattr(self.bot_instance, 'websocket_client') and self.bot_instance.websocket_client:
                    ws_client = self.bot_instance.websocket_client
                    if hasattr(ws_client, 'websocket') and ws_client.websocket:
                        try:
                            import asyncio
                            loop = asyncio.get_event_loop()
                            if hasattr(ws_client.websocket, 'close'):
                                loop.run_until_complete(ws_client.websocket.close())
                        except Exception as e:
                            logger.debug(f"Error closing WebSocket for reconnection: {e}")
        except Exception as e:
            logger.warning(f"Error triggering reconnection: {e}")

    def _run_bot_with_monitoring(self):
        """Run the bot - simplified to just run without reconnection monitoring"""
        import asyncio

        try:
            # Create event loop for this thread (Python 3.13+ requirement)
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                logger.debug(f"Created new event loop for bot thread")
            except Exception as loop_error:
                logger.warning(f"Could not create event loop for bot thread: {loop_error}")

            # Run the bot (this blocks until bot stops)
            self.bot_instance.run()

        except KeyboardInterrupt:
            logger.info(f"🛑 Keyboard interrupt received for {self.bot_name}")
            raise
        except Exception as e:
            logger.error(f"Error running {self.bot_name}: {e}")
            raise
        finally:
            # Clean up event loop
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_closed():
                    loop.close()
            except Exception:
                pass

    def _keepalive_ping(self):
        """Keep connection alive with periodic health checks"""
        wait = 60  # Start with 1 minute
        while not self.shutdown_requested:
            try:
                if self.bot_instance and hasattr(self.bot_instance, 'teams'):
                    # Simple API call to test connection health
                    ping_start = time.time()
                    self.bot_instance.teams.people.me()
                    ping_duration = time.time() - ping_start

                    self.last_successful_ping = datetime.now()
                    self.consecutive_failures = 0
                    wait = self.keepalive_interval  # Reset to normal interval
                    logger.debug(f"Keepalive ping successful for {self.bot_name} ({ping_duration:.2f}s)")

                time.sleep(wait)
            except (ConnectionResetError, ConnectionAbortedError, OSError, RequestsConnectionError, ProtocolError) as conn_error:
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    logger.warning(f"Keepalive ping failed for {self.bot_name} with connection error (failure #{self.consecutive_failures}/{self.max_keepalive_failures}): {conn_error}")

                    # Check if we've exceeded max failures - trigger reconnection
                    if self.consecutive_failures >= self.max_keepalive_failures:
                        logger.error(f"❌ Max keepalive failures ({self.max_keepalive_failures}) reached. Triggering reconnection...")
                        self._trigger_reconnection(f"Max keepalive failures: {type(conn_error).__name__}")
                        break  # Exit keepalive thread - will restart with new bot instance

                    self._log_connection_issue(f"Connection error: {type(conn_error).__name__}")
                    wait = min(wait * 2, self.max_keepalive_interval)
                    time.sleep(wait)
            except Exception as e:
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    logger.warning(f"Keepalive ping failed for {self.bot_name} (failure #{self.consecutive_failures}/{self.max_keepalive_failures}): {e}")

                    # Check if we've exceeded max failures - trigger reconnection
                    if self.consecutive_failures >= self.max_keepalive_failures:
                        logger.error(f"❌ Max keepalive failures ({self.max_keepalive_failures}) reached. Triggering reconnection...")
                        self._trigger_reconnection("Max keepalive failures")
                        break  # Exit keepalive thread - will restart with new bot instance

                    self._log_connection_issue("Connection issue detected")
                    wait = min(wait * 2, self.max_keepalive_interval)  # Exponential backoff
                    time.sleep(wait)

    def _graceful_shutdown(self):
        """Perform graceful shutdown cleanup with proper WebSocket handling"""
        try:
            self.shutdown_requested = True
            logger.debug(f"🛑 Performing graceful shutdown of {self.bot_name}...")

            # Stop monitoring threads
            if self.keepalive_thread and self.keepalive_thread.is_alive():
                logger.debug("Stopping keepalive monitoring...")

            # Properly close bot instance and WebSocket connections
            if self.bot_instance:
                logger.debug("Closing WebSocket connections...")
                try:
                    # Enhanced WebSocket cleanup with asyncio event loop handling
                    if hasattr(self.bot_instance, 'websocket_client') and self.bot_instance.websocket_client:
                        ws_client = self.bot_instance.websocket_client

                        # Close the WebSocket connection
                        if hasattr(ws_client, 'websocket') and ws_client.websocket:
                            import asyncio
                            try:
                                # Get or create event loop for cleanup
                                try:
                                    loop = asyncio.get_event_loop()
                                    if loop.is_closed():
                                        raise RuntimeError("Event loop is closed")
                                except RuntimeError:
                                    # Create new event loop if needed
                                    loop = asyncio.new_event_loop()
                                    asyncio.set_event_loop(loop)
                                    logger.debug("Created new event loop for WebSocket cleanup")

                                # Close WebSocket with timeout
                                if hasattr(ws_client.websocket, 'close'):
                                    try:
                                        close_task = ws_client.websocket.close()
                                        loop.run_until_complete(asyncio.wait_for(close_task, timeout=5.0))
                                        logger.debug("WebSocket closed gracefully")
                                    except asyncio.TimeoutError:
                                        logger.warning("WebSocket close timed out, forcing closure")
                                    except Exception as ws_close_error:
                                        logger.warning(f"WebSocket close error: {ws_close_error}")

                                # Give time for cleanup
                                import time
                                time.sleep(0.5)

                            except Exception as ws_error:
                                logger.warning(f"WebSocket cleanup error: {ws_error}")

                        # Try additional cleanup methods
                        if hasattr(ws_client, 'close'):
                            try:
                                ws_client.close()
                            except Exception as e:
                                logger.debug(f"WebSocket client close method error: {e}")

                    # Try bot-level stop method
                    if hasattr(self.bot_instance, 'stop'):
                        try:
                            self.bot_instance.stop()
                        except Exception as e:
                            logger.debug(f"Bot stop method error: {e}")

                    logger.debug("WebSocket connections closed")
                except Exception as close_error:
                    logger.warning(f"Error closing WebSocket: {close_error}")

                # Clear bot instance
                logger.debug("Clearing bot instance...")
                self.bot_instance = None

            logger.debug(f"✅ {self.bot_name} shutdown complete")

        except Exception as e:
            logger.error(f"Error during graceful shutdown of {self.bot_name}: {e}")

    def run_with_reconnection(self):
        """Run bot once - keep alive with health monitoring (no automatic reconnection)"""

        # Allow a few retries ONLY for initial startup failures
        # Once the bot is running, health monitoring keeps it alive
        max_startup_retries = 3
        retry_delay = 10

        for attempt in range(max_startup_retries):
            if self.shutdown_requested:
                break

            try:
                logger.info(f"🚀 Starting {self.bot_name} (attempt {attempt + 1}/{max_startup_retries})")

                # Small delay on retry for startup failures
                if attempt > 0:
                    logger.debug(f"⏳ Waiting {retry_delay}s before retry...")
                    time.sleep(retry_delay)

                start_time = datetime.now()

                # Create bot instance
                logger.info(f"🌐 Creating bot connection...")
                self.bot_instance = self.bot_factory()

                # Extract bot name from instance if not provided
                if not self.bot_name:
                    if hasattr(self.bot_instance, 'bot_name'):
                        self.bot_name = self.bot_instance.bot_name
                    elif hasattr(self.bot_instance, 'name'):
                        self.bot_name = self.bot_instance.name
                    else:
                        self.bot_name = "UnknownBot"

                logger.info(f"✅ {self.bot_name} created successfully")

                # Run custom initialization if provided
                if self.initialization_func:
                    logger.debug(f"🧠 Initializing {self.bot_name} components...")
                    try:
                        import inspect
                        sig = inspect.signature(self.initialization_func)
                        if len(sig.parameters) > 0:
                            if not self.initialization_func(self.bot_instance):
                                logger.error(f"❌ Failed to initialize {self.bot_name}. Retrying...")
                                continue
                        else:
                            if not self.initialization_func():
                                logger.error(f"❌ Failed to initialize {self.bot_name}. Retrying...")
                                continue
                    except Exception as init_error:
                        logger.error(f"❌ Initialization function failed: {init_error}")
                        if attempt < max_startup_retries - 1:
                            continue
                        else:
                            raise

                # Calculate initialization time
                init_duration = (datetime.now() - start_time).total_seconds()
                logger.info(f"🚀 {self.bot_name} is up and running (startup in {init_duration:.1f}s)...")
                print(f"🚀 {self.bot_name} is up and running (startup in {init_duration:.1f}s)...", flush=True)

                # Record bot start time for monitoring
                self._bot_start_time = datetime.now()
                self._bot_running = True

                # Start the bot (this will block until failure or shutdown)
                logger.debug(f"🌐 Starting {self.bot_name} main loop...")
                logger.info(f"💓 Keepalive monitoring active - will reconnect after {self.max_keepalive_failures} failures")

                # Run the bot - this blocks until user stops it or fatal error
                self._run_bot_with_monitoring()

                # If we reach here, the bot stopped normally
                logger.info(f"{self.bot_name} stopped normally")
                self._bot_running = False
                break

            except KeyboardInterrupt:
                logger.info(f"🛑 {self.bot_name} stopped by user (Ctrl+C)")
                self._bot_running = False
                break
            except Exception as e:
                logger.error(f"❌ {self.bot_name} failed during startup: {e}", exc_info=True)
                self._bot_running = False

                # Only retry if this is a startup failure (not a runtime failure)
                if attempt < max_startup_retries - 1:
                    logger.warning(f"🔄 Retrying startup in {retry_delay}s...")
                    try:
                        self._graceful_shutdown()
                    except Exception:
                        pass
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60)  # Cap at 60s
                else:
                    logger.error(f"❌ Failed to start {self.bot_name} after {max_startup_retries} attempts")
                    raise

    def run(self):
        """
        Main entry point - starts bot with resilience features
        """
        try:
            # Start keepalive monitoring thread
            self.keepalive_thread = threading.Thread(target=self._keepalive_ping, daemon=True)
            self.keepalive_thread.start()
            logger.debug(f"💓 Keepalive monitoring started for {self.bot_name}")

            # Run bot with reconnection logic
            self.run_with_reconnection()

        except Exception as e:
            logger.error(f"Fatal error in {self.bot_name}: {e}", exc_info=True)
            self._graceful_shutdown()
            sys.exit(1)


def create_resilient_main(bot_factory: Callable[[], Any],
                          initialization_func: Optional[Callable[[], bool]] = None,
                          bot_name: Optional[str] = None):
    """
    Convenience function to create a resilient main() function
    
    Usage:
        def create_my_bot():
            return WebexBot(...)
        
        def initialize_my_bot():
            return True
        
        main = create_resilient_main(create_my_bot, initialize_my_bot)
        
        if __name__ == "__main__":
            main()
    """

    def main():
        resilient_runner = ResilientBot(
            bot_factory=bot_factory,
            initialization_func=initialization_func,
            bot_name=bot_name
        )
        resilient_runner.run()

    return main
