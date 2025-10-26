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

# Handle ConnectionAbortedError for older Python versions
try:
    ConnectionAbortedError
except NameError:
    ConnectionAbortedError = ConnectionError

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
                 keepalive_interval: int = 120,  # More frequent for proxy handling
                 max_keepalive_interval: int = 600,
                 proxy_detection: bool = True,  # Enable ZScaler proxy detection
                 proactive_reconnection_interval: Optional[int] = None,  # Proactive reconnect (seconds)
                 disable_proxy_interval_adjustment: bool = False):  # Don't adjust intervals for proxy
        """
        Initialize resilient bot runner

        Args:
            bot_factory: Function that creates and returns a bot instance
            initialization_func: Optional function for custom initialization
            bot_name: Optional bot name (will be extracted from bot instance if not provided)
            max_retries: Maximum number of restart attempts
            initial_retry_delay: Initial delay between retries (seconds)
            max_retry_delay: Maximum delay between retries (seconds)
            keepalive_interval: Normal keepalive ping interval (seconds)
            max_keepalive_interval: Maximum keepalive ping interval (seconds)
            proxy_detection: Enable ZScaler proxy detection
            proactive_reconnection_interval: Force clean reconnect at this interval (seconds, None to disable)
            disable_proxy_interval_adjustment: Don't automatically adjust intervals when proxy detected
        """
        self.bot_name = bot_name  # Will be set after bot creation if not provided
        self.bot_factory = bot_factory
        self.initialization_func = initialization_func
        self.max_retries = max_retries
        self.initial_retry_delay = initial_retry_delay
        self.max_retry_delay = max_retry_delay
        self.keepalive_interval = keepalive_interval
        self.max_keepalive_interval = max_keepalive_interval
        self.proxy_detection = proxy_detection
        self.proactive_reconnection_interval = proactive_reconnection_interval
        self.disable_proxy_interval_adjustment = disable_proxy_interval_adjustment

        # Runtime state
        self.bot_instance = None
        self.shutdown_requested = False
        self.keepalive_thread = None
        self.websocket_monitor_thread = None
        self.proactive_reconnection_thread = None
        self.exception_handler_thread = None
        self.last_successful_ping = datetime.now()
        self.consecutive_failures = 0
        self._reconnection_needed = False
        self._last_reconnection_attempt = datetime.min
        self._bot_start_time = None

        # Setup signal handlers
        self._setup_signal_handlers()

        # Setup asyncio exception handler for unhandled futures
        self._setup_exception_handler()

        # Detect proxy environment
        if proxy_detection:
            self._detect_proxy_environment()

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""

        def signal_handler(sig, _):
            logger.info(f"🛑 Signal {sig} received, shutting down {self.bot_name}...")
            self.shutdown_requested = True
            self._graceful_shutdown()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def _setup_exception_handler(self):
        """Setup asyncio exception handler to catch unhandled future exceptions"""
        try:
            import asyncio
            import functools

            def exception_handler(loop, context):
                """Handle asyncio exceptions, particularly from unhandled futures"""
                exception = context.get('exception')
                if exception:
                    logger.warning(f"Asyncio exception caught for {self.bot_name}: {exception}")

                    # Check if this is a connection-related error
                    if (isinstance(exception, (ConnectionResetError, ConnectionAbortedError, OSError, RequestsConnectionError, ProtocolError)) or
                        self._is_proxy_related_error(exception)):
                        logger.warning(f"Connection-related asyncio exception detected for {self.bot_name}")
                        if not self.shutdown_requested:
                            # Trigger reconnection for connection errors
                            logger.warning(f"Triggering reconnection for {self.bot_name} due to asyncio connection error")
                            self._reconnection_needed = True
                else:
                    logger.warning(f"Asyncio context error for {self.bot_name}: {context}")

            # Set the exception handler if we're in an event loop context
            try:
                loop = asyncio.get_event_loop()
                loop.set_exception_handler(exception_handler)
                logger.debug(f"Asyncio exception handler set for {self.bot_name}")
            except RuntimeError:
                # No event loop running, will be set when one is created
                logger.debug(f"No event loop running yet for {self.bot_name}, exception handler will be set later")

        except ImportError:
            logger.debug("Asyncio not available, skipping exception handler setup")
        except Exception as e:
            logger.warning(f"Could not setup asyncio exception handler: {e}")

    def _detect_proxy_environment(self):
        """Detect if we're running behind a proxy (like ZScaler)"""
        try:
            import subprocess
            import os

            # Check for ZScaler process
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
            if "zscaler" in result.stdout.lower():
                logger.debug(f"🛡️ ZScaler proxy detected for {self.bot_name} - enabling enhanced monitoring")

                # Only adjust intervals if not disabled
                if not self.disable_proxy_interval_adjustment:
                    # Reduce ping intervals for proxy environments
                    self.keepalive_interval = min(60, self.keepalive_interval)
                    logger.debug(f"📉 Adjusted intervals for ZScaler: keepalive={self.keepalive_interval}s, websocket={WEBSOCKET_PING_INTERVAL}s")
                else:
                    logger.debug(f"✓ Keeping configured intervals: keepalive={self.keepalive_interval}s, websocket={WEBSOCKET_PING_INTERVAL}s")

                # Enable proactive reconnection every 10 minutes if not already set
                if self.proactive_reconnection_interval is None:
                    self.proactive_reconnection_interval = 600  # 10 minutes
                    logger.debug(f"🔄 Proactive reconnection enabled: every {self.proactive_reconnection_interval}s to avoid ZScaler timeouts")
                return True

            # Check environment variables
            proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
            for var in proxy_vars:
                if os.environ.get(var):
                    logger.debug(f"🛡️ Proxy environment detected for {self.bot_name}: {var}")
                    return True

            return False
        except Exception as e:
            logger.warning(f"Could not detect proxy environment: {e}")
            return False
            
    def _is_proxy_related_error(self, error):
        """Check if an error is likely related to proxy issues"""
        error_str = str(error).lower()
        error_type = type(error).__name__.lower()

        # Check both error message and exception type
        proxy_indicators = [
            'connection reset',
            'connection aborted',
            'ssl handshake failed',
            'tunnel connection failed',
            'proxy',
            'certificate verify failed',
            'connection refused',
            'timed out',
            'network is unreachable',
            'errno 54',  # Connection reset by peer
            'errno 61',  # Connection refused
            'protocolerror',
            'connectionresetarror',
            'connectionabortederror'
        ]

        # Check for specific exception types
        connection_exceptions = [
            'connectionreseterror',
            'connectionabortederror',
            'connectionrefusederror',
            'protocolerror',
            'sslerror'
        ]

        return (any(indicator in error_str for indicator in proxy_indicators) or
                any(exc_type in error_type for exc_type in connection_exceptions))
        
    def _trigger_reconnection(self, reason):
        """Trigger a bot reconnection due to connection issues"""
        # Use DEBUG for proactive reconnections, WARNING for error-driven reconnections
        if "proactive" in reason.lower():
            logger.debug(f"🔄 Triggering {self.bot_name} reconnection: {reason}")
        else:
            logger.warning(f"🔄 Triggering {self.bot_name} reconnection: {reason}")

        # Check if we've had too many recent reconnections to avoid thrashing
        current_time = datetime.now()
        if hasattr(self, '_last_reconnection_attempt'):
            time_since_last = (current_time - self._last_reconnection_attempt).total_seconds()
            if time_since_last < 60:  # Don't reconnect more than once per minute
                logger.debug(f"Skipping reconnection for {self.bot_name} - too soon after last attempt ({time_since_last:.0f}s)")
                return

        self._last_reconnection_attempt = current_time

        try:
            if self.bot_instance:
                logger.debug(f"Forcing shutdown of {self.bot_name} for reconnection...")
                # Force close the current bot instance
                self._graceful_shutdown()

                # Give extra time for WebSocket cleanup
                cleanup_delay = 10 if self.proxy_detection else 5
                logger.debug(f"Waiting {cleanup_delay}s for complete connection cleanup...")
                time.sleep(cleanup_delay)

                # Clear the bot instance to force a fresh connection
                self.bot_instance = None
                logger.debug(f"Bot instance cleared for {self.bot_name}")

        except Exception as e:
            logger.error(f"Error during forced reconnection: {e}")

        # Set a flag to indicate reconnection is needed
        self._reconnection_needed = True

    def _run_bot_with_monitoring(self):
        """Run the bot with monitoring for reconnection requests"""
        try:
            # For now, just run the bot directly since the threading approach
            # has asyncio event loop issues. The keepalive and websocket monitoring
            # threads will handle reconnection detection.
            self.bot_instance.run()

        except Exception as e:
            logger.error(f"Error running {self.bot_name}: {e}")
            raise

    def _proactive_reconnection_monitor(self):
        """Proactively reconnect at regular intervals to avoid proxy timeouts"""
        while not self.shutdown_requested:
            try:
                if self._bot_start_time is None:
                    # Wait for bot to start
                    time.sleep(10)
                    continue

                # Calculate time since bot started
                uptime = (datetime.now() - self._bot_start_time).total_seconds()

                # If we're approaching the reconnection interval, trigger clean reconnect
                if uptime >= self.proactive_reconnection_interval:
                    logger.info(f"⏰ Proactive reconnection triggered for {self.bot_name} after {uptime:.0f}s uptime")
                    self._trigger_reconnection("Proactive reconnection to avoid proxy timeout")
                    break

                # Sleep and check again
                time.sleep(30)  # Check every 30 seconds

            except Exception as e:
                if not self.shutdown_requested:
                    logger.warning(f"Proactive reconnection monitor error for {self.bot_name}: {e}")
                    time.sleep(60)

    def _websocket_monitor(self):
        """Monitor WebSocket connection health with proxy-aware logic and future exception handling"""
        while not self.shutdown_requested:
            try:
                if self.bot_instance and hasattr(self.bot_instance, 'websocket_client'):
                    ws_client = self.bot_instance.websocket_client

                    # Check WebSocket connection state
                    if hasattr(ws_client, 'websocket') and ws_client.websocket:
                        # Try to send a ping if supported
                        try:
                            if hasattr(ws_client.websocket, 'ping'):
                                ws_client.websocket.ping()
                                logger.debug(f"WebSocket ping sent for {self.bot_name}")
                        except (ConnectionResetError, ConnectionAbortedError, OSError, RequestsConnectionError, ProtocolError) as conn_error:
                            logger.warning(f"WebSocket ping failed with connection error for {self.bot_name}: {conn_error}")
                            self._trigger_reconnection(f"WebSocket connection error: {type(conn_error).__name__}")
                            break
                        except Exception as ping_error:
                            if self._is_proxy_related_error(ping_error):
                                logger.warning(f"WebSocket ping failed due to proxy issue: {ping_error}")
                                self._trigger_reconnection("WebSocket ping failure")
                                break
                            else:
                                logger.debug(f"WebSocket ping failed: {ping_error}")

                    # Check if we haven't had a successful ping in too long
                    time_since_last_ping = (datetime.now() - self.last_successful_ping).total_seconds()
                    if time_since_last_ping > 300:  # 5 minutes
                        logger.warning(f"No successful ping for {self.bot_name} in {time_since_last_ping:.0f}s")
                        if self.consecutive_failures > 3:
                            self._trigger_reconnection("Extended connection silence")
                            break

                time.sleep(WEBSOCKET_PING_INTERVAL)
            except (ConnectionResetError, ConnectionAbortedError, OSError, RequestsConnectionError, ProtocolError) as conn_error:
                if not self.shutdown_requested:
                    logger.warning(f"WebSocket monitor connection error for {self.bot_name}: {conn_error}")
                    self._trigger_reconnection(f"WebSocket monitor connection error: {type(conn_error).__name__}")
                    break
            except Exception as e:
                if not self.shutdown_requested:
                    logger.warning(f"WebSocket monitor error for {self.bot_name}: {e}")
                    time.sleep(WEBSOCKET_PING_INTERVAL * 2)

    def _keepalive_ping(self):
        """Keep connection alive with periodic health checks"""
        wait = 60  # Start with 1 minute

        while not self.shutdown_requested:
            try:
                if self.bot_instance and hasattr(self.bot_instance, 'teams'):
                    # Try a simple API call to test connection health
                    self.bot_instance.teams.people.me()
                    self.last_successful_ping = datetime.now()
                    self.consecutive_failures = 0
                    wait = self.keepalive_interval  # Reset to normal interval
                    logger.debug(f"Keepalive ping successful for {self.bot_name}")
                time.sleep(wait)
            except (ConnectionResetError, ConnectionAbortedError, OSError, RequestsConnectionError, ProtocolError) as conn_error:
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    logger.warning(f"Keepalive ping failed for {self.bot_name} with connection error (failure #{self.consecutive_failures}): {conn_error}")
                    logger.warning(f"Connection error detected for {self.bot_name}. Triggering immediate reconnection...")
                    self._trigger_reconnection(f"Connection error: {type(conn_error).__name__}")
                    break
            except Exception as e:
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    logger.warning(f"Keepalive ping failed for {self.bot_name} (failure #{self.consecutive_failures}): {e}")

                    # Check if this looks like a proxy/network issue
                    if self._is_proxy_related_error(e):
                        logger.warning(f"Detected proxy-related error for {self.bot_name}. Triggering reconnection...")
                        self._trigger_reconnection("Proxy connection issue detected")
                        break

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
            if self.websocket_monitor_thread and self.websocket_monitor_thread.is_alive():
                logger.debug("Stopping WebSocket monitoring...")
            if self.proactive_reconnection_thread and self.proactive_reconnection_thread.is_alive():
                logger.debug("Stopping proactive reconnection monitoring...")

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
        """Run bot with automatic reconnection on failures"""
        retry_delay = self.initial_retry_delay

        for attempt in range(self.max_retries):
            if self.shutdown_requested:
                break

            try:
                logger.info(f"🚀 Starting {self.bot_name} (attempt {attempt + 1}/{self.max_retries})")

                # Enhanced delay for proxy environments - ZScaler needs more time
                if attempt > 0:
                    proxy_delay = 20 if self.proxy_detection else 15
                    logger.debug(f"⏳ Waiting {proxy_delay}s for previous WebSocket connections to clean up...")
                    time.sleep(proxy_delay)  # Extra time for proxy environments

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
                print(f"🚀 {self.bot_name} is up and running (startup in {init_duration:.1f}s)...", flush=True)

                # Record bot start time for proactive reconnection
                self._bot_start_time = datetime.now()

                # Start the bot (this will block and run forever, or until reconnection is needed)
                logger.debug(f"🌐 Starting {self.bot_name} main loop...")

                # Run the bot with reconnection monitoring
                self._run_bot_with_monitoring()

                # Check if reconnection was requested
                if self._reconnection_needed:
                    self._reconnection_needed = False
                    self.shutdown_requested = False  # Reset shutdown flag for reconnection
                    self._bot_start_time = None  # Reset start time
                    logger.debug(f"🔄 Reconnection requested for {self.bot_name}, restarting...")

                    # Restart monitoring threads after reconnection
                    logger.debug(f"🔄 Restarting monitoring threads...")

                    # Restart keepalive thread
                    if not self.keepalive_thread or not self.keepalive_thread.is_alive():
                        self.keepalive_thread = threading.Thread(target=self._keepalive_ping, daemon=True)
                        self.keepalive_thread.start()
                        logger.debug(f"💓 Keepalive monitoring restarted")

                    # Restart WebSocket monitor thread
                    if not self.websocket_monitor_thread or not self.websocket_monitor_thread.is_alive():
                        self.websocket_monitor_thread = threading.Thread(target=self._websocket_monitor, daemon=True)
                        self.websocket_monitor_thread.start()
                        logger.debug(f"🔌 WebSocket monitoring restarted")

                    # Restart proactive reconnection thread if enabled
                    if self.proactive_reconnection_interval:
                        if not self.proactive_reconnection_thread or not self.proactive_reconnection_thread.is_alive():
                            self.proactive_reconnection_thread = threading.Thread(target=self._proactive_reconnection_monitor, daemon=True)
                            self.proactive_reconnection_thread.start()
                            logger.debug(f"⏰ Proactive reconnection monitoring restarted")

                    continue

                # If we reach here, the bot stopped normally
                logger.info(f"{self.bot_name} stopped normally")
                break

            except KeyboardInterrupt:
                logger.info(f"🛑 {self.bot_name} stopped by user (Ctrl+C)")
                break
            except (ConnectionResetError, ConnectionAbortedError, OSError, RequestsConnectionError, ProtocolError) as conn_error:
                logger.error(f"❌ {self.bot_name} crashed with connection error: {conn_error}")
                logger.warning(f"🔗 Connection-related crash detected for {self.bot_name}")
                retry_delay = min(retry_delay * 1.2, self.max_retry_delay)  # Gentle backoff for connection issues

                # Enhanced cleanup before retry for connection errors
                logger.debug(f"🧹 Performing cleanup after {self.bot_name} connection error...")
                try:
                    self._graceful_shutdown()
                    cleanup_delay = 5 if self.proxy_detection else 3
                    time.sleep(cleanup_delay)
                except Exception as cleanup_error:
                    logger.warning(f"Cleanup error after connection failure: {cleanup_error}")
                    time.sleep(8 if self.proxy_detection else 5)

                if attempt < self.max_retries - 1:
                    logger.debug(f"🔄 Restarting {self.bot_name} after connection error in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"❌ Max retries exceeded after connection error. {self.bot_name} will not restart.")
                    raise

            except Exception as e:
                logger.error(f"❌ {self.bot_name} crashed with error: {e}", exc_info=True)

                # Check if this is a proxy-related crash
                if self._is_proxy_related_error(e):
                    logger.warning(f"🛡️ Proxy-related crash detected for {self.bot_name}")
                    retry_delay = min(retry_delay * 1.5, self.max_retry_delay)  # Gentler backoff for proxy issues
                else:
                    retry_delay = min(retry_delay * 2, self.max_retry_delay)  # Standard exponential backoff

                # Enhanced cleanup before retry
                logger.debug(f"🧹 Performing cleanup after {self.bot_name} crash...")
                try:
                    self._graceful_shutdown()
                    # Extra delay for proxy environments
                    cleanup_delay = 5 if self.proxy_detection else 3
                    time.sleep(cleanup_delay)
                except Exception as cleanup_error:
                    logger.warning(f"Cleanup error: {cleanup_error}")
                    # Even if cleanup fails, give time for connections to timeout
                    time.sleep(8 if self.proxy_detection else 5)

                if attempt < self.max_retries - 1:
                    logger.debug(f"🔄 Restarting {self.bot_name} in {retry_delay} seconds...")
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

            # If bot_name not set yet, try to create a temporary bot to extract the name
            if not self.bot_name:
                try:
                    temp_bot = self.bot_factory()
                    if hasattr(temp_bot, 'bot_name'):
                        self.bot_name = temp_bot.bot_name
                    elif hasattr(temp_bot, 'name'):
                        self.bot_name = temp_bot.name
                    # Clean up temp bot
                    del temp_bot
                except Exception as e:
                    logger.warning(f"Could not extract bot name for process detection: {e}")
                    return 0

            # Final check - if bot_name is still None, we can't do process detection
            if not self.bot_name:
                logger.warning("Bot name is still None after extraction attempt - skipping process detection")
                return 0
                
            bot_script = f"{self.bot_name.lower()}.py"

            # Check for other Python processes running the same bot script
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True
            )

            competing_processes = []
            for line in result.stdout.split('\n'):
                # More robust matching - check for python processes with our bot script
                # Handle different path formats: relative, absolute, with/without full paths
                if ("python" in line.lower() and
                        (bot_script in line or
                         f"webex_bots/{bot_script}" in line or
                         f"/{bot_script}" in line.split()[-1] if line.split() else False)):

                    # Extract PID (usually the second column)
                    parts = line.split()
                    if len(parts) > 1:
                        try:
                            pid = int(parts[1])
                            if pid != current_pid:
                                # Double-check this is actually our bot by looking at the full command
                                if any(bot_script in part for part in parts):
                                    competing_processes.append(pid)
                        except ValueError:
                            continue

            # Kill competing processes
            if competing_processes:
                logger.debug(f"🔫 Found {len(competing_processes)} competing {self.bot_name} process(es). Terminating...")
                for pid in competing_processes:
                    try:
                        logger.debug(f"Killing process {pid}...")
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

                        logger.debug(f"✅ Successfully terminated process {pid}")
                    except OSError as e:
                        logger.warning(f"Could not kill process {pid}: {e}")

                # Wait longer for proper WebSocket cleanup and avoid race conditions
                logger.debug("⏳ Waiting 5s for complete WebSocket cleanup...")
                time.sleep(5)

                # Double-check no processes are still starting up
                logger.debug("🔍 Performing final process check...")
                time.sleep(2)
            else:
                logger.debug(f"✅ No competing {self.bot_name} processes detected")

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
                logger.debug(f"🧹 Cleaned up {killed_count} competing process(es). Starting {self.bot_name}...")

            # Start keepalive monitoring thread
            self.keepalive_thread = threading.Thread(target=self._keepalive_ping, daemon=True)
            self.keepalive_thread.start()
            logger.debug(f"💓 Keepalive monitoring started for {self.bot_name}")

            # Start WebSocket monitoring thread for enhanced proxy handling
            self.websocket_monitor_thread = threading.Thread(target=self._websocket_monitor, daemon=True)
            self.websocket_monitor_thread.start()
            logger.debug(f"🔌 WebSocket monitoring started for {self.bot_name}")

            # Start proactive reconnection thread if enabled
            if self.proactive_reconnection_interval:
                self.proactive_reconnection_thread = threading.Thread(target=self._proactive_reconnection_monitor, daemon=True)
                self.proactive_reconnection_thread.start()
                logger.debug(f"⏰ Proactive reconnection monitoring started for {self.bot_name} (interval: {self.proactive_reconnection_interval}s)")

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
