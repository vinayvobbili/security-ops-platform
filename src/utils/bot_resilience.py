# /src/utils/bot_resilience.py
"""
Bot Resilience Framework

Provides common resilience patterns for all Webex bots:
- Automatic reconnection with exponential backoff
- Health monitoring and keepalive functionality
- Graceful shutdown handling
- Signal handlers for clean exits

Usage:
    from src.utils.bot_resilience import ResilientBot

    def create_my_bot():
        return WebexBot(...)
    
    def initialize_my_bot(bot):
        # Custom initialization logic
        return True
    
    # Run with resilience
    resilient_runner = ResilientBot(
        bot_name="MyBot",
        bot_factory=create_my_bot,
        initialization_func=initialize_my_bot
    )
    resilient_runner.run()
"""

import logging
import signal
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Callable, Optional, Any

# Import socket timeout sentinel value (private API, but needed for proper timeout handling)
try:
    # noinspection PyProtectedMember,PyUnresolvedReferences
    _GLOBAL_DEFAULT_TIMEOUT = socket._GLOBAL_DEFAULT_TIMEOUT  # type: ignore[attr-defined]
except AttributeError:
    # Fallback sentinel object if not available (shouldn't happen, but defensive)
    _GLOBAL_DEFAULT_TIMEOUT = object()

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

# Guard to avoid repeated global monkey patches if multiple bots created
_WEBSOCKETS_PATCHED = False
_SIGNAL_HANDLERS_SET = False


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
                 max_keepalive_failures: int = 5,
                 max_connection_age_hours: int = 12,
                 max_idle_minutes: int = 10,
                 enable_self_ping: bool = False,
                 self_ping_interval_minutes: int = 5,
                 self_ping_timeout_seconds: int = 60,
                 peer_bot_email: Optional[str] = None,
                 peer_ping_interval_minutes: int = 10):
        """
        Initialize resilient bot runner with multi-layered firewall traversal strategy

        Multi-layered defense against firewall/NAT connection timeouts:
        1. TCP keepalive (60s): Keeps firewall connection tracking tables alive - ROOT CAUSE FIX
        2. WebSocket ping (10s): Application-level keepalive for quick failure detection
        3. API health checks (120s): Detects stale application state
        4. Peer ping (10min): Bot sends periodic message to another bot to keep both inbound paths active
        5. Idle timeout (10min): Proactive reconnection if no messages received (VM networks)
        6. Max age (12h): Prevents long-lived connection degradation
        7. Socket write timeout (180s): Prevents hangs during large file uploads on unreliable networks

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
            max_connection_age_hours: Force reconnection after this many hours (prevents stale connections)
            max_idle_minutes: Force reconnection if no messages received (default 10min for VM networks with aggressive firewalls)
            enable_self_ping: Enable periodic self-ping to validate inbound firewall path (deprecated, use peer_bot_email instead)
            self_ping_interval_minutes: Send self-ping every N minutes to test inbound connectivity (deprecated)
            self_ping_timeout_seconds: Reconnect if self-ping not received within N seconds (deprecated)
            peer_bot_email: Email of another bot to send periodic pings to (recommended over self-ping)
            peer_ping_interval_minutes: Send peer ping every N minutes (default 10min)
        """
        # Suppress noisy logs for all bots
        # These INFO/WARNING-level logs create excessive noise without adding value
        # Suppress all webex_bot warnings (bot-to-bot messages, self-messages, command not found, etc.)
        logging.getLogger('webex_bot').setLevel(logging.ERROR)  # Covers all webex_bot submodules
        logging.getLogger('webexpythonsdk').setLevel(logging.ERROR)  # SDK warnings
        logging.getLogger('urllib3').setLevel(logging.ERROR)  # HTTP connection pool warnings
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)  # Async loop warnings

        # Apply SDK timeout patch for all bots using this resilience framework
        # The WebSocket client makes HTTP calls to register/refresh devices, and the default 60s timeout
        # is too short for unreliable networks, causing "Read timed out" errors
        try:
            import webexpythonsdk.config
            webexpythonsdk.config.DEFAULT_SINGLE_REQUEST_TIMEOUT = 180
            logger.info("⏱️  Increased SDK HTTP timeout from 60s to 180s for device registration")
        except Exception as timeout_patch_error:
            logger.warning(f"⚠️  Could not patch SDK timeout: {timeout_patch_error}")

        # CRITICAL FIX: Patch socket-level write timeouts for VM network environments
        # The VM has severe network issues (20K+ TCP timeouts), causing write operations to hang
        # Python's socket library by default has NO write timeout, so uploads can hang forever
        try:
            import socket
            from urllib3.util import connection

            # Store the original create_connection function
            _orig_create_connection = connection.create_connection

            def create_connection_with_timeout(address, timeout=None, *args, **kwargs):
                """Wrapper that sets both read AND write timeouts on sockets"""
                sock = _orig_create_connection(address, timeout, *args, **kwargs)

                # Set socket-level timeouts for BOTH read and write operations
                # This prevents hangs during large file uploads on unreliable networks
                # Must check for both None AND _GLOBAL_DEFAULT_TIMEOUT sentinel value
                if timeout is not None and timeout != _GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                else:
                    # Default to 180s if no timeout specified or sentinel value used
                    sock.settimeout(180.0)

                return sock

            # Monkey-patch urllib3's connection module (used by requests)
            connection.create_connection = create_connection_with_timeout
            logger.info("⏱️  Patched socket write timeouts to prevent hangs on VM network (180s)")
        except Exception as socket_patch_error:
            logger.warning(f"⚠️  Could not patch socket timeouts: {socket_patch_error}")

        # Apply WebSocket and TCP keepalive patches to prevent firewall connection tracking timeouts
        # When behind firewalls/NAT (especially on VMs), idle connections get dropped from firewall
        # state tables even if WebSocket pings work. TCP keepalive keeps firewall tracking alive.
        try:
            import websockets
            import socket
            import functools

            # Store the original connect function
            original_connect = websockets.connect

            # Create a wrapper that adds both WebSocket pings AND TCP keepalive
            # This must be a regular function, not async, to preserve the context manager protocol
            def connect_with_keepalive(*args, **kwargs):
                # Set VERY aggressive ping interval (10 seconds) to prevent stale connections
                kwargs.setdefault('ping_interval', 10)
                kwargs.setdefault('ping_timeout', 5)

                # Get the original connection context manager
                connection_context = original_connect(*args, **kwargs)

                # Wrap it to enable TCP keepalive after connection is established
                class TCPKeepaliveConnection:
                    def __init__(self, ws_connection):
                        self._connection = ws_connection

                    async def __aenter__(self):
                        # Establish the WebSocket connection
                        websocket = await self._connection.__aenter__()

                        # Enable TCP keepalive at socket level to keep firewall connection tracking alive
                        # This is the ROOT CAUSE FIX for firewall timeout issues
                        try:
                            sock = websocket.transport.get_extra_info('socket')
                            if sock:
                                # Enable TCP keepalive
                                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                                # Platform-specific keepalive tuning for aggressive firewall traversal
                                import platform
                                if platform.system() == 'Linux':
                                    # Linux: Start keepalive after 60s idle, probe every 30s, 3 probes before declaring dead
                                    # This ensures firewalls see activity at least every 60s
                                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)  # Start after 60s idle
                                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)  # Probe every 30s
                                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)  # 3 probes
                                    logger.debug("🔧 Enabled aggressive TCP keepalive for Linux (60s idle, 30s interval)")
                                elif platform.system() == 'Darwin':  # macOS
                                    # macOS: Start keepalive after 60s idle
                                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 60)  # Keepalive time
                                    logger.debug("🔧 Enabled TCP keepalive for macOS (60s idle)")
                                else:
                                    logger.debug("🔧 Enabled basic TCP keepalive (OS defaults)")

                                logger.debug("✅ TCP keepalive enabled on WebSocket to keep firewall connection tracking alive")
                        except Exception as tcp_keepalive_error:
                            logger.warning(f"⚠️  Could not enable TCP keepalive on socket: {tcp_keepalive_error}")

                        return websocket

                    async def __aexit__(self, *exit_args, **exit_kwargs):
                        return await self._connection.__aexit__(*exit_args, **exit_kwargs)

                return TCPKeepaliveConnection(connection_context)

            # Replace the connect function globally
            websockets.connect = connect_with_keepalive
            logger.info("🔧 Patched WebSocket with TCP keepalive to prevent firewall connection timeout")
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
        self.max_connection_age_hours = max_connection_age_hours
        self.max_idle_minutes = max_idle_minutes
        self.enable_self_ping = enable_self_ping
        self.self_ping_interval_minutes = self_ping_interval_minutes
        self.self_ping_timeout_seconds = self_ping_timeout_seconds
        self.peer_bot_email = peer_bot_email
        self.peer_ping_interval_minutes = peer_ping_interval_minutes

        # Runtime state
        self.bot_instance = None
        self.shutdown_requested = False
        self._reconnect_requested = False  # Flag set by keepalive or explicit trigger
        self.keepalive_thread = None
        self.last_successful_ping = datetime.now()
        self.consecutive_failures = 0
        self._bot_start_time = None
        self._bot_running = False  # Track if bot is currently running
        self._last_message_received = datetime.now()  # Track last incoming message to detect stale connections

        # Peer ping state for mutual inbound path validation
        self._last_peer_ping_sent = None  # Timestamp of last peer ping sent

        # Setup signal handlers
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown (only once globally)"""
        global _SIGNAL_HANDLERS_SET
        if _SIGNAL_HANDLERS_SET:
            return

        def signal_handler(sig, _):
            logger.info(f"🛑 Signal {sig} received, initiating graceful shutdown of {self.bot_name}...")
            self.shutdown_requested = True
            # Don't call sys.exit immediately - let the run loop exit naturally
            # This prevents race conditions with event loop cleanup

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        _SIGNAL_HANDLERS_SET = True

    def update_message_received(self):
        """
        Update the timestamp of the last received message.
        Call this from your message handler to prevent idle timeout reconnections.
        """
        self._last_message_received = datetime.now()
        logger.debug(f"📨 Message activity recorded for {self.bot_name}")

    def _send_peer_ping(self):
        """
        Send a health check message to a peer bot to keep both bots' inbound paths active.
        Returns True if sent successfully, False otherwise.
        """
        if not self.peer_bot_email:
            return False

        if not self.bot_instance or not hasattr(self.bot_instance, 'teams'):
            logger.debug("Cannot send peer ping - bot instance not ready")
            return False

        try:
            # Send peer ping (avoiding command keywords to prevent response loops)
            self.bot_instance.teams.messages.create(
                toPersonEmail=self.peer_bot_email,
                text=f"🔔 Peer ping from {self.bot_name} @ {datetime.now().strftime('%H:%M:%S')}"
            )

            self._last_peer_ping_sent = datetime.now()
            logger.info(f"✅ Sent peer ping to {self.peer_bot_email} successfully")
            return True

        except Exception as e:
            logger.warning(f"❌ Failed to send peer ping to {self.peer_bot_email}: {e}")
            return False

    def _log_connection_issue(self, reason):
        """Log a connection issue without triggering reconnection"""
        logger.warning(f"⚠️ Connection issue detected for {self.bot_name}: {reason}")
        logger.info(f"🔄 Bot will continue running - monitoring active")

    def _trigger_reconnection(self, reason):
        """Trigger bot reconnection by stopping the current instance (non-fatal)"""
        logger.warning(f"🔄 Triggering reconnection for {self.bot_name}: {reason}")
        self._reconnect_requested = True
        try:
            if self.bot_instance:
                # Try to stop the bot gracefully if supported
                if hasattr(self.bot_instance, 'stop'):
                    try:
                        self.bot_instance.stop()
                    except Exception as e:  # noqa: S110
                        logger.debug(f"Bot stop() during reconnection failed: {e}")
                if hasattr(self.bot_instance, 'websocket_client') and self.bot_instance.websocket_client:
                    ws_client = self.bot_instance.websocket_client
                    if hasattr(ws_client, 'websocket') and ws_client.websocket:
                        try:
                            import asyncio
                            loop = asyncio.get_event_loop()
                            if hasattr(ws_client.websocket, 'close'):
                                loop.run_until_complete(ws_client.websocket.close())
                        except Exception as e:  # noqa: S110
                            logger.debug(f"Error closing WebSocket for reconnection: {e}")
        except Exception as e:  # noqa: S110
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
            except (RuntimeError, AttributeError, OSError):
                # Ignore errors during event loop cleanup (loop already closed, not available, network errors, etc.)
                pass

    def _keepalive_ping(self):
        """Keep connection alive with periodic health checks; requests reconnection on failure"""
        wait = 60  # Start with 1 minute
        while not self.shutdown_requested and not self._reconnect_requested:
            try:
                if self.bot_instance and hasattr(self.bot_instance, 'teams'):
                    # Peer ping interval check - send periodic pings to peer bot
                    if self.peer_bot_email and self.peer_ping_interval_minutes > 0:
                        should_send_peer_ping = False

                        if self._last_peer_ping_sent is None:
                            # First peer ping - send after 1 minute of uptime
                            if self._bot_start_time and (datetime.now() - self._bot_start_time).total_seconds() >= 60:
                                should_send_peer_ping = True
                        else:
                            minutes_since_last_peer_ping = (datetime.now() - self._last_peer_ping_sent).total_seconds() / 60
                            if minutes_since_last_peer_ping >= self.peer_ping_interval_minutes:
                                should_send_peer_ping = True

                        if should_send_peer_ping:
                            logger.info(f"👋 Sending peer ping to {self.peer_bot_email} to keep inbound paths active...")
                            self._send_peer_ping()

                    # Idle timeout check
                    if self._last_message_received and self.max_idle_minutes > 0:
                        idle_minutes = (datetime.now() - self._last_message_received).total_seconds() / 60
                        if idle_minutes >= self.max_idle_minutes:
                            logger.warning(f"💀 No messages received for {idle_minutes:.1f} minutes (max: {self.max_idle_minutes})")
                            logger.warning("🔄 Connection appears stale - forcing reconnection to prevent missed messages")
                            self._trigger_reconnection(f"Idle timeout after {idle_minutes:.1f}m without messages")
                            break
                    # Max age check
                    if self._bot_start_time and self.max_connection_age_hours > 0:
                        connection_age_hours = (datetime.now() - self._bot_start_time).total_seconds() / 3600
                        if connection_age_hours >= self.max_connection_age_hours:
                            logger.warning(f"🔄 Connection has been alive for {connection_age_hours:.1f}h (max: {self.max_connection_age_hours}h)")
                            logger.warning("🔄 Forcing proactive reconnection to prevent stale connection issues")
                            self._trigger_reconnection(f"Proactive reconnect after {connection_age_hours:.1f}h")
                            break
                    # Health ping
                    ping_start = time.time()
                    self.bot_instance.teams.people.me()
                    ping_duration = time.time() - ping_start
                    self.last_successful_ping = datetime.now()
                    self.consecutive_failures = 0
                    wait = self.keepalive_interval
                    logger.debug(f"Keepalive ping successful for {self.bot_name} ({ping_duration:.2f}s)")
                time.sleep(wait)
            except (ConnectionResetError, ConnectionAbortedError, OSError, RequestsConnectionError, ProtocolError) as conn_error:
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    logger.warning(f"Keepalive ping failed for {self.bot_name} with connection error (failure #{self.consecutive_failures}/{self.max_keepalive_failures}): {conn_error}")
                    if self.consecutive_failures >= self.max_keepalive_failures:
                        logger.error(f"❌ Max keepalive failures ({self.max_keepalive_failures}) reached. Triggering reconnection...")
                        self._trigger_reconnection(f"Max keepalive failures: {type(conn_error).__name__}")
                        break
                    self._log_connection_issue(f"Connection error: {type(conn_error).__name__}")
                    wait = min(wait * 2, self.max_keepalive_interval)
                    time.sleep(wait)
            except Exception as e:  # noqa: S110
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    logger.warning(f"Keepalive ping failed for {self.bot_name} (failure #{self.consecutive_failures}/{self.max_keepalive_failures}): {e}")
                    if self.consecutive_failures >= self.max_keepalive_failures:
                        logger.error(f"❌ Max keepalive failures ({self.max_keepalive_failures}) reached. Triggering reconnection...")
                        self._trigger_reconnection("Max keepalive failures")
                        break
                    self._log_connection_issue("Connection issue detected")
                    wait = min(wait * 2, self.max_keepalive_interval)
                    time.sleep(wait)

    def _graceful_shutdown(self):
        """Perform graceful shutdown cleanup with proper WebSocket handling"""
        try:
            self.shutdown_requested = True
            logger.info(f"🛑 Performing graceful shutdown of {self.bot_name}...")

            if self.keepalive_thread and self.keepalive_thread.is_alive():
                logger.debug("Stopping keepalive monitoring thread...")

            if not self.bot_instance:
                logger.info(f"✅ {self.bot_name} shutdown complete")
                return

            # Close WebSocket connection if it exists
            if hasattr(self.bot_instance, 'websocket_client') and self.bot_instance.websocket_client:
                ws_client = self.bot_instance.websocket_client

                if hasattr(ws_client, 'websocket') and ws_client.websocket:
                    import asyncio

                    # Get or create event loop for cleanup
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_closed():
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            logger.debug("Created new event loop for WebSocket cleanup")
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        logger.debug("Created new event loop for WebSocket cleanup")

                    # Close WebSocket with timeout and suppress errors
                    if hasattr(ws_client.websocket, 'close'):
                        try:
                            close_task = ws_client.websocket.close()
                            loop.run_until_complete(asyncio.wait_for(close_task, timeout=2.0))
                            logger.debug("WebSocket closed gracefully")
                        except asyncio.TimeoutError:
                            logger.debug("WebSocket close timed out (expected during shutdown)")
                        except RuntimeError as e:
                            # Suppress "Event loop is closed" and "no running event loop" errors during shutdown
                            if "event loop" in str(e).lower():
                                logger.debug(f"WebSocket cleanup skipped - event loop already closed")
                            else:
                                logger.debug(f"WebSocket close runtime error: {e}")
                        except Exception as ws_close_error:  # noqa: S110 - Broad exception is intentional for cleanup
                            logger.debug(f"WebSocket close error (suppressed during shutdown): {ws_close_error}")

                # Try additional cleanup methods (but don't wait)
                if hasattr(ws_client, 'close'):
                    try:
                        ws_client.close()
                    except Exception:  # noqa: S110 - Suppress all errors during emergency cleanup
                        pass

            # Try bot-level stop method
            if hasattr(self.bot_instance, 'stop'):
                try:
                    self.bot_instance.stop()
                except Exception:  # noqa: S110 - Suppress all errors during emergency cleanup
                    pass

            # Clear bot instance
            self.bot_instance = None
            logger.info(f"✅ {self.bot_name} shutdown complete")

        except Exception as e:  # noqa: S110 - Broad exception is intentional for shutdown
            # Outer safety net - should rarely be hit since inner operations are protected
            # but critical to prevent crashes during final cleanup (e.g., corrupted state, firewall issues)
            logger.debug(f"Shutdown error (suppressed): {e}")

    def run_with_reconnection(self):
        """Run bot for a single lifecycle with startup retries. Returns when bot stops or reconnection requested."""
        max_startup_retries = 3
        retry_delay = 10
        for attempt in range(max_startup_retries):
            if self.shutdown_requested or self._reconnect_requested:
                break
            try:
                logger.info(f"🚀 Starting {self.bot_name or 'Bot'} (attempt {attempt + 1}/{max_startup_retries})")
                if attempt > 0:
                    logger.debug(f"⏳ Waiting {retry_delay}s before retry...")
                    time.sleep(retry_delay)
                start_time = datetime.now()
                logger.info("🌐 Creating bot connection...")
                self.bot_instance = self.bot_factory()
                # Extract bot name if not defined yet
                if not self.bot_name:
                    if hasattr(self.bot_instance, 'bot_name'):
                        self.bot_name = self.bot_instance.bot_name
                    elif hasattr(self.bot_instance, 'name'):
                        self.bot_name = self.bot_instance.name
                    else:
                        self.bot_name = "UnknownBot"
                logger.info(f"✅ {self.bot_name} created successfully")
                # Initialization callback
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
                    except Exception as init_error:  # noqa: S110
                        logger.error(f"❌ Initialization function failed: {init_error}")
                        if attempt < max_startup_retries - 1:
                            continue
                        else:
                            raise
                init_duration = (datetime.now() - start_time).total_seconds()
                logger.info(f"🚀 {self.bot_name} is up and running (startup in {init_duration:.1f}s)...")
                print(f"🚀 {self.bot_name} is up and running (startup in {init_duration:.1f}s)...", flush=True)
                self._bot_start_time = datetime.now()
                self._bot_running = True
                # Start keepalive monitoring for this lifecycle
                self.keepalive_thread = threading.Thread(target=self._keepalive_ping, daemon=True)
                self.keepalive_thread.start()
                logger.debug(f"💓 Keepalive monitoring started for {self.bot_name}")
                logger.info(f"💓 Keepalive monitoring active - will reconnect after {self.max_keepalive_failures} failures")
                if self.peer_bot_email:
                    logger.info(f"👋 Peer ping enabled - will ping {self.peer_bot_email} every {self.peer_ping_interval_minutes}min to keep inbound paths active")
                # Block until bot finishes
                self._run_bot_with_monitoring()
                logger.info(f"{self.bot_name} run loop exited")
                self._bot_running = False
                break
            except KeyboardInterrupt:
                logger.info(f"🛑 {self.bot_name} stopped by user (Ctrl+C)")
                self._bot_running = False
                break
            except Exception as e:  # noqa: S110
                logger.error(f"❌ {self.bot_name} failed during startup: {e}", exc_info=True)
                self._bot_running = False
                if attempt < max_startup_retries - 1:
                    logger.warning(f"🔄 Retrying startup in {retry_delay}s...")
                    try:
                        self._graceful_shutdown()
                    except (RuntimeError, AttributeError, OSError):
                        # Ignore errors during cleanup - we're already in an error state
                        # _graceful_shutdown() is already defensive internally, so only common error types expected
                        pass
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60)
                else:
                    logger.error(f"❌ Failed to start {self.bot_name} after {max_startup_retries} attempts")
                    raise

    def run(self):
        """Main entry point - manages lifecycle with automatic reconnection using exponential backoff."""
        attempt = 0
        while not self.shutdown_requested:
            self._reconnect_requested = False
            try:
                self.run_with_reconnection()  # Single lifecycle
            except Exception as e:  # noqa: S110
                logger.error(f"Runtime failure for {self.bot_name}: {e}", exc_info=True)
                self._reconnect_requested = True
            # Decide next action
            if self.shutdown_requested:
                break
            if self._reconnect_requested:
                attempt += 1
                if 0 <= self.max_retries < attempt:
                    logger.error(f"❌ Max reconnection attempts ({self.max_retries}) exceeded. Shutting down {self.bot_name}.")
                    break
                # Exponential backoff
                delay = min(self.initial_retry_delay * (2 ** (attempt - 1)), self.max_retry_delay)
                logger.warning(f"🔄 Reconnecting {self.bot_name} in {delay}s (attempt {attempt}/{self.max_retries if self.max_retries >= 0 else '∞'})...")
                # Clean up previous instance before retry
                try:
                    self._graceful_shutdown()
                except (RuntimeError, AttributeError, OSError):
                    # Ignore errors during cleanup - we're already in an error state
                    # _graceful_shutdown() is already defensive internally, so only common error types expected
                    pass
                time.sleep(delay)
                continue
            else:
                # Normal exit (no reconnection requested)
                break
        # Final cleanup
        self._graceful_shutdown()


def enable_message_tracking(bot_instance, resilient_runner):
    """
    Enable automatic message activity tracking for idle detection.

    Wraps the bot's message processing to notify the resilience framework
    whenever a message is received, enabling idle timeout detection.

    Args:
        bot_instance: The WebexBot instance
        resilient_runner: The ResilientBot instance managing this bot

    Usage:
        def my_initialization(bot_instance):
            # Enable idle detection
            enable_message_tracking(bot_instance, resilient_runner)
            # ... rest of initialization
            return True
    """
    if not bot_instance or not hasattr(bot_instance, 'process_incoming_message'):
        logger.warning("Cannot enable message tracking - bot instance invalid or missing process_incoming_message")
        return

    # Wrap the bot's process_incoming_message to track message activity
    original_process_incoming_message = bot_instance.process_incoming_message

    def tracked_process_incoming_message(teams_message, activity):
        """Wrapper that updates message timestamp for idle detection"""
        # Always update message timestamp for ANY incoming message (including peer pings)
        resilient_runner.update_message_received()

        # Check if this is a peer ping health check message
        message_text = teams_message.text if hasattr(teams_message, 'text') else ''
        if message_text and 'health check @' in message_text:
            # This is a peer ping - log it and don't process further (prevents command execution)
            sender_email = activity.get('actor', {}).get('emailAddress', 'unknown')
            logger.info(f"📨 Received peer ping from {sender_email} - connection healthy")
            # Don't return None - let the message be processed normally but it won't match any commands
            # This ensures the health check is logged but doesn't trigger bot responses

        # Call original message processor
        return original_process_incoming_message(teams_message, activity)

    # Replace with tracked version
    bot_instance.process_incoming_message = tracked_process_incoming_message
    logger.info("✅ Message activity tracking enabled for idle detection")


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
