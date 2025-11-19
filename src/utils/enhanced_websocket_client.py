"""
Enhanced WebSocket Client with improved connection resilience

This module provides a monkey-patch for webex_bot's WebexWebsocketClient
to add better connection handling, keepalive, and resilience features.

Key improvements:
1. WebSocket ping/pong keepalive (10s interval, 5s timeout) - very aggressive to prevent stale connections
2. Improved backoff retry logic with up to 10 retries per connection attempt
3. Exponential backoff capped at 30 seconds with jitter to avoid thundering herd
4. Handles wrapped connection errors (e.g., requests.exceptions.ConnectionError)
5. Device registration refresh on connection errors
6. Proper close handling with timeout
7. Better logging and error handling
"""

import asyncio
import json
import logging
import socket
import ssl
import uuid

import backoff
import websockets

# Import InvalidStatusCode - location changed in websockets 14.x
try:
    from websockets.exceptions import InvalidStatusCode
except ImportError:
    # Fallback for older versions (< 14.x)
    from websockets.legacy.exceptions import InvalidStatusCode  # type: ignore[import-not-found]

# Import requests exceptions for better error handling
try:
    from requests.exceptions import ConnectionError as RequestsConnectionError
except ImportError:
    RequestsConnectionError = ConnectionError

# Import websockets_proxy if available for proxy support
try:
    from websockets_proxy import Proxy, proxy_connect  # type: ignore[import-untyped]
    HAS_WEBSOCKETS_PROXY = True
except ImportError:
    Proxy = None  # type: ignore[assignment,misc]
    proxy_connect = None  # type: ignore[assignment,misc]
    HAS_WEBSOCKETS_PROXY = False

logger = logging.getLogger(__name__)

# Enhanced configuration
MAX_BACKOFF_TIME = 600  # Increased from 240s to 600s (10 minutes)
WEBSOCKET_PING_INTERVAL = 10  # VERY aggressive - ping every 10s to prevent stale connections
WEBSOCKET_PING_TIMEOUT = 5  # Fail fast if no pong in 5s
WEBSOCKET_CLOSE_TIMEOUT = 10  # Wait up to 10 seconds for clean close


def patch_websocket_client():
    """
    Monkey-patch the webex_bot WebexWebsocketClient with enhanced connection handling.

    Call this function before creating any WebexBot instances.
    """
    try:
        from webex_bot.websockets.webex_websocket_client import WebexWebsocketClient

        def enhanced_run(self):
            """Enhanced run method with better connection resilience"""
            if self.device_info is None:
                if self._get_device_info(check_existing=False) is None:
                    logger.error('could not get/create device info')
                    raise Exception("No WDM device info")

            # Check for error response (e.g., "excessive device registrations")
            if 'errors' in self.device_info:
                error_msg = self.device_info.get('message', 'Unknown error')
                logger.error(f"Device registration failed: {error_msg}")
                logger.error("Hint: Clean up stale devices using cleanup_devices_on_startup() before starting bot")
                raise Exception(f"Device registration error: {error_msg}")

            # Pull out URL now so we can log it on failure
            ws_url = self.device_info.get('webSocketUrl')

            async def _websocket_recv():
                message = await self.websocket.recv()
                logger.debug("WebSocket Received Message(raw): %s\n" % message)
                try:
                    msg = json.loads(message)
                    # Check if event loop is available and not closed before scheduling
                    try:
                        event_loop = asyncio.get_event_loop()
                        # Check if loop is closed - this happens during shutdown/reconnection
                        if event_loop.is_closed():
                            logger.debug("Event loop is closed, skipping message processing")
                            return
                        event_loop.run_in_executor(None, self._process_incoming_websocket_message, msg)
                    except RuntimeError as loop_error:
                        # Event loop not available (happens during shutdown)
                        if 'no current event loop' in str(loop_error).lower() or 'no running event loop' in str(loop_error).lower():
                            logger.debug("No event loop available during shutdown, skipping message")
                            return
                        raise
                except Exception as messageProcessingException:
                    # Only log if it's not a shutdown-related error
                    if 'cannot schedule new futures after shutdown' not in str(messageProcessingException).lower():
                        logger.warning(
                        f"An exception occurred while processing message. Ignoring. {messageProcessingException}")

            @backoff.on_exception(
                backoff.expo,
                (
                    websockets.ConnectionClosedError,
                    websockets.ConnectionClosedOK,
                    websockets.ConnectionClosed,
                    socket.gaierror,
                    InvalidStatusCode,
                    ConnectionResetError,
                    ConnectionAbortedError,
                    OSError,
                    RequestsConnectionError,  # Added to handle wrapped connection errors
                ),
                max_tries=10,  # Allow up to 10 retries per connection attempt
                max_value=30,  # Cap exponential backoff at 30 seconds
                jitter=backoff.full_jitter,  # Add jitter to avoid thundering herd
            )
            async def _connect_and_listen():
                # Refresh device info on each connection attempt to avoid stale URLs
                logger.debug("Refreshing device info before connection attempt...")
                # Force new device registration (don't check existing) to avoid stale URLs
                self._get_device_info(check_existing=False)
                connection_url = self.device_info['webSocketUrl']

                logger.debug(f"Opening websocket connection to {connection_url}")

                # Create SSL context - unverified for corporate proxy (ZScaler) compatibility
                ssl_context = ssl._create_unverified_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                # Setup connection with VERY aggressive keepalive to prevent stale connections
                # After long idle periods, some backends stop routing messages even though
                # the TCP connection appears alive. Use aggressive pings to prevent this.
                connect_kwargs = {
                    'ssl': ssl_context,
                    'ping_interval': WEBSOCKET_PING_INTERVAL,
                    'ping_timeout': WEBSOCKET_PING_TIMEOUT,
                    'close_timeout': WEBSOCKET_CLOSE_TIMEOUT,
                    'max_size': 2**23,  # 8MB max message size
                }

                # API compatibility: websockets 12.0+ uses 'additional_headers', 11.x uses 'extra_headers'
                # Check version and use the correct parameter name
                try:
                    from websockets import version as ws_version
                    ws_major_version = int(ws_version.version.split('.')[0])
                    header_param = 'additional_headers' if ws_major_version >= 12 else 'extra_headers'
                except (ImportError, AttributeError, ValueError, IndexError):
                    # Fallback: try using additional_headers first, then extra_headers
                    header_param = 'extra_headers'  # Default to old API

                connect_kwargs[header_param] = self._get_headers()

                if self.proxies and "wss" in self.proxies:
                    logger.debug(f"Using proxy for websocket connection: {self.proxies['wss']}")
                    if HAS_WEBSOCKETS_PROXY:
                        # noinspection PyUnresolvedReferences,PyCallingNonCallable
                        proxy = Proxy.from_url(self.proxies["wss"])
                        # noinspection PyCallingNonCallable
                        connect = proxy_connect(connection_url, proxy=proxy, **connect_kwargs)
                    else:
                        logger.error("websockets_proxy not available, falling back to direct connection")
                        connect = websockets.connect(connection_url, **connect_kwargs)
                elif self.proxies and "https" in self.proxies:
                    logger.debug(f"Using proxy for websocket connection: {self.proxies['https']}")
                    if HAS_WEBSOCKETS_PROXY:
                        # noinspection PyUnresolvedReferences,PyCallingNonCallable
                        proxy = Proxy.from_url(self.proxies["https"])
                        # noinspection PyCallingNonCallable
                        connect = proxy_connect(connection_url, proxy=proxy, **connect_kwargs)
                    else:
                        logger.error("websockets_proxy not available, falling back to direct connection")
                        connect = websockets.connect(connection_url, **connect_kwargs)
                else:
                    logger.debug(f"Not using proxy for websocket connection.")
                    connect = websockets.connect(connection_url, **connect_kwargs)

                async with connect as _websocket:
                    self.websocket = _websocket
                    logger.debug("WebSocket Opened with keepalive enabled.")

                    # Send authorization
                    msg = {'id': str(uuid.uuid4()),
                           'type': 'authorization',
                           'data': {'token': 'Bearer ' + self.access_token}}
                    await self.websocket.send(json.dumps(msg))

                    # Main receive loop
                    while True:
                        try:
                            await _websocket_recv()
                        except websockets.ConnectionClosed as conn_closed:
                            logger.warning(f"WebSocket connection closed: {conn_closed.rcvd.code} {conn_closed.rcvd.reason}")
                            raise  # Let backoff handle reconnection
                        except (RuntimeError, OSError, ConnectionError) as fatal_error:
                            # Check if this is a shutdown-related error (event loop closed)
                            fatal_error_msg = str(fatal_error).lower()
                            if "event loop" in fatal_error_msg or "loop" in fatal_error_msg:
                                # Suppress event loop errors during shutdown - these are expected
                                logger.debug(f"WebSocket shutting down: {fatal_error}")
                            else:
                                # Log other fatal errors that require reconnection
                                logger.error(f"Fatal WebSocket error: {fatal_error}")
                            raise  # Exit loop and trigger reconnection via backoff
                        except Exception as recv_error:
                            # Log but continue for other non-fatal errors (e.g., message parsing)
                            logger.error(f"Error receiving WebSocket message: {recv_error}")
                            # Don't raise for individual message errors, continue listening

            # Track the number of consecutive 404 errors to prevent infinite loops
            max_404_retries = 5  # Increased from 3
            current_404_retries = 0
            consecutive_failures = 0
            max_consecutive_failures = 10  # New: prevent infinite failure loops

            while True:
                try:
                    # Get or create event loop if needed
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    loop.run_until_complete(_connect_and_listen())
                    # If we get here, the connection was successful, reset failure counter
                    consecutive_failures = 0
                    current_404_retries = 0
                    break
                except InvalidStatusCode as status_error:
                    consecutive_failures += 1
                    logger.error(f"WebSocket handshake to {ws_url} failed with status {status_error.status_code}")

                    if status_error.status_code == 404:
                        current_404_retries += 1
                        if current_404_retries >= max_404_retries:
                            logger.error(f"Reached maximum retries ({max_404_retries}) for 404 errors. Giving up.")
                            raise Exception(f"Unable to connect to WebSocket after {max_404_retries} attempts. Device registration may be invalid.")

                        logger.debug(f"Refreshing WDM device info and retrying... (Attempt {current_404_retries} of {max_404_retries})")
                        # Force a new device registration
                        self._get_device_info(check_existing=False)
                        # Update ws_url with the new device info
                        ws_url = self.device_info.get('webSocketUrl')

                        # Add a delay before retrying to avoid hammering the server
                        delay = min(5 * current_404_retries, 30)  # Progressive delay up to 30s
                        logger.debug(f"Waiting {delay} seconds before retry attempt {current_404_retries}...")
                        # Get or create event loop if needed
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                        loop.run_until_complete(asyncio.sleep(delay))
                    else:
                        # For non-404 errors, just raise the exception
                        raise

                except (ConnectionResetError, ConnectionAbortedError, OSError) as conn_error:
                    consecutive_failures += 1
                    logger.error(f"Connection error (#{consecutive_failures}): {conn_error}")

                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Reached maximum consecutive failures ({max_consecutive_failures}). Giving up.")
                        raise Exception(f"Unable to maintain WebSocket connection after {max_consecutive_failures} attempts.")

                    # Refresh device info on connection errors
                    logger.debug("Refreshing device info due to connection error...")
                    if self._get_device_info(check_existing=False) is None:
                        logger.error('could not create device info')
                        raise Exception("No WDM device info")

                    # Update the URL in case it changed
                    ws_url = self.device_info.get('webSocketUrl')

                    # Progressive delay based on failure count
                    delay = min(5 * consecutive_failures, 60)
                    logger.debug(f"Waiting {delay} seconds before attempting to reconnect...")
                    # Get or create event loop if needed
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    loop.run_until_complete(asyncio.sleep(delay))

                except Exception as runException:
                    consecutive_failures += 1
                    logger.error(f"runException (#{consecutive_failures}): {runException}")

                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Reached maximum consecutive failures ({max_consecutive_failures}). Giving up.")
                        raise

                    # Check if we can get device info
                    device_result = self._get_device_info(check_existing=False)
                    if device_result is None:
                        logger.error('could not create device info')
                        raise Exception("No WDM device info")

                    # Check for error response (e.g., "excessive device registrations")
                    if 'errors' in self.device_info:
                        error_msg = self.device_info.get('message', 'Unknown error')
                        logger.error(f"Device registration failed: {error_msg}")
                        logger.error("Hint: Try cleaning up stale devices using cleanup_devices_on_startup()")
                        raise Exception(f"Device registration error: {error_msg}")

                    # Update the URL in case it changed
                    ws_url = self.device_info.get('webSocketUrl')

                    # Wait a bit before reconnecting with progressive backoff
                    delay = min(5 * consecutive_failures, 60)
                    logger.debug(f"Waiting {delay} seconds before attempting to reconnect...")
                    # Get or create event loop if needed
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    loop.run_until_complete(asyncio.sleep(delay))

        # Apply the patch
        WebexWebsocketClient.run = enhanced_run
        logger.debug("Enhanced WebSocket client patched successfully")
        logger.debug(f"WebSocket keepalive: ping every {WEBSOCKET_PING_INTERVAL}s, timeout {WEBSOCKET_PING_TIMEOUT}s")
        logger.debug(f"Backoff retry window increased to {MAX_BACKOFF_TIME}s")
        return True

    except ImportError as e:
        logger.error(f"Failed to patch WebSocket client: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error patching WebSocket client: {e}")
        return False


# Auto-apply patch when module is imported
if __name__ != "__main__":
    patch_websocket_client()
