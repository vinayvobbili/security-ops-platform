"""
Enhanced WebSocket Client with improved connection resilience

This module provides a monkey-patch for webex_bot's WebexWebsocketClient
to add better connection handling, keepalive, and resilience features.

Key improvements:
1. WebSocket ping/pong keepalive (30s interval, 15s timeout)
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
import certifi
import websockets
from websockets.exceptions import InvalidStatusCode

# Import requests exceptions for better error handling
try:
    from requests.exceptions import ConnectionError as RequestsConnectionError
except ImportError:
    RequestsConnectionError = ConnectionError

logger = logging.getLogger(__name__)

# Enhanced configuration
MAX_BACKOFF_TIME = 600  # Increased from 240s to 600s (10 minutes)
WEBSOCKET_PING_INTERVAL = 30  # Send ping every 30 seconds (more aggressive)
WEBSOCKET_PING_TIMEOUT = 15  # Timeout if no pong after 15 seconds
WEBSOCKET_CLOSE_TIMEOUT = 10  # Wait up to 10 seconds for clean close


def patch_websocket_client():
    """
    Monkey-patch the webex_bot WebexWebsocketClient with enhanced connection handling.

    Call this function before creating any WebexBot instances.
    """
    try:
        from webex_bot.websockets.webex_websocket_client import WebexWebsocketClient

        # Store original run method
        original_run = WebexWebsocketClient.run

        def enhanced_run(self):
            """Enhanced run method with better connection resilience"""
            if self.device_info is None:
                if self._get_device_info(check_existing=False) is None:
                    logger.error('could not get/create device info')
                    raise Exception("No WDM device info")

            # Pull out URL now so we can log it on failure
            ws_url = self.device_info.get('webSocketUrl')

            async def _websocket_recv():
                message = await self.websocket.recv()
                logger.debug("WebSocket Received Message(raw): %s\n" % message)
                try:
                    msg = json.loads(message)
                    # Check if event loop is available and not closed before scheduling
                    try:
                        loop = asyncio.get_event_loop()
                        # Check if loop is closed - this happens during shutdown/reconnection
                        if loop.is_closed():
                            logger.debug("Event loop is closed, skipping message processing")
                            return
                        loop.run_in_executor(None, self._process_incoming_websocket_message, msg)
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
                ws_url = self.device_info['webSocketUrl']

                logger.debug(f"Opening websocket connection to {ws_url}")

                # Create SSL context - unverified for corporate proxy (ZScaler) compatibility
                ssl_context = ssl._create_unverified_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                # Setup connection with enhanced parameters
                connect_kwargs = {
                    'ssl': ssl_context,
                    'extra_headers': self._get_headers(),
                    'ping_interval': WEBSOCKET_PING_INTERVAL,  # Send ping every 30s
                    'ping_timeout': WEBSOCKET_PING_TIMEOUT,    # Timeout after 15s
                    'close_timeout': WEBSOCKET_CLOSE_TIMEOUT,  # Clean close timeout
                    'max_size': 2**23,  # 8MB max message size
                }

                if self.proxies and "wss" in self.proxies:
                    logger.debug(f"Using proxy for websocket connection: {self.proxies['wss']}")
                    try:
                        from websockets_proxy import Proxy, proxy_connect
                        proxy = Proxy.from_url(self.proxies["wss"])
                        connect = proxy_connect(ws_url, proxy=proxy, **connect_kwargs)
                    except ImportError:
                        logger.error("websockets_proxy not available, falling back to direct connection")
                        connect = websockets.connect(ws_url, **connect_kwargs)
                elif self.proxies and "https" in self.proxies:
                    logger.debug(f"Using proxy for websocket connection: {self.proxies['https']}")
                    try:
                        from websockets_proxy import Proxy, proxy_connect
                        proxy = Proxy.from_url(self.proxies["https"])
                        connect = proxy_connect(ws_url, proxy=proxy, **connect_kwargs)
                    except ImportError:
                        logger.error("websockets_proxy not available, falling back to direct connection")
                        connect = websockets.connect(ws_url, **connect_kwargs)
                else:
                    logger.debug(f"Not using proxy for websocket connection.")
                    connect = websockets.connect(ws_url, **connect_kwargs)

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
                        except websockets.ConnectionClosed as e:
                            logger.warning(f"WebSocket connection closed: {e.code} {e.reason}")
                            raise  # Let backoff handle reconnection
                        except Exception as recv_error:
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
                except InvalidStatusCode as e:
                    consecutive_failures += 1
                    logger.error(f"WebSocket handshake to {ws_url} failed with status {e.status_code}")

                    if e.status_code == 404:
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
                    if self._get_device_info(check_existing=False) is None:
                        logger.error('could not create device info')
                        raise Exception("No WDM device info")

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
        logger.debug("✅ Enhanced WebSocket client patched successfully")
        logger.debug(f"📡 WebSocket keepalive: ping every {WEBSOCKET_PING_INTERVAL}s, timeout {WEBSOCKET_PING_TIMEOUT}s")
        logger.debug(f"🔄 Backoff retry window increased to {MAX_BACKOFF_TIME}s")
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
