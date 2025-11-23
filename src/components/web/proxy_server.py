"""Proxy Server Implementation for Web Dashboard."""

import asyncio
import http.client
import http.server
import logging
import select
import socket
import socketserver
import threading
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlsplit

import pytz

logger = logging.getLogger(__name__)

BUFFER_SIZE = 16384
MAX_CONNECTIONS = 100


class ConnectionPool:
    """HTTP connection pool for reusing connections."""

    def __init__(self, max_connections=100):
        self.pool: Dict[str, List[http.client.HTTPConnection]] = {}
        self.max_connections = max_connections
        self.lock = threading.RLock()

    def get_connection(self, host):
        """Get a connection from the pool or create a new one."""
        with self.lock:
            if host not in self.pool:
                self.pool[host] = []

            if self.pool[host]:
                return self.pool[host].pop()
            else:
                return http.client.HTTPConnection(host)

    def release_connection(self, host, conn):
        """Release a connection back to the pool."""
        with self.lock:
            if host not in self.pool:
                self.pool[host] = []

            if len(self.pool[host]) < self.max_connections:
                self.pool[host].append(conn)
            else:
                conn.close()


# Global connection pool
connection_pool = ConnectionPool(max_connections=MAX_CONNECTIONS)


def _relay_sockets(client, target):
    """Simple synchronous socket relay that avoids HTTP processing.

    Args:
        client: Client socket
        target: Target socket
    """
    try:
        # Set non-blocking mode to handle disconnections gracefully
        client.settimeout(1.0)
        target.settimeout(1.0)

        sockets = [client, target]

        # Keep transferring data between client and target
        while True:
            try:
                # Check if sockets are still valid before select
                if client.fileno() == -1 or target.fileno() == -1:
                    break

                # Wait until a socket is ready to be read
                readable, _, exceptional = select.select(sockets, [], sockets, 1.0)

                if exceptional:
                    break

                if not readable:
                    continue

                for sock in readable:
                    # Check socket validity again
                    if sock.fileno() == -1:
                        continue

                    # Determine the destination socket
                    dest = target if sock is client else client

                    # Check destination socket validity
                    if dest.fileno() == -1:
                        return

                    try:
                        data = sock.recv(BUFFER_SIZE)
                        if not data:
                            return
                        dest.sendall(data)
                    except (socket.error, ConnectionResetError, BrokenPipeError, OSError) as sock_err:
                        if hasattr(sock_err, 'errno') and sock_err.errno == 9:
                            return
                        return

            except (OSError, ValueError) as select_err:
                if hasattr(select_err, 'errno') and select_err.errno == 9:
                    break
                return

    except Exception as exc:
        logger.error(f"Unexpected error during socket relay: {exc}", exc_info=True)

    finally:
        # Ensure sockets are properly closed
        for sock in [client, target]:
            try:
                if sock and sock.fileno() != -1:
                    sock.close()
            except (OSError, AttributeError):
                pass


async def _async_select(client_sock, target_sock):
    """Async-compatible version of select operation using running loop (Python 3.13 safe).

    Args:
        client_sock: Client socket
        target_sock: Target socket

    Returns:
        List of readable sockets
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.get_event_loop_policy().new_event_loop()

    readable = []
    for sock in [client_sock, target_sock]:
        try:
            if await loop.sock_recv(sock, 1):
                readable.append(sock)
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass

    return readable


def relay_data_async(client_sock, target_sock):
    """Efficiently relays data bidirectionally between client_sock and target_sock.

    Uses a dedicated event loop to avoid deprecated get_event_loop() patterns.

    Args:
        client_sock: Client socket
        target_sock: Target socket
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        # Use two separate buffers for better performance
        client_to_target = bytearray(BUFFER_SIZE)
        target_to_client = bytearray(BUFFER_SIZE)

        while True:
            try:
                r = loop.run_until_complete(
                    asyncio.wait_for(_async_select(client_sock, target_sock), timeout=2.0)
                )
            except asyncio.TimeoutError:
                r = []
            except Exception as exc:
                logger.error(f"Unexpected error during async relay: {exc}", exc_info=True)
                break

            if not r:
                # Check if connections are still alive
                if client_sock.fileno() == -1 or target_sock.fileno() == -1:
                    break

            if client_sock in r:
                view = memoryview(client_to_target)
                bytes_read = client_sock.recv_into(view)
                if not bytes_read:
                    break
                target_sock.sendall(view[:bytes_read])

            if target_sock in r:
                view = memoryview(target_to_client)
                bytes_read = target_sock.recv_into(view)
                if not bytes_read:
                    break
                client_sock.sendall(view[:bytes_read])

    except Exception as relay_err:
        logger.error(f"Error during relay: {relay_err}")

    finally:
        try:
            loop.close()
        except Exception as exc:
            logger.error(f"Error closing event loop during cleanup: {exc}", exc_info=True)
        for sock in [client_sock, target_sock]:
            try:
                sock.close()
            except (OSError, AttributeError):
                pass


class OptimizedProxy(http.server.BaseHTTPRequestHandler):
    """Optimized HTTP/HTTPS proxy handler."""

    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.proxy_http_request()

    def do_POST(self):
        self.proxy_http_request()

    def do_PUT(self):
        self.proxy_http_request()

    def do_DELETE(self):
        self.proxy_http_request()

    def do_HEAD(self):
        self.proxy_http_request()

    def do_CONNECT(self):
        """Handle HTTPS CONNECT requests."""
        target_host = "unknown"
        target_port = "unknown"

        try:
            # Parse target address
            target_host, target_port = self.path.split(':', 1)
            target_port = int(target_port)

            eastern = pytz.timezone('US/Eastern')
            timestamp = datetime.now(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
            client_ip = self.client_address[0] if hasattr(self, 'client_address') else 'Unknown'
            logger.info(f"[{timestamp}] CONNECT request from {client_ip} to {target_host}:{target_port}")

            # Connect to target server
            target_sock = socket.create_connection((target_host, target_port), timeout=30)

            # Send 200 Connection Established response
            try:
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                target_sock.close()
                return

            # Create connection pipes
            client_socket = self.connection

            # Set reasonable timeouts
            try:
                client_socket.settimeout(30)
                target_sock.settimeout(30)
            except (OSError, AttributeError):
                target_sock.close()
                return

            # Start bidirectional relay
            _relay_sockets(client_socket, target_sock)

        except ValueError:
            try:
                self.send_error(400, "Bad Request: Invalid target address")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        except (socket.timeout, socket.gaierror):
            try:
                self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        except (ConnectionRefusedError, OSError) as conn_err:
            try:
                if hasattr(conn_err, 'errno') and conn_err.errno == 9:
                    return
                self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        except Exception as exc:
            try:
                logger.error(f"CONNECT error: {exc}")
                self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def proxy_http_request(self):
        """Handle regular HTTP requests (not HTTPS via CONNECT)."""
        url = self.path

        if url.startswith('https://'):
            logger.warning("Client tried to send HTTPS directly. Use CONNECT for HTTPS tunneling")
            self.send_error(501, "HTTPS GET/POST proxy not implemented (use CONNECT)")
            return

        try:
            parts = urlsplit(url)
            netloc = parts.netloc
            path = parts.path
            query = parts.query
            fragment = parts.fragment

            full_path = path
            if query:
                full_path += '?' + query
            if fragment:
                full_path += '#' + fragment

            # Check if client accepts gzip encoding
            accept_encoding = self.headers.get('Accept-Encoding', '')
            supports_gzip = 'gzip' in accept_encoding.lower()

            headers = {}
            for h in self.headers:
                if h.lower() not in ['proxy-connection', 'transfer-encoding', 'connection']:
                    headers[h] = self.headers[h]

            # Add support for gzip if client accepts it
            if supports_gzip and 'Accept-Encoding' not in headers:
                headers['Accept-Encoding'] = 'gzip'

            # Use connection pool
            conn = connection_pool.get_connection(netloc)

            if self.command == 'GET':
                conn.request(self.command, full_path, headers=headers)
            else:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length) if content_length > 0 else None
                conn.request(self.command, full_path, body=body, headers=headers)

            response = conn.getresponse()

            self.send_response(response.status)

            # Prepare for potential gzip compression
            for h, v in response.getheaders():
                if h.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(h, v)

            self.end_headers()

            # Read response content in larger chunks
            content = b''
            while True:
                chunk = response.read(BUFFER_SIZE)
                if not chunk:
                    break
                content += chunk

            # Return the connection to the pool
            connection_pool.release_connection(netloc, conn)

            # Send response data to client
            self.wfile.write(content)

        except (BrokenPipeError, ConnectionResetError, OSError) as conn_err:
            if hasattr(conn_err, 'errno') and conn_err.errno == 9:
                return
            logger.error(f"Connection error during HTTP proxy request: {conn_err}")
            try:
                self.send_error(502, "Bad Gateway")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        except Exception as exc:
            logger.error(f"Error during HTTP proxy request: {exc}")
            try:
                self.send_error(502, "Bad Gateway")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass


def start_proxy_server(proxy_port: int):
    """Start the optimized proxy server.

    Args:
        proxy_port: Port to run proxy server on
    """
    handler = OptimizedProxy
    logger.info(f"Starting optimized proxy on port {proxy_port}")

    try:
        # Enable address reuse to avoid "address already in use" errors
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer(("", proxy_port), handler) as httpd:
            httpd.serve_forever()
    except Exception as exc:
        logger.error(f"Failed to start proxy: {exc}")
