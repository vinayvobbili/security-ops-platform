import asyncio
import http.client
import http.server
import socket
import socketserver
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List
from urllib.parse import urlsplit

import select

# Performance optimization constants
PROXY_PORT = 8080
BUFFER_SIZE = 16384  # Increased from default 4096
NUM_WORKERS = 10
MAX_CONNECTIONS = 100

# Global thread pool for HTTP requests
http_pool = ThreadPoolExecutor(max_workers=NUM_WORKERS)


# HTTP connection pool for reusing connections
class ConnectionPool:
    def __init__(self, max_connections=100):
        self.pool: Dict[str, List[http.client.HTTPConnection]] = {}
        self.max_connections = max_connections
        self.lock = threading.RLock()

    def get_connection(self, host):
        with self.lock:
            if host not in self.pool:
                self.pool[host] = []

            if self.pool[host]:
                return self.pool[host].pop()
            else:
                return http.client.HTTPConnection(host)

    def release_connection(self, host, conn):
        with self.lock:
            if host not in self.pool:
                self.pool[host] = []

            if len(self.pool[host]) < self.max_connections:
                self.pool[host].append(conn)
            else:
                conn.close()


# Create a global connection pool
connection_pool = ConnectionPool(max_connections=MAX_CONNECTIONS)


# Optimized proxy handler with connection pooling and async support
class OptimizedProxy(http.server.SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'  # Enable keep-alive

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
        # Parse target address
        target_host, target_port = self.path.split(':', 1)
        target_port = int(target_port)

        print(f"CONNECT request to {target_host}:{target_port}")

        try:
            # Connect to target server
            target_sock = socket.create_connection((target_host, target_port), timeout=60)

            # Send 200 Connection Established response
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")

            # Create connection pipes
            client_socket = self.connection

            # Set reasonable timeouts
            client_socket.settimeout(60)
            target_sock.settimeout(60)

            # Start bidirectional relay
            self._relay_sockets(client_socket, target_sock)

            return

        except Exception as e:
            print(f"CONNECT error: {e}")
            self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            return

    def _relay_sockets(self, client, target):
        """Simple synchronous socket relay that avoids HTTP processing"""
        sockets = [client, target]

        # Keep transferring data between client and target
        while True:
            # Wait until a socket is ready to be read
            readable, _, exceptional = select.select(sockets, [], sockets, 60)

            if exceptional:
                break

            if not readable:
                continue  # Timeout, try again

            for sock in readable:
                # Determine the destination socket
                dest = target if sock is client else client

                try:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        return  # Connection closed
                    dest.sendall(data)
                except (socket.error, ConnectionResetError, BrokenPipeError):
                    return  # Any socket error means we're done

    def proxy_http_request(self):
        # This part handles regular HTTP requests (not HTTPS via CONNECT)
        url = self.path

        if url.startswith('https://'):
            print(f"Warning: Client tried to send HTTPS directly. Use CONNECT for HTTPS tunneling")
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
            is_gzipped = False
            for h, v in response.getheaders():
                if h.lower() == 'content-encoding' and 'gzip' in v.lower():
                    is_gzipped = True
                if h.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(h, v)

            self.end_headers()

            # Read response content in larger chunks for better performance
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

        except Exception as e:
            print(f"Error during HTTP proxy request: {e}")
            self.send_error(502, "Bad Gateway")

    def relay_data(self, client_sock, target_sock):
        """Synchronous wrapper to run the async relay function in a thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.relay_data_async(client_sock, target_sock))
        finally:
            loop.close()

    async def relay_data_async(self, client_sock, target_sock):
        """Efficiently relays data bidirectionally between client_sock and target_sock using asyncio streams."""
        client_writer = None
        target_writer = None

        try:
            # Create asyncio stream readers/writers from the sockets
            client_reader, client_writer = await asyncio.open_connection(sock=client_sock)
            target_reader, target_writer = await asyncio.open_connection(sock=target_sock)

            async def relay(reader, writer, name):
                try:
                    while True:
                        data = await reader.read(BUFFER_SIZE)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except (ConnectionError, BrokenPipeError):
                    pass
                except Exception as e:
                    print(f"Error in {name} relay: {e}")

            # Create tasks for bidirectional data relay
            tasks = [
                asyncio.create_task(relay(client_reader, target_writer, "client->target")),
                asyncio.create_task(relay(target_reader, client_writer, "target->client"))
            ]

            # Wait until either direction completes
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            # Cancel pending tasks
            for task in pending:
                task.cancel()

            # Wait for cancelled tasks to finish
            if pending:
                try:
                    await asyncio.wait(pending, return_when=asyncio.ALL_COMPLETED)
                except asyncio.CancelledError:
                    pass

        except Exception as e:
            print(f"Error setting up relay: {e}")
        finally:
            # Close stream writers
            if client_writer:
                try:
                    client_writer.close()
                    await client_writer.wait_closed()
                except Exception:
                    pass

            if target_writer:
                try:
                    target_writer.close()
                    await target_writer.wait_closed()
                except Exception:
                    pass

            # No need to close the original sockets as they are managed by the writers


def main():
    # Enable address reuse to avoid "address already in use" errors
    socketserver.TCPServer.allow_reuse_address = True

    print(f"Starting optimized proxy on port {PROXY_PORT}")
    try:
        # Use ThreadingTCPServer for concurrent connections
        with socketserver.ThreadingTCPServer(("", PROXY_PORT), OptimizedProxy) as httpd:
            httpd.serve_forever()
    except Exception as e:
        print(f"Failed to start proxy: {e}")
        print("This often means the port is in use or you need Administrator privileges to bind to it.")


if __name__ == "__main__":
    # Create a new event loop instead of trying to get the current one
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    main()
