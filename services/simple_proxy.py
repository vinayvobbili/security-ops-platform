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
        # This handles HTTPS tunneling
        target_host, target_port = self.path.split(':', 1)
        target_port = int(target_port)

        print(f"CONNECT request to {target_host}:{target_port}")

        try:
            # Establish direct connection to the target server
            target_sock = socket.create_connection((target_host, target_port), timeout=60)

            # Send 200 OK to the client to establish the tunnel
            self.send_response(200)
            self.send_header('Proxy-agent', self.server_version)
            self.end_headers()

            # Set sockets to non-blocking for async operation
            self.connection.setblocking(False)
            target_sock.setblocking(False)

            # Use ThreadPoolExecutor for async operation
            future = http_pool.submit(
                self.relay_data_async,
                self.connection,
                target_sock
            )

        except Exception as e:
            print(f"CONNECT error establishing tunnel to {target_host}:{target_port}: {e}")
            self.send_error(502, "Bad Gateway")
            try:
                self.connection.close()
            except:
                pass

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

    def relay_data_async(self, client_sock, target_sock):
        """Efficiently relays data bidirectionally between client_sock and target_sock."""
        try:
            # Use two separate buffers for better performance
            client_to_target = bytearray(BUFFER_SIZE)
            target_to_client = bytearray(BUFFER_SIZE)

            while True:
                # Select with a timeout to prevent high CPU usage
                r, _, _ = asyncio.get_event_loop().run_until_complete(
                    asyncio.wait_for(
                        self._async_select(client_sock, target_sock),
                        timeout=2.0
                    )
                )

                if not r:
                    # Check if connections are still alive
                    if client_sock.fileno() == -1 or target_sock.fileno() == -1:
                        break

                if client_sock in r:
                    # Use memory view for zero-copy slicing
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

        except (ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
            # Common connection errors - log but don't clutter logs
            pass
        except Exception as e:
            print(f"Error during relay: {e}")
        finally:
            for sock in [client_sock, target_sock]:
                try:
                    sock.close()
                except:
                    pass

    async def _async_select(self, client_sock, target_sock):
        """Async-compatible version of select operation"""
        loop = asyncio.get_event_loop()
        readable = []
        for sock in [client_sock, target_sock]:
            try:
                if await loop.sock_recv(sock, 1, peek=True):
                    readable.append(sock)
            except:
                pass
        return readable, [], []


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
    # Setup asyncio event loop
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    main()
