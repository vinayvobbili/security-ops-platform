import http.server
import socketserver
import socket  # Ensure socket is imported
import select  # For non-blocking I/O in relay
import ssl
import os
import http.client  # For making HTTP requests to target (though CONNECT bypasses it for body)

# Define the port you want the proxy to listen on
PORT = 8080


class SimpleProxy(http.server.SimpleHTTPRequestHandler):
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
            # Use socket.create_connection for robust connection
            target_sock = socket.create_connection((target_host, target_port), timeout=60)

            # Send 200 OK to the client to establish the tunnel
            self.send_response(200)
            self.send_header('Proxy-agent', self.server_version)
            self.end_headers()

            # Now, relay data between client and target
            # self.connection is the socket connected to the client (your Mac)
            self.relay_data(self.connection, target_sock)

        except Exception as e:
            print(f"CONNECT error establishing tunnel to {target_host}:{target_port}: {e}")
            self.send_error(502, "Bad Gateway")
            # Ensure connections are closed if an error occurs
            try:
                self.connection.close()
            except:
                pass
            try:
                if 'target_sock' in locals() and target_sock:
                    target_sock.close()
            except:
                pass

    def proxy_http_request(self):
        # This part handles regular HTTP requests (not HTTPS via CONNECT)
        url = self.path

        if url.startswith('https://'):
            print(f"Warning: Client tried to send HTTPS GET/POST directly. Use CONNECT for HTTPS tunneling: {url}")
            self.send_error(501, "HTTPS GET/POST proxy not implemented (use CONNECT)")
            return

        try:
            parts = http.client.urlsplit(url)
            netloc = parts.netloc
            path = parts.path
            query = parts.query
            fragment = parts.fragment

            full_path = path
            if query:
                full_path += '?' + query
            if fragment:
                full_path += '#' + fragment

            headers = {}
            for h in self.headers:
                # Filter out proxy-specific headers and connection headers that might cause issues
                if h.lower() not in ['proxy-connection', 'transfer-encoding', 'connection']:
                    headers[h] = self.headers[h]

            # Use http.client for internal request to the destination
            conn = http.client.HTTPConnection(netloc)

            if self.command == 'GET':
                conn.request(self.command, full_path, headers=headers)
            else:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length) if content_length > 0 else None
                conn.request(self.command, full_path, body=body, headers=headers)

            response = conn.getresponse()

            # Send response back to the client
            self.send_response(response.status)
            for h, v in response.getheaders():
                # Filter out problematic headers from response
                if h.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(h, v)
            self.end_headers()
            self.wfile.write(response.read())
            conn.close()  # Close connection to target
        except Exception as e:
            print(f"Error during HTTP proxy request: {e}")
            self.send_error(502, "Bad Gateway")

    def relay_data(self, client_sock, target_sock):
        """Relays data bidirectionally between client_sock and target_sock."""
        sockets = [client_sock, target_sock]
        try:
            while True:
                # Wait until one of the sockets is ready for reading
                # Using select.select for non-blocking I/O
                readable, _, _ = select.select(sockets, [], [], 1)  # 1 second timeout for polling

                if not readable:
                    # If no data for 1 second, check if connections are still alive
                    # This helps prevent infinite loops if one side closes silently
                    if client_sock.fileno() == -1 or target_sock.fileno() == -1:
                        break  # One of the sockets is closed, break out

                for sock in readable:
                    if sock is client_sock:
                        data = client_sock.recv(4096)
                        if not data:
                            return  # Client closed connection
                        target_sock.sendall(data)
                    elif sock is target_sock:
                        data = target_sock.recv(4096)
                        if not data:
                            return  # Target closed connection
                        client_sock.sendall(data)
        except Exception as e:
            print(f"Error during relay: {e}")
        finally:
            # Ensure both sockets are closed when relay ends
            try:
                client_sock.close()
            except:
                pass
            try:
                target_sock.close()
            except:
                pass


Handler = SimpleProxy

print(f"Starting proxy on port {PORT}")
try:
    # Use ThreadingTCPServer to handle multiple concurrent connections
    with socketserver.ThreadingTCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()
except Exception as e:
    print(f"Failed to start proxy: {e}")
    print("This often means the port is in use or you need Administrator privileges to bind to it.")
    print("Try a higher port number (e.g., 8080 or 8888) if you're not running as admin.")
    input("Press Enter to exit...")  # Keep window open for manual exit
