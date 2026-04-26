#!/usr/bin/env python3.14
"""Ollama proxy server - hides model name behind an API key."""

import json
import os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import URLError
import socket

API_KEY = os.environ.get("OLLAMA_PROXY_API_KEY", "change-me")
MODEL = os.environ["OLLAMA_PROXY_MODEL"]
PORT = int(os.environ.get("OLLAMA_PROXY_PORT", "11435"))
TIMEOUT = int(os.environ.get("OLLAMA_PROXY_TIMEOUT", "300"))

class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/chat":
            self.send_error(404)
            return

        if self.headers.get("Authorization") != f"Bearer {API_KEY}":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized"}).encode())
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))

        payload = {"model": MODEL, "messages": body.get("messages", []), "stream": False}
        for key in ("format", "options", "temperature", "top_p", "top_k", "keep_alive"):
            if key in body:
                payload[key] = body[key]
        payload = json.dumps(payload).encode()

        try:
            req = Request(
                "http://localhost:11433/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=TIMEOUT) as resp:
                result = resp.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(result)
        except socket.timeout:
            self.send_response(504)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "request timed out"}).encode())
        except URLError as e:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def log_message(self, fmt, *args):  # noqa: A002
        print(args[0])

ThreadingHTTPServer(("0.0.0.0", PORT), ProxyHandler).serve_forever()  # type: ignore[arg-type]
