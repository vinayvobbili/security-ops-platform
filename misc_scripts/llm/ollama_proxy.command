#!/bin/bash
cd "$(dirname "$0")" || exit 1

LOG="ollama_proxy.log"

nohup python3.14 - >> "$LOG" 2>&1 << 'PROXY' &
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import URLError

API_KEY = "some-secret-key-here"  # change this
MODEL = "qwen3:32b"
PORT = 11435

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
                "http://localhost:11434/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req) as resp:
                result = resp.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(result)
        except URLError as e:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def log_message(self, format, *args):
        print(args[0])

HTTPServer(("0.0.0.0", PORT), ProxyHandler).serve_forever()
PROXY

echo ""
echo "  Ollama proxy started on port 11435 (PID: $!)"
echo "  Logs: $(pwd)/$LOG"
echo ""
echo "  You can close this window — the proxy keeps running."
echo "  To stop it later:  kill $!"
echo ""
