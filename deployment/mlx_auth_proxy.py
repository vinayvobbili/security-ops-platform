"""Bearer-auth reverse proxy in front of mac-m1's local mlx-lm.

Listens on 0.0.0.0:11435 and forwards every request to http://127.0.0.1:8000.
Validates `Authorization: Bearer <token>` on every request, rejecting with 401
if missing or wrong. Streaming responses (SSE chat completions) pass through.

Also hides the underlying model: clients don't need to send a `model` field
(if they do, it's overwritten with MLX_BACKEND_MODEL before forwarding), and
`/v1/models` is rewritten to expose only MLX_PUBLIC_MODEL.

Why this exists: vllm-mlx supports `--api-key`, but turning it on at the
underlying server would also force lab-vm's reverse-tunnel consumers
(the security assistant bot, the Windows triage agent, scheduler) to send the token. To keep that path
unchanged, mlx-lm binds to 127.0.0.1:8000 (only reachable via local
connections, including SSH-tunneled ones) and this proxy is the sole
auth-enforced surface for direct corp-network access on m1's IP.

Env vars:
  MLX_AUTH_HOST      Bind host. Default: 0.0.0.0
  MLX_AUTH_PORT      Bind port. Default: 11435
  MLX_UPSTREAM       Upstream base URL. Default: http://127.0.0.1:8000
  MLX_BEARER_TOKEN   Required token. Proxy refuses to start if empty.
  MLX_BACKEND_MODEL  Model name sent to mlx-lm. Default: mlx-community/GLM-4.7-Flash-8bit
  MLX_PUBLIC_MODEL   Model id surfaced to clients via /v1/models. Default: default
"""

import json
import logging
import os
import sys
import time

import requests
from flask import Flask, Response, jsonify, request, stream_with_context
from waitress import serve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("mlx-auth-proxy")

HOST = os.environ.get("MLX_AUTH_HOST", "0.0.0.0")
PORT = int(os.environ.get("MLX_AUTH_PORT", "11435"))
UPSTREAM = os.environ.get("MLX_UPSTREAM", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("MLX_BEARER_TOKEN", "").strip()
BACKEND_MODEL = os.environ.get("MLX_BACKEND_MODEL", "mlx-community/GLM-4.7-Flash-8bit").strip()
PUBLIC_MODEL = os.environ.get("MLX_PUBLIC_MODEL", "default").strip()

if not TOKEN:
    logger.error("MLX_BEARER_TOKEN is empty — refusing to start an unauthenticated proxy")
    sys.exit(1)

app = Flask(__name__)

HOP_BY_HOP_RESPONSE_HEADERS = {
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "upgrade",
}


def _authorized() -> bool:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth[len("Bearer "):].strip() == TOKEN


@app.route("/v1/models", methods=["GET"])
def models():
    if not _authorized():
        return jsonify({"error": {"message": "missing or invalid bearer token", "type": "unauthorized"}}), 401
    return jsonify({
        "object": "list",
        "data": [{
            "id": PUBLIC_MODEL,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "ir-mlx",
        }],
    })


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy(path: str):
    if not _authorized():
        return jsonify({"error": {"message": "missing or invalid bearer token", "type": "unauthorized"}}), 401

    url = f"{UPSTREAM}/{path}" if path else UPSTREAM
    qs = request.query_string.decode()
    if qs:
        url = f"{url}?{qs}"

    fwd_headers = {
        k: v for k, v in request.headers
        if k.lower() not in ("host", "authorization", "content-length")
    }
    body = request.get_data()

    # Override the model field for any JSON POST so callers don't need to know
    # (or be able to pick) the underlying model. If the body isn't JSON or
    # doesn't have a model field, leave it alone.
    if request.method == "POST" and body:
        ctype = (request.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype or body.lstrip().startswith(b"{"):
            try:
                payload = json.loads(body)
                if isinstance(payload, dict):
                    payload["model"] = BACKEND_MODEL
                    body = json.dumps(payload).encode()
                    fwd_headers["Content-Type"] = "application/json"
            except (ValueError, TypeError):
                pass

    try:
        upstream = requests.request(
            method=request.method,
            url=url,
            headers=fwd_headers,
            data=body,
            stream=True,
            timeout=600,
        )
    except Exception as e:
        logger.exception("upstream connect failed")
        return jsonify({"error": {"message": f"upstream connect: {e}", "type": "upstream_error"}}), 502

    resp_headers = [
        (k, v) for k, v in upstream.headers.items()
        if k.lower() not in HOP_BY_HOP_RESPONSE_HEADERS
    ]
    upstream_ctype = (upstream.headers.get("content-type") or "").lower()

    # JSON response: rewrite the `model` field in-place so clients only see PUBLIC_MODEL.
    if "application/json" in upstream_ctype:
        raw = upstream.content
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and "model" in obj:
                obj["model"] = PUBLIC_MODEL
                raw = json.dumps(obj).encode()
        except (ValueError, TypeError):
            pass
        return Response(raw, status=upstream.status_code, headers=resp_headers)

    # SSE stream: parse each `data: {...}` line, rewrite the `model` field.
    if "text/event-stream" in upstream_ctype:
        return Response(stream_with_context(_rewrite_sse(upstream)), status=upstream.status_code, headers=resp_headers)

    # Anything else: pass through unchanged.
    def _iter():
        for chunk in upstream.iter_content(chunk_size=None):
            if chunk:
                yield chunk
    return Response(stream_with_context(_iter()), status=upstream.status_code, headers=resp_headers)


def _rewrite_sse(upstream):
    """Iterate SSE events, rewriting the `model` field in each `data:` JSON payload."""
    buffer = b""
    for chunk in upstream.iter_content(chunk_size=None):
        if not chunk:
            continue
        buffer += chunk
        while b"\n\n" in buffer:
            event, buffer = buffer.split(b"\n\n", 1)
            yield _rewrite_sse_event(event) + b"\n\n"
    if buffer:
        yield _rewrite_sse_event(buffer)


def _rewrite_sse_event(event: bytes) -> bytes:
    out = []
    for line in event.split(b"\n"):
        if line.startswith(b"data: "):
            payload = line[6:]
            if payload.strip() == b"[DONE]":
                out.append(line)
                continue
            try:
                obj = json.loads(payload)
                if isinstance(obj, dict) and "model" in obj:
                    obj["model"] = PUBLIC_MODEL
                    out.append(b"data: " + json.dumps(obj).encode())
                    continue
            except (ValueError, TypeError):
                pass
        out.append(line)
    return b"\n".join(out)


if __name__ == "__main__":
    logger.info(f"listening on {HOST}:{PORT} → {UPSTREAM}")
    serve(app, host=HOST, port=PORT, threads=8)
