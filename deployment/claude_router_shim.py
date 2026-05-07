"""Front-door shim for ir-claude-router (claude-code-router on 8050).

Adds two things ccr lacks for vanilla `claude` clients:
  1. `GET /v1/models` returning the local-model roster, for SDK / curl /
     IDE-plugin discovery. Claude Code's `/model` picker is hardwired to
     three tier names (Opus / Sonnet / Haiku) and does NOT read this
     endpoint — clients wire each tier to one of these ids via the
     `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL` env vars.
  2. Aliases for human-friendly model names. Clients send a friendly id
     (e.g. `glm-4.7-flash`); the shim rewrites it to ccr's expected
     `provider,model` form on each `/v1/messages` request.

Everything else (including streaming SSE) is proxied unchanged to ccr.
"""
from __future__ import annotations

import json
import os
from typing import AsyncIterator

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

CCR_UPSTREAM = os.environ.get("CCR_UPSTREAM", "http://127.0.0.1:8050")
SHIM_HOST = os.environ.get("CCR_SHIM_HOST", "0.0.0.0")
SHIM_PORT = int(os.environ.get("CCR_SHIM_PORT", "8051"))
SHIM_APIKEY = os.environ["CCR_APIKEY"]

# Optional: dump every /v1/messages request body to disk for diagnostics.
# Set CCR_SHIM_CAPTURE_DIR=/tmp/shim_captures to enable.
CAPTURE_DIR = os.environ.get("CCR_SHIM_CAPTURE_DIR", "")

MODEL_MAP: dict[str, str] = {
    "glm-4.7-flash": "glm,glm-4.7-flash",
    "glm-4.7-flash-think": "glm,glm-4.7-flash",
    "qwen2.5-coder-32b": "coder,qwen2.5-coder-32b",
    "laguna": "laguna,laguna-xs.2:q8_0",
}
DEFAULT_ALIAS = "glm-4.7-flash"

DISPLAY_NAMES = {
    "glm-4.7-flash": "GLM 4.7 Flash",
    "glm-4.7-flash-think": "GLM 4.7 Flash (think-tagged)",
    "qwen2.5-coder-32b": "Qwen2.5 Coder 32B",
    "laguna": "Laguna xs.2",
}

# Aliases that should ask the model to wrap chain-of-thought in
# <think>...</think> tags so the upstream's deepseek_r1 reasoning parser
# can route it to `reasoning_content` instead of leaking prose into
# `content`. GLM-Flash under Claude Code's stock system prompt verbalizes
# its reasoning without markers — this nudges it back.
THINK_TAG_ALIASES = {"glm-4.7-flash-think"}

THINK_TAG_INSTRUCTION = (
    "If you write any internal reasoning or planning before answering, "
    "wrap it in <think>...</think> tags. You MUST always emit the "
    "user-facing answer (or tool call) AFTER the closing </think>. "
    "Never end your response inside <think> or with empty content."
)

# Aliases whose upstream streaming is broken for tool calls (vllm-mlx
# qwen/hermes parsers stream JSON as content deltas instead of tool_use
# blocks). For these, force non-streaming upstream and synthesize Anthropic
# SSE events from the buffered response. Trades typewriter effect for
# correct tool_use block rendering — fine for a coding helper since tool
# calls aren't visible until the user confirms anyway.
BUFFER_TO_STREAM_ALIASES = {"qwen2.5-coder-32b"}

# Map upstream HTTP status to Anthropic error type. Anything outside this
# table falls back to api_error. Used by the error sanitizer below.
ERROR_TYPE_BY_STATUS = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    413: "request_too_large",
    429: "rate_limit_error",
    500: "api_error",
    502: "api_error",
    503: "api_error",
    504: "api_error",
    529: "overloaded_error",
}


def _sanitized_error_response(status_code: int, upstream_body: bytes | None) -> JSONResponse:
    """Return a clean Anthropic-format error, never leaking the upstream body.

    ccr's default error shape is a Node stack trace that exposes the operator's
    home directory, node version, and the @musistudio/claude-code-router package
    path. Clients only need to know the request failed; the real body goes to
    server logs for the operator to debug.
    """
    error_type = ERROR_TYPE_BY_STATUS.get(status_code, "api_error")
    generic_message = {
        400: "Invalid request",
        401: "Authentication failed",
        403: "Permission denied",
        404: "Not found",
        413: "Request too large",
        429: "Rate limited",
    }.get(status_code, "Upstream error")

    if upstream_body:
        try:
            preview = upstream_body[:2000].decode(errors="replace")
        except Exception:
            preview = "<binary body>"
        print(f"[shim] upstream {status_code}: {preview}", flush=True)

    return JSONResponse(
        status_code=status_code,
        content={
            "type": "error",
            "error": {"type": error_type, "message": generic_message},
        },
    )


def _synth_anthropic_sse(message: dict) -> AsyncIterator[bytes]:
    """Convert a non-streaming Anthropic Messages response into the SSE
    event stream Claude Code expects. Yields fully-formed SSE byte chunks."""
    async def _gen() -> AsyncIterator[bytes]:
        def _ev(event: str, data: dict) -> bytes:
            return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()

        msg_meta = {
            "id": message.get("id", ""),
            "type": "message",
            "role": message.get("role", "assistant"),
            "content": [],
            "model": message.get("model", ""),
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }
        yield _ev("message_start", {"type": "message_start", "message": msg_meta})

        for idx, block in enumerate(message.get("content", []) or []):
            btype = block.get("type")
            if btype == "text":
                yield _ev("content_block_start", {
                    "type": "content_block_start", "index": idx,
                    "content_block": {"type": "text", "text": ""},
                })
                yield _ev("content_block_delta", {
                    "type": "content_block_delta", "index": idx,
                    "delta": {"type": "text_delta", "text": block.get("text", "")},
                })
                yield _ev("content_block_stop", {
                    "type": "content_block_stop", "index": idx,
                })
            elif btype == "tool_use":
                yield _ev("content_block_start", {
                    "type": "content_block_start", "index": idx,
                    "content_block": {
                        "type": "tool_use",
                        "id": block.get("id", ""),
                        "name": block.get("name", ""),
                        "input": {},
                    },
                })
                yield _ev("content_block_delta", {
                    "type": "content_block_delta", "index": idx,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": json.dumps(block.get("input", {})),
                    },
                })
                yield _ev("content_block_stop", {
                    "type": "content_block_stop", "index": idx,
                })

        yield _ev("message_delta", {
            "type": "message_delta",
            "delta": {
                "stop_reason": message.get("stop_reason"),
                "stop_sequence": message.get("stop_sequence"),
            },
            "usage": message.get("usage", {}),
        })
        yield _ev("message_stop", {"type": "message_stop"})

    return _gen()


def _inject_think_instruction(payload: dict) -> None:
    """Append a 'use <think> tags' nudge to the request's system field."""
    system = payload.get("system")
    if system is None:
        payload["system"] = THINK_TAG_INSTRUCTION
        return
    if isinstance(system, str):
        payload["system"] = system.rstrip() + "\n\n" + THINK_TAG_INSTRUCTION
        return
    if isinstance(system, list):
        system.append({"type": "text", "text": THINK_TAG_INSTRUCTION})


def _strip_billing_header(payload: dict) -> None:
    """Drop Claude Code's `x-anthropic-billing-header` system block.

    Why: Claude Code injects a small system block of the form
    `x-anthropic-billing-header: cc_version=...; cc_entrypoint=cli; cch=<hash>`
    whose `cch` value rotates every turn. Anthropic's cloud uses it for
    billing/conversation tracking; local upstreams (vllm-mlx) just see it as
    81 bytes of system text. With our SimpleEngine prefix-KV cache, that
    rotating field changes the system-prefix hash each turn → every turn is
    a cache miss → 200s prefill on a 38K-token system block. Removing this
    block makes the system prefix byte-stable turn-over-turn so the cache
    actually hits.
    """
    system = payload.get("system")
    if not isinstance(system, list):
        return
    payload["system"] = [
        b for b in system
        if not (
            isinstance(b, dict)
            and isinstance(b.get("text"), str)
            and b["text"].lstrip().lower().startswith("x-anthropic-billing-header")
        )
    ]


app = FastAPI(title="ir-claude-router shim")
client = httpx.AsyncClient(base_url=CCR_UPSTREAM, timeout=httpx.Timeout(None))


def _check_auth(request: Request) -> None:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if auth.removeprefix("Bearer ") != SHIM_APIKEY:
        raise HTTPException(status_code=401, detail="Invalid bearer token")


@app.get("/v1/models")
async def list_models(request: Request) -> JSONResponse:
    _check_auth(request)
    data = [
        {
            "id": alias,
            "type": "model",
            "display_name": DISPLAY_NAMES.get(alias, alias),
            "created_at": "2026-05-06T00:00:00Z",
        }
        for alias in MODEL_MAP
    ]
    return JSONResponse(
        {
            "data": data,
            "has_more": False,
            "first_id": data[0]["id"],
            "last_id": data[-1]["id"],
        }
    )


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(full_path: str, request: Request) -> Response:
    _check_auth(request)
    body = await request.body()

    client_wants_stream = False
    buffered_alias = False

    if full_path == "v1/messages" and body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            alias = payload.get("model") or DEFAULT_ALIAS
            payload["model"] = MODEL_MAP.get(alias, alias)
            _strip_billing_header(payload)
            if alias in THINK_TAG_ALIASES:
                _inject_think_instruction(payload)
            if alias in BUFFER_TO_STREAM_ALIASES and payload.get("stream"):
                client_wants_stream = True
                buffered_alias = True
                payload["stream"] = False
            if CAPTURE_DIR:
                try:
                    os.makedirs(CAPTURE_DIR, exist_ok=True)
                    import time
                    fname = f"{int(time.time()*1000)}-{alias}.json"
                    with open(os.path.join(CAPTURE_DIR, fname), "wb") as f:
                        f.write(json.dumps(payload, indent=2).encode())
                except Exception:
                    pass
            body = json.dumps(payload).encode()

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {"host", "content-length", "accept"}
    }
    if buffered_alias:
        headers["accept"] = "application/json"

    upstream = client.build_request(
        request.method,
        "/" + full_path,
        params=request.query_params,
        headers=headers,
        content=body,
    )
    try:
        response = await client.send(upstream, stream=True)
    except httpx.RequestError as exc:
        print(f"[shim] upstream connect failed: {exc!r}", flush=True)
        return JSONResponse(
            status_code=502,
            content={
                "type": "error",
                "error": {"type": "api_error", "message": "Upstream unavailable"},
            },
        )

    if response.status_code >= 400:
        try:
            err_body = await response.aread()
        finally:
            await response.aclose()
        return _sanitized_error_response(response.status_code, err_body)

    if buffered_alias and client_wants_stream and response.status_code == 200:
        try:
            full = await response.aread()
            message = json.loads(full)
        finally:
            await response.aclose()
        return StreamingResponse(
            _synth_anthropic_sse(message),
            status_code=200,
            headers={"content-type": "text/event-stream", "cache-control": "no-cache"},
        )

    async def iter_body() -> AsyncIterator[bytes]:
        try:
            async for chunk in response.aiter_raw():
                yield chunk
        finally:
            await response.aclose()

    resp_headers = {
        k: v
        for k, v in response.headers.items()
        if k.lower() not in {"content-length", "content-encoding", "transfer-encoding"}
    }
    return StreamingResponse(
        iter_body(), status_code=response.status_code, headers=resp_headers
    )


if __name__ == "__main__":
    uvicorn.run(app, host=SHIM_HOST, port=SHIM_PORT, log_level="info")
