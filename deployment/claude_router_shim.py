"""Front-door shim for ir-claude-router (claude-code-router on 8050).

Adds two things ccr lacks for vanilla `claude` clients:
  1. `GET /v1/models` returning claude-prefixed entries so Claude Code's
     `/model` picker can discover local LLMs (it filters to ids starting
     with `claude` or `anthropic`).
  2. Aliases for human-friendly model names. The picker shows
     `claude-qwen3-32b`; the shim rewrites this to ccr's expected
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

MODEL_MAP: dict[str, str] = {
    "claude-qwen3-32b": "qwen,/Users/vvobbilichetty/models/Qwen3-32B-8bit",
    "claude-glm-4.7-flash": "glm,glm-4.7-flash",
    "claude-laguna": "laguna,laguna-xs.2:q8_0",
}
DEFAULT_ALIAS = "claude-qwen3-32b"

DISPLAY_NAMES = {
    "claude-qwen3-32b": "Qwen3 32B",
    "claude-glm-4.7-flash": "GLM 4.7 Flash",
    "claude-laguna": "Laguna xs.2",
}

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

    if full_path == "v1/messages" and body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            alias = payload.get("model") or DEFAULT_ALIAS
            payload["model"] = MODEL_MAP.get(alias, alias)
            body = json.dumps(payload).encode()

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {"host", "content-length"}
    }

    upstream = client.build_request(
        request.method,
        "/" + full_path,
        params=request.query_params,
        headers=headers,
        content=body,
    )
    response = await client.send(upstream, stream=True)

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
