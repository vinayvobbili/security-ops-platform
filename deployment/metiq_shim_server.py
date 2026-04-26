"""OpenAI-compatible shim in front of the internal LLM gateway.

Translates `POST /v1/chat/completions` (OpenAI schema) into the internal LLM gateway's
`/api/usecases/{id}/chat` call and wraps the response back into an OpenAI
chat-completion JSON object. Falls back to a local mac-m1 mlx-lm endpoint
on any the internal LLM gateway failure, or when the caller asks for something the internal LLM gateway can't do
(tools, streaming).

Why this exists: we want to retire the mac-m3 GLM-4.7-Flash-4bit analysis
process and route default/web-app/scheduler analysis traffic through the internal LLM gateway
(GPT-4.1) without rewriting every call site. All callers already do
`OpenAI(base_url=LLM_BASE_URL).chat.completions.create(...)`, so pointing
`LLM_BASE_URL` at this shim is a one-line config change per caller. See
`project_metiq_default_llm.md` in the lab-vm1 memory for the broader plan.

Behavior:
  - Non-tool, non-stream requests → the internal LLM gateway first, fall back to m1 on failure
  - `tools=` present → skip the internal LLM gateway entirely, reverse-proxy to m1
  - `stream=true` → skip the internal LLM gateway entirely, reverse-proxy streaming response to m1
  - Any the internal LLM gateway exception / non-2xx / timeout → fall back to m1
  - If BOTH the internal LLM gateway and m1 fail, return 502 with both error bodies

Env vars:
  METIQ_SHIM_HOST            Bind host. Default: 127.0.0.1
  METIQ_SHIM_PORT            Bind port. Default: 8011
  METIQ_SHIM_FALLBACK_URL    Fallback base URL. Default: http://localhost:8015/v1
  METIQ_SHIM_TIMEOUT         Per-upstream timeout seconds. Default: 60
  METIQ_SHIM_MODEL_NAME      Reported model name for non-fallback responses. Default: metiq-gpt-4.1
"""

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, Response, jsonify, request, stream_with_context
from waitress import serve

from services.metiq import the internal LLM gatewayClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ir-metiq-shim")

HOST = os.environ.get("METIQ_SHIM_HOST", "127.0.0.1")
PORT = int(os.environ.get("METIQ_SHIM_PORT", "8011"))
# Extra bind addresses (comma-separated host:port pairs) so containers on
# the docker bridge (<internal-host>) can reach the shim via host.docker.internal.
# Default binds to docker0 in addition to the primary HOST/PORT.
EXTRA_LISTEN = os.environ.get("METIQ_SHIM_EXTRA_LISTEN", "<internal-host>")
FALLBACK_URL = os.environ.get("METIQ_SHIM_FALLBACK_URL", "http://localhost:8015/v1").rstrip("/")  # m1 analysis (GLM-4.7-Flash)
TIMEOUT = int(os.environ.get("METIQ_SHIM_TIMEOUT", "60"))
MODEL_NAME = os.environ.get("METIQ_SHIM_MODEL_NAME", "metiq-gpt-4.1")

app = Flask(__name__)
_metiq: Optional[the internal LLM gatewayClient] = None

# Tracks the most recent outcome of a real the internal LLM gateway call so Mission Control
# can distinguish "shim is up, the internal LLM gateway is healthy" from "shim is up, serving
# via fallback because the internal LLM gateway is failing". Only updated by chat_completions
# paths that actually attempt the internal LLM gateway — /v1/models never touches it.
_upstream_state: Dict[str, Any] = {
    "last_success_ts": None,
    "last_failure_ts": None,
    "last_failure_reason": None,
}


def _record_upstream(success: bool, reason: Optional[str] = None) -> None:
    now = time.time()
    if success:
        _upstream_state["last_success_ts"] = now
    else:
        _upstream_state["last_failure_ts"] = now
        _upstream_state["last_failure_reason"] = reason


def _upstream_status() -> Dict[str, Any]:
    s = _upstream_state["last_success_ts"]
    f = _upstream_state["last_failure_ts"]
    if s is None and f is None:
        status = "unknown"
    elif f is None or (s is not None and s >= f):
        status = "healthy"
    else:
        status = "degraded"
    return {
        "status": status,
        "last_success_ts": s,
        "last_failure_ts": f,
        "last_failure_reason": _upstream_state["last_failure_reason"] if status != "healthy" else None,
        "seconds_since_success": (time.time() - s) if s else None,
    }


def _get_client() -> the internal LLM gatewayClient:
    global _metiq
    if _metiq is None:
        _metiq = the internal LLM gatewayClient()
        logger.info(f"metiq client configured={_metiq.is_configured()} endpoint={_metiq.endpoint}")
    return _metiq


def _split_openai_messages(messages: List[Dict[str, Any]]) -> Tuple[str, str, List[Dict[str, Any]]]:
    """Flatten OpenAI messages into (system_prefix, last_user_message, history).

    the internal LLM gateway has no system role and takes (prompt, history) separately. We merge
    all `system` messages into a prefix prepended to the last user turn. All
    prior non-last messages become history entries using the internal LLM gateway's {role, content}
    shape with `User`/`Agent` capitalization.
    """
    systems: List[str] = []
    conv: List[Dict[str, Any]] = []
    for m in messages or []:
        role = (m.get("role") or "").lower()
        content = m.get("content") or ""
        if isinstance(content, list):
            # OpenAI multi-part content — keep only text parts
            content = "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
        if role == "system":
            if content:
                systems.append(content)
            continue
        if role in ("user", "assistant"):
            conv.append({"role": "User" if role == "user" else "Agent", "content": content})

    if not conv:
        return "\n\n".join(systems), "", []

    last = conv[-1]
    history = conv[:-1]
    prompt = last["content"] if last["role"] == "User" else ""
    if systems:
        prompt = "\n\n".join(systems) + ("\n\n" + prompt if prompt else "")
    return "\n\n".join(systems), prompt, history


def _sanitize(text: str) -> str:
    """Strip control characters that break JSON parsers in downstream consumers.

    the internal LLM gateway (GPT-4.1) doesn't honour response_format and may emit literal
    control chars (e.g. newlines) inside JSON string values.  Preserves
    \\n (0x0a), \\r (0x0d), and \\t (0x09) which are valid in most contexts.
    """
    import re
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)


def _wrap_openai_response(content: str, tokens_used: int, model: str) -> Dict[str, Any]:
    content = _sanitize(content)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": int(tokens_used or 0),
            "total_tokens": int(tokens_used or 0),
        },
    }


def _fallback_proxy(path: str, payload: Dict[str, Any], stream: bool) -> Response:
    """Reverse-proxy to the fallback OpenAI-compatible endpoint (m1)."""
    url = f"{FALLBACK_URL}{path}"
    t0 = time.time()
    try:
        if stream:
            upstream = requests.post(url, json=payload, stream=True, timeout=TIMEOUT)
            dt_ms = (time.time() - t0) * 1000.0
            logger.info(f"fallback stream → {url} status={upstream.status_code} took={dt_ms:.0f}ms")

            def _iter():
                for chunk in upstream.iter_content(chunk_size=None):
                    if chunk:
                        yield chunk

            return Response(
                stream_with_context(_iter()),
                status=upstream.status_code,
                content_type=upstream.headers.get("content-type", "text/event-stream"),
            )
        upstream = requests.post(url, json=payload, timeout=TIMEOUT)
        dt_ms = (time.time() - t0) * 1000.0
        logger.info(f"fallback → {url} status={upstream.status_code} took={dt_ms:.0f}ms")
        return Response(upstream.content, status=upstream.status_code, content_type=upstream.headers.get("content-type", "application/json"))
    except Exception as e:
        logger.exception("fallback upstream failed")
        return jsonify({"error": {"message": f"fallback upstream error: {e}", "type": "upstream_error"}}), 502


@app.route("/health", methods=["GET"])
def health():
    try:
        client = _get_client()
        configured = client.is_configured()
    except Exception as e:
        configured = False
        logger.warning(f"metiq client init failed: {e}")
    return jsonify({
        "status": "ok",
        "metiq_configured": configured,
        "fallback_url": FALLBACK_URL,
        "model_name": MODEL_NAME,
        "upstream": _upstream_status(),
    })


@app.route("/v1/models", methods=["GET"])
def models():
    return jsonify({
        "object": "list",
        "data": [
            {"id": MODEL_NAME, "object": "model", "created": int(time.time()), "owned_by": "metiq-shim"},
        ],
        "metiq_shim": {
            "upstream": _upstream_status(),
            "fallback_url": FALLBACK_URL,
            "model_name": MODEL_NAME,
        },
    })


@app.route("/openai/deployments/<deployment>/chat/completions", methods=["POST"])
def azure_style_chat_completions(deployment: str):
    """Azure-OpenAI-shape compat: Azure SDK hits this URL, we route it through
    the same the internal LLM gateway/fallback logic as /v1/chat/completions. Lets vendor apps
    configured for Azure OpenAI (e.g. the DB Security sidecar) use the internal LLM gateway with
    no code change — just point AZURE_OPENAI_ENDPOINT at the shim.
    The `api-version` query param is accepted and ignored."""
    return chat_completions()


@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    messages = payload.get("messages") or []
    has_tools = bool(payload.get("tools") or payload.get("functions"))
    is_stream = bool(payload.get("stream"))

    if has_tools or is_stream:
        reason = "tools" if has_tools else "stream"
        logger.info(f"route=fallback reason={reason} msgs={len(messages)}")
        return _fallback_proxy("/chat/completions", payload, stream=is_stream)

    try:
        client = _get_client()
        if not client.is_configured():
            raise RuntimeError("metiq client not configured")
    except Exception as e:
        _record_upstream(success=False, reason=f"client init: {str(e)[:120]}")
        logger.warning(f"metiq unavailable, falling back: {e}")
        return _fallback_proxy("/chat/completions", payload, stream=False)

    _, prompt, history = _split_openai_messages(messages)
    if not prompt:
        return jsonify({"error": {"message": "no user message in payload", "type": "bad_request"}}), 400

    t0 = time.time()
    try:
        resp = client.chat(message=prompt, history=history, timeout=TIMEOUT)
        dt_ms = (time.time() - t0) * 1000.0
        content = (resp.get("content") or "").strip()
        tokens = resp.get("tokensUsed") or 0
        _record_upstream(success=True)
        logger.info(f"route=metiq msgs={len(messages)} tokens={tokens} took={dt_ms:.0f}ms")
        return jsonify(_wrap_openai_response(content, tokens, MODEL_NAME))
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else 0
        _record_upstream(success=False, reason=f"http {code}")
        logger.warning(f"metiq http {code}, falling back: {e}")
        return _fallback_proxy("/chat/completions", payload, stream=False)
    except Exception as e:
        _record_upstream(success=False, reason=f"{type(e).__name__}: {str(e)[:120]}")
        logger.warning(f"metiq exception, falling back: {e}")
        return _fallback_proxy("/chat/completions", payload, stream=False)


if __name__ == "__main__":
    try:
        _get_client()
    except Exception as e:
        logger.warning(f"eager metiq init failed (shim will still serve via fallback): {e}")
    listen = f"{HOST}:{PORT}"
    if EXTRA_LISTEN:
        listen = listen + " " + EXTRA_LISTEN.replace(",", " ")
    logger.info(f"listening on {listen} fallback={FALLBACK_URL} model={MODEL_NAME}")
    serve(app, listen=listen, threads=4)
