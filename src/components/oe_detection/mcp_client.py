"""Lightweight MCP client for FastMCP 3.x servers via streamable-http transport."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

logger = logging.getLogger("oe_detector")

_SSE_DATA_RE = re.compile(r"^data: (.+)$", re.MULTILINE)


def _parse_sse_json(text: str) -> dict:
    """Extract the first JSON object from an SSE text/event-stream response."""
    match = _SSE_DATA_RE.search(text)
    if match:
        return json.loads(match.group(1))
    return {}


class MCPClient:
    """Wraps JSON-RPC calls to a FastMCP 3.x streamable-http server.

    Handles the MCP session lifecycle:
      1. initialize + notifications/initialized on first call
      2. tools/call with session header on each call
      3. SSE response parsing
    """

    def __init__(self, server_url: str, server_name: str, timeout: int = 30):
        self.server_url = server_url.rstrip("/")
        self.server_name = server_name
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)
        self._session_id: str | None = None
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            h["mcp-session-id"] = self._session_id
        return h

    def _post(self, payload: dict) -> dict:
        """Post a JSON-RPC message, parse SSE or JSON response."""
        response = self._client.post(
            self.server_url, json=payload, headers=self._headers()
        )
        response.raise_for_status()

        ct = response.headers.get("content-type", "")
        if "text/event-stream" in ct:
            return _parse_sse_json(response.text)
        if "application/json" in ct:
            return response.json()
        # Notifications return 202/204 with no body
        return {}

    def _ensure_session(self) -> None:
        """Initialize MCP session if not already established."""
        if self._session_id:
            return

        resp = self._client.post(
            self.server_url,
            json={
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "oe-detector", "version": "1.0"},
                },
            },
            headers=self._headers(),
        )
        resp.raise_for_status()
        self._session_id = resp.headers.get("mcp-session-id")

        # Send initialized notification
        self._client.post(
            self.server_url,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=self._headers(),
        )

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict:
        try:
            self._ensure_session()
        except Exception as e:
            logger.error(f"MCP session init failed for {self.server_name}: {e}")
            return {}

        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }

        try:
            result = self._post(payload)

            if "error" in result:
                logger.error(
                    f"MCP error from {self.server_name}/{tool_name}: {result['error']}"
                )
                return {}

            content = result.get("result", {}).get("content", [])
            if content and content[0].get("type") == "text":
                try:
                    return json.loads(content[0]["text"])
                except json.JSONDecodeError:
                    return {"raw_text": content[0]["text"]}
            return result.get("result", {})

        except httpx.HTTPError as e:
            logger.error(f"HTTP error calling {self.server_name}/{tool_name}: {e}")
            # Reset session on error so next call re-initializes
            self._session_id = None
            return {}
        except Exception as e:
            logger.error(f"Unexpected error calling {self.server_name}/{tool_name}: {e}")
            self._session_id = None
            return {}

    def close(self):
        self._client.close()
