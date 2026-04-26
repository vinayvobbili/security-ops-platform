"""Lightweight MCP client for FastMCP 3.x servers via streamable-http transport.

General-purpose client for the IR bot to communicate with the MCP server.
Supports tool discovery (list_tools) and tool execution (call_tool).
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger("mcp_client")

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
      2. tools/list for tool discovery
      3. tools/call with session header on each call
      4. SSE response parsing
    """

    def __init__(self, server_url: str, timeout: int = 300):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        # Per-phase httpx timeout; the wall-clock deadline in _post is the
        # real backstop because SSE keepalive bytes reset httpx's read timer.
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
        """Post a JSON-RPC message, parse SSE or JSON response.

        Streams the response and enforces a wall-clock deadline (self.timeout).
        Necessary because the MCP server emits SSE keepalive bytes during slow
        tool calls, which reset httpx's per-byte read timer and let calls
        otherwise hang indefinitely.
        """
        deadline = time.monotonic() + self.timeout
        chunks: list[bytes] = []
        with self._client.stream(
            "POST", self.server_url, json=payload, headers=self._headers()
        ) as response:
            response.raise_for_status()
            ct = response.headers.get("content-type", "")
            for chunk in response.iter_bytes():
                if time.monotonic() > deadline:
                    raise httpx.ReadTimeout(
                        f"Wall-clock timeout: MCP call exceeded {self.timeout}s"
                    )
                chunks.append(chunk)

        body = b"".join(chunks).decode("utf-8", errors="replace")
        if "text/event-stream" in ct:
            return _parse_sse_json(body)
        if "application/json" in ct:
            return json.loads(body) if body else {}
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
                    "clientInfo": {"name": "ir-bot", "version": "1.0"},
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

    def list_tools(self) -> list[dict]:
        """Discover available tools from the MCP server.

        Returns:
            List of tool descriptors, each with 'name', 'description', and 'inputSchema'.
        """
        try:
            self._ensure_session()
        except Exception as e:
            logger.error(f"MCP session init failed during list_tools: {e}")
            return []

        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
            "params": {},
        }

        try:
            result = self._post(payload)

            if "error" in result:
                logger.error(f"MCP error during list_tools: {result['error']}")
                return []

            return result.get("result", {}).get("tools", [])

        except httpx.HTTPError as e:
            logger.error(f"HTTP error during list_tools: {e}")
            self._session_id = None
            return []
        except Exception as e:
            logger.error(f"Unexpected error during list_tools: {e}")
            self._session_id = None
            return []

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Call a tool on the MCP server.

        Returns:
            str: The text content from the tool response, or an error message.
        """
        try:
            self._ensure_session()
        except Exception as e:
            logger.error(f"MCP session init failed for {tool_name}: {e}")
            return f"MCP connection error: {e}"

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
                error_msg = result["error"]
                logger.error(f"MCP error from {tool_name}: {error_msg}")
                return f"Tool error: {error_msg}"

            content = result.get("result", {}).get("content", [])
            if content and content[0].get("type") == "text":
                return content[0]["text"]
            return json.dumps(result.get("result", {}))

        except httpx.HTTPError as e:
            logger.error(f"HTTP error calling {tool_name}: {e}")
            self._session_id = None
            return f"HTTP error calling {tool_name}: {e}"
        except Exception as e:
            logger.error(f"Unexpected error calling {tool_name}: {e}")
            self._session_id = None
            return f"Error calling {tool_name}: {e}"

    def close(self):
        self._client.close()
