"""Entrypoints for the IR MCP server.

Default (no flags):
  Bind 127.0.0.1:8200 with the full toolset, no auth — intended for
  in-VM consumers (scheduler, bots, local Claude Code via .mcp.json).

--public:
  Bind 127.0.0.1:8202 with a fail-closed readonly allowlist + per-user
  PAT auth. Designed to sit behind nginx at gdnr.the-company.com/mcp so the
  team can point their Claude Code clients at it. PATs are the same ones
  users mint at /account for the CCR shim — one token works for both
  surfaces.
"""
import argparse

import uvicorn
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from mcp_server.server import logger, mcp


class PATAuthMiddleware(BaseHTTPMiddleware):
    """Per-user PAT auth for /mcp.

    Looks the bearer up against the same `pats` table the CCR shim uses,
    records (pat_id, client_ip) usage, and fires a Webex new-IP alert
    (source="MCP") on the first request from a previously-unseen IP.
    Lookup + usage + alert are all best-effort — they never raise out of
    dispatch.
    """

    async def dispatch(self, request, call_next):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth.removeprefix("Bearer ").strip()

        try:
            from web.auth import db as auth_db
            from web.auth import notifications as auth_notifications
            from web.auth import security as auth_security
        except Exception:
            logger.exception("MCP auth import failed")
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        row = auth_db.lookup_pat(auth_security.hash_token(token))
        if row is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        client_ip = _client_ip(request)
        try:
            is_new_ip = auth_db.record_pat_usage(row["id"], client_ip)
        except Exception:
            logger.exception("MCP record_pat_usage failed")
            is_new_ip = False
        if is_new_ip:
            try:
                auth_notifications.notify_pat_new_ip(
                    row["email"], row["name"], client_ip, source="MCP",
                )
            except Exception:
                logger.exception("MCP notify_pat_new_ip failed")

        return await call_next(request)


def _client_ip(request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def main() -> None:
    parser = argparse.ArgumentParser(description="IR MCP server")
    parser.add_argument(
        "--public",
        action="store_true",
        help="Fail-closed readonly mode bound to :8202 with per-user PAT auth",
    )
    args = parser.parse_args()

    if args.public:
        # Fail-closed: disable everything, then re-enable only readonly-tagged tools.
        # A new tool without the "readonly" tag will NOT be exposed.
        mcp.enable(tags={"readonly"}, only=True)
        app = mcp.http_app(
            transport="streamable-http",
            path="/mcp",
            middleware=[Middleware(PATAuthMiddleware)],
        )
        logger.info("Starting IR MCP (PUBLIC, readonly+PAT) on http://127.0.0.1:8202/mcp")
        uvicorn.run(app, host="127.0.0.1", port=8202, log_level="info")
    else:
        logger.info("Starting IR MCP (private, full toolset) on http://127.0.0.1:8200/mcp")
        mcp.run(transport="streamable-http", host="127.0.0.1", port=8200)


if __name__ == "__main__":
    main()
