"""Web search tools via local SearXNG instance."""

import logging

import httpx

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

SEARXNG_URL = "http://127.0.0.1:8888/search"
SEARCH_TIMEOUT_SECONDS = 20
MAX_SNIPPET_CHARS = 200


def _truncate(text: str) -> str:
    if len(text) <= MAX_SNIPPET_CHARS:
        return text
    return text[:MAX_SNIPPET_CHARS].rsplit(" ", 1)[0] + "..."


@mcp.tool(tags={"readonly"})
def web_search(query: str, num_results: int = 10) -> dict:
    """Search the internet using the local SearXNG search instance.

    Runs a web search and returns titles, URLs, and content snippets.
    Also returns news results when available.
    Use for current events, recent security news, CVE details, vendor
    advisories, threat actor profiles, or any topic needing live data.

    Args:
        query: Search query string
        num_results: Maximum number of results to return (default 10)
    """
    try:
        resp = httpx.get(
            SEARXNG_URL,
            params={"q": query, "format": "json", "categories": "general,news"},
            timeout=SEARCH_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.error(f"SearXNG search failed: {e}")
        return {"error": str(e), "results": []}

    results = []
    for r in data.get("results", [])[:num_results]:
        results.append({
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "snippet": _truncate(r.get("content", "")),
            "source": r.get("engine", ""),
            "published": r.get("publishedDate", ""),
        })

    return {
        "query": query,
        "total_found": len(data.get("results", [])),
        "results": results,
    }
