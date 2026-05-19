# /my_bot/tools/internal_urls_tools.py
"""
Internal URL Lookup Tools

Looks up team / internal application URLs (and phone numbers) from the
favorite URLs store at data/favorite_urls/favorite_urls.json. This is the
canonical source for internal tool URLs (XSIAM consoles, Splunk, QRadar,
DILT, ServiceNow forms, OneNote pages, etc.). Web search will NOT find these.
"""

from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool
from src.utils.tool_decorator import log_tool_call


def _tokens(text: str) -> set:
    return {t for t in "".join(c if c.isalnum() else " " for c in text.lower()).split() if t}


def _score(query: str, name: str) -> int:
    """Higher is better. 0 = no match."""
    q = (query or "").strip().lower()
    n = (name or "").strip().lower()
    if not q or not n:
        return 0
    if q == n:
        return 1000
    if q in n:
        return 500 + (100 if n.startswith(q) else 0)
    if n in q:
        return 300
    # Token-overlap fallback. Require >= 2 shared tokens so a single generic
    # word ("security", "form", "tool") doesn't surface a false positive for
    # an unrelated query (e.g. "abnormal security" sharing only "security"
    # with "Approved Offensive Security Testing Form").
    q_tokens = _tokens(q)
    n_tokens = _tokens(n)
    overlap = q_tokens & n_tokens
    if len(overlap) >= 2:
        return 50 + 10 * len(overlap)
    return 0


@readonly_tool
@log_tool_call
def lookup_internal_url(query: str) -> str:
    """ALWAYS call this tool first when the user asks for the URL, link, address, or phone number
    of an internal tool, console, form, or team resource (e.g. "what's the URL for DILT?",
    "link to XSIAM", "Splunk URL", "phone number for the help desk").
    Do NOT web-search internal acronyms or tool names — they will not show up there.
    Searches the team's favorite URLs store and returns matching entries with their URL or phone."""
    from src.components.web.favorite_urls_handler import load_urls

    q = (query or "").strip()
    items = load_urls()

    if not q:
        lines = ["**Internal URLs (all categories):**"]
        by_cat: dict = {}
        for it in items:
            by_cat.setdefault(it.get("category", "General"), []).append(it)
        for cat in sorted(by_cat):
            lines.append(f"\n_{cat}_")
            for it in by_cat[cat]:
                target = it.get("url") or it.get("phone_number") or ""
                lines.append(f"- {it.get('name', '?')} → {target}")
        return "\n".join(lines)

    scored = [(s, it) for it in items if (s := _score(q, it.get("name", ""))) > 0]
    scored.sort(key=lambda x: -x[0])

    if not scored:
        return (
            f"No internal URL found for '{q}' in the favorite URLs store. "
            "If this is an external service, try a web search; otherwise it may not be cataloged yet."
        )

    top = scored[:5]
    lines = [f"**Internal URL match for '{q}':**"]
    for _, it in top:
        name = it.get("name", "?")
        category = it.get("category", "General")
        if it.get("url"):
            lines.append(f"- **{name}** ({category}) → {it['url']}")
        elif it.get("phone_number"):
            lines.append(f"- **{name}** ({category}) ☎ {it['phone_number']}")
    return "\n".join(lines)
