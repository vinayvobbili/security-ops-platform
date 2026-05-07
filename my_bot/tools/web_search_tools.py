"""
Web Search Tools Module

Internet search via local SearXNG instance for current events, news, and general knowledge.
SearXNG handles search engine fan-out, rate limiting, and retries server-side.
Returns both web and news results in a single call to minimize agentic loop round trips.
"""

import logging
import re
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

SEARXNG_URL = "http://127.0.0.1:8888/search"
SEARCH_TIMEOUT_SECONDS = 20
MAX_SNIPPET_CHARS = 200

FETCH_TIMEOUT_SECONDS = 15
FETCH_MAX_BYTES = 2_000_000
FETCH_USER_AGENT = "Mozilla/5.0 (compatible; IR-the security assistant bot/1.0; +https://gdnr.the-company.com)"
RENDER_TIMEOUT_SECONDS = 25
RENDER_MIN_SIGNAL = 3  # high-signal IOC count below which we retry with headless browser


def _truncate(text: str) -> str:
    if len(text) <= MAX_SNIPPET_CHARS:
        return text
    return text[:MAX_SNIPPET_CHARS].rsplit(" ", 1)[0] + "..."


def _format_result(i: int, r: dict) -> str:
    title = r.get("title", "No title")
    content = _truncate(r.get("content", "No snippet"))
    url = r.get("url", "")
    engines = ", ".join(r.get("engines", []))
    return f"[{i}] {title}\n    {content}\n    Source: {url}\n    Engines: {engines}"


@tool
@log_tool_call
def search_web(query: str, max_results: int = 5) -> str:
    """Search the internet for current events, news, or any topic that requires up-to-date information.

    Returns BOTH general web results AND recent news articles in a single call.
    IMPORTANT: Do NOT call this tool more than once per user query. Synthesize your answer from these results.

    Args:
        query: The search query string.
        max_results: Number of results per section (default 5, max 10).
    """
    try:
        max_results = min(max(max_results, 1), 10)
        logger.info(f"Web search via SearXNG: '{query}' (max_results={max_results})")

        # Single request to SearXNG — it fans out to multiple engines server-side
        params = {
            "q": query,
            "format": "json",
            "categories": "general,news",
            "safesearch": "1",
        }
        resp = httpx.get(SEARXNG_URL, params=params, timeout=SEARCH_TIMEOUT_SECONDS)
        resp.raise_for_status()
        data = resp.json()

        all_results = data.get("results", [])
        if not all_results:
            return f"No search results found for: {query}"

        # Split into web and news based on SearXNG category metadata
        web_results = []
        news_results = []
        for r in all_results:
            cats = r.get("category", "")
            if "news" in cats:
                news_results.append(r)
            else:
                web_results.append(r)

        sections = []
        if web_results:
            formatted = [_format_result(i, r) for i, r in enumerate(web_results[:max_results], 1)]
            sections.append("=== Web Results ===\n" + "\n\n".join(formatted))

        if news_results:
            formatted = [_format_result(i, r) for i, r in enumerate(news_results[:max_results], 1)]
            sections.append("=== News Results ===\n" + "\n\n".join(formatted))

        if not sections:
            return f"No search results found for: {query}"

        return "\n\n".join(sections)

    except httpx.TimeoutException:
        logger.warning(f"SearXNG search timed out for: {query}")
        return f"Search timed out for: {query}"
    except Exception as e:
        logger.error(f"SearXNG search error: {e}")
        return f"Error performing web search: {str(e)}"


_IOC_SECTION_RE = re.compile(r"indicators?\s+of\s+compromise|\biocs?\b", re.IGNORECASE)
_HTML_HEADING_RE = re.compile(r"<h([1-6])[^>]*>(.*?)</h\1>", re.IGNORECASE | re.DOTALL)
_MD_HEADING_RE = re.compile(r"^[ \t]*(#+)[ \t]+(.+)$", re.MULTILINE)

GENERIC_EMAIL_PREFIXES = {
    "contact", "support", "abuse", "vulnerability", "security",
    "info", "help", "admin", "postmaster", "webmaster",
    "noreply", "no-reply", "press", "media", "legal", "privacy",
    "sales", "hello", "team",
}


def _scope_to_ioc_section(html: str) -> str:
    """Return just the 'Indicators of Compromise' section of the page, or ''.

    Looks for an HTML heading (h1-h6) or markdown-style heading whose text matches
    the IOC section pattern, and slices from that heading until the next heading
    of the same-or-higher level.
    """
    # HTML headings
    for m in _HTML_HEADING_RE.finditer(html):
        level = int(m.group(1))
        heading_text = re.sub(r"<[^>]+>", " ", m.group(2))
        if _IOC_SECTION_RE.search(heading_text):
            start = m.start()
            stop = len(html)
            for nm in _HTML_HEADING_RE.finditer(html, m.end()):
                if int(nm.group(1)) <= level:
                    stop = nm.start()
                    break
            return html[start:stop]

    # Markdown-style headings (rare in HTML, common in rendered intel pages copied as text)
    for m in _MD_HEADING_RE.finditer(html):
        level = len(m.group(1))
        if _IOC_SECTION_RE.search(m.group(2)):
            start = m.start()
            stop = len(html)
            for nm in _MD_HEADING_RE.finditer(html, m.end()):
                if len(nm.group(1)) <= level:
                    stop = nm.start()
                    break
            return html[start:stop]

    return ""


def _url_host(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return ""
    return host[4:] if host.startswith("www.") else host


def _clean_entities(entities, source_host: str) -> None:
    """Drop same-host URLs/emails and generic support addresses. Mutates in-place."""
    host = (source_host or "").lower()
    host = host[4:] if host.startswith("www.") else host

    if host:
        entities.urls = [
            u for u in entities.urls
            if (h := _url_host(u)) and h != host and not h.endswith("." + host)
        ]
        entities.emails = [
            e for e in entities.emails
            if "@" in e and not (
                e.split("@", 1)[1] == host or e.split("@", 1)[1].endswith("." + host)
            )
        ]

    entities.emails = [
        e for e in entities.emails
        if e.split("@", 1)[0].lower() not in GENERIC_EMAIL_PREFIXES
    ]


# IOC patterns the security assistant bot has no first-party hunt tool for. Each entry names the
# integration that would close the gap so the analyst knows what to build/ask for.
# "scan=domains" reclassifies items already pulled by the extractor (moves out of
# entities.domains); "scan=text" finds patterns the extractor misses entirely.
_GAP_PATTERNS = [
    {
        "name": "Google OAuth client ID",
        "pattern": re.compile(r"\b\d+-[a-z0-9]+\.apps\.googleusercontent\.com\b", re.IGNORECASE),
        "scan": "domains",
        "needs": "Google Workspace Admin SDK Reports API (admin.reports.audit.readonly)",
    },
    {
        "name": "AWS access key",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "scan": "text",
        "needs": "AWS CloudTrail query access",
    },
    {
        "name": "GitHub token",
        "pattern": re.compile(r"\bgh[opsur]_[A-Za-z0-9]{36,}\b"),
        "scan": "text",
        "needs": "GitHub Enterprise audit log API (org owner token)",
    },
    {
        "name": "Google API key",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "scan": "text",
        "needs": "Google Cloud Audit Logs",
    },
    {
        "name": "Slack token",
        "pattern": re.compile(r"\bxox[bapr]-[A-Za-z0-9\-]{10,}\b"),
        "scan": "text",
        "needs": "Slack audit log API (Enterprise Grid)",
    },
    {
        "name": "Stripe live key",
        "pattern": re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
        "scan": "text",
        "needs": "Stripe API audit log",
    },
    {
        "name": "NPM token",
        "pattern": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "scan": "text",
        "needs": "NPM org audit log",
    },
    {
        "name": "JWT",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "scan": "text",
        "needs": "Issuer-specific audit trail (varies)",
    },
]


def _classify_gaps(entities, text: str) -> dict:
    """Find IOC-like values the security assistant bot has no hunt tool for.

    Reclassifies matches out of entities.domains (in-place) when appropriate,
    and scans raw text for secret/token patterns the entity extractor misses.

    Returns: {gap_name: {"values": [...], "needs": "..."}}
    """
    gaps: dict = {}

    for rule in _GAP_PATTERNS:
        name = rule["name"]
        pat = rule["pattern"]

        if rule["scan"] == "domains":
            matched = [d for d in entities.domains if pat.search(d)]
            if matched:
                entities.domains = [d for d in entities.domains if d not in matched]
                gaps[name] = {"values": matched, "needs": rule["needs"]}
        else:  # scan raw text
            matched = list(dict.fromkeys(pat.findall(text)))
            if matched:
                gaps[name] = {"values": matched, "needs": rule["needs"]}

    return gaps


def _extract_from_html(html: str, source_host: str):
    """Run entity extraction with IOC-section scoping + same-host/generic filters.

    Returns (entities, used_scoping: bool, gaps: dict).
    """
    from src.utils.entity_extractor import extract_entities

    scoped = _scope_to_ioc_section(html)
    used_scoping = False
    if scoped:
        entities = extract_entities(scoped)
        used_text = scoped
        used_scoping = True
        if entities.is_empty():
            # Safety net: scoped block was a false positive or empty — try the whole page
            entities = extract_entities(html)
            used_text = html
            used_scoping = False
    else:
        entities = extract_entities(html)
        used_text = html

    _clean_entities(entities, source_host)
    gaps = _classify_gaps(entities, used_text)
    return entities, used_scoping, gaps


def _high_signal_count(entities) -> int:
    return (
        len(entities.hashes["md5"])
        + len(entities.hashes["sha1"])
        + len(entities.hashes["sha256"])
        + len(entities.cves)
        + len(entities.ips)
    )


_SPA_MARKERS = (
    'id="__next"', "__NEXT_DATA__",                    # Next.js
    'id="root"></div>', 'id="root"> </div>',           # React CRA
    'id="app"></div>',                                 # Vue
    'ng-version=',                                     # Angular
)


def _looks_like_spa(html: str) -> bool:
    """Return True if the HTML is a client-rendered SPA shell with no real content."""
    sample = html[:50000].lower()
    markers = tuple(m.lower() for m in _SPA_MARKERS)
    return any(m in sample for m in markers)


def _render_with_playwright(url: str) -> str:
    """Render a URL with headless Chromium and return the post-JS HTML."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(user_agent=FETCH_USER_AGENT)
            page = context.new_page()
            try:
                page.goto(url, wait_until="networkidle", timeout=RENDER_TIMEOUT_SECONDS * 1000)
            except Exception:
                # networkidle can hang on pages that keep polling — fall back to domcontentloaded
                page.goto(url, wait_until="domcontentloaded", timeout=RENDER_TIMEOUT_SECONDS * 1000)
            return page.content()
        finally:
            browser.close()


def _format_hash_section(label: str, values: list) -> str:
    if not values:
        return ""
    shown = values[:20]
    more = f" (+{len(values) - len(shown)} more)" if len(values) > len(shown) else ""
    return f"{label} ({len(values)}): " + ", ".join(shown) + more


def _format_list_section(label: str, values: list, limit: int = 30) -> str:
    if not values:
        return ""
    shown = values[:limit]
    more = f" (+{len(values) - len(shown)} more)" if len(values) > len(shown) else ""
    return f"{label} ({len(values)}): " + ", ".join(shown) + more


@tool
@log_tool_call
def fetch_url_and_extract_iocs(url: str) -> str:
    """Fetch a web page (threat advisory, blog, vendor bulletin) and extract IOCs from it.

    USE THIS TOOL when a user shares a URL to a threat report and asks to pull IOCs,
    or when they ask to hunt IOCs from an advisory page. After extraction, the analyst
    can pivot on the returned IPs/domains/hashes with VirusTotal, QRadar, CrowdStrike,
    Tanium, etc.

    Extracts: IPs, domains, URLs, file hashes (MD5/SHA1/SHA256), CVEs, malicious
    filenames, emails, threat actor names, malware families, MITRE technique IDs.
    Handles defanged IOCs (hxxp, [.], [@]) automatically.

    For JS-rendered pages (Next.js, React SPAs, dashboards), automatically retries
    with headless Chromium when the initial fetch yields too few high-signal IOCs.

    The output may also include a "Hunt gaps" section listing IOC types the security assistant bot
    has no tool to hunt (OAuth client IDs, AWS keys, GitHub tokens, JWTs, etc.).
    Do NOT attempt to pivot on hunt-gap items with VT/QRadar/Tanium — they will
    return noise. Instead, tell the analyst the gap exists and what integration
    would be needed.

    Args:
        url: Full URL to fetch (http:// or https://). Arbitrary web pages are
             supported; the HTML is stripped and parsed for IOCs.

    Returns:
        A formatted list of extracted IOCs grouped by type, or an error message.
    """
    if not url or not url.lower().startswith(("http://", "https://")):
        return "Error: url must start with http:// or https://"

    try:
        logger.info(f"Fetching URL for IOC extraction: {url}")
        source_host = _url_host(url)
        headers = {"User-Agent": FETCH_USER_AGENT}
        with httpx.Client(follow_redirects=True, timeout=FETCH_TIMEOUT_SECONDS, headers=headers) as client:
            resp = client.get(url)
            resp.raise_for_status()
            content = resp.content[:FETCH_MAX_BYTES]

        try:
            text = content.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            text = content.decode("utf-8", errors="replace")

        entities, scoped, gaps = _extract_from_html(text, source_host)
        source = "httpx"

        # SPA fallback: if httpx yields little of value OR the page is an unrendered
        # JS shell, retry with headless Chromium and keep whichever result is richer.
        if _high_signal_count(entities) < RENDER_MIN_SIGNAL or _looks_like_spa(text):
            try:
                logger.info(f"Sparse IOC yield from httpx, retrying with Playwright: {url}")
                rendered_html = _render_with_playwright(url)
                rendered_entities, rendered_scoped, rendered_gaps = _extract_from_html(
                    rendered_html[:FETCH_MAX_BYTES * 2], source_host
                )
                if _high_signal_count(rendered_entities) > _high_signal_count(entities) or (
                    not gaps and rendered_gaps
                ):
                    entities = rendered_entities
                    scoped = rendered_scoped
                    gaps = rendered_gaps
                    source = "httpx + playwright render"
            except Exception as e:
                logger.warning(f"Playwright render fallback failed for {url}: {e}")

        note_bits = [source]
        if scoped:
            note_bits.append("scoped to IOC section")
        source_note = ", ".join(note_bits)

        if entities.is_empty() and not gaps:
            return f"No IOCs found on {url} ({source_note})."

        summary = entities.summary()
        if entities.is_empty() and gaps:
            summary = "Only hunt-gap IOCs found (see below)"
        lines = [f"IOCs extracted from {url} ({source_note})",
                 f"Summary: {summary}", ""]
        sections = [
            _format_list_section("IPs", entities.ips),
            _format_list_section("Domains", entities.domains),
            _format_list_section("URLs", entities.urls, limit=20),
            _format_list_section("Filenames", entities.filenames),
            _format_hash_section("MD5", entities.hashes["md5"]),
            _format_hash_section("SHA1", entities.hashes["sha1"]),
            _format_hash_section("SHA256", entities.hashes["sha256"]),
            _format_list_section("CVEs", entities.cves),
            _format_list_section("Emails", entities.emails),
            _format_list_section("Threat actors", entities.threat_actors),
            _format_list_section("Malware families", entities.malware_families),
            _format_list_section("MITRE techniques", entities.mitre_techniques),
        ]
        lines.extend(s for s in sections if s)

        if gaps:
            lines.append("")
            lines.append("Hunt gaps — IOC types the security assistant bot has no tool for:")
            for gap_name, info in gaps.items():
                values = info["values"]
                shown = ", ".join(values[:5])
                more = f" (+{len(values) - 5} more)" if len(values) > 5 else ""
                lines.append(f"  {gap_name} ({len(values)}): {shown}{more}")
                lines.append(f"    needs: {info['needs']}")

        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        return f"Error: HTTP {e.response.status_code} when fetching {url}"
    except httpx.TimeoutException:
        return f"Error: timed out fetching {url}"
    except httpx.HTTPError as e:
        return f"Error fetching {url}: {e}"
    except Exception as e:
        logger.error(f"fetch_url_and_extract_iocs failed for {url}: {e}", exc_info=True)
        return f"Error extracting IOCs from {url}: {e}"
