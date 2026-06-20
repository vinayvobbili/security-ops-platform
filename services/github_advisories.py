"""Security advisory monitor (Detection Engineering job).

Hourly poller for newly published advisories across several supply-chain /
vulnerability feeds. On detecting advisories not seen before it posts a Webex
digest (Aide bot) and emails the AppSec team. Nothing is sent when there is
nothing new.

Sources are a mix of code-defined built-ins and user-added ones (managed from
the "Sources" modal on the /cs-advisories page):

    built-in:
        github          GitHub Advisory DB, reviewed + critical
        github_malware  GitHub Advisory DB, malware (typosquat / malicious pkgs)
        osv_npm/osv_pypi OSV.dev malicious-package advisories (MAL-*) per ecosystem
        cisa_kev        CISA Known Exploited Vulnerabilities catalog
    user-added (stored in custom_sources):
        osv (extra ecosystems: Go, Maven, RubyGems, crates.io, NuGet, …)
        rss (a blog/Atom feed, each entry LLM-triaged for package-compromise
             relevance — the "class-2" lane; e.g. vendor security blogs)

Each source is just a fetcher returning *normalized records* (see
``services.github_advisories_db.upsert_advisory`` for the shape), so a new kind
of source is a new entry in the catalog. Sources that can't be expressed as an
RSS feed or OSV ecosystem need real plumbing — the modal lets a reviewer request
one, which pings the team on Webex to re-engage engineering.

State (dedup + triage) lives in SQLite via ``services.github_advisories_db``.
The first time a source is polled its current backlog is baselined silently
(seeded + hidden, or — for OSV — just a high-water timestamp) so onboarding a
feed doesn't replay its history as alerts. Cross-source duplicates are deduped
by alias.

Entry point: ``poll_critical_advisories(room_id=None)`` — wired into
``src/de_scheduler.py`` to run every hour at :00.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable

import requests
from webexpythonsdk import WebexAPI

from my_config import get_config
from services import github_advisories_db as db
from src.utils.webex_messaging import send_message

logger = logging.getLogger(__name__)
CONFIG = get_config()

REQUEST_TIMEOUT = 30

# GitHub Advisory DB
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
GITHUB_PER_PAGE = 100  # newest-first; far more than an hour's worth

# OSV.dev — list just the malicious-package (MAL-*) objects via the public GCS
# JSON API (cheap metadata: name + updated time) and fetch full JSON only for
# new ones. The per-ecosystem ``updated`` high-water mark is the dedup key.
OSV_BUCKET_LIST = "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o"
OSV_OBJECT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{name}"
OSV_MAX_FETCH_PER_RUN = 300  # cap full-content fetches per cycle (post-baseline)
AI_PREPOP_MAX_PER_RUN = 25  # cap synchronous AI prepopulation so a flood can't starve alerts
# Ecosystems a reviewer may add from the modal (built-ins npm/PyPI excluded).
OSV_ADDABLE_ECOSYSTEMS = ("Go", "Maven", "RubyGems", "crates.io", "NuGet", "Packagist", "Pub", "Hex")

# CISA Known Exploited Vulnerabilities
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# RSS / blog feeds (class-2 lane)
RSS_MAX_ENTRIES = 40  # newest entries considered per feed per cycle


# ---------------------------------------------------------------------------
# Source catalog (built-in + user-added)
# ---------------------------------------------------------------------------
# ``digest``: whether genuinely-new rows from this source go into the email/Webex
# alert. High-volume malicious-package feeds (GitHub Malware, OSV npm/PyPI) emit
# ~100 reviewed packages per poll — far too noisy to blast hourly — so they are
# queue-only: still upserted as visible/triageable rows in /cs-advisories (and
# escalatable to Package Compromise Assessment), just excluded from the digest.
# Only the low-volume, individually-critical feeds (GitHub Advisory, CISA KEV)
# notify.
BUILTIN_SOURCES = [
    {"key": "github",         "label": "GitHub Advisory", "type": "github_reviewed", "config": {}, "digest": True},
    {"key": "github_malware", "label": "GitHub Malware",  "type": "github_malware",  "config": {}, "digest": False},
    {"key": "osv_npm",        "label": "OSV npm",   "type": "osv", "config": {"ecosystem": "npm"},  "digest": False},
    {"key": "osv_pypi",       "label": "OSV PyPI",  "type": "osv", "config": {"ecosystem": "PyPI"}, "digest": False},
    {"key": "cisa_kev",       "label": "CISA KEV",  "type": "cisa_kev", "config": {}, "digest": True},
]
_BUILTIN_KEYS = {s["key"] for s in BUILTIN_SOURCES}


def get_source_specs() -> list[dict[str, Any]]:
    """The effective source list: code-defined built-ins + user-added rows."""
    specs = [{**s, "builtin": True} for s in BUILTIN_SOURCES]
    for cs in db.list_custom_sources():
        specs.append({
            "key": cs["key"], "label": cs["label"], "type": cs["type"],
            "config": cs.get("config") or {}, "builtin": False,
            "digest": cs.get("digest", True),
        })
    return specs


def source_labels_map() -> dict[str, str]:
    return {s["key"]: s["label"] for s in get_source_specs()}


def _fetcher_for(spec: dict[str, Any]) -> Callable[[], list[dict[str, Any]]]:
    t = spec.get("type")
    key = spec["key"]
    cfg = spec.get("config") or {}
    if t == "github_reviewed":
        return lambda: _fetch_github("reviewed")
    if t == "github_malware":
        return lambda: _fetch_github("malware")
    if t == "osv":
        return lambda: _fetch_osv_eco(key, cfg.get("ecosystem", "npm"))
    if t == "cisa_kev":
        return _fetch_cisa_kev
    if t == "rss":
        return lambda: _fetch_rss(key, spec.get("label") or key, cfg.get("url", ""))
    logger.warning("[Advisories] Unknown source type %r for %r", t, key)
    return lambda: []


def is_builtin(key: str) -> bool:
    return key in _BUILTIN_KEYS


# ---------------------------------------------------------------------------
# Source: GitHub Advisory Database
# ---------------------------------------------------------------------------
def _fetch_github(advisory_type: str) -> list[dict[str, Any]]:
    """Fetch newest GitHub advisories of ``advisory_type`` ('reviewed' or
    'malware'). 'reviewed' is filtered to critical severity; 'malware' (malicious
    packages) is taken as-is since those advisories carry no useful severity.

    The public endpoint needs no auth (60 req/hr per IP). We deliberately do NOT
    use ``CONFIG.github_token`` (a corp GitHub Enterprise token public github.com
    rejects with 401); an optional ``GITHUB_ADVISORIES_TOKEN`` public PAT lifts
    the limit to 5000/hr, and a bad one falls back to unauthenticated.
    """
    params = {
        "type": advisory_type,
        "sort": "published",
        "direction": "desc",
        "per_page": GITHUB_PER_PAGE,
    }
    if advisory_type == "reviewed":
        params["severity"] = "critical"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = CONFIG.github_advisories_token
    if token:
        headers["Authorization"] = f"Bearer {token}"

    resp = requests.get(GITHUB_ADVISORIES_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
    if resp.status_code == 401 and token:
        logger.warning("[Advisories] GITHUB_ADVISORIES_TOKEN rejected (401) — retrying unauthenticated")
        headers.pop("Authorization", None)
        resp = requests.get(GITHUB_ADVISORIES_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    data = resp.json()
    if not isinstance(data, list):
        logger.error("[Advisories] Unexpected GitHub response shape: %s", type(data).__name__)
        return []
    source = "github" if advisory_type == "reviewed" else "github_malware"
    return [_normalize_github(a, source) for a in data if a.get("ghsa_id")]


def _normalize_github(adv: dict[str, Any], source: str) -> dict[str, Any]:
    ghsa = adv.get("ghsa_id")
    identifiers = [i.get("value") for i in (adv.get("identifiers") or []) if i.get("value")]
    packages, ecosystem = _packages_from_github(adv)
    return {
        "source": source,
        "source_id": ghsa,
        "cve_id": adv.get("cve_id"),
        "aliases": [ghsa, *identifiers, adv.get("cve_id")],
        "summary": adv.get("summary"),
        "description": adv.get("description"),
        "severity": adv.get("severity") or ("malicious" if source == "github_malware" else None),
        "ecosystem": ecosystem,
        "packages": packages,
        "published_at": adv.get("published_at"),
        "html_url": adv.get("html_url") or (f"https://github.com/advisories/{ghsa}" if ghsa else None),
        "raw": adv,
    }


def _packages_from_github(adv: dict[str, Any]) -> tuple[list[str], str | None]:
    packages, ecosystem = [], None
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        name = pkg.get("name")
        eco = pkg.get("ecosystem")
        if name:
            packages.append(f"{name} ({eco})" if eco else name)
            ecosystem = ecosystem or eco
    return packages, ecosystem


# ---------------------------------------------------------------------------
# Source: OSV.dev malicious packages (one source per ecosystem)
# ---------------------------------------------------------------------------
def _list_osv_malicious(eco: str) -> list[tuple[str, str, str]]:
    """List ``(mal_id, updated_iso, object_name)`` for every MAL-* object in an
    ecosystem, paginating the public GCS JSON listing API (anonymous, cheap)."""
    out: list[tuple[str, str, str]] = []
    page_token = None
    while True:
        params = {"prefix": f"{eco}/MAL-", "fields": "items(name,updated),nextPageToken", "maxResults": 1000}
        if page_token:
            params["pageToken"] = page_token
        resp = requests.get(OSV_BUCKET_LIST, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("items") or []:
            name = item.get("name") or ""
            base = name.rsplit("/", 1)[-1]
            if base.startswith("MAL-") and base.endswith(".json"):
                out.append((base[:-5], item.get("updated"), name))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return out


def _fetch_osv_eco(source_key: str, eco: str) -> list[dict[str, Any]]:
    """Return new OSV malicious-package (MAL-*) advisories for one ecosystem.

    The malicious-package backlog is huge (npm alone is six figures), so unlike
    by-id sources we do NOT seed it as rows. The first poll records only the GCS
    ``updated`` high-water mark (returns []); thereafter we fetch+emit the full
    JSON only for objects updated past that mark — genuinely new malicious
    packages. The high-water timestamp IS the dedup mechanism.
    """
    state = db.get_poll_state(source_key)
    high_water = (state.get("cursor") or {}).get("hw_updated")
    # Baseline is defined by HAVING a high-water mark, not merely by a poll_state
    # row existing. A row with no hw_updated (created by source registration or an
    # interrupted first poll) must count as NOT-yet-baselined — otherwise the
    # ``updated <= high_water`` dedup guard below is dead and the whole backlog
    # floods the queue as new cards.
    baselined = bool(high_water)
    new_high_water = high_water
    records: list[dict[str, Any]] = []
    fetched = 0
    capped = False

    try:
        listing = _list_osv_malicious(eco)
    except Exception as e:
        logger.error("[Advisories] OSV listing failed for %s: %s", eco, e)
        return []

    for mal_id, updated, name in listing:
        if updated and (not new_high_water or updated > new_high_water):
            new_high_water = updated
        if not baselined:
            continue  # baseline = high-water only; seed no rows
        if high_water and updated and updated <= high_water:
            continue
        if fetched >= OSV_MAX_FETCH_PER_RUN:
            capped = True
            continue
        try:
            resp = requests.get(OSV_OBJECT_URL.format(name=name), timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.warning("[Advisories] OSV object fetch failed for %s: %s", name, e)
            continue
        fetched += 1
        records.append(_normalize_osv(data, eco, source_key))

    if capped:
        # A full-cap batch means we're draining a bulk republish / onboarding
        # backlog, not seeing a normal hour's worth of genuinely-new malicious
        # packages. Flag these so the poller records them hidden instead of
        # firing 300 cards + 300 LLM triages + a 300-row email. new_high_water
        # already advanced to the max seen, so the next cycle comes back clean.
        logger.warning("[Advisories] OSV %s fetch capped at %d — recording hidden, not notifying",
                       eco, OSV_MAX_FETCH_PER_RUN)
        for r in records:
            r["_baseline_seed"] = True
    db.set_poll_state(source_key, cursor={"hw_updated": new_high_water} if new_high_water else {})
    return records


def _normalize_osv(data: dict[str, Any], fallback_eco: str, source_key: str) -> dict[str, Any]:
    osv_id = data.get("id")
    aliases = list(data.get("aliases") or [])
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    packages, ecosystem = [], None
    for aff in data.get("affected") or []:
        pkg = aff.get("package") or {}
        name = pkg.get("name")
        eco = pkg.get("ecosystem")
        if name:
            packages.append(f"{name} ({eco})" if eco else name)
            ecosystem = ecosystem or eco
    return {
        "source": source_key,
        "source_id": osv_id,
        "cve_id": cve,
        "aliases": [osv_id, *aliases],
        "summary": data.get("summary") or (data.get("details") or "")[:200],
        "description": data.get("details"),
        "severity": "malicious",
        "ecosystem": ecosystem or fallback_eco,
        "packages": packages,
        "published_at": data.get("published"),
        "html_url": f"https://osv.dev/vulnerability/{osv_id}" if osv_id else None,
        "raw": data,
    }


# ---------------------------------------------------------------------------
# Source: CISA Known Exploited Vulnerabilities
# ---------------------------------------------------------------------------
def _fetch_cisa_kev() -> list[dict[str, Any]]:
    resp = requests.get(CISA_KEV_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    out = []
    for v in data.get("vulnerabilities") or []:
        cve = v.get("cveID")
        if not cve:
            continue
        product = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
        out.append({
            "source": "cisa_kev",
            "source_id": cve,
            "cve_id": cve,
            "aliases": [cve],
            "summary": v.get("vulnerabilityName") or product or cve,
            "description": v.get("shortDescription"),
            "severity": "known_exploited",
            "ecosystem": None,
            "packages": [product] if product else [],
            "published_at": v.get("dateAdded"),
            "html_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "raw": v,
        })
    return out


# ---------------------------------------------------------------------------
# Source: RSS / Atom feeds (class-2 lane, LLM-triaged)
# ---------------------------------------------------------------------------
_TAG_RE = re.compile(r"<[^>]+>")
_TRIAGE_KEYWORDS = (
    "malicious", "malware", "compromis", "supply chain", "supply-chain", "typosquat",
    "backdoor", "trojan", "credential", "exfiltrat", "npm", "pypi", "package", "rce",
    "remote code execution", "zero-day", "0-day", "exploited", "cve-",
)


def _strip_html(text: str) -> str:
    return _TAG_RE.sub("", text or "").replace("&nbsp;", " ").strip()


def _rss_date(raw: str) -> str | None:
    if not raw:
        return None
    try:
        return parsedate_to_datetime(raw).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except ValueError:
        return raw


def _parse_feed(content: bytes) -> list[dict[str, str]]:
    """Parse an RSS 2.0 or Atom feed into entries. Namespace-agnostic."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        logger.warning("[Advisories] RSS parse error: %s", e)
        return []
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    items = root.findall(".//item") or root.findall(".//entry")
    entries = []
    for it in items:
        title = (it.findtext("title") or "").strip()
        link_el = it.find("link")
        link = ""
        if link_el is not None:
            link = (link_el.text or link_el.get("href") or "").strip()
        guid = (it.findtext("guid") or it.findtext("id") or link or title).strip()
        summary = (it.findtext("description") or it.findtext("summary") or it.findtext("content") or "")
        entries.append({
            "id": guid, "title": title, "url": link,
            "summary": _strip_html(summary)[:1200],
            "published": (it.findtext("pubDate") or it.findtext("published") or it.findtext("updated") or "").strip(),
        })
    return entries


def _heuristic_triage(title: str, summary: str) -> dict[str, Any]:
    blob = f"{title} {summary}".lower()
    relevant = any(k in blob for k in _TRIAGE_KEYWORDS)
    return {"relevant": relevant, "summary": title or summary[:200], "packages": [], "severity": "info"}


def _triage_rss_entry(title: str, summary: str) -> dict[str, Any]:
    """Decide whether a blog/RSS post is a package-compromise / critical-vuln
    item, and extract a short summary + packages. Uses the LLM with a keyword
    heuristic fallback so the source still works if the LLM is unavailable."""
    try:
        from my_bot.utils.llm_factory import create_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        sys = (
            "You triage security blog/advisory posts for a Package Compromise "
            "Assessment queue. Decide if the post describes a compromised or "
            "malicious software package, a supply-chain compromise, or a critical "
            "vulnerability relevant to defenders. Reply with ONLY a JSON object: "
            '{"relevant": true|false, "summary": "<=300 chars", '
            '"packages": ["name", ...], "severity": "critical|high|malicious|info"}.'
        )
        user = f"TITLE: {title}\n\nCONTENT: {summary[:1500]}"
        resp = create_llm().invoke([SystemMessage(content=sys), HumanMessage(content=user)])
        text = resp.content if hasattr(resp, "content") else str(resp)
        data = _extract_json(text)
        if isinstance(data, dict) and "relevant" in data:
            return {
                "relevant": bool(data.get("relevant")),
                "summary": (data.get("summary") or title)[:300],
                "packages": [str(p) for p in (data.get("packages") or [])][:20],
                "severity": data.get("severity") or "info",
            }
    except Exception as e:
        logger.warning("[Advisories] RSS LLM triage failed (%s) — using heuristic", e)
    return _heuristic_triage(title, summary)


def _extract_json(text: str) -> Any:
    """Pull the first JSON value — object OR array — out of an LLM reply.

    Handles both shapes: some prompts ask for an object (``{...}``), the FAQ asks
    for an array (``[{...}, ...]``). We pick whichever bracket type opens first
    and match it to that type's last closing bracket, falling back to the other
    candidate if the first doesn't parse."""
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if "```" in text[3:] else text.strip("`")
        text = text.lstrip("json").strip()
    candidates = []
    obj_start, obj_end = text.find("{"), text.rfind("}")
    if obj_start != -1 and obj_end > obj_start:
        candidates.append((obj_start, obj_end + 1))
    arr_start, arr_end = text.find("["), text.rfind("]")
    if arr_start != -1 and arr_end > arr_start:
        candidates.append((arr_start, arr_end + 1))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])  # outermost value = first bracket to open
    for start, end in candidates:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            continue
    return None


def _fetch_rss(source_key: str, label: str, url: str) -> list[dict[str, Any]]:
    """Fetch a feed. On baseline, return all current entries (seeded hidden by
    the poller). Thereafter, LLM-triage only unseen entries: relevant ones are
    returned as new cards; irrelevant ones are seeded hidden so they aren't
    re-triaged every cycle."""
    if not url:
        return []
    baselined = db.is_baselined(source_key)
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "IR-AdvisoryMonitor/1.0"})
        resp.raise_for_status()
        entries = _parse_feed(resp.content)
    except Exception as e:
        logger.error("[Advisories] RSS fetch failed for %s (%s): %s", source_key, url, e)
        return []

    if not baselined:
        return [_rss_record(source_key, e, {"summary": e["title"], "severity": "info", "packages": []})
                for e in entries[:RSS_MAX_ENTRIES] if e.get("id")]

    relevant, irrelevant = [], []
    for e in entries[:RSS_MAX_ENTRIES]:
        sid = e.get("id")
        if not sid or db.get_advisory(db.make_uid(source_key, sid)):
            continue  # already triaged
        verdict = _triage_rss_entry(e["title"], e["summary"])
        rec = _rss_record(source_key, e, verdict)
        (relevant if verdict.get("relevant") else irrelevant).append(rec)
    if irrelevant:
        db.bulk_seed(irrelevant)  # remember as hidden so we don't re-triage
        logger.info("[Advisories] RSS %s: %d new entries judged not relevant (hidden)", source_key, len(irrelevant))
    return relevant


def _rss_record(source_key: str, entry: dict[str, str], verdict: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": source_key,
        "source_id": entry["id"],
        "aliases": [entry["id"]],
        "summary": verdict.get("summary") or entry["title"],
        "description": entry.get("summary"),
        "severity": verdict.get("severity") or "info",
        "packages": verdict.get("packages") or [],
        "published_at": _rss_date(entry.get("published", "")),
        "html_url": entry.get("url"),
        "raw": {"title": entry.get("title"), "feed_summary": entry.get("summary"), "triage": verdict},
    }


# ---------------------------------------------------------------------------
# Webex: request a source that needs custom plumbing
# ---------------------------------------------------------------------------
def notify_source_request(description: str, requested_by: str = "") -> bool:
    """Ping the team on Webex that a reviewer wants a source we can't add from
    the modal (i.e. it needs a real fetcher). Returns True if the ping was sent."""
    token = CONFIG.webex_bot_access_token_aide
    room_id = CONFIG.webex_room_id_dev_test_space
    if not token or not room_id:
        logger.warning("[Advisories] Cannot send source request — Webex not configured")
        return False
    by = f" (requested by {requested_by})" if requested_by else ""
    md = (
        "🆕 **New advisory source requested**" + by + "\n\n"
        f"> {description.strip()[:1500]}\n\n"
        "_This needs a fetcher/parser to be wired up. Re-engage engineering to add it._"
    )
    send_message(WebexAPI(access_token=token), room_id, markdown=md)
    logger.info("[Advisories] Source request sent to Webex: %s", description[:120])
    return True


# ---------------------------------------------------------------------------
# AI triage assist (per-advisory, local LLM with fallback)
# ---------------------------------------------------------------------------
def _now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _now_et() -> str:
    """Current time in US/Eastern for display, e.g. ``06/16/2026 7:38 PM EDT``."""
    import pytz
    return datetime.now(pytz.timezone("US/Eastern")).strftime("%m/%d/%Y %-I:%M %p %Z")


def fmt_et(value: Any) -> str:
    """Format a UTC/ISO timestamp (or datetime) as US/Eastern for display:
    ``MM/DD/YYYY H:MM AM/PM EDT``. Returns the input stringified on parse failure."""
    import pytz
    eastern = pytz.timezone("US/Eastern")
    dt = value
    if isinstance(value, str):
        s = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return value
    if not isinstance(dt, datetime):
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(eastern).strftime("%m/%d/%Y %-I:%M %p %Z")


def _intel_rows(items: Any, keys: tuple[str, ...], cap: int = 25) -> list[dict[str, str]]:
    """Coerce an LLM list-of-objects into clean {key: str} rows, dropping empties.
    A bare string is accepted as the first key (e.g. a next-step-ish list)."""
    out: list[dict[str, str]] = []
    if not isinstance(items, list):
        return out
    for it in items[:cap]:
        if isinstance(it, dict):
            row = {k: str(it.get(k) or "").strip()[:400] for k in keys}
            if any(row.values()):
                out.append(row)
        elif isinstance(it, str) and it.strip():
            out.append({keys[0]: it.strip()[:400]})
    return out


def _intel_steps(items: Any, cap: int = 8) -> list[str]:
    out: list[str] = []
    if isinstance(items, list):
        for s in items[:cap]:
            if isinstance(s, str) and s.strip():
                out.append(s.strip()[:400])
            elif isinstance(s, dict):
                v = str(s.get("step") or s.get("action") or s.get("text") or "").strip()
                if v:
                    out.append(v[:400])
    return out


def generate_ai_triage(adv: dict[str, Any]) -> dict[str, Any]:
    """LLM assessment of one advisory: likely exposure, a recommended action
    (escalate/investigate/close), a short rationale, a paste-ready triage note,
    plus extracted threat intel — IOCs, MITRE ATT&CK TTPs, threat actors, and
    suggested next steps. Falls back to a deterministic heuristic if the LLM is
    unavailable."""
    pkgs = ", ".join(adv.get("packages") or []) or "n/a"
    ctx = (
        f"Source: {adv.get('source')}\n"
        f"ID: {adv.get('source_id')}\n"
        f"CVE: {adv.get('cve_id') or 'none'}\n"
        f"Severity: {adv.get('severity')}\n"
        f"Ecosystem: {adv.get('ecosystem') or 'n/a'}\n"
        f"Affected packages: {pkgs}\n\n"
        f"Summary: {adv.get('summary')}\n\n"
        f"Description:\n{(adv.get('description') or '')[:3500]}"
    )
    try:
        from my_bot.utils.llm_factory import create_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        sys = (
            "You are a SOC analyst triaging a security advisory for the Package "
            "Compromise Assessment queue at a large enterprise (the company). Assess our "
            "LIKELY exposure, recommend an action, and extract structured threat "
            "intelligence. Be concrete about what to check (dependency manifests/SBOM, "
            "build pipelines, affected services).\n"
            "GROUNDING RULES: include IOCs ONLY when the indicator is explicitly present "
            "in the advisory text (malicious package name/version, domain, IP, URL, file "
            "hash, email) — never invent or guess one. TTPs MAY be inferred from described "
            "behavior; use MITRE ATT&CK technique IDs (e.g. T1195.001) with their names. "
            "List threat actors/campaigns only if named or strongly implied. Use empty "
            "arrays when nothing applies — do not pad.\n"
            "Reply with ONLY a JSON object:\n"
            '{"exposure": "<2-3 sentences on whether/how we might be exposed and what to check>", '
            '"recommendation": "escalate|investigate|close", '
            '"rationale": "<1-2 sentences>", '
            '"suggested_note": "<a concise triage note the reviewer can paste>", '
            '"iocs": [{"type": "package|domain|ip|url|hash|email", "value": "...", "note": "..."}], '
            '"ttps": [{"id": "T1195.001", "name": "Compromise Software Supply Chain"}], '
            '"threat_actors": [{"name": "...", "note": "..."}], '
            '"next_steps": ["<3-6 concrete actions>"]}'
        )
        resp = create_llm().invoke([SystemMessage(content=sys), HumanMessage(content=ctx)])
        text = resp.content if hasattr(resp, "content") else str(resp)
        data = _extract_json(text)
        if isinstance(data, dict) and data.get("recommendation"):
            rec = str(data.get("recommendation")).strip().lower()
            return {
                "exposure": str(data.get("exposure") or "").strip()[:1500],
                "recommendation": rec if rec in ("escalate", "investigate", "close") else "investigate",
                "rationale": str(data.get("rationale") or "").strip()[:600],
                "suggested_note": str(data.get("suggested_note") or "").strip()[:1500],
                "iocs": _intel_rows(data.get("iocs"), ("type", "value", "note")),
                "ttps": _intel_rows(data.get("ttps"), ("id", "name")),
                "threat_actors": _intel_rows(data.get("threat_actors"), ("name", "note")),
                "next_steps": _intel_steps(data.get("next_steps")),
                "model": "llm",
                "generated_at": _now_z(),
            }
    except Exception as e:
        logger.warning("[Advisories] AI triage failed (%s) — heuristic fallback", e)

    high_risk = adv.get("source", "").startswith(("github_malware", "osv")) or \
        adv.get("severity") in ("malicious", "critical", "known_exploited")
    pkg_list = adv.get("packages") or []
    return {
        "exposure": f"Affected: {pkgs}. Check whether these are present in our dependency "
                    "manifests/SBOM and build pipelines, and which services pull them.",
        "recommendation": "escalate" if high_risk else "investigate",
        "rationale": "Heuristic assessment (LLM unavailable).",
        "suggested_note": f"Reviewed {adv.get('source_id')} ({pkgs}). Checking exposure via SBOM/dependency scan.",
        "iocs": [{"type": "package", "value": p, "note": "affected package"} for p in pkg_list[:25]],
        "ttps": ([{"id": "T1195.001",
                   "name": "Compromise Software Supply Chain: Software Dependencies and Development Tools"}]
                 if high_risk else []),
        "threat_actors": [],
        "next_steps": [
            "Search SBOM / dependency manifests for the affected package(s) and version(s).",
            "Check build pipelines and artifact caches for the affected versions.",
            "Identify which services pull the dependency and assess blast radius.",
            "If present, pin or upgrade to a safe version and rotate any exposed secrets/tokens.",
        ],
        "model": "heuristic",
        "generated_at": _now_z(),
    }


ADVISORY_FAQ_QUESTIONS = [
    "Should we declare a CAPD (Clear and Present Danger) for this advisory?",
    "Is this vulnerability easy to exploit?",
    "Are we likely to be affected?",
    "How urgent is remediation, and what's the realistic blast radius?",
    "What should the advisory owner do first?",
]


def generate_advisory_faq(adv: dict[str, Any]) -> dict[str, Any]:
    """Answer a fixed set of CAPD-decision questions about an advisory via the LLM,
    grounded in the advisory facts (+ any cached AI assessment). Returns
    ``{items: [{q, a}], model, generated_at}``."""
    pkgs = ", ".join(adv.get("packages") or []) or "n/a"
    ai = adv.get("ai_assessment") or {}
    ai_line = ""
    if isinstance(ai, dict) and ai.get("exposure"):
        ai_line = f"\nPrior AI exposure note: {ai.get('exposure')}\nPrior recommendation: {ai.get('recommendation')}"
    ctx = (
        f"ID: {adv.get('source_id')}\n"
        f"CVE: {adv.get('cve_id') or 'none'}\n"
        f"Severity: {adv.get('severity')}\n"
        f"Affected packages/products: {pkgs}\n\n"
        f"Summary: {adv.get('summary')}\n\n"
        f"Description:\n{(adv.get('description') or '')[:3000]}{ai_line}"
    )
    questions = "\n".join(f"{i+1}. {q}" for i, q in enumerate(ADVISORY_FAQ_QUESTIONS))
    try:
        from my_bot.utils.llm_factory import create_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        sys = (
            "You are a senior detection & response analyst at a large enterprise (the company), "
            "helping the advisory owner make a CAPD (Clear and Present Danger) decision. "
            "Answer EACH question concisely (2-4 sentences), decisively, and grounded in the "
            "advisory facts. Where our specific exposure is unknown, say what to check rather "
            "than assuming worst-case. For the CAPD question give a clear lean (yes/no/【needs X】) "
            "with the reasoning.\n"
            "Reply with ONLY a JSON array, one object per question IN ORDER: "
            '[{"q": "<the question>", "a": "<your answer>"}].'
        )
        user = ctx + "\n\nQUESTIONS:\n" + questions
        resp = create_llm().invoke([SystemMessage(content=sys), HumanMessage(content=user)])
        text = resp.content if hasattr(resp, "content") else str(resp)
        data = _extract_json(text)
        items = []
        if isinstance(data, list):
            for row in data:
                if isinstance(row, dict) and row.get("a"):
                    items.append({"q": str(row.get("q") or "").strip()[:300],
                                  "a": str(row.get("a") or "").strip()[:1500]})
        if items:
            return {"items": items, "model": "llm", "generated_at": _now_z()}
    except Exception as e:
        logger.warning("[Advisories] FAQ generation failed: %s", e)
    # Fallback: questions with a graceful "unavailable" note so the UI still renders.
    return {
        "items": [{"q": q, "a": "AI answer unavailable right now — try again shortly."}
                  for q in ADVISORY_FAQ_QUESTIONS],
        "model": "unavailable",
        "generated_at": _now_z(),
    }


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def _fmt_date(published_at: str | None) -> str:
    if not published_at:
        return "unknown"
    try:
        dt = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
    except ValueError:
        return published_at


def _page_url(native_id: str) -> str:
    """The triage page for an advisory (resolved by native id via alias lookup)."""
    base = (os.environ.get("WEB_SERVER_BASE_URL") or "http://gdnr.the-company.com").rstrip("/")
    return f"{base}/cs-advisories/{native_id}"


def _notif_fields(rec: dict[str, Any], labels: dict[str, str]) -> dict[str, str]:
    sid = rec.get("source_id") or "unknown"
    pkgs = ", ".join(rec.get("packages") or [])
    return {
        "source_label": labels.get(rec.get("source", ""), rec.get("source", "")),
        "id": sid,
        "cve_id": rec.get("cve_id") or "—",
        "summary": (rec.get("summary") or "(no summary)").strip(),
        "severity": rec.get("severity") or "—",
        "packages": (pkgs[:200] + "…") if len(pkgs) > 200 else (pkgs or "—"),
        "published": _fmt_date(rec.get("published_at")),
        "github_url": rec.get("html_url") or "",
        "page_url": _page_url(sid),
    }


# ---------------------------------------------------------------------------
# Notification channels
# ---------------------------------------------------------------------------
def _post_webex(fields: list[dict[str, str]], room_id: str) -> None:
    token = CONFIG.webex_bot_access_token_aide
    if not token:
        logger.warning("[Advisories] No Aide bot token configured — skipping Webex")
        return
    if not room_id:
        logger.warning("[Advisories] No Webex room configured — skipping Webex")
        return

    now = _now_et()
    count = len(fields)
    lines = [
        f"🚨 **{count} new security advisor{'y' if count == 1 else 'ies'}** 🔐",
        f"_Polled {now}_",
        "",
    ]
    for f in fields:
        pkg = f"  📦 {f['packages']}\n" if f["packages"] != "—" else ""
        lines.append(
            f"• `{f['source_label']}` **{f['id']}** ({f['cve_id']}) — {f['summary']}  \n"
            f"{pkg}"
            f"  📅 {f['published']} · [Review]({f['page_url']}) · [Source]({f['github_url']})"
        )
    send_message(WebexAPI(access_token=token), room_id, markdown="\n".join(lines))
    logger.info("[Advisories] Posted Webex digest of %d advisory(ies)", count)


def _digest_recipients() -> tuple[list[str], str | None]:
    """Resolve the digest's To / Cc.

    To = the AppSec team mailbox plus everyone who self-subscribed from the
    /cs-advisories page; Cc = the configured owner (APPSEC_TEAM_EMAIL_CC).
    Addresses are deduped case-insensitively and a Cc address is never also
    listed in To.
    """
    cc = CONFIG.appsec_team_email_cc or None
    cc_keys = {cc.strip().lower()} if cc else set()

    to: list[str] = []
    seen: set[str] = set()
    candidates = [CONFIG.appsec_team_email] if CONFIG.appsec_team_email else []
    candidates += db.list_subscribers()
    for addr in candidates:
        key = (addr or "").strip().lower()
        if not key or key in cc_keys or key in seen:
            continue
        seen.add(key)
        to.append(addr)
    return to, cc


def _send_email(fields: list[dict[str, str]]) -> None:
    to, cc = _digest_recipients()
    if not to:
        logger.info("[Advisories] No digest recipients (APPSEC_TEAM_EMAIL unset, no subscribers) — skipping email")
        return

    from services.xsoar_email import send_email  # lazy: pulls XSOAR client

    count = len(fields)
    subject = f"[CRITICAL] {count} new security advisor{'y' if count == 1 else 'ies'}"

    text_blocks, html_blocks = [], []
    for f in fields:
        text_blocks.append(
            f"Source:     {f['source_label']}\n"
            f"ID:         {f['id']}\n"
            f"CVE ID:     {f['cve_id']}\n"
            f"Severity:   {f['severity']}\n"
            f"Packages:   {f['packages']}\n"
            f"Published:  {f['published']}\n"
            f"Summary:    {f['summary']}\n"
            f"Review:     {f['page_url']}\n"
            f"Source URL: {f['github_url']}\n"
        )
        pkg_line = (
            f"<div style=\"font-size:13px;color:#24292e;\">📦 {f['packages']}</div>"
            if f["packages"] != "—" else ""
        )
        html_blocks.append(
            "<div style=\"margin:0 0 18px;padding:12px 14px;border-left:4px solid #b31d28;"
            "background:#fafbfc;font-family:Arial,sans-serif;\">"
            f"<div style=\"font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6f42c1;font-weight:700;\">{f['source_label']}</div>"
            f"<div style=\"font-size:15px;font-weight:bold;\">{f['id']} "
            f"<span style=\"color:#586069;font-weight:normal;\">({f['cve_id']})</span></div>"
            f"<div style=\"margin:6px 0;color:#24292e;\">{f['summary']}</div>"
            f"{pkg_line}"
            f"<div style=\"font-size:13px;color:#586069;margin-top:4px;\">Published {f['published']} · "
            f"<a href=\"{f['page_url']}\" style=\"color:#0366d6;font-weight:600;\">Review &amp; triage</a> · "
            f"<a href=\"{f['github_url']}\">View source</a></div>"
            "</div>"
        )

    body = (
        f"{count} new security advisor{'y' if count == 1 else 'ies'} detected.\n\n"
        + "\n".join(text_blocks)
    )
    html_body = (
        "<div style=\"font-family:Arial,sans-serif;\">"
        f"<h2 style=\"color:#b31d28;\">🚨 {count} new security advisor{'y' if count == 1 else 'ies'}</h2>"
        + "".join(html_blocks)
        + "<p style=\"font-size:12px;color:#959da5;\">Automated alert from the IR "
        "Detection Engineering advisory monitor. Click <b>Review &amp; triage</b> "
        "to add notes, close, or escalate to Package Compromise Assessment.</p></div>"
    )

    send_email(to, subject, body, cc=cc, html_body=html_body)
    logger.info("[Advisories] Emailed %d recipient(s) (cc=%s) about %d advisory(ies)", len(to), cc or "—", count)


# ---------------------------------------------------------------------------
# Veracode SCA exposure enrichment
# ---------------------------------------------------------------------------
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _advisory_cves(adv: dict[str, Any]) -> list[str]:
    """All CVE ids referenced by an advisory (primary cve_id + any CVE aliases)."""
    cves = set()
    if adv.get("cve_id"):
        cves.add(str(adv["cve_id"]).upper())
    for alias in adv.get("aliases") or []:
        if alias and _CVE_RE.fullmatch(str(alias).strip()):
            cves.add(str(alias).upper())
    return sorted(cves)


def _advisory_packages(adv: dict[str, Any]) -> list[str]:
    """Bare open-source package names an advisory affects (ecosystem suffix dropped).

    Advisory ``packages`` entries are stored as ``"name (ecosystem)"``; the
    Veracode lookup matches on the bare component name, so strip the suffix.
    """
    names = set()
    for entry in adv.get("packages") or []:
        if not entry:
            continue
        name = str(entry).split(" (")[0].strip()
        if name:
            names.add(name)
    return sorted(names)


# ---------------------------------------------------------------------------
# Direct package / repo links (for OSS Governance → RPT ingestion)
# ---------------------------------------------------------------------------
# The advisory ``html_url`` points at the *advisory* (GHSA / OSV / NVD page), not
# at the package itself. The OSS Governance team wants a link straight to the
# vulnerable package so they can pivot from it and tie it to RPT for blocking.
# We derive a canonical "view this package" registry URL per ecosystem, plus the
# upstream GitHub repo when the advisory references one.
_REGISTRY_URL_TEMPLATES = {
    "npm": "https://www.npmjs.com/package/{name}",
    "pypi": "https://pypi.org/project/{name}/",
    "go": "https://pkg.go.dev/{name}",
    "rubygems": "https://rubygems.org/gems/{name}",
    "crates.io": "https://crates.io/crates/{name}",
    "cargo": "https://crates.io/crates/{name}",
    "nuget": "https://www.nuget.org/packages/{name}",
    "packagist": "https://packagist.org/packages/{name}",
    "composer": "https://packagist.org/packages/{name}",
    "pub": "https://pub.dev/packages/{name}",
    "hex": "https://hex.pm/packages/{name}",
}


def _split_package_entry(entry: str) -> tuple[str, str]:
    """``"@mastra/core (npm)"`` → ``("@mastra/core", "npm")``; no suffix → eco ``""``."""
    s = (entry or "").strip()
    if s.endswith(")") and " (" in s:
        name, _, eco = s.rpartition(" (")
        return name.strip(), eco[:-1].strip()
    return s, ""


def _registry_url(name: str, ecosystem: str | None) -> str | None:
    """Canonical package-page URL for ``name`` in ``ecosystem``, or ``None``."""
    name = (name or "").strip()
    eco = (ecosystem or "").strip().lower()
    if not name:
        return None
    if eco == "maven":  # names are ``group:artifact``
        group, sep, artifact = name.partition(":")
        if sep:
            return f"https://central.sonatype.com/artifact/{group}/{artifact}"
        return f"https://central.sonatype.com/search?q={name}"
    tmpl = _REGISTRY_URL_TEMPLATES.get(eco)
    return tmpl.format(name=name) if tmpl else None


def _github_repo_url(raw: dict[str, Any]) -> str | None:
    """First GitHub source-repo URL referenced by the advisory, trimmed to the
    ``github.com/<owner>/<repo>`` root (skips github.com/advisories pages)."""
    refs = (raw or {}).get("references") or []
    for r in refs:
        url = (r.get("url") if isinstance(r, dict) else r) or ""
        m = re.search(r"https?://github\.com/([^/\s]+)/([^/\s#?]+)", url)
        if not m or m.group(1).lower() == "advisories":
            continue
        owner, repo = m.group(1), m.group(2).removesuffix(".git")
        return f"https://github.com/{owner}/{repo}"
    return None


def advisory_package_links(adv: dict[str, Any]) -> list[dict[str, str]]:
    """Per-package links for an advisory: ``[{name, ecosystem, registry_url, repo_url}]``.

    Gives OSS Governance a direct pivot to each vulnerable package (registry page
    + upstream repo) rather than only the advisory URL. De-duplicated by name+eco.
    """
    raw = adv.get("raw") or adv.get("raw_json") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            raw = {}
    repo_url = _github_repo_url(raw)
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in adv.get("packages") or []:
        name, eco = _split_package_entry(str(entry))
        eco = eco or (adv.get("ecosystem") or "")
        key = (name, eco.lower())
        if not name or key in seen:
            continue
        seen.add(key)
        out.append({
            "name": name,
            "ecosystem": eco,
            "registry_url": _registry_url(name, eco) or "",
            "repo_url": repo_url or "",
        })
    return out


# ---------------------------------------------------------------------------
# Package grouping + bulk environment check (clear a whole campaign at once)
# ---------------------------------------------------------------------------
# A supply-chain campaign drops dozens-to-hundreds of look-alike packages (e.g.
# every package under an npm scope like @mastra). Rather than open each one, an
# analyst searches the shared token, checks the whole set against our environment
# in one shot, and — if none are present — clears them all at once.

def package_group(query: str, advisories: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Advisories whose affected packages match ``query`` (case-insensitive
    substring, e.g. an npm scope ``@mastra``). Returns the de-duplicated package
    set + member advisories so the queue can be cleared as a group."""
    q = (query or "").strip().lower()
    if not q:
        return {"query": query or "", "advisory_count": 0, "package_count": 0,
                "packages": [], "ecosystems": [], "members": []}
    if advisories is None:
        advisories = db.list_advisories()
    members: list[dict[str, Any]] = []
    pkgset: set[str] = set()
    ecosystems: set[str] = set()
    for a in advisories:
        matched: list[str] = []
        for entry in a.get("packages") or []:
            name, eco = _split_package_entry(str(entry))
            if q in name.lower() or q in str(entry).lower():
                matched.append(name)
                pkgset.add(name)
                if eco:
                    ecosystems.add(eco)
        if matched:
            members.append({
                "source_id": a.get("source_id"),
                "uid": a.get("uid"),
                "packages": sorted(set(matched)),
                "first_seen": (a.get("first_seen_at") or "")[:10],
                "status": a.get("status"),
            })
    members.sort(key=lambda m: m["first_seen"])
    return {
        "query": query or "",
        "advisory_count": len(members),
        "package_count": len(pkgset),
        "packages": sorted(pkgset),
        "ecosystems": sorted(ecosystems),
        "members": members,
    }


def group_environment_check(packages: list[str]) -> dict[str, Any]:
    """Veracode SCA presence check across a set of package names. Compact summary
    for the bulk-clear UI. NB: a miss is 'no open SCA finding references it', not
    absolute proof of absence from every app's full SBOM — surfaced to the user."""
    pkgs = sorted({p for p in (packages or []) if p})
    if not pkgs:
        return {"checked": False, "error": "no packages to check"}
    try:
        from services import veracode
        res = veracode.component_exposure(pkgs)
    except Exception as e:  # noqa: BLE001 — env check is best-effort
        return {"checked": False, "error": str(e)[:200]}
    present = sorted((res.get("packages") or {}).keys())
    return {
        "checked": True,
        "configured": bool(res.get("configured")),
        "indexing": bool(res.get("indexing")),
        "exposed": bool(res.get("exposed")),
        "affected_app_count": res.get("affected_app_count", 0),
        "present_packages": present,
        "package_count": len(pkgs),
        "summary": res.get("summary_text") or "",
        "error": res.get("error"),
    }


# ---------------------------------------------------------------------------
# Cross-source corroboration
# ---------------------------------------------------------------------------
# Each feed (GitHub Advisories, OSV npm/PyPI, CISA KEV, custom RSS, …) emits
# independently. When the SAME CVE / alias id / package surfaces in more than one
# feed, that is independent confirmation — a stronger signal than any single feed.
# We compute it in-memory over the visible list (cheap) and annotate each row.

def _corroboration_keys(adv: dict[str, Any]) -> set[tuple]:
    """Identity keys an advisory can be matched on across sources: its CVE, any
    alias id (GHSA/CVE/MAL/…), and each affected package (name+ecosystem)."""
    keys: set[tuple] = set()
    cve = (adv.get("cve_id") or "").strip().upper()
    if cve:
        keys.add(("id", cve))
    for al in adv.get("aliases") or []:
        if isinstance(al, str) and al.strip():
            keys.add(("id", al.strip().upper()))
    for entry in adv.get("packages") or []:
        if not entry:
            continue
        s = str(entry)
        name = s.split(" (")[0].strip().lower()
        eco = ""
        if " (" in s and s.endswith(")"):
            eco = s[s.rfind(" (") + 2:-1].strip().lower()
        if name:
            keys.add(("pkg", name, eco))
    return keys


def compute_corroboration(advisories: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map advisory uid -> corroboration info when the same CVE/alias/package is
    seen in 2+ *different* sources. Returns only corroborated advisories.

    Value: ``{sources: [labels...], source_count: N (incl. self), peers:
    [{uid, source, label, source_id, via}], via: [human reasons]}``.
    """
    labels = source_labels_map()
    index: dict[tuple, list[str]] = {}
    meta: dict[str, dict[str, Any]] = {}
    for a in advisories:
        uid = a.get("uid") or a.get("source_id")
        if not uid:
            continue
        keys = _corroboration_keys(a)
        meta[uid] = {
            "keys": keys,
            "source": a.get("source"),
            "source_id": a.get("source_id"),
            "label": labels.get(a.get("source"), a.get("source") or "—"),
        }
        for k in keys:
            index.setdefault(k, []).append(uid)

    def _via_label(k: tuple) -> str:
        if k[0] == "id":
            return k[1]
        return k[1] + (f" ({k[2]})" if len(k) > 2 and k[2] else "")

    out: dict[str, dict[str, Any]] = {}
    for uid, m in meta.items():
        peers: dict[str, set] = {}
        for k in m["keys"]:
            for other in index.get(k, []):
                if other == uid or meta[other]["source"] == m["source"]:
                    continue  # cross-source only
                peers.setdefault(other, set()).add(k)
        if not peers:
            continue
        peer_list = []
        via_all: set = set()
        for puid, vks in peers.items():
            pm = meta[puid]
            via = sorted(_via_label(k) for k in vks)
            via_all.update(via)
            peer_list.append({
                "uid": puid, "source": pm["source"], "label": pm["label"],
                "source_id": pm["source_id"], "via": via,
            })
        peer_list.sort(key=lambda p: p["label"])
        distinct_sources = {m["source"]} | {p["source"] for p in peer_list}
        out[uid] = {
            "sources": sorted({p["label"] for p in peer_list} | {m["label"]}),
            "source_count": len(distinct_sources),
            "peers": peer_list,
            "via": sorted(via_all)[:6],
        }
    return out


# ---------------------------------------------------------------------------
# Campaign clustering — group likely-related malicious-package advisories
# ---------------------------------------------------------------------------
# Supply-chain attacks arrive in waves: one actor publishes many typosquats in a
# short window. Each lands as its own advisory row. Clustering them surfaces the
# campaign instead of N look-alike rows. Heuristic + conservative: link two
# advisories only on strong signals (shared distinctive name tokens, a shared
# AI-extracted threat actor, or a shared IOC) within a time window.

_CAMPAIGN_STOP_TOKENS = {
    "the", "and", "for", "lib", "js", "node", "core", "api", "app", "src",
    "test", "tests", "utils", "util", "common", "data", "client", "server",
    "service", "services", "plugin", "module", "package", "react", "vue",
    "python", "py", "npm", "pypi", "io", "com", "www", "dev", "new", "get",
    "set", "v1", "v2", "v3", "x64", "x86", "win", "mac", "linux",
}


def _campaign_tokens(adv: dict[str, Any]) -> set[str]:
    """Distinctive lowercase tokens from an advisory's package names."""
    import re
    toks: set[str] = set()
    for entry in adv.get("packages") or []:
        name = str(entry).split(" (")[0]
        # strip scope (@scope/name -> name + scope), split on non-alnum
        for part in re.split(r"[^a-z0-9]+", name.lower()):
            if len(part) >= 3 and not part.isdigit() and part not in _CAMPAIGN_STOP_TOKENS:
                toks.add(part)
    return toks


def _campaign_actors(adv: dict[str, Any]) -> set[str]:
    ai = adv.get("ai_assessment") or {}
    out: set[str] = set()
    for a in (ai.get("threat_actors") or []):
        if isinstance(a, str) and a.strip():
            out.add(a.strip().lower())
        elif isinstance(a, dict) and a.get("name"):
            out.add(str(a["name"]).strip().lower())
    return out


def _campaign_iocs(adv: dict[str, Any]) -> set[str]:
    ai = adv.get("ai_assessment") or {}
    out: set[str] = set()
    for i in (ai.get("iocs") or []):
        if isinstance(i, dict) and i.get("value"):
            out.add(str(i["value"]).strip().lower())
    return out


def compute_campaigns(advisories: list[dict[str, Any]], window_days: int = 14,
                      min_shared_tokens: int = 2) -> list[dict[str, Any]]:
    """Cluster likely-related malicious-package advisories. Returns a list of
    clusters (size >= 2), largest first. Each: ``{size, sources, ecosystems,
    common_tokens, span_days, members:[{source_id, uid, packages, first_seen}]}``."""
    from datetime import datetime as _dt

    # Only package/malware advisories participate.
    cand = [a for a in advisories if (a.get("packages") and (
        a.get("source", "").startswith("osv") or "malware" in (a.get("source") or "")
        or str(a.get("source_id") or "").startswith("MAL")))]
    n = len(cand)
    if n < 2:
        return []

    feats = []
    for a in cand:
        ts = a.get("first_seen_at") or a.get("published_at") or ""
        try:
            d = _dt.fromisoformat(str(ts).replace("Z", "+00:00")) if ts else None
        except ValueError:
            d = None
        feats.append({
            "tokens": _campaign_tokens(a), "actors": _campaign_actors(a),
            "iocs": _campaign_iocs(a), "when": d,
            "eco": (a.get("ecosystem") or "").lower(), "adv": a,
        })

    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    for i in range(n):
        for j in range(i + 1, n):
            fi, fj = feats[i], feats[j]
            # time window (skip the check if either date is missing)
            if fi["when"] and fj["when"] and abs((fi["when"] - fj["when"]).days) > window_days:
                continue
            shared_tokens = fi["tokens"] & fj["tokens"]
            linked = (
                len(shared_tokens) >= min_shared_tokens
                or bool(fi["actors"] & fj["actors"])
                or bool(fi["iocs"] & fj["iocs"])
            )
            if linked:
                union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    labels = source_labels_map()
    clusters = []
    for members in groups.values():
        if len(members) < 2:
            continue
        advs = [feats[i]["adv"] for i in members]
        tok_counts: dict[str, int] = {}
        for i in members:
            for t in feats[i]["tokens"]:
                tok_counts[t] = tok_counts.get(t, 0) + 1
        common = sorted([t for t, c in tok_counts.items() if c >= 2],
                        key=lambda t: tok_counts[t], reverse=True)[:6]
        dates = [feats[i]["when"] for i in members if feats[i]["when"]]
        span = (max(dates) - min(dates)).days if len(dates) >= 2 else 0
        clusters.append({
            "size": len(members),
            "sources": sorted({labels.get(a.get("source"), a.get("source") or "—") for a in advs}),
            "ecosystems": sorted({(a.get("ecosystem") or "").strip() for a in advs if a.get("ecosystem")}),
            "common_tokens": common,
            "span_days": span,
            "members": sorted([
                {"source_id": a.get("source_id"), "uid": a.get("uid"),
                 "packages": a.get("packages") or [],
                 "first_seen": (a.get("first_seen_at") or "")[:10]}
                for a in advs
            ], key=lambda m: m["first_seen"]),
        })
    clusters.sort(key=lambda c: c["size"], reverse=True)
    return clusters


# ---------------------------------------------------------------------------
# Owner-run capabilities (detail page)
# ---------------------------------------------------------------------------
# The detail page surfaces the SOC's existing tooling as owner-clickable
# capabilities. JFrog runs server-side and persists its result; the heavier /
# iframe tools are launched via deep-links pre-targeted at the advisory.
def advisory_capability_links(adv: dict[str, Any]) -> dict[str, Any]:
    """Deep-links to the heavier/iframe capabilities, pre-aimed at this advisory.
    A value of None means that tool isn't configured/available."""
    cves = _advisory_cves(adv)
    pkgs = _advisory_packages(adv)
    term = cves[0] if cves else (pkgs[0] if pkgs else None)

    falcon = None
    if term:
        try:
            from src.components.tipper_analyzer.formatters import _get_falcon_logscale_link
            falcon = _get_falcon_logscale_link(f'"{term}"', window="30d")
        except Exception as e:
            logger.debug("[Advisories] Falcon deep-link unavailable: %s", e)

    return {
        # "Were we touched?" — pre-filled Falcon LogScale search for the CVE/package.
        "crowdstrike": falcon,
        # On-demand analyst hunt workbench (our app, paste-CTI driven).
        "hunt": "/hunt-workbench",
        # BAS platform — launch only; running TTPs requires SOC coordination.
        "attackiq": CONFIG.attackiq_base_url or None,
        # External attack-surface / asset discovery — not yet onboarded.
        "runzero": None,
    }


def _summarize_rf_vuln(raw: Any, cves: list[str]) -> dict[str, Any]:
    """Tolerantly summarize a Recorded Future SOAR enrichment response for a CVE
    into ``{summary_text, risk_score, risk_level, rules}``. The SOAR shape varies,
    so dig defensively and fall back to a generic message."""
    if isinstance(raw, dict) and raw.get("error"):
        return {"summary_text": f"Recorded Future error: {raw['error']}", "error": raw["error"]}
    results = []
    if isinstance(raw, dict):
        data = raw.get("data") or raw
        results = data.get("results") or data.get("data") or []
    top = results[0] if isinstance(results, list) and results else None
    if not isinstance(top, dict):
        return {"summary_text": f"No Recorded Future intelligence returned for {', '.join(cves)}."}
    risk = top.get("risk") or {}
    score = risk.get("score")
    level = risk.get("level") or risk.get("criticalityLabel")
    rules = []
    evidence = risk.get("evidenceDetails") or (risk.get("rule") or {}).get("evidence") or []
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("rule"):
            rules.append(ev["rule"])
    if score is not None:
        summary = f"Recorded Future risk score {score}" + (f" ({level})" if level else "")
    else:
        summary = "Enriched (no risk score returned)."
    if rules:
        summary += " — " + "; ".join(rules[:5])
    return {"summary_text": summary, "risk_score": score, "risk_level": level, "rules": rules[:8]}


# ---------------------------------------------------------------------------
# CAPD scorecard — a grounded "do we declare a CAPD?" verdict
# ---------------------------------------------------------------------------
# Replaces the generic "assume worst-case" Sentinel email with a scored decision
# built entirely from data we already pull: EPSS + CISA KEV (cve_priority/epss),
# CVSS (advisory record), our software exposure (Veracode SCA + cached JFrog),
# active-threat intel (cached Recorded Future), and patch availability. Each
# category is graded 0–4 with a fixed weight; the weighted mean (over categories
# we have data for) is normalized to 0–100 and banded. Two hard overrides apply.
CAPD_WEIGHTS = {
    "exploitability": 25,
    "exposure": 25,
    "active_threat": 20,
    "severity": 15,
    "reachability": 10,
    "patch": 5,
}
CAPD_BANDS = {"declare": "DECLARE CAPD", "monitor": "MONITOR", "none": "NO ACTION"}


def _capd_cvss(adv: dict[str, Any]) -> dict[str, Any]:
    """Pull {score, vector} from the advisory's raw record (best-effort), matching
    the detail-page logic: GitHub carries ``cvss={score, vector_string}``; OSV
    carries ``severity`` as a list of ``{type, score(=vector string)}``."""
    raw = adv.get("raw") or {}
    score, vector = None, ""
    cvss = raw.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score") or cvss.get("base_score")
        vector = cvss.get("vector_string") or cvss.get("vector") or ""
    if not vector:
        sev = raw.get("severity")
        if isinstance(sev, list):
            for s in sev:
                if isinstance(s, dict) and s.get("score"):
                    vector = s.get("score")  # OSV stores the vector string here
                    break
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    return {"score": score, "vector": vector or ""}


def _capd_reachability(cves: list[str]) -> dict[str, Any]:
    """Reachability from internet-exposure scanners — Shodan + Censys.

    Two independent scanners corroborate "is this vuln internet-reachable?". When
    ``SHODAN_ORG``/``SHODAN_NET`` is configured the query is scoped to our
    footprint → a true "are WE internet-exposed?" signal (any host => max). With
    no scope it's a global "how exposed is this vuln on the internet" proxy,
    clearly labelled and capped at 3 so it never alone forces a DECLARE. Censys
    (``CENSYS_API_ID``/``CENSYS_API_SECRET``) is a second, vendor-independent
    source; the higher reading wins and both are cited. Either source
    missing or erroring degrades gracefully — we score from whatever responded.

    Only the primary CVE is queried — aliases describe the same flaw, so summing
    double-counts, and one call per scanner bounds the worst-case latency.
    """
    if not cves:
        return _cat("reachability", "External reachability", None,
                    "No CVE to check internet exposure (scanners need a CVE).", "—")
    cve = cves[0]
    org = (CONFIG.shodan_org or "").strip()
    net = (CONFIG.shodan_net or "").strip()
    scoped = bool(org or net)

    readings: list[tuple[str, int]] = []  # (source, host count)
    notes: list[str] = []                 # degraded-source evidence fragments

    # --- Shodan (free host/count) ---
    try:
        from services.shodan_monitor import get_client as _shodan_client
        sc = _shodan_client()
        if sc.is_configured():
            scope = ""
            if org:
                scope += f' org:"{org}"'
            if net:
                scope += f" net:{net}"
            res = sc.count(f"vuln:{cve}{scope}")
            if res.get("error"):
                notes.append(f"Shodan unavailable ({res['error']})")
            else:
                readings.append(("Shodan", int(res.get("total") or 0)))
    except Exception as e:  # noqa: BLE001 — never let enrichment break the scorecard
        logger.debug("[CAPD] Shodan reachability failed: %s", e)
        notes.append("Shodan lookup failed")

    # --- Censys (hosts search count; reuses the same footprint scope) ---
    try:
        from services.censys import CENSYS_CVE_FIELD, get_client as _censys_client
        cc = _censys_client()
        if cc.is_configured():
            # Platform CenQL host query; reuses the same footprint scope as Shodan.
            q = f'{CENSYS_CVE_FIELD}: "{cve}"'
            if net:
                q += f" and host.ip: {net}"
            if org:
                q += (f' and (host.autonomous_system.name: "{org}"'
                      f' or host.whois.organization.name: "{org}")')
            res = cc.count(q)
            if res.get("error"):
                notes.append(f"Censys unavailable ({res['error']})")
            else:
                readings.append(("Censys", int(res.get("total") or 0)))
    except Exception as e:  # noqa: BLE001
        logger.debug("[CAPD] Censys reachability failed: %s", e)
        notes.append("Censys lookup failed")

    if not readings:
        msg = "; ".join(notes) if notes else "No internet-exposure scanner configured."
        return _cat("reachability", "External reachability", None, msg, "—")

    sources = " + ".join(s for s, _ in readings)
    if scoped:  # scoped to us → authoritative
        hits = [(s, t) for s, t in readings if t > 0]
        if hits:
            ev = "; ".join(f"{s}: {t}" for s, t in hits)
            return _cat("reachability", "External reachability", 4,
                        f"Internet-exposed host(s) in our footprint run a service vulnerable "
                        f"to {cve} — {ev}.", sources)
        return _cat("reachability", "External reachability", 0,
                    f"No internet-exposed host in our footprint matches {cve} ({sources}).", sources)
    # global proxy (no org/net scope) — bucket the largest reading, cap at 3
    top = max(t for _, t in readings)
    score = 3 if top >= 100000 else 2 if top >= 1000 else 1 if top >= 1 else 0
    ev = "; ".join(f"{s}: ~{t:,}" for s, t in readings)
    return _cat("reachability", "External reachability", score,
                f"Host(s) worldwide expose a service vulnerable to {cve} — {ev} "
                f"(global — set SHODAN_ORG to scope to our fleet).", sources)


def _cat(key: str, label: str, score: int | None, evidence: str, source: str) -> dict[str, Any]:
    """One scorecard category. ``score=None`` → insufficient data (excluded from
    the denominator so a thin scorecard reads honestly)."""
    return {
        "key": key, "label": label, "weight": CAPD_WEIGHTS[key], "max": 4,
        "score": score, "sufficient": score is not None,
        "pct": int(round((score / 4) * 100)) if score is not None else None,
        "evidence": evidence, "source": source,
    }


def compute_capd_scorecard(adv: dict[str, Any]) -> dict[str, Any]:
    """Grade an advisory across six weighted categories and roll them into a
    0–100 CAPD risk score + band. Every input is native (no new vendor calls
    beyond Veracode's cached SCA index + already-cached capability results).
    Returns the full scorecard dict; never raises (degrades to insufficient)."""
    cves = _advisory_cves(adv)
    cvss = _capd_cvss(adv)
    vector = (cvss.get("vector") or "").upper()
    network = "AV:N" in vector
    low_complexity = "AC:L" in vector

    # --- active-exploitation signals (KEV + EPSS), cheap & cached ---
    kev = False
    epss_pct = None  # percentile rank (0..1)
    if cves:
        try:
            from services.cve_priority import is_kev
            kev = any(is_kev(c) for c in cves)
        except Exception as e:  # noqa: BLE001
            logger.debug("[CAPD] KEV lookup failed: %s", e)
        try:
            from services.epss import get_epss
            for c in cves:
                d = get_epss(c) or {}
                p = d.get("percentile")
                if isinstance(p, (int, float)):
                    epss_pct = max(epss_pct or 0.0, float(p))
        except Exception as e:  # noqa: BLE001
            logger.debug("[CAPD] EPSS lookup failed: %s", e)

    # --- our software exposure (Veracode SCA, cheap cached index) ---
    veracode = enrich_veracode(adv)
    vc_apps = (veracode or {}).get("affected_app_count", 0) if isinstance(veracode, dict) else 0
    # plus any previously-run JFrog Xray result
    cached = {}
    try:
        cached = db.get_capability_results(adv.get("uid") or adv.get("source_id") or "")
    except Exception:  # noqa: BLE001
        cached = {}
    jf = (cached.get("jfrog") or {}).get("result") if isinstance(cached.get("jfrog"), dict) else None
    jf_exposed = bool(jf.get("exposed")) if isinstance(jf, dict) else False

    # --- active-threat intel (cached Recorded Future, if the owner ran it) ---
    ti = (cached.get("threatintel") or {}).get("result") if isinstance(cached.get("threatintel"), dict) else None
    rf_score = ti.get("risk_score") if isinstance(ti, dict) else None
    rf_level = ti.get("risk_level") if isinstance(ti, dict) else None

    cats: list[dict[str, Any]] = []

    # 1) Exploitability — KEV is the ceiling; else EPSS percentile, +1 for AV:N/AC:L.
    if kev:
        cats.append(_cat("exploitability", "Exploitability", 4,
                         "On CISA KEV — known-exploited in the wild right now.", "CISA KEV"))
    elif epss_pct is not None or vector:
        if epss_pct is None:
            s = 2 if (network and low_complexity) else 1
            ev = f"No EPSS; CVSS vector {'network/low-complexity' if network else 'present'}."
        else:
            s = 4 if epss_pct >= 0.90 else 3 if epss_pct >= 0.70 else 2 if epss_pct >= 0.40 else 1 if epss_pct >= 0.10 else 0
            if network and low_complexity:
                s = min(4, s + 1)
            ev = f"EPSS {epss_pct:.0%} percentile" + (" · network/low-complexity vector" if network and low_complexity else "")
        cats.append(_cat("exploitability", "Exploitability", s, ev, "EPSS / CVSS"))
    else:
        cats.append(_cat("exploitability", "Exploitability", None,
                         "No EPSS or CVSS vector available.", "—"))

    # 2) Severity — CVSS base score.
    sc = cvss.get("score")
    if isinstance(sc, (int, float)):
        s = 4 if sc >= 9 else 3 if sc >= 7 else 2 if sc >= 4 else 1
        cats.append(_cat("severity", "Severity", s, f"CVSS base score {sc:g}.", "CVSS"))
    else:
        cats.append(_cat("severity", "Severity", None, "No CVSS base score on record.", "—"))

    # 3) Our software exposure — Veracode SCA + cached JFrog Xray.
    if vc_apps or jf_exposed:
        bits = []
        if vc_apps:
            bits.append(f"{vc_apps} application(s) carry the affected component (Veracode SCA)")
        if jf_exposed:
            bits.append("present in our artifacts (JFrog Xray)")
        cats.append(_cat("exposure", "Our exposure (software)", 4, "; ".join(bits) + ".", "Veracode / JFrog"))
    elif veracode is not None or cves or _advisory_packages(adv):
        cats.append(_cat("exposure", "Our exposure (software)", 0,
                         "No affected applications found in Veracode SCA (findings-only — "
                         "not proof of absence; confirm against SBOM).", "Veracode SCA"))
    else:
        cats.append(_cat("exposure", "Our exposure (software)", None,
                         "No CVE or package to correlate against the SCA index.", "—"))

    # 4) External reachability — internet exposure of the vulnerability via Shodan
    # (free host/count `vuln:` query; scoped to our footprint when SHODAN_ORG/NET
    # is set, else a clearly-labelled global signal).
    cats.append(_capd_reachability(cves))

    # 5) Active threat — KEV or Recorded Future risk score.
    if kev:
        cats.append(_cat("active_threat", "Active threat", 4,
                         "CISA KEV — active exploitation observed.", "CISA KEV"))
    elif isinstance(rf_score, (int, float)):
        s = 4 if rf_score >= 65 else 3 if rf_score >= 25 else 2 if rf_score >= 5 else 1
        cats.append(_cat("active_threat", "Active threat", s,
                         f"Recorded Future risk score {rf_score:g}" + (f" ({rf_level})" if rf_level else "") + ".",
                         "Recorded Future"))
    elif epss_pct is not None and epss_pct >= 0.70:
        cats.append(_cat("active_threat", "Active threat", 2,
                         f"Elevated EPSS ({epss_pct:.0%}) — real-world exploitation signal.", "EPSS"))
    elif cves:
        cats.append(_cat("active_threat", "Active threat", 0,
                         "No active-exploitation evidence (not on KEV; run Threat Intel for actor context).",
                         "CISA KEV"))
    else:
        cats.append(_cat("active_threat", "Active threat", None,
                         "No CVE to check for active exploitation.", "—"))

    # 6) Patch availability — risk is HIGHER when no fix has shipped. GitHub
    # advisories carry first_patched_version per affected package.
    raw = adv.get("raw") or {}
    vulns = raw.get("vulnerabilities") or []
    pkgs = adv.get("packages") or []
    if vulns:
        patched = any((v or {}).get("first_patched_version") for v in vulns)
        if patched:
            cats.append(_cat("patch", "Patch availability", 1, "A fixed version has shipped.", "Advisory"))
        else:
            cats.append(_cat("patch", "Patch availability", 4,
                            "No fixed version published yet — remediation window is open.", "Advisory"))
    elif pkgs:
        cats.append(_cat("patch", "Patch availability", None,
                         "No structured fix data (package-only advisory).", "—"))
    else:
        cats.append(_cat("patch", "Patch availability", None, "No package/fix data on the advisory.", "—"))

    # --- roll up: weighted mean over sufficient categories ---
    num = sum((c["score"] / 4) * c["weight"] for c in cats if c["sufficient"])
    den = sum(c["weight"] for c in cats if c["sufficient"])
    score = int(round((num / den) * 100)) if den else 0

    band = "declare" if score >= 70 else "monitor" if score >= 40 else "none"

    # --- hard overrides ---
    override = None
    confirmed_exposure = bool(vc_apps or jf_exposed)
    if kev and confirmed_exposure:
        band, override = "declare", {
            "fired": True,
            "reason": "Override: on CISA KEV AND confirmed to run in our environment — "
                      "declare a CAPD regardless of composite score.",
        }
    elif not confirmed_exposure and not kev and band == "declare":
        band, override = "monitor", {
            "fired": True,
            "reason": "Override: no confirmed software exposure and not known-exploited — "
                      "capped at MONITOR pending an SBOM/dependency confirmation.",
        }

    result = {
        "score": score,
        "band": band,
        "band_label": CAPD_BANDS[band],
        "categories": cats,
        "override": override,
        "weights_basis": den,
        "verdict": _capd_verdict(adv, score, band, cats, override),
        "generated_at": _now_z(),
    }
    return result


def _capd_verdict(adv: dict[str, Any], score: int, band: str,
                  cats: list[dict[str, Any]], override: dict | None) -> str:
    """A 2–3 sentence plain-language CAPD verdict, grounded ONLY in the computed
    sub-scores (the LLM phrases the evidence; it does not re-judge). Falls back to a
    deterministic sentence if the LLM is unavailable."""
    drivers = "; ".join(f"{c['label']}: {c['evidence']}" for c in cats if c["sufficient"])
    fallback = (f"CAPD score {score}/100 → {CAPD_BANDS[band]}. " +
                (override["reason"] + " " if override else "") +
                f"Top signals — {drivers[:600]}")
    try:
        from my_bot.utils.llm_factory import create_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        sys = (
            "You are a SOC lead writing the one-paragraph CAPD (Clear and Present Danger) "
            "verdict for a security advisory. You are given a pre-computed risk score, a "
            "band, and the scored evidence. Phrase a crisp 2-3 sentence verdict that a "
            "leader can act on. DO NOT invent facts or re-score — only explain the evidence "
            "given. Lead with the decision (declare / monitor / no action) and why."
        )
        ctx = (
            f"Advisory: {adv.get('source_id')} ({adv.get('cve_id') or 'no CVE'})\n"
            f"Computed score: {score}/100 → {CAPD_BANDS[band]}\n"
            + (f"Override: {override['reason']}\n" if override else "")
            + f"Scored evidence:\n{drivers}"
        )
        resp = create_llm().invoke([SystemMessage(content=sys), HumanMessage(content=ctx)])
        text = (resp.content if hasattr(resp, "content") else str(resp)).strip()
        return text[:900] or fallback
    except Exception as e:  # noqa: BLE001
        logger.debug("[CAPD] verdict LLM unavailable: %s", e)
        return fallback


def _qradar_were_we_touched(adv: dict[str, Any]) -> dict[str, Any]:
    """SIEM-side "were we touched?" — a fast presence-check (LIMIT 1) over the
    advisory's network indicators (IP/domain extracted by AI triage) across a 1h
    window (QRadar's practical sweet spot; a full COUNT over 4h is too slow for a
    button). Deeper hunts go to the Hunt Workbench. Returns
    ``{summary_text, exposed?, ...}``.
    """
    ai = adv.get("ai_assessment") or {}
    ips, domains = [], []
    for i in (ai.get("iocs") or []):
        if not isinstance(i, dict) or not i.get("value"):
            continue
        t = str(i.get("type", "")).lower()
        v = str(i.get("value")).strip()
        if t == "ip" and v not in ips:
            ips.append(v)
        elif t in ("domain", "url") and v not in domains:
            domains.append(v)
    ips, domains = ips[:6], domains[:6]

    if not ips and not domains:
        # No network IOCs — typical for software-supply-chain CVEs. Render neutral
        # (omit `exposed`) rather than a misleading green "clear".
        return {"summary_text": "No network indicators (IP/domain) on this advisory to "
                "search the SIEM for — typical for software-supply-chain advisories. "
                "Use the JFrog/Veracode exposure checks and the Hunt Workbench instead.",
                "searched": 0}

    from services.qradar import QRadarClient, _escape_aql_value
    client = QRadarClient()
    if not client.is_configured():
        return {"error": "QRadar is not configured"}

    conds = []
    for ip in ips:
        e = _escape_aql_value(ip)
        conds.append(f"sourceip = '{e}' OR destinationip = '{e}'")
    for d in domains:
        conds.append(f"URL ILIKE '%{_escape_aql_value(d)}%'")
    # LIMIT 1 short-circuits on the first match → fast presence/absence check.
    aql = (f"SELECT sourceip, destinationip, starttime FROM events "
           f"WHERE ({') OR ('.join(conds)}) LIMIT 1 LAST 1 HOURS")

    res = client.run_aql_search(aql, timeout=150, max_results=1)
    if isinstance(res, dict) and res.get("error"):
        return {"error": f"QRadar search failed: {res['error']}"}
    events = (res or {}).get("events") or []
    touched = bool(events)

    n = len(ips) + len(domains)
    iocs_str = ", ".join((ips + domains)[:6])
    if touched:
        return {"summary_text": f"⚠️ Matching activity found in the last 1h for "
                f"{n} indicator(s) ({iocs_str}). Investigate in QRadar and pivot to the "
                f"Hunt Workbench for a wider window.", "exposed": True, "searched": n}
    return {"summary_text": f"No SIEM hits in the last 1h for {n} indicator(s) "
            f"({iocs_str}). Note: 1h is QRadar's practical AQL window — widen the hunt "
            f"via the Hunt Workbench.", "exposed": False, "searched": n}


# ---------------------------------------------------------------------------
# Async capability jobs — for slow capabilities (e.g. QRadar Ariel searches,
# which carry heavy queue/startup latency and routinely exceed 150s). The web
# app is a single multi-threaded Waitress process, so an in-memory registry is
# sufficient; completed results are also persisted to the DB so they survive a
# reload (and a restart, via the saved capability result).
# ---------------------------------------------------------------------------
ASYNC_CAPABILITIES = {"qradar", "fleet_posture", "threat_analysis"}
_CAP_JOBS: dict[tuple[str, str], dict[str, Any]] = {}
_CAP_JOBS_LOCK = threading.Lock()


def start_capability_job(adv: dict[str, Any], capability: str, run_by: str = "",
                         opts: dict[str, Any] | None = None) -> dict[str, Any]:
    """Kick off a background capability run. Returns the current job state. A
    capability already running for this advisory is not started twice. ``opts`` is
    forwarded to ``run_advisory_capability`` (e.g. ``audience``)."""
    uid = adv.get("uid") or adv.get("source_id") or ""
    jkey = (uid, capability)
    with _CAP_JOBS_LOCK:
        cur = _CAP_JOBS.get(jkey)
        if cur and cur.get("state") == "running":
            return {"state": "running"}
        _CAP_JOBS[jkey] = {"state": "running", "started_at": _now_z()}

    def _worker() -> None:
        try:
            res = run_advisory_capability(adv, capability, opts=opts)
            result = res.get("result") if res.get("ok") else None
            if res.get("ok") and isinstance(result, dict) and not result.get("error"):
                try:
                    db.save_capability_result(uid, capability, result, run_by)
                except Exception as e:  # noqa: BLE001 — persistence is best-effort
                    logger.warning("[Advisories] persist %s result failed: %s", capability, e)
                with _CAP_JOBS_LOCK:
                    _CAP_JOBS[jkey] = {"state": "done", "result": result, "finished_at": _now_z()}
            else:
                err = (result or {}).get("error") if isinstance(result, dict) else None
                with _CAP_JOBS_LOCK:
                    _CAP_JOBS[jkey] = {"state": "error",
                                       "error": err or res.get("error") or "capability failed",
                                       "finished_at": _now_z()}
        except Exception as e:  # noqa: BLE001
            logger.error("[Advisories] async %s job failed: %s", capability, e, exc_info=True)
            with _CAP_JOBS_LOCK:
                _CAP_JOBS[jkey] = {"state": "error", "error": str(e), "finished_at": _now_z()}

    threading.Thread(target=_worker, name=f"cap-{capability}-{uid}", daemon=True).start()
    return {"state": "running"}


def get_capability_job(adv: dict[str, Any], capability: str) -> dict[str, Any] | None:
    """Current state of a background capability job, or None if none is tracked."""
    uid = adv.get("uid") or adv.get("source_id") or ""
    with _CAP_JOBS_LOCK:
        job = _CAP_JOBS.get((uid, capability))
        return dict(job) if job else None


def run_advisory_capability(adv: dict[str, Any], capability: str,
                            opts: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a server-side capability check for an advisory and return a normalized
    result dict ``{ok, result?, error?}``. Supported: jfrog (Xray exposure),
    threatintel (Recorded Future CVE enrichment), threat_analysis (native CTI).
    ``opts`` carries per-capability parameters (e.g. ``audience`` for
    threat_analysis); ignored by capabilities that don't use it."""
    opts = opts or {}
    cves = _advisory_cves(adv)
    if capability == "capd_scorecard":
        try:
            return {"ok": True, "result": compute_capd_scorecard(adv)}
        except Exception as e:
            logger.error("[Advisories] CAPD scorecard failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"CAPD scorecard failed: {e}"}
    if capability == "qradar":
        try:
            return {"ok": True, "result": _qradar_were_we_touched(adv)}
        except Exception as e:
            logger.error("[Advisories] QRadar lookup failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"QRadar lookup failed: {e}"}
    if capability == "fleet_posture":
        try:
            from services.advisory_posture import fleet_posture
            return {"ok": True, "result": fleet_posture(adv)}
        except Exception as e:
            logger.error("[Advisories] Fleet posture failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"Fleet posture check failed: {e}"}
    if capability == "app_owners":
        try:
            from services.advisory_app_owners import app_owners
            return {"ok": True, "result": app_owners(adv)}
        except Exception as e:
            logger.error("[Advisories] App-owners lookup failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"App-owners lookup failed: {e}"}
    if capability == "attack_surface":
        try:
            from services.advisory_app_owners import attack_surface
            return {"ok": True, "result": attack_surface(adv)}
        except Exception as e:
            logger.error("[Advisories] Attack-surface lookup failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"Attack-surface lookup failed: {e}"}
    if capability == "jfrog":
        if not cves:
            return {"ok": False, "error": "advisory has no CVE to check in JFrog Xray"}
        try:
            from services.jfrog import exposure
            return {"ok": True, "result": exposure(cve_ids=cves)}
        except Exception as e:
            logger.error("[Advisories] JFrog exposure failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"JFrog check failed: {e}"}
    if capability == "threat_analysis":
        try:
            from services.advisory_threat_analysis import threat_analysis
            return {"ok": True, "result": threat_analysis(adv, audience=opts.get("audience"))}
        except Exception as e:
            logger.error("[Advisories] Threat analysis failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"Threat analysis failed: {e}"}
    if capability == "threatintel":
        if not cves:
            return {"ok": False, "error": "advisory has no CVE for threat-intel enrichment"}
        try:
            from services.recorded_future import get_client
            client = get_client()
            if not client.is_configured():
                return {"ok": False, "error": "Recorded Future not configured"}
            raw = client.enrich(vulnerabilities=cves)
            return {"ok": True, "result": _summarize_rf_vuln(raw, cves)}
        except Exception as e:
            logger.error("[Advisories] Recorded Future enrichment failed: %s", e, exc_info=True)
            return {"ok": False, "error": f"Threat-intel lookup failed: {e}"}
    return {"ok": False, "error": f"unknown capability {capability!r}"}


def enrich_veracode(adv: dict[str, Any]) -> dict[str, Any] | None:
    """Check Veracode SCA: do any of our applications carry the vulnerable component?

    Correlates on both axes against our SCA index — the advisory's CVE(s) and the
    affected open-source package name(s). The package axis is what catches
    malicious-package advisories (OSV ``MAL-*``) that carry no CVE at all.

    Returns the exposure summary (see ``services.veracode.exposure``) or ``None``
    when there's nothing to check / Veracode isn't configured, so callers can skip
    persisting an empty result.
    """
    cves = _advisory_cves(adv)
    packages = _advisory_packages(adv)
    if not cves and not packages:
        return None
    try:
        from services.veracode import get_client
        client = get_client()
        if not client.is_configured():
            return None
        return client.exposure(cve_ids=cves, packages=packages)
    except Exception as e:  # never let enrichment break the poll
        logger.warning("[Advisories] Veracode enrichment failed for %s: %s",
                       adv.get("source_id"), e)
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def poll_critical_advisories(room_id: str | None = None,
                             source_keys: list[str] | None = None) -> None:
    """Poll every enabled source and notify on genuinely new advisories.

    Args:
        room_id: Webex room for the digest. Defaults to the dev test space.
        source_keys: If given, poll only these source keys (e.g. ['cisa_kev'])
            instead of the full catalog. Used to run individually-critical,
            low-volume feeds on a tighter cadence than the hourly sweep.
    """
    room_id = room_id or CONFIG.webex_room_id_dev_test_space
    all_new: list[dict[str, Any]] = []
    labels = source_labels_map()
    wanted = set(source_keys) if source_keys else None

    for spec in get_source_specs():
        name = spec["key"]
        if wanted is not None and name not in wanted:
            continue
        digest = spec.get("digest", True)
        if not db.is_source_enabled(name):
            logger.info("[Advisories] Source %r disabled — skipping", name)
            continue
        try:
            records = _fetcher_for(spec)()
        except Exception as e:
            logger.error("[Advisories] Source %r fetch failed: %s", name, e, exc_info=True)
            continue

        if not db.is_baselined(name):
            # First poll: record the current backlog as a hidden baseline, fast
            # and silent. (OSV self-baselines a timestamp and returns [].)
            seeded = db.bulk_seed([{**r, "source": r.get("source", name)} for r in records if r.get("source_id")])
            db.mark_baselined(name)
            logger.info("[Advisories] Cold start — baselined %r (seeded %d) without notifying", name, seeded)
            continue

        new_for_source = []
        seed_hidden = []
        for rec in records:
            rec.setdefault("source", name)
            if not rec.get("source_id"):
                continue
            if rec.pop("_baseline_seed", False):
                seed_hidden.append(rec)  # backlog drainage — record but never notify
                continue
            if db.upsert_advisory(rec):
                new_for_source.append(rec)
        if seed_hidden:
            n = db.bulk_seed(seed_hidden)
            logger.info("[Advisories] %r draining backlog — seeded %d hidden (no notify)", name, n)
        if new_for_source:
            if digest:
                logger.info("[Advisories] %d new from %r", len(new_for_source), name)
                all_new.extend(new_for_source)
            else:
                # Queue-only feed: rows are persisted (visible + triageable), but
                # this source is too high-volume to alert on, so it stays out of
                # the digest and the bounded AI prepopulation. Pages triage on demand.
                logger.info("[Advisories] %d new from %r — queue-only (excluded from digest)",
                            len(new_for_source), name)

    if not all_new:
        logger.info("[Advisories] No new advisories")
        return

    # NOTIFY FIRST — the alert is the critical path. Rows are already persisted,
    # so build the digest and fire Webex/email before any slow enrichment. A
    # previous ordering ran AI prepopulation first; on a large batch it blew past
    # the scheduler's job timeout and the job was killed before the alert ever
    # fired (genuinely-new advisories went unannounced two polls running).
    fields = [_notif_fields(r, labels) for r in all_new]
    logger.info("[Advisories] %d new advisory(ies) detected across sources", len(fields))

    # Notify on both channels independently so one failure doesn't suppress the
    # other. Rows are already persisted above, so a notification failure never
    # loses the advisory — it just won't re-alert (it's no longer "new").
    for channel, fn in (("Webex", lambda: _post_webex(fields, room_id)),
                        ("email", lambda: _send_email(fields))):
        try:
            fn()
        except Exception as e:
            logger.error("[Advisories] %s notification failed: %s", channel, e, exc_info=True)

    # Prepopulate the AI assessment so a reviewer who clicks the link lands on an
    # already-triaged page. Best-effort and bounded: it runs AFTER the alert, so
    # even if this is slow (or the job is killed mid-way), the notification has
    # already gone out. Beyond the cap, pages regenerate their assessment on demand.
    to_prepop = all_new[:AI_PREPOP_MAX_PER_RUN]
    if len(all_new) > AI_PREPOP_MAX_PER_RUN:
        logger.warning("[Advisories] %d new — prepopulating AI for first %d only; rest on demand",
                       len(all_new), AI_PREPOP_MAX_PER_RUN)
    ai_ok = 0
    for rec in to_prepop:
        uid = db.make_uid(rec["source"], rec["source_id"])
        # Skip advisories that already have a cached assessment (e.g. from a
        # cross-source duplicate that was triaged under a different alias).
        existing = db.get_advisory(uid)
        if existing and existing.get("ai_assessment"):
            continue
        try:
            assessment = generate_ai_triage(rec)
            db.save_ai_assessment(uid, assessment)
            ai_ok += 1
        except Exception as e:
            logger.warning("[Advisories] Prepopulate AI triage failed for %s: %s",
                           rec.get("source_id"), e)
        # Veracode SCA exposure: which of our apps carry the vulnerable component.
        # The CVE->apps index is cached (6h TTL), so only the first lookup after
        # expiry pays the portfolio scan; the rest are dict hits.
        try:
            veracode = enrich_veracode(rec)
            if veracode is not None:
                db.save_veracode_enrichment(uid, veracode)
        except Exception as e:
            logger.warning("[Advisories] Veracode enrichment failed for %s: %s",
                           rec.get("source_id"), e)
    logger.info("[Advisories] Pre-triaged %d/%d new digest advisory(ies) via AI", ai_ok, len(to_prepop))
