"""Security advisory monitor (Detection Engineering job).

Hourly poller for newly published advisories across several supply-chain /
vulnerability feeds. On detecting advisories not seen before it posts a Webex
digest (Toodles bot) and emails the AppSec team. Nothing is sent when there is
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
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if "```" in text[3:] else text.strip("`")
        text = text.lstrip("json").strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
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
    token = CONFIG.webex_bot_access_token_toodles
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
# AI triage assist (per-advisory, m1 -> s1)
# ---------------------------------------------------------------------------
def _now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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
                "model": "gpt-4.1",
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
    token = CONFIG.webex_bot_access_token_toodles
    if not token:
        logger.warning("[Advisories] No Toodles bot token configured — skipping Webex")
        return
    if not room_id:
        logger.warning("[Advisories] No Webex room configured — skipping Webex")
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
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


def _send_email(fields: list[dict[str, str]]) -> None:
    to = CONFIG.appsec_team_email
    if not to:
        logger.info("[Advisories] APPSEC_TEAM_EMAIL not set — skipping email")
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

    send_email(to, subject, body, cc=CONFIG.appsec_team_email_cc, html_body=html_body)
    logger.info("[Advisories] Emailed AppSec (%s) about %d advisory(ies)", to, count)


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
def poll_critical_advisories(room_id: str | None = None) -> None:
    """Poll every enabled source and notify on genuinely new advisories.

    Args:
        room_id: Webex room for the digest. Defaults to the dev test space.
    """
    room_id = room_id or CONFIG.webex_room_id_dev_test_space
    all_new: list[dict[str, Any]] = []
    labels = source_labels_map()

    for spec in get_source_specs():
        name = spec["key"]
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
    for rec in to_prepop:
        uid = db.make_uid(rec["source"], rec["source_id"])
        try:
            assessment = generate_ai_triage(rec)
            db.save_ai_assessment(uid, assessment)
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
