"""
EPSS (Exploit Prediction Scoring System, FIRST.org) client with on-disk cache.

EPSS gives the probability a CVE will be exploited in the wild in the next 30
days, plus the percentile rank of that probability across all scored CVEs. It's
a free, keyless bulk API that refreshes once daily, so the cache TTL is 1 day.

Entry points:
  get_epss(cve_id) -> {"epss": float, "percentile": float} | None
  get_epss_bulk(cve_ids) -> {cve_id: {"epss": float, "percentile": float}}

A CVE with no EPSS score (e.g. too new / RESERVED) is absent from the bulk
result and returns None from get_epss. Network failures degrade gracefully:
cached scores are still served, uncached CVEs come back None / absent.
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "threat_intel" / "epss_cache"
CACHE_TTL_SECONDS = 24 * 3600  # 1 day — EPSS recomputes scores daily
REQUEST_TIMEOUT = 20
CHUNK_SIZE = 100  # CVEs per HTTP request (API default limit is 100)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id.upper()}.json"


def _load_cached(cve_id: str) -> Optional[dict]:
    path = _cache_path(cve_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning("Corrupt EPSS cache entry, re-fetching: %s", path)
        return None
    if time.time() - data.get("fetched_at", 0) > CACHE_TTL_SECONDS:
        return None
    return {"epss": data["epss"], "percentile": data["percentile"]}


def _save_cache(cve_id: str, score: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "epss": score["epss"],
        "percentile": score["percentile"],
        "fetched_at": time.time(),
    }
    _cache_path(cve_id).write_text(json.dumps(payload, indent=2))


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _fetch_chunk(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch one batch of CVEs from the EPSS API. Returns {} on failure."""
    try:
        resp = requests.get(
            EPSS_API_URL,
            params={"cve": ",".join(cve_ids)},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        logger.warning("EPSS fetch failed for %d CVEs: %s", len(cve_ids), e)
        return {}

    if resp.status_code != 200:
        logger.warning("EPSS returned %s: %s", resp.status_code, resp.text[:200])
        return {}

    try:
        body = resp.json()
    except ValueError as e:
        logger.warning("EPSS returned non-JSON body: %s", e)
        return {}

    out: dict[str, dict] = {}
    for row in body.get("data") or []:
        cve = (row.get("cve") or "").upper()
        if not cve:
            continue
        try:
            score = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
        except (KeyError, TypeError, ValueError):
            logger.debug("EPSS row missing/invalid score for %s: %r", cve, row)
            continue
        out[cve] = score
        _save_cache(cve, score)
    return out


def get_epss_bulk(cve_ids: list[str], force_refresh: bool = False) -> dict[str, dict]:
    """Resolve many CVE IDs to their EPSS scores, batching API calls.

    Returns {cve_id: {"epss": float, "percentile": float}} for every CVE that
    has a score. CVEs with no EPSS score (or unreachable when uncached) are
    simply absent from the returned dict. Reads served from the 1-day on-disk
    cache; only cache-miss CVEs hit the network, chunked into CHUNK_SIZE per
    request.
    """
    result: dict[str, dict] = {}
    to_fetch: list[str] = []

    seen: set[str] = set()
    for raw in cve_ids:
        if not raw or not CVE_RE.match(raw):
            logger.debug("skipping invalid CVE ID: %r", raw)
            continue
        cve = raw.upper()
        if cve in seen:
            continue
        seen.add(cve)

        if not force_refresh:
            cached = _load_cached(cve)
            if cached is not None:
                result[cve] = cached
                continue
        to_fetch.append(cve)

    for chunk in _chunks(to_fetch, CHUNK_SIZE):
        result.update(_fetch_chunk(chunk))

    return result


def get_epss(cve_id: str, force_refresh: bool = False) -> Optional[dict]:
    """Fetch the EPSS score for a single CVE, with on-disk caching.

    Returns {"epss": float, "percentile": float}, or None if the CVE has no
    EPSS score or the fetch failed with nothing cached.
    """
    if not CVE_RE.match(cve_id):
        raise ValueError(f"invalid CVE ID: {cve_id!r}")
    return get_epss_bulk([cve_id], force_refresh=force_refresh).get(cve_id.upper())
