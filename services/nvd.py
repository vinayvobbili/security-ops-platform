"""
NVD (National Vulnerability Database) client with on-disk cache.

Resolves a CVE ID to its structured vulnerability data — primarily the list of
affected products as CPE 2.3 URIs with version bounds. Used by the CVE exposure
correlator to turn `CVE-YYYY-NNNN` into a concrete set of "vulnerable if
installed" predicates to check against asset inventory.

Entry point: get_cve(cve_id) -> dict | None
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "threat_intel" / "nvd_cve_cache"
CACHE_TTL_SECONDS = 30 * 24 * 3600  # 30 days — CPE data rarely changes post-publication
REQUEST_TIMEOUT = 20


def _alert(issue_key: str, subject: str, detail: str) -> None:
    """Lazy-imported to keep services/nvd.py free of cycle risk."""
    try:
        from src.components.cve_exposure.alerts import notify_dev_space
        notify_dev_space(issue_key, subject, detail)
    except Exception as e:
        logger.debug("alert suppressed: %s", e)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


@dataclass
class CpeMatch:
    """A single CPE match entry from an NVD configuration node."""
    cpe: str                          # e.g. cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*
    vulnerable: bool
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None


def _headers() -> dict:
    cfg = get_config("scheduler")
    key = getattr(cfg, "nvd_api_key", None)
    return {"X-ApiKey": key} if key else {}


def _cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id.upper()}.json"


def _load_cached(cve_id: str) -> Optional[dict]:
    path = _cache_path(cve_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning("Corrupt NVD cache entry, re-fetching: %s", path)
        return None
    if time.time() - data.get("fetched_at", 0) > CACHE_TTL_SECONDS:
        return None
    return data


def _save_cache(cve_id: str, payload: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {**payload, "fetched_at": time.time()}
    _cache_path(cve_id).write_text(json.dumps(payload, indent=2))


def _extract_cpe_matches(cve_obj: dict) -> list[dict]:
    """Walk NVD's configurations → nodes → cpeMatch tree into a flat list."""
    out: list[dict] = []
    for cfg in cve_obj.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                out.append({
                    "cpe": m.get("criteria"),
                    "vulnerable": bool(m.get("vulnerable")),
                    "version_start_including": m.get("versionStartIncluding"),
                    "version_start_excluding": m.get("versionStartExcluding"),
                    "version_end_including": m.get("versionEndIncluding"),
                    "version_end_excluding": m.get("versionEndExcluding"),
                })
    return out


def _severity(cve_obj: dict) -> Optional[dict]:
    """Pick the highest-priority CVSS metric available (v3.1 > v3.0 > v2)."""
    metrics = cve_obj.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            d = entries[0].get("cvssData", {}) or {}
            return {
                "version": d.get("version"),
                "base_score": d.get("baseScore"),
                "base_severity": d.get("baseSeverity") or entries[0].get("baseSeverity"),
                "vector": d.get("vectorString"),
            }
    return None


def _description(cve_obj: dict) -> str:
    for d in cve_obj.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def get_cve(cve_id: str, force_refresh: bool = False) -> Optional[dict]:
    """Fetch a CVE record from NVD, with on-disk caching.

    Returns a dict with keys: cve_id, published, description, severity, cpe_matches.
    Returns None if NVD has no record for that CVE or the fetch fails.
    """
    if not CVE_RE.match(cve_id):
        raise ValueError(f"invalid CVE ID: {cve_id!r}")
    cve_id = cve_id.upper()

    if not force_refresh:
        cached = _load_cached(cve_id)
        if cached is not None:
            return cached

    try:
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=_headers(),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        logger.warning("NVD fetch failed for %s: %s", cve_id, e)
        _alert("nvd_unreachable", "NVD unreachable",
               f"Request to services.nvd.nist.gov failed: `{e}`. Exposure correlation "
               f"will return no results until NVD is reachable again.")
        return None

    if resp.status_code == 404:
        return None
    if resp.status_code in (401, 403):
        logger.error("NVD rejected API key for %s: %s", cve_id, resp.status_code)
        _alert("nvd_auth_failed", f"NVD auth failed ({resp.status_code})",
               "The `NVD_API_KEY` was rejected. Exposure correlation will fall back "
               "to unauthenticated rate limits until the key is rotated. "
               "Re-issue at https://nvd.nist.gov/developers/request-an-api-key "
               "and update `.secrets.age`.")
        return None
    if resp.status_code != 200:
        logger.warning("NVD returned %s for %s: %s", resp.status_code, cve_id, resp.text[:200])
        return None

    body = resp.json()
    vulns = body.get("vulnerabilities") or []
    if not vulns:
        logger.info("NVD has no record for %s", cve_id)
        return None
    cve_obj = vulns[0].get("cve", {})

    payload = {
        "cve_id": cve_id,
        "published": cve_obj.get("published"),
        "last_modified": cve_obj.get("lastModified"),
        "description": _description(cve_obj),
        "severity": _severity(cve_obj),
        "cpe_matches": _extract_cpe_matches(cve_obj),
    }
    _save_cache(cve_id, payload)
    return payload
