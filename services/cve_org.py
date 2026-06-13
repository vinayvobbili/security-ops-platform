"""CVE.org (MITRE CVE Program) client — the authoritative upstream CVE records.

NVD ingests these records and enriches them with CPE applicability + normalized
CVSS, but lags on recent CVEs (the NVD "Awaiting Analysis" backlog). CVE.org has
the record — description, CNA-provided affected products/packages, often CVSS —
the moment the CNA publishes. We use it to:

* **rescue** CVEs NVD hasn't analyzed yet (``nvd_found=false`` holes), and
* add CNA **package names** (e.g. ``gnutls``, ``curl``), which are frequently a
  cleaner component identifier for OS/base-image packages than NVD's CPE.

Source: CVE Services API (``https://cveawg.mitre.org/api/cve/<id>``), CVE JSON
5.x. No API key, no meaningful rate limit. On-disk cached like ``services.nvd``.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
API_URL = "https://cveawg.mitre.org/api/cve/"
CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "threat_intel" / "cveorg_cache"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # recent records still settle; refresh weekly
REQUEST_TIMEOUT = 20

# CVSS metric keys in CVE JSON 5.x, highest priority first.
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


def _cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id.upper()}.json"


def _load_cached(cve_id: str) -> Optional[dict]:
    path = _cache_path(cve_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if time.time() - data.get("fetched_at", 0) > CACHE_TTL_SECONDS:
        return None
    return data


def _save_cache(cve_id: str, payload: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _cache_path(cve_id).write_text(json.dumps({**payload, "fetched_at": time.time()}, indent=2))


def _containers(obj: dict) -> List[dict]:
    """The CNA container plus any ADP (Authorized Data Publisher, e.g. CISA) ones."""
    c = obj.get("containers", {}) or {}
    out: List[dict] = []
    if c.get("cna"):
        out.append(c["cna"])
    out.extend(c.get("adp", []) or [])
    return out


def _description(obj: dict) -> str:
    for cont in _containers(obj):
        for d in cont.get("descriptions", []) or []:
            if (d.get("lang", "").lower().startswith("en")) and d.get("value"):
                return d["value"]
    return ""


def _severity(obj: dict) -> Optional[dict]:
    for cont in _containers(obj):
        for m in cont.get("metrics", []) or []:
            for k in _CVSS_KEYS:
                d = m.get(k)
                if d and d.get("baseScore") is not None:
                    return {
                        "version": d.get("version") or k.replace("cvssV", "").replace("_", "."),
                        "base_score": d.get("baseScore"),
                        "base_severity": d.get("baseSeverity"),
                        "vector": d.get("vectorString"),
                    }
    return None


def _products(obj: dict) -> List[dict]:
    """Distinct affected product/package identifiers from CNA + ADP ``affected[]``."""
    out: List[dict] = []
    seen = set()
    for cont in _containers(obj):
        for a in cont.get("affected", []) or []:
            label = a.get("packageName") or a.get("product") or ""
            key = (a.get("vendor") or "", label)
            if label and key not in seen:
                seen.add(key)
                out.append({
                    "vendor": a.get("vendor"),
                    "product": a.get("product"),
                    "package": a.get("packageName"),
                    "cpes": a.get("cpes") or [],
                })
    return out


def _cwes(obj: dict) -> List[str]:
    out: List[str] = []
    for cont in _containers(obj):
        for pt in cont.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                cwe = d.get("cweId") or d.get("description")
                if cwe and cwe not in out:
                    out.append(cwe)
    return out


def get_cve_org(cve_id: str, force_refresh: bool = False) -> Optional[dict]:
    """Fetch a CVE 5.x record from CVE.org, with on-disk caching.

    Returns ``{cve_id, source, description, severity, products, cwes, published}``
    or ``None`` if CVE.org has no usable record (404 or REJECTED).
    """
    if not CVE_RE.match(cve_id):
        raise ValueError(f"invalid CVE ID: {cve_id!r}")
    cve_id = cve_id.upper()

    if not force_refresh:
        cached = _load_cached(cve_id)
        if cached is not None:
            return cached if cached.get("found") else None

    try:
        resp = requests.get(API_URL + cve_id, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        logger.warning("CVE.org fetch failed for %s: %s", cve_id, e)
        return None

    if resp.status_code == 404:
        _save_cache(cve_id, {"cve_id": cve_id, "found": False})
        return None
    if resp.status_code != 200:
        logger.warning("CVE.org returned %s for %s: %s", resp.status_code, cve_id, resp.text[:200])
        return None

    obj = resp.json()
    meta = obj.get("cveMetadata", {}) or {}
    if (meta.get("state") or "").upper() == "REJECTED":
        _save_cache(cve_id, {"cve_id": cve_id, "found": False, "state": "REJECTED"})
        return None

    payload = {
        "cve_id": cve_id,
        "source": "cve.org",
        "found": True,
        "published": meta.get("datePublished"),
        "description": _description(obj),
        "severity": _severity(obj),
        "products": _products(obj),
        "cwes": _cwes(obj),
    }
    _save_cache(cve_id, payload)
    return payload
