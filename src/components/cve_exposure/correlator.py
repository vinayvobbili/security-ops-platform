"""
CVE → installed-software correlator.

Pipeline:
  1. For each CVE, fetch NVD record (cpe_matches + severity).
  2. From each vulnerable CPE, derive (vendor, product) and a keyword for
     substring matching against installed app names.
  3. Run a single batched Tanium scan with the union of keywords.
  4. For each Tanium row, check every CVE's CPE list: does the app name
     look like this product+vendor, and does the installed version fall
     in the CPE's version range?
  5. Emit ExposureRecord rows tagged confirmed or potential.

One Tanium fleet scan per call, even with many CVEs. The scan is the
expensive step; CVE fan-out in memory is cheap.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional

from packaging.version import InvalidVersion, Version

from services import nvd
from services.tanium import TaniumClient

logger = logging.getLogger(__name__)

# CPE products shorter than this are too generic (e.g. "go", "nx") and produce
# huge false-positive sets when substring-matched against app names.
MIN_KEYWORD_LEN = 4


@dataclass
class ExposureRecord:
    cve_id: str
    severity: Optional[str]      # e.g. "CRITICAL", "HIGH"
    cvss_score: Optional[float]
    asset: str
    os: str
    source: str                  # Tanium instance name
    app: str
    version: str
    matched_cpe: str
    confidence: str              # "confirmed" | "potential"
    reason: str
    environment: Optional[str] = None   # SNOW env: production / dev / staging / unknown
    ci_class: Optional[str] = None      # SNOW: server / workstation / VM / etc.

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class CorrelationResult:
    """Outcome of a correlate_cves call.

    `scanned=False` means Tanium was never queried — NVD gave no usable CPEs
    after filtering (firmware / short slugs / no record). This is a distinct
    outcome from `scanned=True, records=[]` (scanned, no exposure found) and
    downstream formatters should say so instead of claiming a clean bill of
    health.
    """
    records: List[ExposureRecord]
    scanned: bool
    skip_reason: Optional[str] = None  # "no_usable_cpes" when scanned=False


# ---- CPE helpers -----------------------------------------------------------

def _parse_cpe(cpe: str) -> Optional[dict]:
    """Parse a CPE 2.3 URI into {part, vendor, product}. Returns None if malformed."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4]}


def _cpe_keyword(product: str) -> str:
    """Turn a CPE product slug into a substring-matchable keyword."""
    return product.replace("_", " ").strip().lower()


# Model-number slug like "ds-2cd2032-i", "6bk1602-0aa12-0tp0" — two or more digit
# runs is a reliable signal. Single-digit-run slugs like "log4j" or "windows_10"
# look like real software and are kept.
_MULTI_DIGIT_RUN_RE = re.compile(r"\d+\D+\d+")


def _is_likely_endpoint_software(product: str) -> bool:
    """Filter CPE products that can't meaningfully match installed-app strings.

    The NVD affected-products list for a single CVE often includes dozens of
    device firmware / hardware model entries (IP cameras, PLCs, routers) that
    are irrelevant when scanning endpoint software inventories. Each bogus
    keyword costs a full-fleet substring scan, so we drop them up front.
    """
    p = product.lower()
    if "firmware" in p:
        return False
    if _MULTI_DIGIT_RUN_RE.search(p):
        return False
    return True


# ---- version comparison ----------------------------------------------------

def _ver(v: Optional[str]) -> Optional[Version]:
    if not v or v == "*":
        return None
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _version_in_range(installed: str, cpe_match: dict) -> tuple[bool, str]:
    """Check if installed version satisfies the CPE version range.

    Returns (satisfies, reason). When the installed version cannot be parsed,
    returns (False, 'unparseable') so the caller can downgrade to 'potential'.
    """
    v = _ver(installed)
    if v is None:
        return (False, "version-unparseable")

    start_inc = _ver(cpe_match.get("version_start_including"))
    start_exc = _ver(cpe_match.get("version_start_excluding"))
    end_inc = _ver(cpe_match.get("version_end_including"))
    end_exc = _ver(cpe_match.get("version_end_excluding"))

    # No range at all — NVD says any version of this product is vulnerable.
    if not any((start_inc, start_exc, end_inc, end_exc)):
        return (True, "no-range-any-version-vulnerable")

    if start_inc and v < start_inc:
        return (False, f"version<{start_inc} (start-including)")
    if start_exc and v <= start_exc:
        return (False, f"version<={start_exc} (start-excluding)")
    if end_inc and v > end_inc:
        return (False, f"version>{end_inc} (end-including)")
    if end_exc and v >= end_exc:
        return (False, f"version>={end_exc} (end-excluding)")
    return (True, "version-in-range")


# ---- CVE fan-out -----------------------------------------------------------

def _collect_cpe_candidates(cve_ids: Iterable[str]) -> tuple[dict, list[dict]]:
    """Resolve each CVE to its vulnerable CPE entries via NVD.

    Returns:
        cve_meta: {cve_id: {severity, cvss_score, description}}
        cpe_candidates: flat list of {cve_id, cpe, vendor, product, keyword, range...}
    """
    cve_meta: dict = {}
    candidates: list[dict] = []
    for raw in cve_ids:
        cve_id = raw.strip().upper()
        try:
            record = nvd.get_cve(cve_id)
        except Exception as e:  # ValueError on bad format
            logger.warning("Skipping invalid/failed CVE %s: %s", cve_id, e)
            continue
        if not record:
            logger.info("No NVD record for %s", cve_id)
            continue

        sev = record.get("severity") or {}
        cve_meta[cve_id] = {
            "severity": sev.get("base_severity"),
            "cvss_score": sev.get("base_score"),
            "description": record.get("description", ""),
        }

        for m in record.get("cpe_matches", []):
            if not m.get("vulnerable"):
                continue
            parsed = _parse_cpe(m.get("cpe"))
            if not parsed or parsed["part"] not in ("a", "o"):
                continue
            if not _is_likely_endpoint_software(parsed["product"]):
                continue
            keyword = _cpe_keyword(parsed["product"])
            if len(keyword) < MIN_KEYWORD_LEN:
                continue
            candidates.append({
                "cve_id": cve_id,
                "cpe": m["cpe"],
                "vendor": parsed["vendor"],
                "product": parsed["product"],
                "keyword": keyword,
                "match": m,
            })
    return cve_meta, candidates


# ---- asset enrichment ------------------------------------------------------

def _enrich_with_snow(records: List[ExposureRecord]) -> None:
    """Populate environment + ci_class on each record from the SNOW host cache.

    Mutates records in-place. Failures are logged but never raised — exposure
    findings are still useful without env metadata. Lookups are batched by
    unique hostname so a fleet-wide finding doesn't cause N redundant calls.
    """
    if not records:
        return
    unique_hosts = sorted({r.asset for r in records if r.asset})
    if not unique_hosts:
        return
    try:
        from services.service_now import ServiceNowClient
        client = ServiceNowClient()
    except Exception as e:
        logger.warning("SNOW client init failed; skipping env enrichment: %s", e)
        return

    by_host: dict = {}
    for host in unique_hosts:
        try:
            details = client.get_host_details(host) or {}
            by_host[host] = {
                "environment": details.get("environment"),
                "ci_class": details.get("ciClass") or details.get("category"),
            }
        except Exception as e:
            logger.debug("SNOW lookup failed for %s: %s", host, e)
            by_host[host] = {}

    for r in records:
        info = by_host.get(r.asset, {})
        r.environment = info.get("environment") or None
        r.ci_class = info.get("ci_class") or None


# ---- inventory source ------------------------------------------------------

def _fetch_matching_rows(
    keywords: List[str],
    tanium_client: Optional[TaniumClient],
    endpoint_limit: Optional[int],
    use_cache: bool,
) -> List[dict]:
    """Pull software rows from the cache by default, fall back to live scan."""
    import time as _t
    from src.components.cve_exposure.alerts import notify_dev_space

    if use_cache:
        from services import tanium_inventory
        if tanium_inventory.is_cache_fresh():
            t0 = _t.time()
            rows = tanium_inventory.find_software_matches(keywords)
            logger.info(
                "Cache hit: %d rows in %.0fms (fresh inventory)",
                len(rows), (_t.time() - t0) * 1000,
            )
            return rows
        status = tanium_inventory.get_sync_status()
        logger.warning(
            "Inventory cache stale/missing (status=%s); falling back to live Tanium scan",
            status.get("status") if status else "none",
        )
        notify_dev_space(
            "inventory_cache_stale",
            "Inventory cache stale — falling back to live scans",
            "The Tanium installed-software cache is stale or missing. Each tipper "
            "with CVEs will trigger a ~5 min live fleet scan instead of a sub-second "
            "cache lookup. Investigate the daily inventory sync (04:30 ET).",
        )

    try:
        client = tanium_client or TaniumClient()
        return client.find_installed_software(keywords=keywords, endpoint_limit=endpoint_limit)
    except Exception as e:
        logger.error("Live Tanium scan also failed: %s", e)
        notify_dev_space(
            "tanium_live_scan_failed",
            "Live Tanium scan failed",
            f"Cache was stale and the live fallback also raised: `{type(e).__name__}: {e}`. "
            f"CVE exposure correlation will return zero results until Tanium is reachable. "
            f"Tippers will get an empty 'no exposure' comment, which understates risk.",
        )
        return []


# ---- tipper-text candidates (no NVD) ---------------------------------------

def _collect_tipper_candidates(vulnerable_products: List[dict]) -> list[dict]:
    """Build candidate entries from LLM-extracted product mentions.

    Each input dict: {product, vendor?, version_constraint?}. We build the same
    candidate shape used for NVD-derived candidates so the matcher can treat them
    uniformly. cve_id becomes 'TIPPER:<product> <version_constraint>' so the
    synthetic ID is human-readable in downstream output. version_constraint is
    NOT machine-parsed (could be free-form like '< 2.5.30' or 'all 1.x'), so the
    matcher will downgrade these to 'potential' confidence by design.
    """
    out: list[dict] = []
    for vp in vulnerable_products or []:
        product = (vp.get("product") or "").strip()
        if not product:
            continue
        keyword = product.lower()
        if len(keyword) < MIN_KEYWORD_LEN:
            continue
        vendor = (vp.get("vendor") or "").strip().lower() or "*"
        constraint = (vp.get("version_constraint") or "").strip()
        synthetic_id = f"TIPPER:{product}" + (f" {constraint}" if constraint else "")
        out.append({
            "cve_id": synthetic_id,
            "cpe": f"tipper:{product}",
            "vendor": vendor,
            "product": product,
            "keyword": keyword,
            # Empty match dict — _version_in_range will see no bounds and treat
            # the row as 'no-range-any-version-vulnerable'. We cap confidence
            # to 'potential' for tipper-flagged matches in _match_row_to_cpe.
            "match": {},
            "_tipper_flagged": True,
        })
    return out


# ---- per-row matching ------------------------------------------------------

def _match_row_to_cpe(row: dict, candidate: dict) -> Optional[tuple[str, str]]:
    """Test one Tanium row against one CPE candidate.

    Returns (confidence, reason) if a match, else None. Tipper-flagged
    candidates (no NVD-validated version range) are always capped at 'potential'
    since we can't programmatically verify the installed version is affected.
    """
    app_lower = row["app"].lower()
    keyword = candidate["keyword"]
    vendor = candidate["vendor"].lower()

    if keyword not in app_lower:
        return None

    vendor_match = vendor in app_lower if vendor and vendor != "*" else False

    if candidate.get("_tipper_flagged"):
        # No machine-readable version constraint — best we can say is "potential"
        if vendor_match:
            return ("potential", "tipper-flagged: vendor+product match (version unverified)")
        return ("potential", "tipper-flagged: product match (version unverified)")

    in_range, range_reason = _version_in_range(row["version"], candidate["match"])

    if vendor_match and in_range:
        return ("confirmed", f"vendor+product+{range_reason}")
    if in_range:
        return ("potential", f"product-only+{range_reason}")
    if vendor_match and range_reason == "version-unparseable":
        return ("potential", f"vendor+product+{range_reason}")
    # product matched but version clearly outside range → not an exposure
    return None


# ---- public entry point ----------------------------------------------------

def correlate_cves(
    cve_ids: Iterable[str],
    tanium_client: Optional[TaniumClient] = None,
    endpoint_limit: Optional[int] = None,
    use_cache: bool = True,
    vulnerable_products: Optional[List[dict]] = None,
) -> CorrelationResult:
    """Correlate CVEs (and optional tipper-flagged products) against installed software.

    Default path uses the cached inventory at services.tanium_inventory (fed by
    a daily sync job) for sub-second lookups. If the cache is stale/empty, or
    use_cache=False, falls back to a live Tanium fleet scan (~minutes).

    `vulnerable_products` is an optional list of {product, vendor, version_constraint}
    dicts extracted by the LLM from tipper text — these are products flagged as
    vulnerable WITHOUT an associated CVE ID. They get a direct Tanium lookup;
    findings are always tagged 'potential' with a synthetic id like
    'TIPPER:Apache Struts <2.5.30' since there's no NVD-validated version range.
    """
    cve_ids = list(cve_ids)
    vulnerable_products = list(vulnerable_products or [])
    if not cve_ids and not vulnerable_products:
        return CorrelationResult(records=[], scanned=False, skip_reason="no_input")

    cve_meta, candidates = _collect_cpe_candidates(cve_ids)
    tipper_candidates = _collect_tipper_candidates(vulnerable_products)
    candidates_all = candidates + tipper_candidates
    if not candidates_all:
        logger.info(
            "No CPE candidates from %d CVE(s) and no tipper-flagged products; nothing to correlate",
            len(cve_ids),
        )
        return CorrelationResult(records=[], scanned=False, skip_reason="no_usable_cpes")

    keywords = sorted({c["keyword"] for c in candidates_all})
    logger.info(
        "Correlating %d CVE(s) + %d tipper-flagged product(s) via %d keyword(s): %s",
        len(cve_meta), len(tipper_candidates), len(keywords), keywords,
    )

    rows = _fetch_matching_rows(keywords, tanium_client, endpoint_limit, use_cache)

    # Dedup by (host, app, version, cve) — keep confirmed over potential
    best: dict[tuple, ExposureRecord] = {}
    for row in rows:
        for cand in candidates_all:
            verdict = _match_row_to_cpe(row, cand)
            if not verdict:
                continue
            confidence, reason = verdict
            meta = cve_meta.get(cand["cve_id"], {})
            rec = ExposureRecord(
                cve_id=cand["cve_id"],
                severity=meta.get("severity"),
                cvss_score=meta.get("cvss_score"),
                asset=row["host"],
                os=row["os"],
                source=row["source"],
                app=row["app"],
                version=row["version"],
                matched_cpe=cand["cpe"],
                confidence=confidence,
                reason=reason,
            )
            key = (rec.asset, rec.app, rec.version, rec.cve_id)
            existing = best.get(key)
            if existing is None or (existing.confidence == "potential" and confidence == "confirmed"):
                best[key] = rec

    # Enrich each unique asset with SNOW environment + CI class. SNOW lookups are
    # SQLite-cached, so this is cheap even for large result sets — we batch by
    # unique hostname so we don't re-query the cache for every row.
    _enrich_with_snow(list(best.values()))

    records = sorted(
        best.values(),
        key=lambda r: (0 if r.confidence == "confirmed" else 1, -(r.cvss_score or 0), r.asset),
    )
    return CorrelationResult(records=records, scanned=True)
