"""S3 Bucket Brand Squatting Scanner.

Enumerates S3 bucket names that impersonate a brand by generating permutations
of the brand name combined with common infrastructure and phishing words, then
probing each candidate via unauthenticated HTTP requests.

Designed to integrate with the domain lookalike detector as a complementary
brand-protection vector — S3 buckets live under *.s3.amazonaws.com and are
invisible to DNS-based detection (dnstwist, CT logs, etc.).
"""

import json
import logging
import os
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Generator

import requests

from services.domain_lookalike import DICTIONARY_WORDS
from services.s3_scanner import (
    S3_NS,
    _get_bucket_url,
    _detect_region_from_redirect,
    _new_session,
    _parse_xml,
    _xfind,
)

logger = logging.getLogger(__name__)

# S3 / cloud-infrastructure words not already in DICTIONARY_WORDS
S3_BUCKET_WORDS = [
    "assets", "backup", "backups", "data", "uploads", "static", "media",
    "files", "logs", "images", "docs", "documents", "content", "storage",
    "archive", "archives", "public", "private", "internal", "prod",
    "production", "dev", "development", "staging", "test", "testing",
    "beta", "demo", "cdn", "web", "www", "site", "api", "app",
    "reports", "export", "exports", "import", "imports", "config",
    "resources", "dist", "build", "release", "releases", "artifacts",
    "downloads", "temp", "tmp", "cache", "db", "database",
]

# Merge both word lists, deduplicated
_ALL_WORDS = sorted(set(w.lower() for w in DICTIONARY_WORDS + S3_BUCKET_WORDS))

# S3 bucket naming rules: 3-63 chars, lowercase alphanumeric + hyphens + dots,
# no consecutive dots, must start/end with alphanumeric
_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")

# Year range for {brand}{year} permutations
_YEAR_RANGE = range(2020, 2028)

# Throttle: limit concurrent requests to avoid AWS rate-limiting.
# AWS returns blanket 404s (even on HEAD) when an IP sends too many requests.
# Very conservative — traffic routes through a shared Mac proxy we can't afford to burn.
_THROTTLE = threading.Semaphore(1)
_REQUEST_DELAY = 3.0  # seconds between requests (single worker, sequential)

# Cache directory for scan results — survives browser tab closes
_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "transient" / "s3_brand_cache"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _cache_path(brand: str) -> Path:
    return _CACHE_DIR / f"{brand}.json"


def save_scan_cache(brand: str, data: dict) -> None:
    """Persist scan state to disk.

    Writes to ``{brand}.json`` (latest).  When status is ``"complete"``,
    also saves a dated copy under ``{brand}/{YYYY-MM-DD_HHMMSS}.json``
    so every finished scan is preserved for historical browsing.
    """
    try:
        _cache_path(brand).write_text(json.dumps(data, default=str), encoding="utf-8")
    except Exception as exc:
        logger.error("Failed to write S3 scan cache for %s: %s", brand, exc)

    # Save dated history entry for completed scans
    if data.get("status") == "complete":
        try:
            history_dir = _CACHE_DIR / brand
            history_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y-%m-%d_%H%M%S", time.gmtime())
            history_path = history_dir / f"{ts}.json"
            history_path.write_text(json.dumps(data, default=str), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to write S3 scan history for %s: %s", brand, exc)


def load_scan_cache(brand: str) -> dict | None:
    """Load cached scan results. Returns None if no cache exists."""
    path = _cache_path(brand)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("Failed to read S3 scan cache for %s: %s", brand, exc)
        return None


def list_scan_history(brand: str) -> list[dict]:
    """Return available historical scans for a brand, newest first.

    Each entry: {"scan_id": "2026-03-28_081344", "date": "2026-03-28 08:13:44 UTC",
                 "size": 3628, "found": 20}
    """
    history_dir = _CACHE_DIR / brand
    if not history_dir.is_dir():
        return []

    entries = []
    for p in sorted(history_dir.glob("*.json"), reverse=True):
        scan_id = p.stem  # e.g. "2026-03-28_081344"
        # Parse date from filename: "2026-03-28_081344" → "2026-03-28 08:13:44 UTC"
        try:
            parts = scan_id.split("_")  # ["2026-03-28", "081344"]
            t = parts[1]  # "081344"
            date_str = f"{parts[0]} {t[0:2]}:{t[2:4]}:{t[4:6]} UTC"
        except Exception:
            date_str = scan_id

        found = 0
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            found = data.get("total_found", len(data.get("found_buckets", [])))
        except Exception:
            pass

        entries.append({
            "scan_id": scan_id,
            "date": date_str,
            "size": p.stat().st_size,
            "found": found,
        })
    return entries


def load_scan_history(brand: str, scan_id: str) -> dict | None:
    """Load a specific historical scan by its scan_id."""
    # Validate scan_id to prevent directory traversal
    if not re.match(r"^\d{4}-\d{2}-\d{2}_\d{6}$", scan_id):
        return None
    path = _CACHE_DIR / brand / f"{scan_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("Failed to read S3 scan history %s/%s: %s", brand, scan_id, exc)
        return None


def _is_valid_bucket_name(name: str) -> bool:
    """Validate a candidate bucket name against AWS S3 naming rules."""
    if len(name) < 3 or len(name) > 63:
        return False
    if ".." in name or ".-" in name or "-." in name:
        return False
    return bool(_BUCKET_NAME_RE.match(name))


def generate_bucket_permutations(brand: str) -> list[str]:
    """Generate candidate S3 bucket names from a brand name.

    Patterns: {brand}{word}, {word}{brand}, {brand}-{word}, {word}-{brand},
    {brand}.{word}, {word}.{brand}, {brand}{year}, {brand}-{year}.

    Returns deduplicated, validated bucket names sorted alphabetically.
    """
    brand = brand.lower().strip()
    candidates = set()

    for word in _ALL_WORDS:
        candidates.update([
            f"{brand}{word}",
            f"{word}{brand}",
            f"{brand}-{word}",
            f"{word}-{brand}",
            f"{brand}.{word}",
            f"{word}.{brand}",
        ])

    for year in _YEAR_RANGE:
        candidates.update([
            f"{brand}{year}",
            f"{brand}-{year}",
        ])

    # Also add the bare brand name itself
    candidates.add(brand)

    return sorted(name for name in candidates if _is_valid_bucket_name(name))


def probe_bucket(session: requests.Session, bucket_name: str) -> dict:
    """Probe a single S3 bucket to determine if it exists.

    Uses HEAD first (AWS masks bucket existence on unauthenticated GET by
    returning NoSuchBucket instead of AccessDenied).  HEAD reliably returns
    403 for existing buckets and 404 for non-existent ones.

    If HEAD shows the bucket exists, a follow-up GET checks whether it's
    publicly listable.

    Returns a dict with keys: bucket, exists, listable, status, region, key_count, url.
    Status values: 'exists_public', 'exists_private', 'not_found', 'error'.
    """
    result = {
        "bucket": bucket_name,
        "exists": False,
        "listable": False,
        "status": "not_found",
        "region": None,
        "key_count": 0,
        "url": f"https://{bucket_name}.s3.amazonaws.com",
    }

    base_url = _get_bucket_url(bucket_name)

    with _THROTTLE:
        time.sleep(_REQUEST_DELAY)

        # Try both HEAD and GET — AWS rate-limits them independently.
        # HEAD is more reliable (returns 403 for existing buckets) but AWS
        # sometimes blocks HEAD from an IP while GET still works, or vice versa.
        head_status = None
        get_status = None
        region = None

        # Probe 1: HEAD
        head_conn_error = False
        try:
            resp = session.head(
                f"{base_url}/", timeout=(5, 10), allow_redirects=False
            )
            head_status = resp.status_code
            # Extract region from 301 redirect
            if resp.status_code == 301:
                region = resp.headers.get("x-amz-bucket-region")
                if region:
                    result["region"] = region
                    base_url = _get_bucket_url(bucket_name, region)
                    result["url"] = base_url
                    resp = session.head(
                        f"{base_url}/", timeout=(5, 10), allow_redirects=False
                    )
                    head_status = resp.status_code
        except requests.ConnectionError:
            head_status = None
            head_conn_error = True
        except requests.RequestException:
            head_status = None

        # Probe 2: GET (for listing check and as fallback existence check)
        time.sleep(_REQUEST_DELAY)
        get_resp = None
        get_conn_error = False
        try:
            get_resp = session.get(
                f"{base_url}/?list-type=2", timeout=(5, 10), allow_redirects=False
            )
            get_status = get_resp.status_code
            # Handle GET 301 redirect if HEAD didn't catch the region
            if get_status == 301 and not region:
                region = get_resp.headers.get("x-amz-bucket-region")
                if region:
                    result["region"] = region
                    base_url = _get_bucket_url(bucket_name, region)
                    result["url"] = base_url
                    get_resp = session.get(
                        f"{base_url}/?list-type=2", timeout=(5, 10), allow_redirects=False
                    )
                    get_status = get_resp.status_code
        except requests.ConnectionError:
            get_status = None
            get_conn_error = True
        except requests.RequestException:
            get_status = None

        # If both probes failed due to connection errors (proxy down, network
        # unreachable), surface it as an error — not a silent "not_found".
        if head_conn_error and get_conn_error:
            result["status"] = "error"
            result["error"] = "connection_failed"
            return result

        # Determine existence: bucket exists if EITHER method returns 403
        # (AWS may return 404 on one method while the other still works)
        exists = (head_status == 403 or get_status == 403
                  or head_status == 200 or get_status == 200)

        if not exists:
            return result  # Not found on either method

        result["exists"] = True
        result["status"] = "exists_private"

        # Check if publicly listable from GET response
        if get_resp is not None and get_status == 200:
            root = _parse_xml(get_resp.text)
            if root is not None:
                tag = root.tag
                if tag in (f"{{{S3_NS}}}ListBucketResult", "ListBucketResult"):
                    from services.s3_scanner import _xfindall
                    contents = _xfindall(root, "Contents")
                    result["listable"] = True
                    result["status"] = "exists_public"
                    result["key_count"] = len(contents)

    return result


def scan_brand_buckets(
    brand: str,
    known_good: list[str] | None = None,
) -> dict:
    """Scan for S3 buckets impersonating a brand.

    Runs the scan in the calling thread and pushes events to ``event_queue``.
    Returns the final summary dict directly.

    For SSE streaming, use ``start_scan_with_queue()`` which returns a queue
    that the route can drain with heartbeats.

    Args:
        brand: Brand name to scan (e.g. "the company")
        known_good: List of bucket names known to be legitimately owned

    Returns:
        Summary dict with found_buckets, public_buckets, etc.
    """
    known_good_set = {b.lower() for b in (known_good or [])}

    all_candidates = generate_bucket_permutations(brand)
    candidates = [c for c in all_candidates if c not in known_good_set]

    session = _new_session()

    # Preflight: verify AWS S3 is reachable before firing hundreds of requests.
    try:
        preflight = session.head(
            "https://amazon.s3.amazonaws.com/", timeout=(5, 10),
            allow_redirects=False,
        )
        if preflight.status_code == 404:
            logger.error("S3 preflight: AWS returning blanket 404s — IP is likely rate-limited")
            return {
                "total_candidates": len(candidates), "total_probed": 0,
                "total_found": 0, "total_public": 0, "total_errors": 1,
                "found_buckets": [], "public_buckets": [],
                "error": "AWS S3 returning blanket 404s — IP is likely rate-limited",
            }
    except requests.RequestException as exc:
        logger.error("S3 preflight failed (proxy/network down?): %s", exc)
        return {
            "total_candidates": len(candidates), "total_probed": 0,
            "total_found": 0, "total_public": 0, "total_errors": 1,
            "found_buckets": [], "public_buckets": [],
            "error": f"Cannot reach AWS S3: {exc}",
        }

    found_buckets = []
    public_buckets = []
    checked = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = {
            executor.submit(probe_bucket, session, name): name
            for name in candidates
        }

        for future in as_completed(futures):
            checked += 1
            try:
                result = future.result()
            except Exception as exc:
                errors += 1
                logger.error("Error probing bucket %s: %s",
                             futures[future], exc)
                continue

            if result.get("status") == "error":
                errors += 1
                # Abort early if we see consecutive connection failures
                if errors >= 5:
                    logger.error(
                        "S3 brand scan aborting: %d consecutive connection "
                        "errors — proxy or network likely down", errors
                    )
                    break
                continue

            if result.get("exists"):
                found_buckets.append(result)
                if result.get("listable"):
                    public_buckets.append(result)

    return {
        "total_candidates": len(candidates),
        "total_probed": checked,
        "total_found": len(found_buckets),
        "total_public": len(public_buckets),
        "total_errors": errors,
        "found_buckets": found_buckets,
        "public_buckets": public_buckets,
    }


def start_scan_with_queue(
    brand: str,
    known_good: list[str] | None = None,
) -> tuple[queue.Queue, threading.Thread, dict]:
    """Start an S3 brand scan in a background thread, returning a queue for SSE events.

    The route drains the queue with heartbeats.  Events are dicts with a ``type`` key:
        {"type": "result", ...bucket probe data...}
        {"type": "progress", "checked": N, "total": M, ...}
        {"type": "complete", ...summary...}
        {"type": "error", "error": "..."}

    Returns:
        (event_queue, thread, scan_info)
        scan_info has "total" key set immediately (number of candidates).
    """
    known_good_set = {b.lower() for b in (known_good or [])}
    all_candidates = generate_bucket_permutations(brand)
    candidates = [c for c in all_candidates if c not in known_good_set]

    eq: queue.Queue = queue.Queue()
    scan_info = {"total": len(candidates), "filtered_out": len(all_candidates) - len(candidates)}

    def _run():
        try:
            session = _new_session()

            # Mark scan as in-progress in cache
            save_scan_cache(brand, {
                "status": "running",
                "brand": brand,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_candidates": len(candidates),
                "found_buckets": [],
            })

            # Preflight: verify AWS S3 is reachable before firing 700+ requests.
            # Probe a known-existing bucket — expect 403 (private) or 200 (public).
            # If we get 404 or a connection error, AWS is likely blocking this IP.
            try:
                preflight = session.head(
                    "https://amazon.s3.amazonaws.com/", timeout=(5, 10),
                    allow_redirects=False,
                )
                if preflight.status_code == 404:
                    eq.put({
                        "type": "error",
                        "error": ("AWS S3 is returning blanket 404s — this IP "
                                  "is likely rate-limited. Try again later or "
                                  "use a different network/proxy."),
                    })
                    return
            except requests.RequestException as exc:
                eq.put({
                    "type": "error",
                    "error": f"Cannot reach AWS S3 (connectivity check failed: {exc}). "
                             "Check network/proxy settings.",
                })
                return

            found_buckets = []
            public_buckets = []
            checked = 0
            errors = 0

            with ThreadPoolExecutor(max_workers=1) as executor:
                futures = {
                    executor.submit(probe_bucket, session, name): name
                    for name in candidates
                }

                for future in as_completed(futures):
                    checked += 1
                    try:
                        result = future.result()
                    except Exception as exc:
                        errors += 1
                        logger.error("Error probing bucket %s: %s",
                                     futures[future], exc)
                        continue

                    if result.get("exists"):
                        found_buckets.append(result)
                        if result.get("listable"):
                            public_buckets.append(result)
                        eq.put({
                            "type": "result",
                            **result,
                            "checked": checked,
                            "total": len(candidates),
                        })
                        # Persist incrementally so results survive tab close
                        save_scan_cache(brand, {
                            "status": "running",
                            "brand": brand,
                            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "total_candidates": len(candidates),
                            "checked": checked,
                            "found_buckets": found_buckets,
                        })

                    # Progress every 50 checks
                    if checked % 50 == 0:
                        eq.put({
                            "type": "progress",
                            "phase": "scanning",
                            "checked": checked,
                            "total": len(candidates),
                            "found": len(found_buckets),
                            "public": len(public_buckets),
                        })

            # Final cache with complete status
            save_scan_cache(brand, {
                "status": "complete",
                "brand": brand,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_candidates": len(candidates),
                "total_probed": checked,
                "total_found": len(found_buckets),
                "total_public": len(public_buckets),
                "total_errors": errors,
                "found_buckets": found_buckets,
            })

            eq.put({
                "type": "complete",
                "total_probed": checked,
                "total_found": len(found_buckets),
                "total_public": len(public_buckets),
                "total_errors": errors,
                "found_buckets": found_buckets,
                "public_buckets": public_buckets,
            })
        except Exception as exc:
            logger.error("S3 brand scan failed: %s", exc, exc_info=True)
            eq.put({"type": "error", "error": str(exc)})

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return eq, thread, scan_info
