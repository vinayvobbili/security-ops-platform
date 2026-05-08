"""AWS S3 Public Bucket Scanner.

Reusable scanning logic for both CLI and web UI.
All checks are unauthenticated HTTP requests — no AWS SDK needed.
Checks S3 buckets for public listing, ACL exposure, directory structure,
downloadable content, and PII in exposed files.
"""

import json
import logging
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

TARGETS_FILE = os.path.join(
    os.path.dirname(__file__), "..", "data", "transient", "s3_scan_targets.json"
)

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
_NS = {"s3": S3_NS}

# Max keys to enumerate before stopping
MAX_ENUMERATE_KEYS = 10_000

# Default number of sample files to download
DEFAULT_SAMPLE_COUNT = 5

# Max bytes to download per file
MAX_DOWNLOAD_BYTES = 1_048_576  # 1 MB

# Content types considered text-like (safe to read)
_TEXT_CONTENT_TYPES = {
    "text/", "application/json", "application/xml", "application/csv",
    "application/pdf", "text/csv", "text/plain", "text/html", "text/xml",
    "application/x-yaml", "application/yaml",
}

# File extensions mapped to broad categories for distribution reporting
_EXTENSION_CATEGORIES = {
    ".csv": "CSV", ".tsv": "CSV",
    ".json": "JSON", ".jsonl": "JSON",
    ".xml": "XML",
    ".pdf": "PDF",
    ".txt": "Text", ".log": "Text", ".md": "Text", ".rst": "Text",
    ".html": "HTML", ".htm": "HTML",
    ".jpg": "Image", ".jpeg": "Image", ".png": "Image", ".gif": "Image",
    ".svg": "Image", ".bmp": "Image", ".tiff": "Image", ".webp": "Image",
    ".zip": "Archive", ".gz": "Archive", ".tar": "Archive", ".bz2": "Archive",
    ".7z": "Archive", ".rar": "Archive",
    ".xls": "Excel", ".xlsx": "Excel",
    ".doc": "Word", ".docx": "Word",
    ".ppt": "PowerPoint", ".pptx": "PowerPoint",
    ".py": "Code", ".js": "Code", ".ts": "Code", ".java": "Code",
    ".c": "Code", ".cpp": "Code", ".h": "Code", ".go": "Code",
    ".rb": "Code", ".php": "Code", ".sh": "Code", ".sql": "Code",
    ".parquet": "Parquet", ".avro": "Avro", ".orc": "ORC",
    ".env": "Config", ".cfg": "Config", ".ini": "Config", ".yaml": "Config",
    ".yml": "Config", ".toml": "Config", ".properties": "Config",
    ".bak": "Backup", ".backup": "Backup", ".dump": "Backup",
    ".db": "Database", ".sqlite": "Database", ".sqlite3": "Database",
}

# ─── PII regex patterns ──────────────────────────────────────────────────────

_PII_PATTERNS = {
    "Email": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.ASCII
    ),
    "SSN": re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    ),
    "Phone": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "Date of Birth": re.compile(
        r"\b(?:DOB|date[_\s]?of[_\s]?birth|birthdate|birth[_\s]?date)"
        r"[\s:=]+\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b",
        re.IGNORECASE,
    ),
    "Address": re.compile(
        r"\b\d{1,5}\s+[A-Z][a-zA-Z]+\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard"
        r"|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court|Way|Pl|Place)\b",
        re.IGNORECASE,
    ),
    "Policy Number": re.compile(
        r"\b(?:policy|pol)[#_\s-]*(?:no|num|number)?[#_\s:=-]*[A-Z0-9]{6,15}\b",
        re.IGNORECASE,
    ),
    "RFC (Mexican Tax ID)": re.compile(
        r"\b[A-Z&]{3,4}\d{6}[A-Z\d]{3}\b"
    ),
    "Credit Card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
        r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{0,4}\b"
    ),
}


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    target: str
    bucket: str
    check: str
    status: str  # PASS, FAIL, ERROR, INFO, NOT_FOUND
    detail: str
    http_status: int | None = None
    evidence: dict | None = None

    def to_dict(self) -> dict:
        d = {
            "target": self.target,
            "bucket": self.bucket,
            "check": self.check,
            "status": self.status,
            "detail": self.detail,
            "http_status": self.http_status,
        }
        if self.evidence:
            d["evidence"] = self.evidence
        return d


@dataclass
class ScanReport:
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    results: list[CheckResult] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(r.status in ("PASS", "INFO", "NOT_FOUND") for r in self.results)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")

    def to_dict(self) -> dict:
        total = len(self.results)
        passes = sum(1 for r in self.results if r.status == "PASS")
        fails = sum(1 for r in self.results if r.status == "FAIL")
        errors = sum(1 for r in self.results if r.status == "ERROR")
        infos = sum(1 for r in self.results if r.status == "INFO")
        return {
            "timestamp": self.timestamp,
            "summary": {
                "total": total,
                "pass": passes,
                "fail": fails,
                "error": errors,
                "info": infos,
            },
            "results": [r.to_dict() for r in self.results],
        }


# ─── Config ───────────────────────────────────────────────────────────────────

def load_targets(path: str | None = None) -> dict:
    """Load scan targets from JSON file.

    Expected format:
    {
        "target_key": {
            "label": "Human-readable name",
            "buckets": ["bucket-name-1", "bucket-name-2"],
            "sample_count": 5  // optional, default 5
        }
    }
    """
    p = path or TARGETS_FILE
    try:
        with open(p) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_targets(targets: dict, path: str | None = None):
    p = path or TARGETS_FILE
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump(targets, f, indent=2)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _new_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Accept": "*/*",
    })
    from my_config import get_config
    proxy = (get_config().corp_proxy or "").strip()
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def _human_size(nbytes: int) -> str:
    """Convert byte count to human-readable string."""
    if nbytes < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{nbytes} B"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


def _get_extension(key: str) -> str:
    """Extract lowercase file extension from an S3 key."""
    dot = key.rfind(".")
    if dot == -1 or dot == len(key) - 1:
        return ""
    ext = key[dot:].lower()
    # Strip query-string-like suffixes that occasionally appear
    if "?" in ext:
        ext = ext[:ext.index("?")]
    return ext


def _is_text_content_type(content_type: str) -> bool:
    """Return True if the content type is text-like and safe to read."""
    ct = content_type.lower().split(";")[0].strip()
    return any(ct.startswith(prefix) for prefix in _TEXT_CONTENT_TYPES)


def _parse_xml(text: str) -> ET.Element | None:
    """Safely parse XML, returning root element or None."""
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def _xfind(parent: ET.Element, tag: str) -> ET.Element | None:
    """Find child element trying S3 namespace first, then bare tag.

    Uses explicit ``is not None`` checks because ElementTree elements
    with no *children* evaluate as falsy even when they contain text,
    which breaks ``el.find(ns) or el.find(bare)`` patterns.
    """
    el = parent.find(f"s3:{tag}", _NS)
    if el is not None:
        return el
    return parent.find(tag)


def _xfindall(parent: ET.Element, tag: str) -> list[ET.Element]:
    """findall with S3 namespace fallback."""
    els = parent.findall(f"s3:{tag}", _NS)
    if els:
        return els
    return parent.findall(tag)


def _xtext(parent: ET.Element, tag: str) -> str | None:
    """findtext with S3 namespace fallback."""
    val = parent.findtext(f"s3:{tag}", namespaces=_NS)
    if val is not None:
        return val
    return parent.findtext(tag)


def _get_bucket_url(bucket: str, region: str | None = None) -> str:
    """Build the S3 virtual-hosted URL for a bucket."""
    if region and region != "us-east-1":
        return f"https://{bucket}.s3.{region}.amazonaws.com"
    return f"https://{bucket}.s3.amazonaws.com"


def _detect_region_from_redirect(session: requests.Session, bucket: str) -> str | None:
    """Follow a 301 redirect to discover the bucket's region."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        resp = session.get(url, timeout=(5, 10), allow_redirects=False)
        if resp.status_code == 301:
            region = resp.headers.get("x-amz-bucket-region")
            if region:
                return region
            # Try parsing the redirect Location header
            location = resp.headers.get("Location", "")
            if ".s3." in location and ".amazonaws.com" in location:
                # e.g. https://bucket.s3.us-west-2.amazonaws.com/
                parts = location.split(".s3.")
                if len(parts) > 1:
                    region_part = parts[1].split(".amazonaws.com")[0]
                    if region_part and region_part != "amazonaws":
                        return region_part
    except requests.RequestException:
        pass
    return None


def _detect_pii(text: str) -> dict:
    """Run PII regex patterns against text content.

    Returns dict of {pii_type: {"count": int, "samples": [str, ...]}}
    with up to 3 truncated samples per type.
    """
    findings = {}
    for pii_type, pattern in _PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            unique = list(dict.fromkeys(matches))  # deduplicate, preserve order
            samples = []
            for m in unique[:3]:
                truncated = m[:60] + "..." if len(m) > 60 else m
                # Mask middle of sensitive data
                if pii_type == "SSN" and len(truncated) >= 9:
                    truncated = truncated[:4] + "**-" + truncated[7:]
                elif pii_type == "Credit Card":
                    truncated = truncated[:4] + " **** **** " + truncated[-4:]
                samples.append(truncated)
            findings[pii_type] = {
                "count": len(matches),
                "samples": samples,
            }
    return findings


# ─── Check functions ──────────────────────────────────────────────────────────

def _check_bucket_listing(session: requests.Session, bucket: str,
                          target_key: str) -> tuple[CheckResult, str | None]:
    """Check 1: Attempt to list the bucket contents.

    Returns (CheckResult, effective_url_or_None).
    The effective URL is returned so subsequent checks can use the correct region.
    """
    region = None
    base_url = _get_bucket_url(bucket)

    # First try default endpoint
    try:
        resp = session.get(f"{base_url}/?list-type=2", timeout=(5, 15),
                           allow_redirects=False)
    except requests.RequestException as e:
        return CheckResult(target_key, bucket, "Bucket Listing", "ERROR",
                           f"Connection error: {e}"), None

    # Handle 301 redirect to regional endpoint
    if resp.status_code == 301:
        region = _detect_region_from_redirect(session, bucket)
        if region:
            base_url = _get_bucket_url(bucket, region)
            logger.info("Bucket %s redirected to region %s", bucket, region)
            try:
                resp = session.get(f"{base_url}/?list-type=2", timeout=(5, 15),
                                   allow_redirects=False)
            except requests.RequestException as e:
                return CheckResult(target_key, bucket, "Bucket Listing", "ERROR",
                                   f"Connection error after redirect: {e}"), None
        else:
            # Try with allow_redirects=True as fallback
            try:
                resp = session.get(f"{base_url}/?list-type=2", timeout=(5, 15),
                                   allow_redirects=True)
                if resp.url and ".s3." in resp.url:
                    base_url = resp.url.split("?")[0].rstrip("/")
            except requests.RequestException as e:
                return CheckResult(target_key, bucket, "Bucket Listing", "ERROR",
                                   f"Connection error following redirect: {e}"), None

    if resp.status_code == 404:
        return CheckResult(target_key, bucket, "Bucket Listing", "NOT_FOUND",
                           "Bucket does not exist", resp.status_code), None

    if resp.status_code == 403:
        return CheckResult(target_key, bucket, "Bucket Listing", "PASS",
                           "Bucket listing denied (403 Forbidden)",
                           resp.status_code), base_url

    if resp.status_code != 200:
        return CheckResult(target_key, bucket, "Bucket Listing", "PASS",
                           f"HTTP {resp.status_code}", resp.status_code), base_url

    # Status 200 — check if it's an actual ListBucketResult
    root = _parse_xml(resp.text)
    if root is None:
        return CheckResult(target_key, bucket, "Bucket Listing", "PASS",
                           "Non-XML response", resp.status_code), base_url

    # Check for ListBucketResult (v1 or v2)
    tag = root.tag
    if tag in (f"{{{S3_NS}}}ListBucketResult", "ListBucketResult"):
        # Count keys in this first page
        contents = _xfindall(root, "Contents")
        key_count = len(contents)
        return CheckResult(
            target_key, bucket, "Bucket Listing", "FAIL",
            f"Bucket is publicly listable ({key_count} keys in first page)",
            resp.status_code,
            evidence={"region": region, "first_page_keys": key_count},
        ), base_url

    # Some other XML (e.g., Error)
    error_code = _xtext(root, "Code")
    if error_code == "AccessDenied":
        return CheckResult(target_key, bucket, "Bucket Listing", "PASS",
                           "Access denied", resp.status_code), base_url

    return CheckResult(target_key, bucket, "Bucket Listing", "PASS",
                       f"Unrecognized XML response (root: {tag})",
                       resp.status_code), base_url


def _check_object_enumeration(session: requests.Session, bucket: str,
                              target_key: str,
                              base_url: str) -> CheckResult:
    """Check 2: Paginate listing to enumerate objects, count, size, types.

    Collects up to MAX_ENUMERATE_KEYS objects and stores the first 100 keys
    as sample evidence so the dashboard can show actual filenames.
    """
    total_keys = 0
    total_size = 0
    extension_counter: Counter = Counter()
    sample_objects: list[dict] = []  # first 100 objects with key/size/lastmod
    continuation_token = None
    pages = 0
    max_samples = 100

    while total_keys < MAX_ENUMERATE_KEYS:
        url = f"{base_url}/?list-type=2&max-keys=1000"
        if continuation_token:
            url += f"&continuation-token={continuation_token}"

        try:
            resp = session.get(url, timeout=(5, 30))
        except requests.RequestException as e:
            if total_keys > 0:
                break  # partial results
            return CheckResult(target_key, bucket, "Object Enumeration", "ERROR",
                               f"Connection error: {e}")

        if resp.status_code != 200:
            if total_keys > 0:
                break
            return CheckResult(target_key, bucket, "Object Enumeration", "PASS",
                               f"Listing not accessible (HTTP {resp.status_code})",
                               resp.status_code)

        root = _parse_xml(resp.text)
        if root is None:
            break

        contents = _xfindall(root, "Contents")
        if not contents:
            break

        for item in contents:
            key_el = _xfind(item, "Key")
            size_el = _xfind(item, "Size")
            mod_el = _xfind(item, "LastModified")

            key = key_el.text if key_el is not None else ""
            size = int(size_el.text) if size_el is not None and size_el.text else 0
            lastmod = mod_el.text if mod_el is not None else ""

            total_keys += 1
            total_size += size

            ext = _get_extension(key)
            category = _EXTENSION_CATEGORIES.get(ext, "Other") if ext else "No Extension"
            extension_counter[category] += 1

            if len(sample_objects) < max_samples:
                sample_objects.append({
                    "key": key,
                    "size": size,
                    "size_human": _human_size(size),
                    "last_modified": lastmod[:19] if lastmod else "",
                })

            if total_keys >= MAX_ENUMERATE_KEYS:
                break

        pages += 1

        # Check for continuation
        is_truncated = _xtext(root, "IsTruncated")
        next_token = _xtext(root, "NextContinuationToken")

        if is_truncated and is_truncated.lower() == "true" and next_token:
            continuation_token = next_token
        else:
            break

        time.sleep(0.3)

    if total_keys == 0:
        return CheckResult(target_key, bucket, "Object Enumeration", "INFO",
                           "No objects found in bucket")

    count_label = f"{total_keys:,}+" if total_keys >= MAX_ENUMERATE_KEYS else f"{total_keys:,}"

    # Build file type distribution (top 10)
    type_dist = dict(extension_counter.most_common(10))
    if len(extension_counter) > 10:
        type_dist["(other types)"] = sum(
            c for _, c in extension_counter.most_common()[10:]
        )

    evidence = {
        "object_count": total_keys,
        "capped_at_max": total_keys >= MAX_ENUMERATE_KEYS,
        "total_size": total_size,
        "total_size_human": _human_size(total_size),
        "pages_fetched": pages,
        "file_type_distribution": type_dist,
        "objects": sample_objects,
    }

    return CheckResult(
        target_key, bucket, "Object Enumeration", "FAIL",
        f"{count_label} objects, {_human_size(total_size)} total",
        200, evidence=evidence,
    )


def _check_directory_structure(session: requests.Session, bucket: str,
                               target_key: str,
                               base_url: str) -> CheckResult:
    """Check 3: Use delimiter=/ to expose directory (CommonPrefixes) structure."""
    url = f"{base_url}/?delimiter=/&list-type=2"
    try:
        resp = session.get(url, timeout=(5, 15))
    except requests.RequestException as e:
        return CheckResult(target_key, bucket, "Directory Structure", "ERROR",
                           f"Connection error: {e}")

    if resp.status_code != 200:
        return CheckResult(target_key, bucket, "Directory Structure", "PASS",
                           f"Not accessible (HTTP {resp.status_code})",
                           resp.status_code)

    root = _parse_xml(resp.text)
    if root is None:
        return CheckResult(target_key, bucket, "Directory Structure", "PASS",
                           "Non-XML response", resp.status_code)

    prefixes = _xfindall(root, "CommonPrefixes")
    root_files = _xfindall(root, "Contents")

    directories = []
    for prefix_el in prefixes:
        p = _xtext(prefix_el, "Prefix") or ""
        if p:
            directories.append(p)

    root_file_keys = []
    for content in root_files[:20]:  # cap at 20 for evidence
        key_el = _xfind(content, "Key")
        if key_el is not None and key_el.text:
            root_file_keys.append(key_el.text)

    if not directories and not root_file_keys:
        return CheckResult(target_key, bucket, "Directory Structure", "INFO",
                           "Empty bucket root", resp.status_code)

    detail_parts = []
    if directories:
        detail_parts.append(f"{len(directories)} directories")
    if root_file_keys:
        detail_parts.append(f"{len(root_file_keys)} root files")
    detail = "Exposed: " + ", ".join(detail_parts)

    evidence = {}
    if directories:
        evidence["directories"] = directories[:50]  # cap at 50
        evidence["directory_count"] = len(directories)
    if root_file_keys:
        evidence["root_files"] = root_file_keys
        evidence["root_file_count"] = len(root_file_keys)

    return CheckResult(
        target_key, bucket, "Directory Structure", "FAIL",
        detail, resp.status_code, evidence=evidence,
    )


def _check_acl(session: requests.Session, bucket: str,
               target_key: str, base_url: str) -> CheckResult:
    """Check 4: Attempt to read bucket ACL for public grants."""
    url = f"{base_url}/?acl"
    try:
        resp = session.get(url, timeout=(5, 15))
    except requests.RequestException as e:
        return CheckResult(target_key, bucket, "ACL Check", "ERROR",
                           f"Connection error: {e}")

    if resp.status_code == 403:
        return CheckResult(target_key, bucket, "ACL Check", "PASS",
                           "ACL not publicly readable (403)",
                           resp.status_code)

    if resp.status_code != 200:
        return CheckResult(target_key, bucket, "ACL Check", "PASS",
                           f"HTTP {resp.status_code}", resp.status_code)

    root = _parse_xml(resp.text)
    if root is None:
        return CheckResult(target_key, bucket, "ACL Check", "PASS",
                           "Non-XML response", resp.status_code)

    # Look for grants to AllUsers or AuthenticatedUsers
    public_grants = []
    all_grants = root.findall(f".//{{{S3_NS}}}Grant") or root.findall(".//Grant")

    for grant in all_grants:
        grantee = _xfind(grant, "Grantee")
        permission = _xtext(grant, "Permission") or ""

        if grantee is None:
            continue

        uri = _xtext(grantee, "URI") or ""

        if "AllUsers" in uri:
            public_grants.append({
                "grantee": "AllUsers (everyone on the internet)",
                "permission": permission,
            })
        elif "AuthenticatedUsers" in uri:
            public_grants.append({
                "grantee": "AuthenticatedUsers (any AWS account)",
                "permission": permission,
            })

    if public_grants:
        grant_desc = "; ".join(
            f"{g['grantee']}: {g['permission']}" for g in public_grants
        )
        return CheckResult(
            target_key, bucket, "ACL Check", "FAIL",
            f"Public ACL grants found: {grant_desc}",
            resp.status_code,
            evidence={"public_grants": public_grants},
        )

    return CheckResult(target_key, bucket, "ACL Check", "PASS",
                       "ACL readable but no public grants",
                       resp.status_code)


def _check_sample_download(session: requests.Session, bucket: str,
                           target_key: str, base_url: str,
                           sample_count: int = DEFAULT_SAMPLE_COUNT
                           ) -> tuple[CheckResult, list[dict]]:
    """Check 5: Download first N files and inspect content.

    Returns (CheckResult, downloaded_text_contents) where downloaded_text_contents
    is a list of {"key": str, "content": str} for text files (used by PII check).
    """
    # First, get a listing to find keys to download
    url = f"{base_url}/?list-type=2&max-keys={sample_count * 3}"
    try:
        resp = session.get(url, timeout=(5, 15))
    except requests.RequestException as e:
        return CheckResult(target_key, bucket, "Sample Download", "ERROR",
                           f"Connection error: {e}"), []

    if resp.status_code != 200:
        return CheckResult(target_key, bucket, "Sample Download", "PASS",
                           f"Cannot list objects (HTTP {resp.status_code})",
                           resp.status_code), []

    root = _parse_xml(resp.text)
    if root is None:
        return CheckResult(target_key, bucket, "Sample Download", "PASS",
                           "Non-XML response", resp.status_code), []

    contents = _xfindall(root, "Contents")
    if not contents:
        return CheckResult(target_key, bucket, "Sample Download", "INFO",
                           "No objects to download", resp.status_code), []

    # Collect candidate keys, skip zero-byte "directory" objects
    candidates = []
    for item in contents:
        key_el = _xfind(item, "Key")
        size_el = _xfind(item, "Size")
        key = key_el.text if key_el is not None else ""
        size = int(size_el.text) if size_el is not None and size_el.text else 0
        if key and size > 0:
            candidates.append({"key": key, "size": size})

    if not candidates:
        return CheckResult(target_key, bucket, "Sample Download", "INFO",
                           "Only zero-byte/directory objects found"), []

    downloaded = []
    text_contents = []
    errors = 0

    for obj in candidates[:sample_count]:
        key = obj["key"]
        size = obj["size"]
        obj_url = f"{base_url}/{key}"

        time.sleep(0.3)

        try:
            # Use Range header to limit download size
            headers = {}
            if size > MAX_DOWNLOAD_BYTES:
                headers["Range"] = f"bytes=0-{MAX_DOWNLOAD_BYTES - 1}"

            dl_resp = session.get(obj_url, timeout=(5, 30), headers=headers)
        except requests.RequestException as e:
            errors += 1
            downloaded.append({
                "key": key, "size": size, "status": "error",
                "detail": str(e)[:200],
            })
            continue

        if dl_resp.status_code not in (200, 206):
            errors += 1
            downloaded.append({
                "key": key, "size": size, "status": "denied",
                "http_status": dl_resp.status_code,
            })
            continue

        content_type = dl_resp.headers.get("Content-Type", "application/octet-stream")
        actual_size = len(dl_resp.content)

        entry = {
            "key": key,
            "size": size,
            "size_human": _human_size(size),
            "content_type": content_type,
            "downloaded_bytes": actual_size,
            "http_status": dl_resp.status_code,
        }

        if _is_text_content_type(content_type):
            try:
                text = dl_resp.content.decode("utf-8", errors="replace")
                # Store a preview (first 500 chars)
                entry["preview"] = text[:500]
                entry["status"] = "downloaded_text"
                text_contents.append({"key": key, "content": text})
            except Exception:
                entry["status"] = "downloaded_binary"
        else:
            entry["status"] = "downloaded_binary"
            entry["detail"] = f"Binary file ({content_type})"

        downloaded.append(entry)

    status = "FAIL" if any(d.get("status", "").startswith("downloaded") for d in downloaded) else "PASS"
    detail_parts = []
    text_count = sum(1 for d in downloaded if d.get("status") == "downloaded_text")
    binary_count = sum(1 for d in downloaded if d.get("status") == "downloaded_binary")
    if text_count:
        detail_parts.append(f"{text_count} text files downloaded")
    if binary_count:
        detail_parts.append(f"{binary_count} binary files accessible")
    if errors:
        detail_parts.append(f"{errors} errors")
    detail = "; ".join(detail_parts) if detail_parts else "No files downloaded"

    return CheckResult(
        target_key, bucket, "Sample Download", status,
        detail, 200,
        evidence={"files": downloaded, "total_attempted": len(candidates[:sample_count])},
    ), text_contents


def _check_pii_detection(target_key: str, bucket: str,
                         text_contents: list[dict]) -> CheckResult:
    """Check 6: Scan downloaded text content for PII patterns."""
    if not text_contents:
        return CheckResult(target_key, bucket, "PII Detection", "INFO",
                           "No text content to scan")

    all_findings: dict[str, dict] = {}
    per_file_findings: list[dict] = []

    for item in text_contents:
        key = item["key"]
        content = item["content"]
        file_findings = _detect_pii(content)

        if file_findings:
            per_file_findings.append({
                "key": key,
                "findings": file_findings,
            })
            # Merge into overall findings
            for pii_type, data in file_findings.items():
                if pii_type not in all_findings:
                    all_findings[pii_type] = {"count": 0, "samples": []}
                all_findings[pii_type]["count"] += data["count"]
                # Keep up to 3 unique samples total
                existing = set(all_findings[pii_type]["samples"])
                for s in data["samples"]:
                    if s not in existing and len(all_findings[pii_type]["samples"]) < 3:
                        all_findings[pii_type]["samples"].append(s)
                        existing.add(s)

    if not all_findings:
        return CheckResult(target_key, bucket, "PII Detection", "PASS",
                           f"No PII detected in {len(text_contents)} text files scanned")

    # Build summary
    total_pii = sum(f["count"] for f in all_findings.values())
    types_found = sorted(all_findings.keys())
    detail = f"{total_pii} PII matches across {len(types_found)} types: {', '.join(types_found)}"

    return CheckResult(
        target_key, bucket, "PII Detection", "FAIL",
        detail, evidence={
            "total_matches": total_pii,
            "types": all_findings,
            "files_scanned": len(text_contents),
            "files_with_pii": len(per_file_findings),
            "per_file": per_file_findings,
        },
    )


# ─── Full object listing (for Excel download) ────────────────────────────────

def iter_all_objects(bucket: str, max_keys: int = 100_000):
    """Generator that yields (event_type, data) for streaming all objects in a bucket.

    Yields:
        ("progress", {"status": str, "count": int})
        ("objects", {"objects": list[dict]})   — batches of objects
        ("done", {"total": int})
        ("error", {"error": str})
    """
    session = _new_session()
    base_url = _get_bucket_url(bucket)

    # Detect region redirect
    region = _detect_region_from_redirect(session, bucket)
    if region:
        base_url = _get_bucket_url(bucket, region)

    total = 0
    continuation_token = None

    while total < max_keys:
        url = f"{base_url}/?list-type=2&max-keys=1000"
        if continuation_token:
            url += f"&continuation-token={continuation_token}"

        try:
            resp = session.get(url, timeout=(5, 30))
        except requests.RequestException as e:
            yield ("error", {"error": f"Connection error: {e}"})
            return

        if resp.status_code != 200:
            yield ("error", {"error": f"HTTP {resp.status_code}"})
            return

        root = _parse_xml(resp.text)
        if root is None:
            yield ("error", {"error": "Failed to parse XML response"})
            return

        contents = _xfindall(root, "Contents")
        if not contents:
            break

        batch = []
        for item in contents:
            key_el = _xfind(item, "Key")
            size_el = _xfind(item, "Size")
            mod_el = _xfind(item, "LastModified")
            storage_el = _xfind(item, "StorageClass")

            key = key_el.text if key_el is not None else ""
            size = int(size_el.text) if size_el is not None and size_el.text else 0

            batch.append({
                "key": key,
                "size": size,
                "size_human": _human_size(size),
                "last_modified": (mod_el.text if mod_el is not None else "")[:19],
                "storage_class": storage_el.text if storage_el is not None else "",
                "extension": _get_extension(key) or "",
            })
            total += 1
            if total >= max_keys:
                break

        yield ("objects", {"objects": batch})
        yield ("progress", {"status": f"Listed {total:,} objects...", "count": total})

        is_truncated = _xtext(root, "IsTruncated")
        next_token = _xtext(root, "NextContinuationToken")

        if is_truncated and is_truncated.lower() == "true" and next_token:
            continuation_token = next_token
        else:
            break

        time.sleep(0.3)

    yield ("done", {"total": total})


# ─── Main scan (generator for SSE progress) ──────────────────────────────────

def scan_buckets(targets: dict | None = None, target_filter: str | None = None):
    """Generator that yields (event_type, data) tuples for SSE streaming.

    event_type: 'progress' | 'result' | 'complete' | 'error'

    Args:
        targets: dict of target configs (loaded from file if None)
        target_filter: if set, only scan this target key
    """
    if targets is None:
        targets = load_targets()

    if not targets:
        yield ("error", {"message": "No scan targets configured"})
        return

    if target_filter and target_filter in targets:
        targets = {target_filter: targets[target_filter]}
    elif target_filter and target_filter not in targets:
        yield ("error", {"message": f"Target '{target_filter}' not found"})
        return

    session = _new_session()
    report = ScanReport()

    total_buckets = sum(len(t.get("buckets", [])) for t in targets.values())
    bucket_idx = 0

    for target_key, target_cfg in targets.items():
        label = target_cfg.get("label", target_key)
        buckets = target_cfg.get("buckets", [])
        sample_count = target_cfg.get("sample_count", DEFAULT_SAMPLE_COUNT)

        for bucket in buckets:
            bucket_idx += 1

            yield ("progress", {
                "phase": "checking",
                "target": label,
                "bucket": bucket,
                "bucket_idx": bucket_idx,
                "total_buckets": total_buckets,
                "message": f"[{bucket_idx}/{total_buckets}] Checking bucket: {bucket}...",
            })

            # ── Check 1: Bucket Listing ───────────────────────────────────
            listing_result, effective_url = _check_bucket_listing(
                session, bucket, target_key
            )
            report.results.append(listing_result)
            yield ("result", listing_result.to_dict())

            # If bucket doesn't exist, skip remaining checks
            if listing_result.status == "NOT_FOUND":
                logger.info("Bucket %s does not exist, skipping", bucket)
                continue

            # If listing is denied, remaining enumeration checks will also fail
            # but ACL check can still be attempted
            listing_accessible = listing_result.status == "FAIL"

            if effective_url is None:
                effective_url = _get_bucket_url(bucket)

            time.sleep(0.3)

            # ── Check 2: Object Enumeration ───────────────────────────────
            if listing_accessible:
                yield ("progress", {
                    "phase": "enumerating",
                    "target": label,
                    "bucket": bucket,
                    "bucket_idx": bucket_idx,
                    "total_buckets": total_buckets,
                    "message": f"[{bucket_idx}/{total_buckets}] Enumerating objects in {bucket}...",
                })
                enum_result = _check_object_enumeration(
                    session, bucket, target_key, effective_url
                )
            else:
                enum_result = CheckResult(
                    target_key, bucket, "Object Enumeration", "PASS",
                    "Bucket listing not public, enumeration not possible"
                )
            report.results.append(enum_result)
            yield ("result", enum_result.to_dict())
            time.sleep(0.3)

            # ── Check 3: Directory Structure ──────────────────────────────
            if listing_accessible:
                yield ("progress", {
                    "phase": "directories",
                    "target": label,
                    "bucket": bucket,
                    "bucket_idx": bucket_idx,
                    "total_buckets": total_buckets,
                    "message": f"[{bucket_idx}/{total_buckets}] Checking directory structure of {bucket}...",
                })
                dir_result = _check_directory_structure(
                    session, bucket, target_key, effective_url
                )
            else:
                dir_result = CheckResult(
                    target_key, bucket, "Directory Structure", "PASS",
                    "Bucket listing not public, directory enumeration not possible"
                )
            report.results.append(dir_result)
            yield ("result", dir_result.to_dict())
            time.sleep(0.3)

            # ── Check 4: ACL Check ────────────────────────────────────────
            yield ("progress", {
                "phase": "acl",
                "target": label,
                "bucket": bucket,
                "bucket_idx": bucket_idx,
                "total_buckets": total_buckets,
                "message": f"[{bucket_idx}/{total_buckets}] Checking ACL of {bucket}...",
            })
            acl_result = _check_acl(session, bucket, target_key, effective_url)
            report.results.append(acl_result)
            yield ("result", acl_result.to_dict())
            time.sleep(0.3)

            # ── Check 5: Sample Download ──────────────────────────────────
            if listing_accessible:
                yield ("progress", {
                    "phase": "downloading",
                    "target": label,
                    "bucket": bucket,
                    "bucket_idx": bucket_idx,
                    "total_buckets": total_buckets,
                    "message": f"[{bucket_idx}/{total_buckets}] Downloading samples from {bucket}...",
                })
                sample_result, text_contents = _check_sample_download(
                    session, bucket, target_key, effective_url, sample_count
                )
            else:
                sample_result = CheckResult(
                    target_key, bucket, "Sample Download", "PASS",
                    "Bucket listing not public, cannot identify files to download"
                )
                text_contents = []
            report.results.append(sample_result)
            yield ("result", sample_result.to_dict())
            time.sleep(0.3)

            # ── Check 6: PII Detection ────────────────────────────────────
            if text_contents:
                yield ("progress", {
                    "phase": "pii_scan",
                    "target": label,
                    "bucket": bucket,
                    "bucket_idx": bucket_idx,
                    "total_buckets": total_buckets,
                    "message": f"[{bucket_idx}/{total_buckets}] Scanning for PII in {bucket}...",
                })
                pii_result = _check_pii_detection(target_key, bucket, text_contents)
            else:
                pii_result = CheckResult(
                    target_key, bucket, "PII Detection", "INFO",
                    "No text content available to scan"
                )
            report.results.append(pii_result)
            yield ("result", pii_result.to_dict())

            logger.info("Completed all checks for bucket %s", bucket)

    yield ("complete", report.to_dict())


# ─── CLI entrypoint ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import shutil

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Example targets — edit as needed
    targets = {
        "example": {
            "label": "Example Public Buckets",
            "buckets": [
                # Add bucket names to scan here
            ],
            "sample_count": 5,
        },
    }

    cols = shutil.get_terminal_size().columns

    for event_type, data in scan_buckets(targets):
        if event_type == "progress":
            print(f"\n{'=' * cols}")
            print(f"  {data['message']}")
            print(f"{'=' * cols}")
        elif event_type == "result":
            status = data["status"]
            icon = {"PASS": "[OK]", "FAIL": "[!!]", "ERROR": "[??]",
                    "INFO": "[--]", "NOT_FOUND": "[NF]"}.get(status, "[??]")
            print(f"  {icon} {data['check']:25s} {status:10s} {data['detail']}")
            if data.get("evidence"):
                for k, v in data["evidence"].items():
                    if isinstance(v, (dict, list)):
                        print(f"       {k}: {json.dumps(v, indent=2)[:200]}")
                    else:
                        print(f"       {k}: {v}")
        elif event_type == "complete":
            summary = data["summary"]
            print(f"\n{'=' * cols}")
            print(f"  SCAN COMPLETE  |  Total: {summary['total']}  "
                  f"Pass: {summary['pass']}  Fail: {summary['fail']}  "
                  f"Error: {summary['error']}  Info: {summary['info']}")
            print(f"{'=' * cols}")
        elif event_type == "error":
            print(f"\n  [ERROR] {data.get('message', data)}")
