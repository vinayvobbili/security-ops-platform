"""Cyber Tool Inventory — list of tools owned under the CISO org.

Phase 1 (current): seeded from an Excel snapshot of {EAI ID, App Name}; the rest of the
fields the requester asked for (CISO, Application Long Name, Sr. Business Leader,
Business Working Client, Business Sponsor) are *synthesized* deterministically so
stakeholders can see what the end product will look like.

Phase 2 (planned): swap `_load_inventory()` to call the EAI API once an API key is
provisioned. Keep the row shape identical so the route and UI don't change.
"""

import hashlib
import logging
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

import openpyxl

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "cyber_tool_inventory"
SEED_XLSX = DATA_DIR / "seed_tool_inventory.xlsx"

_CACHE: Optional[List[Dict[str, Any]]] = None
_CACHE_LOCK = Lock()

CISO_NAME = "Dan Antilley"

# Marvel & DC character names — used as obvious "this is fake data" signals.
# They get replaced by real EAI data in Phase 2.
SR_BUSINESS_LEADERS = [
    "Tony Stark", "Bruce Wayne", "Diana Prince", "T'Challa",
    "Stephen Strange", "Carol Danvers", "Nick Fury", "Charles Xavier",
    "Pepper Potts", "Lex Luthor", "Reed Richards", "Selina Kyle",
]

BUSINESS_SPONSORS = [
    "Peter Parker", "Barry Allen", "Wanda Maximoff", "Scott Lang",
    "Hope Van Dyne", "Shuri", "Sam Wilson", "Bucky Barnes",
    "Hal Jordan", "Arthur Curry", "Victor Stone", "Dinah Lance",
]

BUSINESS_WORKING_CLIENTS = [
    "Identity & Access Engineering",
    "Endpoint Security Operations",
    "Network Defense",
    "Threat Intelligence",
    "Data Security & Privacy",
    "Vulnerability Management",
    "Cloud Security",
    "Application Security",
    "Security Architecture",
    "Incident Response",
    "Detection Engineering",
    "Security Operations Center",
]

# Keyword → category for inferring the "long name" suffix
CATEGORY_HINTS = [
    (("crowdstrike", "edr", "endpoint", "carbon black"), "Endpoint Detection & Response"),
    (("vpn", "proxy", "firewall"), "Network Security Gateway"),
    (("ad ", "active directory", "okta", "ping", "mfa", "sso", "iam", "identity", "access"), "Identity & Access Management"),
    (("abnormal", "proofpoint", "mimecast", "email"), "Email Security"),
    (("splunk", "qradar", "siem", "sumo"), "Security Information & Event Management"),
    (("crowdstrike falcon",), "Endpoint Detection & Response"),
    (("xsoar", "soar", "phantom"), "Security Orchestration & Response"),
    (("vault", "secrets", "cyberark", "beyondtrust"), "Privileged Access Management"),
    (("vulnerability", "qualys", "tenable", "nessus", "rapid7"), "Vulnerability Management"),
    (("cloud", "aws", "azure", "gcp", "wiz", "lacework"), "Cloud Security Posture"),
    (("dlp", "varonis", "data loss"), "Data Loss Prevention"),
    (("recorded future", "threat intel", "anomali", "intel 471"), "Threat Intelligence"),
    (("burp", "checkmarx", "veracode", "snyk"), "Application Security Testing"),
    (("zimperium", "lookout", "mobile"), "Mobile Threat Defense"),
    (("certificate", "venafi", "pki"), "Certificate Lifecycle Management"),
    (("backup", "rubrik", "veeam"), "Data Protection"),
]

DEFAULT_CATEGORY = "Enterprise Security Platform"


def _infer_category(app_name: str) -> str:
    """Infer a category suffix from the app name for the long name."""
    lo = app_name.lower()
    for keywords, category in CATEGORY_HINTS:
        if any(kw in lo for kw in keywords):
            return category
    return DEFAULT_CATEGORY


def _stable_pick(seed_text: str, pool: List[str], salt: str) -> str:
    """Deterministically pick from `pool` based on `seed_text` + `salt`."""
    digest = hashlib.md5(f"{salt}|{seed_text}".encode("utf-8")).digest()
    idx = int.from_bytes(digest[:4], "big") % len(pool)
    return pool[idx]


def _synthesize_fields(app_name: str) -> Dict[str, str]:
    """Build the 4 synthetic descriptor fields for a given app."""
    long_name = f"{app_name} — {_infer_category(app_name)}"
    return {
        "ciso": CISO_NAME,
        "app_long_name": long_name,
        "sr_business_leader": _stable_pick(app_name, SR_BUSINESS_LEADERS, "sbl"),
        "business_working_client": _stable_pick(app_name, BUSINESS_WORKING_CLIENTS, "bwc"),
        "business_sponsor": _stable_pick(app_name, BUSINESS_SPONSORS, "sponsor"),
    }


def _load_inventory() -> List[Dict[str, Any]]:
    """Load tool rows from the seed xlsx, enriched with synthetic descriptor fields.
    Returns rows sorted by app_name."""
    if not SEED_XLSX.is_file():
        logger.warning("Cyber tool inventory seed file not found: %s", SEED_XLSX)
        return []

    wb = openpyxl.load_workbook(SEED_XLSX, data_only=True, read_only=True)
    ws = wb.active
    rows: List[Dict[str, Any]] = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row or len(row) < 2:
            continue
        eai_raw, app_name = row[0], row[1]
        if not app_name:
            continue
        eai_id = str(int(eai_raw)) if isinstance(eai_raw, (int, float)) and eai_raw else (
            str(eai_raw).strip() if eai_raw else ""
        )
        app_name_clean = str(app_name).strip()
        record = {"eai_id": eai_id, "app_name": app_name_clean}
        record.update(_synthesize_fields(app_name_clean))
        rows.append(record)
    wb.close()
    rows.sort(key=lambda r: r["app_name"].lower())
    logger.info("Loaded %d cyber tool inventory rows from %s (synthetic descriptors)",
                len(rows), SEED_XLSX.name)
    return rows


def get_inventory(force_reload: bool = False) -> List[Dict[str, Any]]:
    """Return cached inventory rows. Pass force_reload=True to re-read the seed file."""
    global _CACHE
    with _CACHE_LOCK:
        if _CACHE is None or force_reload:
            _CACHE = _load_inventory()
        return list(_CACHE)
