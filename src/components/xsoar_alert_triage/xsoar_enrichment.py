"""IOC extraction and parallel enrichment for XSOAR tickets.

Extracts IOCs from XSOAR ticket fields (name, details, CustomFields) and
enriches them in parallel via VT, AbuseIPDB, and Recorded Future.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from src.utils.entity_extractor import extract_ips, extract_domains, extract_hashes

logger = logging.getLogger(__name__)


def _extract_iocs_from_xsoar_ticket(ticket: dict) -> Dict[str, List[str]]:
    """Extract IOCs from XSOAR ticket fields.

    Pulls from:
    - CustomFields.sourceip → ips
    - name, details, CustomFields.actionsummary → regex extraction
    """
    iocs: Dict[str, List[str]] = {
        "sha256": [],
        "md5": [],
        "ips": [],
        "domains": [],
    }

    custom = ticket.get("CustomFields") or {}

    # Direct IP field
    source_ip = custom.get("sourceip", "")
    if source_ip:
        iocs["ips"].append(source_ip)

    # Combine text fields for regex extraction
    text_parts = []
    for field_name in ("name", "details"):
        val = ticket.get(field_name, "")
        if val:
            text_parts.append(str(val))

    action_summary = custom.get("actionsummary", "")
    if action_summary:
        text_parts.append(str(action_summary))

    combined_text = "\n".join(text_parts)

    if combined_text:
        # Extract IPs
        for ip in extract_ips(combined_text):
            if ip not in iocs["ips"]:
                iocs["ips"].append(ip)

        # Extract domains
        for domain in extract_domains(combined_text):
            if domain not in iocs["domains"]:
                iocs["domains"].append(domain)

        # Extract hashes
        hashes = extract_hashes(combined_text)
        for h in hashes.get("sha256", []):
            if h not in iocs["sha256"]:
                iocs["sha256"].append(h)
        for h in hashes.get("md5", []):
            if h not in iocs["md5"]:
                iocs["md5"].append(h)

    return iocs


def enrich_xsoar_ticket(ticket: dict) -> Dict[str, Any]:
    """Run parallel enrichment for an XSOAR ticket.

    Uses VT, AbuseIPDB, and Recorded Future (no Falcon Intel or device enrichment).

    Returns:
        Dict with enrichment results from all sources.
    """
    # Shared enrichment functions
    from src.components.xsoar_alert_triage.enrichment import (
        _enrich_virustotal,
        _enrich_abuseipdb,
        _enrich_recorded_future,
    )

    iocs = _extract_iocs_from_xsoar_ticket(ticket)
    enrichment: Dict[str, Any] = {"iocs_extracted": iocs}

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_enrich_virustotal, iocs): "virustotal",
            executor.submit(_enrich_abuseipdb, iocs.get("ips", [])): "abuseipdb",
            executor.submit(_enrich_recorded_future, iocs): "recorded_future",
        }

        for future in as_completed(futures, timeout=120):
            source = futures[future]
            try:
                enrichment[source] = future.result()
            except Exception as e:
                logger.warning(f"XSOAR enrichment source '{source}' failed: {e}")
                enrichment[source] = {"error": str(e)}

    logger.info(
        f"XSOAR enrichment complete for ticket {ticket.get('id', 'unknown')}: "
        f"IOCs={len(iocs.get('ips', []))} IPs, {len(iocs.get('sha256', []))} hashes, "
        f"{len(iocs.get('domains', []))} domains"
    )
    return enrichment
