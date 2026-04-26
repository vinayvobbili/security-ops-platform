"""Shared enrichment functions for alert triage.

Provides VirusTotal, AbuseIPDB, and Recorded Future enrichment used by the
XSOAR triage pipeline (via xsoar_enrichment.py).
"""

import ipaddress
import logging
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def _is_external_ip(ip: str) -> bool:
    """Check if an IP is external (not RFC1918/loopback/link-local)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _enrich_virustotal(iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    """Enrich hashes, IPs, domains via VirusTotal (sequential, rate-limited)."""
    try:
        from services.virustotal import VirusTotalClient
        vt = VirusTotalClient()
        if not vt.is_configured():
            return {"error": "VT not configured"}
    except Exception as e:
        return {"error": str(e)}

    results: Dict[str, Any] = {"hashes": {}, "ips": {}, "domains": {}}
    req_count = 0

    # Hashes first (most valuable)
    for h in iocs.get("sha256", [])[:5]:
        try:
            r = vt.lookup_hash(h)
            if "error" not in r:
                stats = r.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                results["hashes"][h] = {"malicious": malicious, "total": total, "threat_level": vt.get_threat_level(stats, is_file=True)}
            req_count += 1
            if req_count % 4 == 0:
                time.sleep(15)
        except Exception as e:
            logger.debug(f"VT hash lookup failed for {h[:16]}: {e}")

    # External IPs
    external_ips = [ip for ip in iocs.get("ips", []) if _is_external_ip(ip)]
    for ip in external_ips[:3]:
        try:
            r = vt.lookup_ip(ip)
            if "error" not in r:
                stats = r.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                results["ips"][ip] = {"malicious": malicious, "total": total}
            req_count += 1
            if req_count % 4 == 0:
                time.sleep(15)
        except Exception as e:
            logger.debug(f"VT IP lookup failed for {ip}: {e}")

    # Domains
    for d in iocs.get("domains", [])[:3]:
        try:
            r = vt.lookup_domain(d)
            if "error" not in r:
                stats = r.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                results["domains"][d] = {"malicious": malicious, "total": total}
            req_count += 1
            if req_count % 4 == 0:
                time.sleep(15)
        except Exception as e:
            logger.debug(f"VT domain lookup failed for {d}: {e}")

    return results


def _enrich_abuseipdb(ips: List[str]) -> Dict[str, Any]:
    """Enrich external IPs via AbuseIPDB."""
    external_ips = [ip for ip in ips if _is_external_ip(ip)]
    if not external_ips:
        return {}

    try:
        from services.abuseipdb import get_client
        client = get_client()
        if not client.is_configured():
            return {"error": "AbuseIPDB not configured"}
    except Exception as e:
        return {"error": str(e)}

    results = {}
    for ip in external_ips[:5]:
        try:
            r = client.check_ip(ip)
            if "error" not in r:
                data = r.get("data", {})
                results[ip] = {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                }
        except Exception as e:
            logger.debug(f"AbuseIPDB check failed for {ip}: {e}")

    return results


def _enrich_recorded_future(iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    """Batch enrich IOCs via Recorded Future."""
    try:
        from services.recorded_future import get_client
        rf = get_client()
        if not rf.is_configured():
            return {"error": "RF not configured"}
    except Exception as e:
        return {"error": str(e)}

    ips = [ip for ip in iocs.get("ips", []) if _is_external_ip(ip)]
    domains = iocs.get("domains", [])[:10]
    hashes = iocs.get("sha256", [])[:10]

    if not (ips or domains or hashes):
        return {}

    try:
        response = rf.enrich(
            ips=ips or None,
            domains=domains or None,
            hashes=hashes or None,
        )
        enriched = rf.extract_enrichment_results(response)
        results = {}
        for item in enriched:
            value = item.get("value", "")
            if value:
                results[value] = {
                    "risk_score": item.get("risk_score"),
                    "risk_level": item.get("risk_level"),
                }
        return results
    except Exception as e:
        logger.debug(f"RF enrichment failed: {e}")
        return {"error": str(e)}


