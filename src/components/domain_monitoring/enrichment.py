"""Domain enrichment with threat intelligence.

This module handles enrichment of domain data with VirusTotal
and Recorded Future threat intelligence.
"""

import logging
import time

from .config import get_vt_client

logger = logging.getLogger(__name__)


def enrich_with_virustotal(domains: list[dict], max_checks: int = 10) -> list[dict]:
    """Enrich domain list with VirusTotal reputation data.

    Args:
        domains: List of domain dicts with 'domain' key
        max_checks: Maximum domains to check (VT rate limit: 4/min on free tier)

    Returns:
        Same list with 'vt_reputation' added to each checked domain
    """
    vt = get_vt_client()
    if not vt:
        return domains

    # Only check up to max_checks domains to respect rate limits
    to_check = domains[:max_checks]

    for i, domain_info in enumerate(to_check):
        domain_name = domain_info.get("domain", "")
        if not domain_name:
            continue

        try:
            logger.info(f"Checking VT reputation for: {domain_name}")
            result = vt.lookup_domain(domain_name)

            if "error" in result:
                domain_info["vt_reputation"] = {"error": result["error"]}
                if "rate limit" in result["error"].lower():
                    logger.warning("VT rate limit hit, stopping enrichment")
                    break
            else:
                # Extract key reputation data
                attrs = result.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                # Determine threat level
                if malicious >= 3:
                    threat_level = "HIGH"
                elif malicious >= 1 or suspicious >= 3:
                    threat_level = "MEDIUM"
                elif suspicious >= 1:
                    threat_level = "LOW"
                else:
                    threat_level = "CLEAN"

                domain_info["vt_reputation"] = {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "threat_level": threat_level,
                    "categories": attrs.get("categories", {}),
                    "registrar": attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date"),
                    "vt_link": f"https://www.virustotal.com/gui/domain/{domain_name}",
                }

                logger.info(f"VT result for {domain_name}: {threat_level} (M:{malicious}/S:{suspicious})")

            # Rate limit: wait between requests (VT free tier: 4/min)
            if i < len(to_check) - 1:
                time.sleep(15)  # 4 requests per minute = 15 sec between requests

        except Exception as e:
            logger.error(f"VT lookup error for {domain_name}: {e}")
            domain_info["vt_reputation"] = {"error": str(e)}

    return domains
