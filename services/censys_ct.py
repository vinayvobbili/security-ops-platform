"""Brand Impersonation Detection via Certificate Transparency Logs.

Searches for SSL certificates to detect brand impersonation attacks that
dnstwist cannot find:
- acme-loan.com (brand-keyword combinations)
- secure-acme.net (keyword-brand combinations)

Methods (in priority order):
1. Shodan SSL search (requires paid plan with query credits)
2. crt.sh wildcard search (often rate-limited for broad searches)
3. crt.sh specific domain check (always works - use with watchlist)

For free tier users: Use the watchlist approach in config.json to check
specific suspicious domains via crt.sh.

Usage:
    from services.censys_ct import search_brand_impersonation, check_domains

    # If you have Shodan paid plan:
    results = search_brand_impersonation("acme", ["acme.com"])

    # For free tier - check specific domains:
    results = check_domains(["acme-loan.com", "secure-acme.net"])
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any

from my_config import get_config

logger = logging.getLogger(__name__)

# Lazy imports
_shodan_client = None
_shodan_available = None


def _get_shodan_client():
    """Get Shodan client if available and configured."""
    global _shodan_client, _shodan_available

    if _shodan_available is False:
        return None

    if _shodan_client is not None:
        return _shodan_client

    config = get_config()
    api_key = config.shodan_api_key

    if not api_key:
        _shodan_available = False
        return None

    try:
        import shodan
        client = shodan.Shodan(api_key)
        # Check if we have query credits
        info = client.info()
        if info.get('query_credits', 0) > 0:
            _shodan_client = client
            _shodan_available = True
            return client
        else:
            logger.info("Shodan has 0 query credits - SSL search unavailable")
            _shodan_available = False
            return None
    except ImportError:
        logger.debug("Shodan library not installed")
        _shodan_available = False
        return None
    except Exception as e:
        logger.warning(f"Shodan init failed: {e}")
        _shodan_available = False
        return None


def is_configured() -> bool:
    """Check if brand impersonation search is available.

    Returns True if Shodan is configured with query credits.
    For free users, use check_domains() with specific domains instead.
    """
    client = _get_shodan_client()
    return client is not None


def _is_legitimate_domain(domain: str, legitimate_domains: list[str]) -> bool:
    """Check if domain is legitimate (exact match or subdomain)."""
    domain = domain.lower().lstrip("*.")
    for legit in legitimate_domains:
        legit = legit.lower()
        if domain == legit or domain.endswith(f".{legit}"):
            return True
    return False


def search_brand_impersonation(
    brand: str,
    legitimate_domains: list[str],
    max_results: int = 100,
    days_back: int = 90,
) -> dict[str, Any]:
    """Search for SSL certificates containing brand name.

    Requires Shodan paid plan with query credits.
    For free users, returns error - use check_domains() instead.

    Args:
        brand: Brand name to search for (e.g., "acme")
        legitimate_domains: List of legitimate domains to exclude
        max_results: Maximum results to retrieve
        days_back: Not used, kept for API compatibility

    Returns:
        Dict with impersonation_domains list or error
    """
    results = {
        "success": False,
        "brand": brand,
        "legitimate_domains": legitimate_domains,
        "impersonation_domains": [],
        "total_results": 0,
        "unique_suspicious_domains": 0,
        "scan_time": datetime.now(timezone.utc).isoformat(),
    }

    client = _get_shodan_client()
    if client is None:
        results["error"] = (
            "Brand impersonation search requires Shodan paid plan. "
            "Free alternative: add suspicious domains to watchlist in config.json"
        )
        return results

    brand_lower = brand.lower()
    brand_pattern = re.compile(re.escape(brand_lower), re.IGNORECASE)
    query = f'ssl.cert.subject.cn:"{brand_lower}"'

    logger.info(f"Searching Shodan for brand '{brand}'")

    try:
        import shodan
        suspicious_domains: dict[str, dict] = {}

        search_results = client.search(query, limit=max_results)
        total_results = search_results.get('total', 0)
        results["total_results"] = total_results

        for match in search_results.get('matches', []):
            ssl_info = match.get('ssl', {})
            cert = ssl_info.get('cert', {})
            subject = cert.get('subject', {})
            issuer = cert.get('issuer', {})

            cn = subject.get('CN', '')
            if not cn:
                continue

            domain = cn.lower().lstrip("*.")

            if not brand_pattern.search(domain):
                continue

            if _is_legitimate_domain(domain, legitimate_domains):
                continue

            if domain not in suspicious_domains:
                suspicious_domains[domain] = {
                    "domain": domain,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "issuer_org": issuer.get('O', 'Unknown'),
                    "ip": match.get('ip_str', ''),
                    "port": match.get('port', 443),
                    "country": match.get('location', {}).get('country_name', ''),
                }
                logger.info(f"Found suspicious domain: {domain}")

        results["success"] = True
        results["impersonation_domains"] = list(suspicious_domains.values())
        results["unique_suspicious_domains"] = len(suspicious_domains)

        logger.info(f"Search complete: {len(suspicious_domains)} suspicious domains")

    except shodan.APIError as e:
        results["error"] = f"Shodan API error: {e}"
    except Exception as e:
        results["error"] = str(e)

    return results


def check_domains(domains: list[str], days_back: int = 90) -> dict[str, Any]:
    """Check specific domains for SSL certificates via crt.sh.

    This works with free tier - no paid API needed.
    Use this with a watchlist of suspicious domains.

    Args:
        domains: List of specific domain names to check
        days_back: How many days back to search

    Returns:
        Dict with domains_with_certs and domains_without_certs
    """
    # Delegate to the existing crt.sh implementation
    from services.cert_transparency import check_suspicious_domains
    return check_suspicious_domains(domains, days_back=days_back)


# Convenience aliases
def check_brand(brand: str, legitimate_domains: list[str]) -> dict[str, Any]:
    """Search for brand impersonation (requires Shodan paid plan)."""
    return search_brand_impersonation(brand, legitimate_domains)
