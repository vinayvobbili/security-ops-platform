"""Certificate Transparency Monitoring Service.

Monitors Certificate Transparency logs for new SSL certificates issued for
monitored domains and their lookalikes. New certificates for lookalike domains
are a strong indicator of attacker preparation for phishing/impersonation.

Uses crt.sh (free) to query CT logs.
"""

import logging
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Request timeout
TIMEOUT = 30

# crt.sh API endpoint
CRT_SH_URL = "https://crt.sh"


class CertTransparencyMonitor:
    """Monitors Certificate Transparency logs for domain certificates."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Research)"
        })

    def search_certificates(self, domain: str, days_back: int = 7) -> dict[str, Any]:
        """Search for certificates issued for a domain in CT logs.

        Args:
            domain: Domain to search for (searches for *.domain and domain)
            days_back: How many days back to search (default 7)

        Returns:
            Dict with certificates found and metadata
        """
        try:
            # Search for certificates matching the domain
            # Using JSON output from crt.sh
            url = f"{CRT_SH_URL}/?q=%.{domain}&output=json"

            logger.info(f"Searching CT logs for: {domain}")
            response = self.session.get(url, timeout=TIMEOUT)

            if response.status_code == 404:
                return {
                    "success": True,
                    "domain": domain,
                    "certificates": [],
                    "total_count": 0,
                    "recent_count": 0,
                    "scan_time": datetime.now(UTC).isoformat(),
                }

            if response.status_code != 200:
                logger.warning(f"crt.sh returned status {response.status_code} for {domain}")
                return {
                    "success": False,
                    "domain": domain,
                    "error": f"crt.sh returned status {response.status_code}",
                }

            # Handle empty response
            if not response.text.strip() or response.text.strip() == "[]":
                return {
                    "success": True,
                    "domain": domain,
                    "certificates": [],
                    "total_count": 0,
                    "recent_count": 0,
                    "scan_time": datetime.now(UTC).isoformat(),
                }

            certs = response.json()

            # Filter for recent certificates
            cutoff_date = datetime.now(UTC) - timedelta(days=days_back)
            recent_certs = []

            for cert in certs:
                # Parse the entry timestamp
                entry_time_str = cert.get("entry_timestamp")
                if entry_time_str:
                    try:
                        # Handle various date formats from crt.sh
                        entry_time = datetime.fromisoformat(entry_time_str.replace("T", " ").split(".")[0])
                        if entry_time >= cutoff_date:
                            recent_certs.append({
                                "id": cert.get("id"),
                                "issuer_name": cert.get("issuer_name"),
                                "common_name": cert.get("common_name"),
                                "name_value": cert.get("name_value"),  # SANs
                                "not_before": cert.get("not_before"),
                                "not_after": cert.get("not_after"),
                                "entry_timestamp": entry_time_str,
                                "serial_number": cert.get("serial_number"),
                            })
                    except (ValueError, TypeError):
                        # If we can't parse the date, include it to be safe
                        recent_certs.append({
                            "id": cert.get("id"),
                            "issuer_name": cert.get("issuer_name"),
                            "common_name": cert.get("common_name"),
                            "name_value": cert.get("name_value"),
                            "not_before": cert.get("not_before"),
                            "not_after": cert.get("not_after"),
                            "entry_timestamp": entry_time_str,
                            "serial_number": cert.get("serial_number"),
                        })

            # Deduplicate by certificate ID
            seen_ids = set()
            unique_certs = []
            for cert in recent_certs:
                cert_id = cert.get("id")
                if cert_id and cert_id not in seen_ids:
                    seen_ids.add(cert_id)
                    unique_certs.append(cert)

            logger.info(f"CT search for {domain}: {len(unique_certs)} recent certs (last {days_back} days)")

            return {
                "success": True,
                "domain": domain,
                "certificates": unique_certs,
                "total_count": len(certs),
                "recent_count": len(unique_certs),
                "days_searched": days_back,
                "scan_time": datetime.now(UTC).isoformat(),
            }

        except requests.exceptions.Timeout:
            logger.error(f"CT search timeout for {domain}")
            return {
                "success": False,
                "domain": domain,
                "error": "Request timed out",
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"CT search error for {domain}: {e}")
            return {
                "success": False,
                "domain": domain,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"CT search unexpected error for {domain}: {e}")
            return {
                "success": False,
                "domain": domain,
                "error": str(e),
            }

    def check_suspicious_domains(
        self,
        domains: list[str],
        days_back: int = 90
    ) -> dict[str, Any]:
        """Check specific suspicious domains for SSL certificates in CT logs.

        Use this to verify if domains from external sources (threat intel feeds,
        typosquatting generators, etc.) have active SSL certificates - a signal
        of attacker preparation.

        Args:
            domains: List of suspicious domain names to check
            days_back: How many days back to search (default 90)

        Returns:
            Dict with domains that have certificates and metadata
        """
        results = {
            "success": True,
            "domains_checked": len(domains),
            "domains_with_certs": [],
            "domains_without_certs": [],
            "days_searched": days_back,
            "scan_time": datetime.now(UTC).isoformat(),
        }

        cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)

        for domain in domains:
            try:
                url = f"{CRT_SH_URL}/?q={domain}&output=json"
                response = self.session.get(url, timeout=TIMEOUT)

                if response.status_code == 404 or not response.text.strip() or response.text.strip() == "[]":
                    results["domains_without_certs"].append(domain)
                    continue

                if response.status_code != 200:
                    logger.warning(f"crt.sh returned {response.status_code} for {domain}")
                    continue

                certs = response.json()

                # Filter for recent certs
                recent_certs = []
                for cert in certs:
                    entry_time_str = cert.get("entry_timestamp")
                    if entry_time_str:
                        try:
                            entry_time = datetime.fromisoformat(
                                entry_time_str.replace("T", " ").split(".")[0]
                            )
                            if entry_time >= cutoff_date:
                                recent_certs.append({
                                    "issuer": cert.get("issuer_name"),
                                    "not_before": cert.get("not_before"),
                                    "not_after": cert.get("not_after"),
                                    "entry_timestamp": entry_time_str,
                                })
                        except (ValueError, TypeError):
                            recent_certs.append({
                                "issuer": cert.get("issuer_name"),
                                "entry_timestamp": entry_time_str,
                            })

                if recent_certs:
                    results["domains_with_certs"].append({
                        "domain": domain,
                        "cert_count": len(recent_certs),
                        "most_recent": recent_certs[0] if recent_certs else None,
                        "crt_sh_link": f"https://crt.sh/?q={domain}",
                    })
                else:
                    results["domains_without_certs"].append(domain)

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout checking {domain}")
            except Exception as e:
                logger.warning(f"Error checking {domain}: {e}")

        logger.info(
            f"CT check: {len(results['domains_with_certs'])}/{len(domains)} "
            f"domains have recent certs"
        )

        return results

    def check_lookalike_certificates(
        self,
        lookalike_domains: list[str],
        days_back: int = 7
    ) -> dict[str, Any]:
        """Check multiple lookalike domains for new certificates.

        Args:
            lookalike_domains: List of lookalike domain names to check
            days_back: How many days back to search

        Returns:
            Dict with results for all domains and summary
        """
        results = {
            "success": True,
            "scan_time": datetime.now(UTC).isoformat(),
            "days_searched": days_back,
            "domains_checked": len(lookalike_domains),
            "domains_with_certs": 0,
            "total_new_certs": 0,
            "high_risk_domains": [],  # Domains with new certs (attacker prep signal)
            "details": {},
        }

        for domain in lookalike_domains:
            result = self.search_certificates(domain, days_back)
            results["details"][domain] = result

            if result.get("success") and result.get("recent_count", 0) > 0:
                results["domains_with_certs"] += 1
                results["total_new_certs"] += result["recent_count"]
                results["high_risk_domains"].append({
                    "domain": domain,
                    "cert_count": result["recent_count"],
                    "certificates": result["certificates"][:5],  # Top 5
                    "crt_sh_link": f"https://crt.sh/?q={domain}",
                })

        logger.info(
            f"CT scan complete: {results['domains_with_certs']}/{len(lookalike_domains)} "
            f"domains have new certs"
        )

        return results


# Singleton instance
_monitor: CertTransparencyMonitor | None = None


def get_monitor() -> CertTransparencyMonitor:
    """Get the singleton CertTransparencyMonitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = CertTransparencyMonitor()
    return _monitor


def search_ct_logs(domain: str, days_back: int = 7) -> dict[str, Any]:
    """Convenience function to search CT logs for a domain."""
    return get_monitor().search_certificates(domain, days_back)


def check_lookalike_certs(domains: list[str], days_back: int = 7) -> dict[str, Any]:
    """Convenience function to check lookalike domains for new certs."""
    return get_monitor().check_lookalike_certificates(domains, days_back)


def check_suspicious_domains(domains: list[str], days_back: int = 90) -> dict[str, Any]:
    """Check specific suspicious domains for SSL certificates.

    Use this to verify if domains have active SSL certificates - a signal
    of attacker preparation. Feed this domains from:
    - Threat intel feeds
    - Typosquatting generators (dnstwist)
    - Manual discovery

    Args:
        domains: List of suspicious domain names to check
        days_back: How many days back to search (default 90)

    Returns:
        Dict with domains that have certificates
    """
    return get_monitor().check_suspicious_domains(domains, days_back)


# ============================================================================
# Brand Keyword Monitoring - Discover NEW impersonation domains
# ============================================================================

import json
from pathlib import Path

# Cache directory for seen certificates
_CACHE_DIR = Path(__file__).parent.parent / "data" / "transient" / "ct_brand_monitor"


def _load_seen_certs(brand: str) -> set[int]:
    """Load previously seen certificate IDs for a brand."""
    cache_file = _CACHE_DIR / f"{brand.lower()}_seen_certs.json"
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                data = json.load(f)
                return set(data.get("cert_ids", []))
        except (json.JSONDecodeError, IOError):
            pass
    return set()


def _save_seen_certs(brand: str, cert_ids: set[int]) -> None:
    """Save seen certificate IDs for a brand."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = _CACHE_DIR / f"{brand.lower()}_seen_certs.json"
    try:
        with open(cache_file, "w") as f:
            json.dump({
                "cert_ids": list(cert_ids),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }, f)
    except IOError as e:
        logger.warning(f"Failed to save seen certs cache: {e}")


# Outstanding threats tracking - threats persist until acknowledged
_THREATS_FILE = _CACHE_DIR / "outstanding_threats.json"


def _load_outstanding_threats() -> dict[str, dict]:
    """Load outstanding (unacknowledged) threats."""
    if _THREATS_FILE.exists():
        try:
            with open(_THREATS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_outstanding_threats(threats: dict[str, dict]) -> None:
    """Save outstanding threats."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(_THREATS_FILE, "w") as f:
            json.dump(threats, f, indent=2, default=str)
    except IOError as e:
        logger.warning(f"Failed to save outstanding threats: {e}")


def add_outstanding_threat(domain: str, threat_data: dict) -> None:
    """Add a domain to outstanding threats."""
    threats = _load_outstanding_threats()
    if domain not in threats:
        threat_data["discovered_at"] = datetime.now(timezone.utc).isoformat()
        threat_data["status"] = "new"
    threats[domain] = threat_data
    _save_outstanding_threats(threats)
    logger.info(f"Added outstanding threat: {domain}")


def get_outstanding_threats(brand: str | None = None) -> list[dict]:
    """Get all outstanding threats, optionally filtered by brand.

    Returns list of threat dicts with domain, issuer, discovered_at, etc.
    These persist in daily alerts until acknowledged.
    """
    threats = _load_outstanding_threats()
    result = []
    for domain, data in threats.items():
        if brand is None or data.get("brand", "").lower() == brand.lower():
            result.append({"domain": domain, **data})
    # Sort by discovery date, newest first
    result.sort(key=lambda x: x.get("discovered_at", ""), reverse=True)
    return result


def acknowledge_threat(domain: str) -> bool:
    """Mark a threat as acknowledged/resolved. Removes from outstanding threats.

    Returns True if threat was found and removed, False if not found.
    """
    threats = _load_outstanding_threats()
    if domain in threats:
        del threats[domain]
        _save_outstanding_threats(threats)
        logger.info(f"Acknowledged threat: {domain}")
        return True
    return False


def acknowledge_all_threats(brand: str | None = None) -> int:
    """Acknowledge all outstanding threats, optionally filtered by brand.

    Returns count of threats acknowledged.
    """
    threats = _load_outstanding_threats()
    if brand:
        to_remove = [d for d, data in threats.items()
                     if data.get("brand", "").lower() == brand.lower()]
    else:
        to_remove = list(threats.keys())

    for domain in to_remove:
        del threats[domain]

    _save_outstanding_threats(threats)
    logger.info(f"Acknowledged {len(to_remove)} threats")
    return len(to_remove)


def _is_legitimate_domain(domain: str, legitimate_domains: list[str]) -> bool:
    """Check if domain is legitimate (exact match or subdomain)."""
    domain = domain.lower().lstrip("*.")
    for legit in legitimate_domains:
        legit = legit.lower()
        if domain == legit or domain.endswith(f".{legit}"):
            return True
    return False


def discover_brand_impersonation(
    brand: str,
    legitimate_domains: list[str],
    hours_back: int = 48,
) -> dict[str, Any]:
    """Discover NEW certificates containing brand name via crt.sh.

    This is the FREE alternative to Censys/Shodan for discovering brand
    impersonation domains like "acme-loan.com" or "secure-acme.net".

    How it works:
    1. Searches crt.sh for certificates containing the brand keyword
    2. Filters out legitimate domains
    3. Compares against previously seen certificates
    4. Returns only NEW, never-before-seen suspicious domains

    Run this every 4-6 hours via scheduler for best coverage.

    Args:
        brand: Brand name to search for (e.g., "acme")
        legitimate_domains: List of legitimate domains to exclude
        hours_back: How many hours back to search (default 48)

    Returns:
        Dict with:
        - success: bool
        - new_domains: list of newly discovered suspicious domains
        - total_certs_checked: total certificates examined
        - error: error message if failed
    """
    results = {
        "success": False,
        "brand": brand,
        "new_domains": [],
        "total_certs_checked": 0,
        "scan_time": datetime.now(timezone.utc).isoformat(),
    }

    brand_lower = brand.lower()

    # Load previously seen certificates
    seen_certs = _load_seen_certs(brand)
    initial_seen_count = len(seen_certs)

    # Search crt.sh for certificates containing the brand
    # %25 is URL-encoded %, so %25acme%25 searches for *acme*
    url = f"{CRT_SH_URL}/?q=%25{brand_lower}%25&output=json"

    logger.info(f"Searching crt.sh for brand '{brand}' impersonation")

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Security Research)"})

        response = session.get(url, timeout=60)  # Longer timeout for wildcard search

        if response.status_code != 200:
            # crt.sh often returns empty or errors for broad searches
            # This is expected - fall back gracefully
            if response.status_code == 503:
                results["error"] = "crt.sh is busy - try again later"
            else:
                results["error"] = f"crt.sh returned {response.status_code}"
            logger.warning(results["error"])
            return results

        if not response.text.strip() or response.text.strip() == "[]":
            # Empty result - might be rate limited or no matches
            results["success"] = True
            results["note"] = "No certificates found (may be rate-limited for broad searches)"
            return results

        certs = response.json()
        results["total_certs_checked"] = len(certs)

        # Filter by time
        cutoff_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours_back)

        new_suspicious = {}

        for cert in certs:
            cert_id = cert.get("id")
            if not cert_id:
                continue

            # Skip if we've seen this cert before
            if cert_id in seen_certs:
                continue

            # Check if recent enough
            entry_time_str = cert.get("entry_timestamp", "")
            if entry_time_str:
                try:
                    entry_time = datetime.fromisoformat(
                        entry_time_str.replace("T", " ").split(".")[0]
                    )
                    if entry_time < cutoff_time:
                        # Old cert, but still mark as seen
                        seen_certs.add(cert_id)
                        continue
                except (ValueError, TypeError):
                    pass

            # Extract domain from common_name or name_value
            common_name = cert.get("common_name", "").lower().lstrip("*.")
            name_value = cert.get("name_value", "").lower()

            # Check all names in the certificate
            domains_to_check = [common_name]
            if name_value:
                domains_to_check.extend(
                    n.strip().lstrip("*.") for n in name_value.split("\n") if n.strip()
                )

            for domain in domains_to_check:
                if not domain or brand_lower not in domain:
                    continue

                # Skip legitimate domains
                if _is_legitimate_domain(domain, legitimate_domains):
                    continue

                # Found a suspicious domain!
                if domain not in new_suspicious:
                    threat_info = {
                        "domain": domain,
                        "cert_id": cert_id,
                        "brand": brand,
                        "issuer": cert.get("issuer_name", "Unknown"),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after"),
                        "entry_timestamp": entry_time_str,
                        "crt_sh_link": f"https://crt.sh/?id={cert_id}",
                    }
                    new_suspicious[domain] = threat_info
                    # Add to outstanding threats - persists until acknowledged
                    add_outstanding_threat(domain, threat_info.copy())
                    logger.warning(f"NEW brand impersonation discovered: {domain}")

            # Mark cert as seen
            seen_certs.add(cert_id)

        # Save updated seen certs
        _save_seen_certs(brand, seen_certs)

        results["success"] = True
        results["new_domains"] = list(new_suspicious.values())
        results["new_count"] = len(new_suspicious)
        results["certs_newly_seen"] = len(seen_certs) - initial_seen_count

        if new_suspicious:
            logger.warning(
                f"Brand monitoring found {len(new_suspicious)} NEW suspicious domains for '{brand}'"
            )
        else:
            logger.info(f"Brand monitoring: no new suspicious domains for '{brand}'")

    except requests.exceptions.Timeout:
        results["error"] = "crt.sh request timed out"
        logger.error(results["error"])
    except requests.exceptions.RequestException as e:
        results["error"] = f"Request failed: {e}"
        logger.error(results["error"])
    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Brand monitoring error: {e}")

    return results


def search_brand_certificates(
    brand: str,
    legitimate_domains: list[str],
    watchlist_domains: list[str] | None = None,
    days_back: int = 90,
) -> dict[str, Any]:
    """Check watchlist domains for SSL certificates in CT logs.

    This is the reliable approach - check specific domains you've identified
    through threat intel, phishing reports, or other sources. Doesn't rely
    on pattern generation which is both a maintenance burden and unreliable.

    Args:
        brand: Brand name (for logging/context)
        legitimate_domains: List of legitimate domains to exclude
        watchlist_domains: Specific domains to check (from config watchlist)
        days_back: How many days back to search (default 90)

    Returns:
        Dict with:
        - success: bool
        - domains: list of suspicious domain dicts with certificates
        - domains_checked: number of domains checked
    """
    import time

    results = {
        "success": False,
        "brand": brand,
        "domains": [],
        "domains_checked": 0,
        "scan_time": datetime.now(timezone.utc).isoformat(),
    }

    # Use watchlist domains if provided
    domains_to_check = watchlist_domains or []

    if not domains_to_check:
        results["success"] = True
        results["note"] = "No watchlist domains configured - add suspicious domains to config.json watchlist"
        return results

    # Filter out legitimate domains
    domains_to_check = [d for d in domains_to_check if not _is_legitimate_domain(d, legitimate_domains)]
    results["domains_checked"] = len(domains_to_check)

    logger.info(f"Checking {len(domains_to_check)} watchlist domains for SSL certificates")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Research)"})

    suspicious_domains: dict[str, dict] = {}
    cutoff_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)

    for domain in domains_to_check:
        url = f"{CRT_SH_URL}/?q={domain}&output=json"

        for attempt in range(2):  # 2 retries
            try:
                response = session.get(url, timeout=20)

                if response.status_code == 404:
                    break
                if response.status_code in (502, 503):
                    time.sleep(2)
                    continue
                if response.status_code != 200:
                    break

                if not response.text.strip() or response.text.strip() == "[]":
                    break

                certs = response.json()
                if not certs:
                    break

                # Find the most recent certificate
                for cert in certs:
                    entry_time_str = cert.get("entry_timestamp", "")
                    if entry_time_str:
                        try:
                            entry_time = datetime.fromisoformat(
                                entry_time_str.replace("T", " ").split(".")[0]
                            )
                            if entry_time >= cutoff_time:
                                suspicious_domains[domain] = {
                                    "domain": domain,
                                    "cert_id": cert.get("id"),
                                    "brand": brand,
                                    "issuer": cert.get("issuer_name", "Unknown"),
                                    "not_before": cert.get("not_before"),
                                    "not_after": cert.get("not_after"),
                                    "entry_timestamp": entry_time_str,
                                    "crt_sh_link": f"https://crt.sh/?id={cert.get('id')}",
                                }
                                logger.info(f"Watchlist domain has certificate: {domain}")
                                break
                        except (ValueError, TypeError):
                            # Can't parse date, include it anyway
                            suspicious_domains[domain] = {
                                "domain": domain,
                                "cert_id": cert.get("id"),
                                "brand": brand,
                                "issuer": cert.get("issuer_name", "Unknown"),
                                "not_before": cert.get("not_before"),
                                "not_after": cert.get("not_after"),
                                "entry_timestamp": entry_time_str,
                                "crt_sh_link": f"https://crt.sh/?id={cert.get('id')}",
                            }
                            break
                break

            except requests.exceptions.Timeout:
                logger.debug(f"Timeout checking {domain}")
                time.sleep(1)
            except Exception as e:
                logger.debug(f"Error checking {domain}: {e}")
                break

    results["success"] = True
    results["domains"] = list(suspicious_domains.values())
    results["domain_count"] = len(suspicious_domains)

    logger.info(f"Watchlist check: {len(suspicious_domains)}/{len(domains_to_check)} domains have certificates")

    return results


def run_brand_monitor(
    brands_config: dict[str, list[str]],
    hours_back: int = 48,
) -> dict[str, Any]:
    """Run brand monitoring for multiple brands.

    Args:
        brands_config: Dict mapping brand name to list of legitimate domains
            e.g., {"acme": ["acme.com", "acmebenefits.com"]}
        hours_back: How many hours back to search

    Returns:
        Dict with results for all brands and summary
    """
    results = {
        "success": True,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "brands_checked": len(brands_config),
        "total_new_domains": 0,
        "all_new_domains": [],
        "brand_results": {},
    }

    for brand, legitimate_domains in brands_config.items():
        brand_result = discover_brand_impersonation(
            brand=brand,
            legitimate_domains=legitimate_domains,
            hours_back=hours_back,
        )
        results["brand_results"][brand] = brand_result

        if brand_result.get("success"):
            new_domains = brand_result.get("new_domains", [])
            results["total_new_domains"] += len(new_domains)
            results["all_new_domains"].extend(new_domains)

    return results
