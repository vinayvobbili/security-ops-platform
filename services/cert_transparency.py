"""Certificate Transparency Monitoring Service.

Monitors Certificate Transparency logs for new SSL certificates issued for
monitored domains and their lookalikes. New certificates for lookalike domains
are a strong indicator of attacker preparation for phishing/impersonation.

Uses crt.sh (free) to query CT logs.
"""

import logging
from datetime import datetime, timedelta
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
                    "scan_time": datetime.utcnow().isoformat(),
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
                    "scan_time": datetime.utcnow().isoformat(),
                }

            certs = response.json()

            # Filter for recent certificates
            cutoff_date = datetime.utcnow() - timedelta(days=days_back)
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
                "scan_time": datetime.utcnow().isoformat(),
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
            "scan_time": datetime.utcnow().isoformat(),
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
