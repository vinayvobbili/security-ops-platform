"""AbuseIPDB Integration for IP Reputation Checking.

Checks IP addresses against AbuseIPDB's community-driven database of
reported malicious IPs (spam, hacking, DDoS, brute force, etc.).

Free tier: 1,000 checks per day.
Get API key at: https://www.abuseipdb.com/account/api
"""

import logging
import socket
from datetime import UTC, datetime
from typing import Any, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
TIMEOUT = 30


class AbuseIPDBClient:
    """Client for AbuseIPDB API."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key. If not provided, loads from config.
        """
        if api_key is None:
            config = get_config()
            api_key = getattr(config, 'abuseipdb_api_key', None)

        self.api_key = api_key
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "Key": self.api_key,
                "Accept": "application/json",
            })

    def is_configured(self) -> bool:
        """Check if the client has an API key configured."""
        return bool(self.api_key)

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict[str, Any]:
        """Check an IP address against AbuseIPDB.

        Args:
            ip: IP address to check
            max_age_days: Only consider reports from the last N days (default 90)

        Returns:
            dict with IP reputation data
        """
        if not self.api_key:
            return {"success": False, "ip": ip, "error": "API key not configured"}

        ip = ip.strip()
        logger.debug(f"Checking AbuseIPDB for IP: {ip}")

        try:
            response = self.session.get(
                f"{ABUSEIPDB_API}/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True,
                },
                timeout=TIMEOUT
            )

            if response.status_code == 401:
                return {"success": False, "ip": ip, "error": "Invalid API key"}
            elif response.status_code == 429:
                return {"success": False, "ip": ip, "error": "Rate limit exceeded"}
            elif response.status_code != 200:
                return {"success": False, "ip": ip, "error": f"HTTP {response.status_code}"}

            data = response.json().get("data", {})

            return {
                "success": True,
                "ip": ip,
                "is_public": data.get("isPublic", True),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "reports": [
                    {
                        "reported_at": r.get("reportedAt"),
                        "categories": r.get("categories", []),
                        "comment": r.get("comment", "")[:200] if r.get("comment") else None,
                    }
                    for r in data.get("reports", [])[:10]  # Limit to 10 reports
                ],
                "abuseipdb_link": f"https://www.abuseipdb.com/check/{ip}",
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB request failed: {e}")
            return {"success": False, "ip": ip, "error": str(e)}

    def check_domain(self, domain: str, max_age_days: int = 90) -> dict[str, Any]:
        """Check a domain's IPs against AbuseIPDB.

        Resolves the domain to IPs and checks each one.

        Args:
            domain: Domain to check
            max_age_days: Only consider reports from the last N days

        Returns:
            dict with reputation data for all IPs
        """
        if not self.api_key:
            return {"success": False, "domain": domain, "error": "API key not configured"}

        domain = domain.strip().lower()
        logger.info(f"Checking AbuseIPDB for domain: {domain}")

        # Resolve domain to IPs
        try:
            ips = socket.gethostbyname_ex(domain)[2]
        except socket.gaierror as e:
            return {
                "success": False,
                "domain": domain,
                "error": f"DNS resolution failed: {e}",
            }

        if not ips:
            return {
                "success": False,
                "domain": domain,
                "error": "No IP addresses found",
            }

        results = {
            "success": True,
            "domain": domain,
            "scan_time": datetime.now(UTC).isoformat(),
            "ips_checked": 0,
            "malicious_ips": [],
            "clean_ips": [],
            "total_abuse_score": 0,
            "max_abuse_score": 0,
            "ip_details": [],
        }

        # Check each IP (limit to 5 to conserve API calls)
        for ip in ips[:5]:
            ip_result = self.check_ip(ip, max_age_days)
            results["ips_checked"] += 1

            if not ip_result.get("success"):
                results["ip_details"].append({
                    "ip": ip,
                    "error": ip_result.get("error"),
                })
                continue

            results["ip_details"].append(ip_result)

            abuse_score = ip_result.get("abuse_confidence_score", 0)
            results["total_abuse_score"] += abuse_score
            results["max_abuse_score"] = max(results["max_abuse_score"], abuse_score)

            # Consider IP malicious if abuse score >= 25
            if abuse_score >= 25:
                results["malicious_ips"].append({
                    "ip": ip,
                    "abuse_score": abuse_score,
                    "total_reports": ip_result.get("total_reports", 0),
                    "isp": ip_result.get("isp"),
                    "country": ip_result.get("country_code"),
                    "last_reported": ip_result.get("last_reported_at"),
                    "link": ip_result.get("abuseipdb_link"),
                })
            else:
                results["clean_ips"].append(ip)

        return results

    def bulk_check_domains(self, domains: list) -> dict[str, Any]:
        """Check multiple domains against AbuseIPDB.

        Args:
            domains: List of domains to check (can be strings or dicts with 'domain' key)

        Returns:
            dict with results for all domains
        """
        if not self.api_key:
            return {"success": False, "error": "API key not configured"}

        results = {
            "success": True,
            "scan_time": datetime.now(UTC).isoformat(),
            "domains_checked": 0,
            "domains_with_malicious_ips": [],
            "clean_domains": [],
            "errors": [],
            "details": {},
        }

        for domain in domains:
            # Handle both string and dict inputs
            if isinstance(domain, dict):
                domain = domain.get("domain", "")
            if not domain:
                continue

            result = self.check_domain(domain)
            results["domains_checked"] += 1
            results["details"][domain] = result

            if not result.get("success"):
                results["errors"].append({
                    "domain": domain,
                    "error": result.get("error"),
                })
                continue

            if result.get("malicious_ips"):
                results["domains_with_malicious_ips"].append({
                    "domain": domain,
                    "malicious_ips": result.get("malicious_ips", []),
                    "max_abuse_score": result.get("max_abuse_score", 0),
                })
            else:
                results["clean_domains"].append(domain)

        logger.info(
            f"AbuseIPDB bulk check: {results['domains_checked']} domains, "
            f"{len(results['domains_with_malicious_ips'])} with malicious IPs"
        )

        return results


# Singleton instance
_client: Optional[AbuseIPDBClient] = None


def get_client() -> AbuseIPDBClient:
    """Get the singleton AbuseIPDBClient instance."""
    global _client
    if _client is None:
        _client = AbuseIPDBClient()
    return _client


def check_ip(ip: str) -> dict[str, Any]:
    """Convenience function to check an IP address."""
    return get_client().check_ip(ip)


def check_domain(domain: str) -> dict[str, Any]:
    """Convenience function to check a domain."""
    return get_client().check_domain(domain)


def bulk_check_domains(domains: list) -> dict[str, Any]:
    """Convenience function to check multiple domains."""
    return get_client().bulk_check_domains(domains)


# Abuse category codes from AbuseIPDB
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def get_category_names(category_ids: list[int]) -> list[str]:
    """Convert category IDs to human-readable names."""
    return [ABUSE_CATEGORIES.get(c, f"Unknown ({c})") for c in category_ids]


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = AbuseIPDBClient()

    if not client.is_configured():
        print("ERROR: ABUSEIPDB_API_KEY not configured")
        print("Get a free API key at: https://www.abuseipdb.com/account/api")
        print("Add ABUSEIPDB_API_KEY to your .env or .secrets.age file")
        sys.exit(1)

    print("AbuseIPDB Client Test")
    print("=" * 50)

    # Test with a known bad IP (if you have one) or a test IP
    print("\nTesting IP check (8.8.8.8 - Google DNS)...")
    result = client.check_ip("8.8.8.8")
    if result.get("success"):
        print(f"  Abuse Score: {result.get('abuse_confidence_score')}")
        print(f"  Total Reports: {result.get('total_reports')}")
        print(f"  ISP: {result.get('isp')}")
    else:
        print(f"  Error: {result.get('error')}")

    print("\n" + "=" * 50)
    print("Test complete!")
