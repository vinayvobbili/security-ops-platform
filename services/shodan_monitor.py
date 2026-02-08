"""Shodan API Client for exposed service monitoring.

Checks for exposed services, open ports, and vulnerabilities on your infrastructure.
Works with free tier (limited to ~100 queries/month) or paid plans.

Free tier usage:
- IP lookups are 1 credit each
- Conservative approach: only check monitored domain IPs, not lookalikes
"""

import logging
import socket
from datetime import UTC, datetime
from typing import Any, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

SHODAN_API_BASE = "https://api.shodan.io"


class ShodanClient:
    """Client for Shodan API."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the Shodan client.

        Args:
            api_key: Shodan API key. If not provided, loads from config.
        """
        if api_key is None:
            config = get_config()
            api_key = getattr(config, 'shodan_api_key', None)

        self.api_key = api_key
        self.session = requests.Session()

    def is_configured(self) -> bool:
        """Check if the client has an API key configured."""
        return bool(self.api_key)

    def _make_request(self, endpoint: str, params: Optional[dict] = None) -> dict[str, Any]:
        """Make request to Shodan API.

        Args:
            endpoint: API endpoint path
            params: Optional query parameters

        Returns:
            dict with response data or error
        """
        if not self.api_key:
            return {"error": "Shodan API key not configured"}

        if params is None:
            params = {}
        params["key"] = self.api_key

        url = f"{SHODAN_API_BASE}/{endpoint}"

        try:
            logger.debug(f"Shodan request: {endpoint}")
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 401:
                return {"error": "Invalid Shodan API key"}
            elif response.status_code == 402:
                return {"error": "Shodan query credits exhausted"}
            elif response.status_code == 404:
                return {"error": "Not found in Shodan"}
            elif response.status_code == 429:
                return {"error": "Shodan rate limit exceeded"}
            else:
                return {"error": f"Shodan API error: {response.status_code}"}

        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Shodan request failed: {e}")
            return {"error": str(e)}

    def get_api_info(self) -> dict[str, Any]:
        """Get API plan information and remaining credits.

        Returns:
            dict with plan info and query/scan credits remaining
        """
        result = self._make_request("api-info")

        if result.get("error"):
            return {"success": False, "error": result["error"]}

        data = result.get("data", {})
        return {
            "success": True,
            "plan": data.get("plan", "unknown"),
            "query_credits": data.get("query_credits", 0),
            "scan_credits": data.get("scan_credits", 0),
        }

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Look up information about an IP address.

        Args:
            ip: IP address to look up

        Returns:
            dict with host information
        """
        logger.info(f"Shodan lookup for IP: {ip}")
        result = self._make_request(f"shodan/host/{ip}")

        if result.get("error"):
            return {"success": False, "ip": ip, "error": result["error"]}

        data = result.get("data", {})

        # Extract key information
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        services = []

        for item in data.get("data", []):
            service = {
                "port": item.get("port"),
                "protocol": item.get("transport", "tcp"),
                "product": item.get("product"),
                "version": item.get("version"),
                "module": item.get("_shodan", {}).get("module"),
            }
            # Check for SSL
            if item.get("ssl"):
                service["ssl"] = True
                service["ssl_cert"] = item.get("ssl", {}).get("cert", {}).get("subject", {})

            services.append(service)

        return {
            "success": True,
            "ip": ip,
            "hostnames": data.get("hostnames", []),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "ports": ports,
            "vulns": vulns,
            "services": services,
            "last_update": data.get("last_update"),
        }

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Look up a domain's infrastructure in Shodan.

        Resolves the domain to IPs and looks up each one.
        Conservative approach for free tier - only checks primary IPs.

        Args:
            domain: Domain to look up

        Returns:
            dict with infrastructure information
        """
        logger.info(f"Shodan lookup for domain: {domain}")

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
            "total_ports": 0,
            "total_vulns": 0,
            "exposed_services": [],
            "vulnerabilities": [],
            "hosts": [],
        }

        # Limit to first 3 IPs to conserve credits on free tier
        for ip in ips[:3]:
            ip_result = self.lookup_ip(ip)
            results["ips_checked"] += 1

            if not ip_result.get("success"):
                results["hosts"].append({
                    "ip": ip,
                    "error": ip_result.get("error"),
                })
                continue

            results["hosts"].append(ip_result)
            results["total_ports"] += len(ip_result.get("ports", []))

            # Collect vulnerabilities
            for vuln in ip_result.get("vulns", []):
                results["total_vulns"] += 1
                results["vulnerabilities"].append({
                    "ip": ip,
                    "cve": vuln,
                })

            # Identify potentially risky exposed services
            for svc in ip_result.get("services", []):
                port = svc.get("port")
                product = svc.get("product", "")
                module = svc.get("module", "")

                # Flag risky services
                risky = False
                risk_reason = None

                if port in [21, 23, 3389, 5900]:  # FTP, Telnet, RDP, VNC
                    risky = True
                    risk_reason = "Remote access service exposed"
                elif port in [1433, 3306, 5432, 27017, 6379]:  # Databases
                    risky = True
                    risk_reason = "Database port exposed"
                elif port == 22 and not domain.endswith(".internal"):
                    # SSH is often intentional, flag but lower priority
                    pass
                elif "admin" in str(product).lower() or "management" in str(module).lower():
                    risky = True
                    risk_reason = "Admin/management interface exposed"

                if risky:
                    results["exposed_services"].append({
                        "ip": ip,
                        "port": port,
                        "product": product,
                        "risk_reason": risk_reason,
                    })

        return results

    def check_credits(self) -> int:
        """Check remaining query credits.

        Returns:
            Number of remaining query credits, or -1 if error
        """
        info = self.get_api_info()
        if info.get("success"):
            return info.get("query_credits", 0)
        return -1


# Singleton instance
_client: Optional[ShodanClient] = None


def get_client() -> ShodanClient:
    """Get the singleton ShodanClient instance."""
    global _client
    if _client is None:
        _client = ShodanClient()
    return _client


def lookup_domain_infrastructure(domain: str) -> dict[str, Any]:
    """Convenience function to look up a domain's infrastructure."""
    return get_client().lookup_domain(domain)


def lookup_ip(ip: str) -> dict[str, Any]:
    """Convenience function to look up an IP address."""
    return get_client().lookup_ip(ip)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = ShodanClient()

    if not client.is_configured():
        print("ERROR: SHODAN_API_KEY not configured")
        print("Get a free API key at: https://account.shodan.io/")
        print("Add SHODAN_API_KEY to your .env or .secrets.age file")
        sys.exit(1)

    print("Shodan Client Test")
    print("=" * 50)

    # Check credits
    info = client.get_api_info()
    if info.get("success"):
        print(f"Plan: {info['plan']}")
        print(f"Query credits: {info['query_credits']}")
        print(f"Scan credits: {info['scan_credits']}")
    else:
        print(f"Error: {info.get('error')}")

    # Test IP lookup (Google DNS)
    print("\nTesting IP lookup (8.8.8.8)...")
    result = client.lookup_ip("8.8.8.8")
    if result.get("success"):
        print(f"  Org: {result.get('org')}")
        print(f"  Ports: {result.get('ports')}")
    else:
        print(f"  Error: {result.get('error')}")

    print("\n" + "=" * 50)
    print("Test complete!")
