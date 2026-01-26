"""abuse.ch Integration for Threat Intelligence.

Provides free threat intelligence from abuse.ch feeds:
- URLhaus: Malicious URLs used for malware distribution
- ThreatFox: IOCs (domains, IPs, hashes) associated with malware
- Feodo Tracker: Botnet C2 servers (Emotet, Dridex, TrickBot, QakBot)

No API key required - completely free.
"""

import logging
from datetime import datetime
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# API endpoints
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1"
FEODO_TRACKER_API = "https://feodotracker.abuse.ch/downloads"

TIMEOUT = 30


class AbuseCHClient:
    """Client for abuse.ch threat intelligence APIs."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "IR-Domain-Monitoring/1.0",
        })
        # Cache for Feodo C2 list (refreshed daily)
        self._feodo_c2_cache: Optional[dict] = None
        self._feodo_cache_time: Optional[datetime] = None

    def check_domain_urlhaus(self, domain: str) -> dict[str, Any]:
        """Check if a domain is in URLhaus (malware distribution).

        Args:
            domain: Domain to check

        Returns:
            dict with URLhaus results
        """
        domain = domain.strip().lower()
        logger.debug(f"Checking URLhaus for domain: {domain}")

        try:
            response = self.session.post(
                f"{URLHAUS_API}/host/",
                data={"host": domain},
                timeout=TIMEOUT
            )

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}"}

            data = response.json()
            query_status = data.get("query_status")

            if query_status == "no_results":
                return {
                    "success": True,
                    "domain": domain,
                    "found": False,
                    "url_count": 0,
                    "urls": [],
                }

            if query_status == "ok":
                urls = data.get("urls", [])
                return {
                    "success": True,
                    "domain": domain,
                    "found": True,
                    "url_count": len(urls),
                    "blacklists": data.get("blacklists", {}),
                    "urls": [
                        {
                            "url": u.get("url"),
                            "url_status": u.get("url_status"),
                            "threat": u.get("threat"),
                            "tags": u.get("tags", []),
                            "date_added": u.get("date_added"),
                        }
                        for u in urls[:20]  # Limit to 20
                    ],
                    "urlhaus_link": f"https://urlhaus.abuse.ch/host/{domain}/",
                }

            return {"success": False, "error": f"Unexpected status: {query_status}"}

        except requests.exceptions.RequestException as e:
            logger.error(f"URLhaus request failed: {e}")
            return {"success": False, "error": str(e)}

    def check_domain_threatfox(self, domain: str) -> dict[str, Any]:
        """Check if a domain is in ThreatFox (malware IOCs).

        Args:
            domain: Domain to check

        Returns:
            dict with ThreatFox results
        """
        domain = domain.strip().lower()
        logger.debug(f"Checking ThreatFox for domain: {domain}")

        try:
            response = self.session.post(
                THREATFOX_API,
                json={"query": "search_ioc", "search_term": domain},
                timeout=TIMEOUT
            )

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}"}

            data = response.json()
            query_status = data.get("query_status")

            if query_status == "no_result":
                return {
                    "success": True,
                    "domain": domain,
                    "found": False,
                    "ioc_count": 0,
                    "iocs": [],
                }

            if query_status == "ok":
                iocs = data.get("data", [])
                return {
                    "success": True,
                    "domain": domain,
                    "found": True,
                    "ioc_count": len(iocs),
                    "iocs": [
                        {
                            "ioc": i.get("ioc"),
                            "ioc_type": i.get("ioc_type"),
                            "threat_type": i.get("threat_type"),
                            "malware": i.get("malware"),
                            "malware_printable": i.get("malware_printable"),
                            "confidence_level": i.get("confidence_level"),
                            "first_seen": i.get("first_seen_utc"),
                            "tags": i.get("tags", []),
                        }
                        for i in iocs[:20]  # Limit to 20
                    ],
                    "threatfox_link": f"https://threatfox.abuse.ch/browse.php?search=ioc:{domain}",
                }

            return {"success": False, "error": f"Unexpected status: {query_status}"}

        except requests.exceptions.RequestException as e:
            logger.error(f"ThreatFox request failed: {e}")
            return {"success": False, "error": str(e)}

    def check_ip_threatfox(self, ip: str) -> dict[str, Any]:
        """Check if an IP is in ThreatFox.

        Args:
            ip: IP address to check

        Returns:
            dict with ThreatFox results
        """
        ip = ip.strip()
        logger.debug(f"Checking ThreatFox for IP: {ip}")

        try:
            response = self.session.post(
                THREATFOX_API,
                json={"query": "search_ioc", "search_term": ip},
                timeout=TIMEOUT
            )

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}"}

            data = response.json()
            query_status = data.get("query_status")

            if query_status == "no_result":
                return {
                    "success": True,
                    "ip": ip,
                    "found": False,
                    "ioc_count": 0,
                }

            if query_status == "ok":
                iocs = data.get("data", [])
                return {
                    "success": True,
                    "ip": ip,
                    "found": True,
                    "ioc_count": len(iocs),
                    "iocs": [
                        {
                            "ioc": i.get("ioc"),
                            "threat_type": i.get("threat_type"),
                            "malware": i.get("malware_printable"),
                            "confidence_level": i.get("confidence_level"),
                            "first_seen": i.get("first_seen_utc"),
                        }
                        for i in iocs[:10]
                    ],
                }

            return {"success": False, "error": f"Unexpected status: {query_status}"}

        except requests.exceptions.RequestException as e:
            logger.error(f"ThreatFox IP request failed: {e}")
            return {"success": False, "error": str(e)}

    def _load_feodo_c2_list(self) -> dict[str, Any]:
        """Load Feodo Tracker C2 IP list (cached for 24h)."""
        now = datetime.utcnow()

        # Use cache if fresh (less than 24 hours old)
        if self._feodo_c2_cache and self._feodo_cache_time:
            age_hours = (now - self._feodo_cache_time).total_seconds() / 3600
            if age_hours < 24:
                return self._feodo_c2_cache

        try:
            response = self.session.get(
                f"{FEODO_TRACKER_API}/ipblocklist.json",
                timeout=TIMEOUT
            )

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}"}

            data = response.json()
            c2_ips = {entry.get("ip_address"): entry for entry in data if entry.get("ip_address")}

            self._feodo_c2_cache = {
                "success": True,
                "c2_ips": c2_ips,
                "total_count": len(c2_ips),
                "loaded_at": now.isoformat(),
            }
            self._feodo_cache_time = now

            logger.info(f"Loaded {len(c2_ips)} Feodo C2 IPs")
            return self._feodo_c2_cache

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to load Feodo C2 list: {e}")
            return {"success": False, "error": str(e)}

    def check_ip_feodo(self, ip: str) -> dict[str, Any]:
        """Check if an IP is a known botnet C2 server.

        Checks against Feodo Tracker (Emotet, Dridex, TrickBot, QakBot, etc.)

        Args:
            ip: IP address to check

        Returns:
            dict with Feodo Tracker results
        """
        ip = ip.strip()

        feodo_data = self._load_feodo_c2_list()
        if not feodo_data.get("success"):
            return {"success": False, "ip": ip, "error": feodo_data.get("error")}

        c2_ips = feodo_data.get("c2_ips", {})

        if ip in c2_ips:
            entry = c2_ips[ip]
            return {
                "success": True,
                "ip": ip,
                "is_c2": True,
                "malware": entry.get("malware"),
                "port": entry.get("port"),
                "status": entry.get("status"),
                "first_seen": entry.get("first_seen"),
                "last_online": entry.get("last_online"),
                "feodo_link": f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            }

        return {
            "success": True,
            "ip": ip,
            "is_c2": False,
        }

    def check_domain_all(self, domain: str) -> dict[str, Any]:
        """Check a domain against all abuse.ch sources.

        Args:
            domain: Domain to check

        Returns:
            dict with combined results from all sources
        """
        domain = domain.strip().lower()
        logger.info(f"Checking abuse.ch for domain: {domain}")

        results = {
            "success": True,
            "domain": domain,
            "scan_time": datetime.utcnow().isoformat(),
            "is_malicious": False,
            "threat_types": [],
            "sources": {},
        }

        # Check URLhaus
        urlhaus = self.check_domain_urlhaus(domain)
        results["sources"]["urlhaus"] = urlhaus
        if urlhaus.get("found"):
            results["is_malicious"] = True
            results["threat_types"].append("malware_distribution")

        # Check ThreatFox
        threatfox = self.check_domain_threatfox(domain)
        results["sources"]["threatfox"] = threatfox
        if threatfox.get("found"):
            results["is_malicious"] = True
            # Extract malware types
            for ioc in threatfox.get("iocs", []):
                malware = ioc.get("malware")
                if malware and malware not in results["threat_types"]:
                    results["threat_types"].append(malware)

        return results

    def check_ip_all(self, ip: str) -> dict[str, Any]:
        """Check an IP against all abuse.ch sources.

        Args:
            ip: IP address to check

        Returns:
            dict with combined results from all sources
        """
        ip = ip.strip()
        logger.info(f"Checking abuse.ch for IP: {ip}")

        results = {
            "success": True,
            "ip": ip,
            "scan_time": datetime.utcnow().isoformat(),
            "is_malicious": False,
            "is_c2": False,
            "threat_types": [],
            "sources": {},
        }

        # Check ThreatFox
        threatfox = self.check_ip_threatfox(ip)
        results["sources"]["threatfox"] = threatfox
        if threatfox.get("found"):
            results["is_malicious"] = True

        # Check Feodo C2
        feodo = self.check_ip_feodo(ip)
        results["sources"]["feodo"] = feodo
        if feodo.get("is_c2"):
            results["is_malicious"] = True
            results["is_c2"] = True
            malware = feodo.get("malware")
            if malware:
                results["threat_types"].append(f"C2:{malware}")

        return results

    def bulk_check_domains(self, domains: list[str]) -> dict[str, Any]:
        """Check multiple domains against abuse.ch.

        Args:
            domains: List of domains to check

        Returns:
            dict with results for all domains
        """
        results = {
            "success": True,
            "scan_time": datetime.utcnow().isoformat(),
            "domains_checked": 0,
            "malicious_domains": [],
            "clean_domains": [],
            "errors": [],
            "details": {},
        }

        for domain in domains:
            if isinstance(domain, dict):
                domain = domain.get("domain", "")
            if not domain:
                continue

            result = self.check_domain_all(domain)
            results["domains_checked"] += 1
            results["details"][domain] = result

            if result.get("is_malicious"):
                results["malicious_domains"].append({
                    "domain": domain,
                    "threat_types": result.get("threat_types", []),
                    "urlhaus": result["sources"].get("urlhaus", {}),
                    "threatfox": result["sources"].get("threatfox", {}),
                })
            else:
                results["clean_domains"].append(domain)

        logger.info(
            f"abuse.ch bulk check: {results['domains_checked']} domains, "
            f"{len(results['malicious_domains'])} malicious"
        )

        return results


# Singleton instance
_client: Optional[AbuseCHClient] = None


def get_client() -> AbuseCHClient:
    """Get the singleton AbuseCHClient instance."""
    global _client
    if _client is None:
        _client = AbuseCHClient()
    return _client


def check_domain(domain: str) -> dict[str, Any]:
    """Convenience function to check a domain against abuse.ch."""
    return get_client().check_domain_all(domain)


def check_ip(ip: str) -> dict[str, Any]:
    """Convenience function to check an IP against abuse.ch."""
    return get_client().check_ip_all(ip)


def bulk_check_domains(domains: list[str]) -> dict[str, Any]:
    """Convenience function to check multiple domains."""
    return get_client().bulk_check_domains(domains)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = AbuseCHClient()

    print("abuse.ch Client Test")
    print("=" * 50)

    # Test URLhaus with a known malicious domain (if any)
    print("\n1. Testing URLhaus domain check...")
    result = client.check_domain_urlhaus("example.com")
    print(f"   Found: {result.get('found', False)}")
    print(f"   URL count: {result.get('url_count', 0)}")

    # Test ThreatFox
    print("\n2. Testing ThreatFox domain check...")
    result = client.check_domain_threatfox("example.com")
    print(f"   Found: {result.get('found', False)}")
    print(f"   IOC count: {result.get('ioc_count', 0)}")

    # Test Feodo C2 list loading
    print("\n3. Testing Feodo C2 list...")
    feodo_data = client._load_feodo_c2_list()
    if feodo_data.get("success"):
        print(f"   Loaded {feodo_data.get('total_count', 0)} C2 IPs")
    else:
        print(f"   Error: {feodo_data.get('error')}")

    # Test combined check
    print("\n4. Testing combined domain check...")
    result = client.check_domain_all("example.com")
    print(f"   Is malicious: {result.get('is_malicious', False)}")
    print(f"   Threat types: {result.get('threat_types', [])}")

    print("\n" + "=" * 50)
    print("Test complete!")
