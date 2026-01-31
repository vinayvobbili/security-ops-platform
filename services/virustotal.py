"""
VirusTotal API Client

Provides integration with VirusTotal API v3 for threat intelligence lookups.
Supports IP addresses, domains, URLs, and file hashes.
"""

import base64
import logging
from typing import Optional, Dict, Any

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

VT_API_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    """Client for interacting with the VirusTotal API v3."""

    def __init__(self):
        self.config = get_config()
        self.api_key = self.config.virustotal_api_key
        self.base_url = VT_API_BASE_URL
        self.timeout = 30

        if not self.api_key:
            logger.warning("VirusTotal API key not configured")

    def is_configured(self) -> bool:
        """Check if the client is properly configured with an API key."""
        return bool(self.api_key)

    def _make_request(self, endpoint: str, method: str = "GET") -> Dict[str, Any]:
        """Make authenticated request to VirusTotal API.

        Args:
            endpoint: API endpoint path
            method: HTTP method (GET or POST)
        """
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}

        headers = {"x-apikey": self.api_key}
        url = f"{self.base_url}/{endpoint}"

        try:
            logger.debug(f"Making VT {method} request to: {endpoint}")
            if method == "POST":
                response = requests.post(url, headers=headers, timeout=self.timeout)
            else:
                response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 404:
                return {"error": "Not found in VirusTotal database"}
            elif status_code == 401:
                return {"error": "Invalid VirusTotal API key"}
            elif status_code == 429:
                return {"error": "VirusTotal API rate limit exceeded (4 req/min for free tier)"}
            else:
                logger.error(f"VirusTotal API error: {status_code}")
                return {"error": f"VirusTotal API error: {status_code}"}

        except requests.exceptions.Timeout:
            logger.error("VirusTotal API request timed out")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """Look up an IP address in VirusTotal.

        Args:
            ip_address: The IP address to look up (e.g., "8.8.8.8")

        Returns:
            dict: VirusTotal API response or error dict
        """
        ip_address = ip_address.strip()
        logger.info(f"Looking up IP in VirusTotal: {ip_address}")
        return self._make_request(f"ip_addresses/{ip_address}")

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up a domain in VirusTotal.

        Args:
            domain: The domain to look up (e.g., "example.com")

        Returns:
            dict: VirusTotal API response or error dict
        """
        # Clean the domain - remove protocol and path if provided
        domain = domain.strip().lower()
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]

        logger.info(f"Looking up domain in VirusTotal: {domain}")
        return self._make_request(f"domains/{domain}")

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Look up a URL in VirusTotal.

        Args:
            url: The full URL to look up (e.g., "https://example.com/page")

        Returns:
            dict: VirusTotal API response or error dict
        """
        url = url.strip()
        logger.info(f"Looking up URL in VirusTotal: {url}")

        # VirusTotal requires URL ID to be base64 encoded (without padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._make_request(f"urls/{url_id}")

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up a file hash in VirusTotal.

        Args:
            file_hash: The file hash to look up (MD5, SHA1, or SHA256)

        Returns:
            dict: VirusTotal API response or error dict
        """
        file_hash = file_hash.strip().lower()
        logger.info(f"Looking up file hash in VirusTotal: {file_hash}")
        return self._make_request(f"files/{file_hash}")

    def reanalyze_domain(self, domain: str) -> Dict[str, Any]:
        """Request re-analysis of a domain.

        Args:
            domain: The domain to reanalyze

        Returns:
            dict: Analysis submission response or error dict
        """
        domain = domain.strip().lower()
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]

        logger.info(f"Requesting reanalysis of domain: {domain}")
        return self._make_request(f"domains/{domain}/analyse", method="POST")

    def reanalyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Request re-analysis of an IP address.

        Args:
            ip_address: The IP address to reanalyze

        Returns:
            dict: Analysis submission response or error dict
        """
        ip_address = ip_address.strip()
        logger.info(f"Requesting reanalysis of IP: {ip_address}")
        return self._make_request(f"ip_addresses/{ip_address}/analyse", method="POST")

    def reanalyze_url(self, url: str) -> Dict[str, Any]:
        """Request re-analysis of a URL.

        Args:
            url: The URL to reanalyze

        Returns:
            dict: Analysis submission response or error dict
        """
        url = url.strip()
        logger.info(f"Requesting reanalysis of URL: {url}")

        # VirusTotal requires URL ID to be base64 encoded (without padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._make_request(f"urls/{url_id}/analyse", method="POST")

    def reanalyze_hash(self, file_hash: str) -> Dict[str, Any]:
        """Request re-analysis of a file hash.

        Args:
            file_hash: The file hash to reanalyze (MD5, SHA1, or SHA256)

        Returns:
            dict: Analysis submission response or error dict
        """
        file_hash = file_hash.strip().lower()
        logger.info(f"Requesting reanalysis of hash: {file_hash}")
        return self._make_request(f"files/{file_hash}/analyse", method="POST")

    def get_analysis(self, analysis_id: str) -> Dict[str, Any]:
        """Get full analysis results including stats.

        Args:
            analysis_id: The analysis ID returned from a reanalyze request

        Returns:
            dict: Full analysis response with status and stats
        """
        return self._make_request(f"analyses/{analysis_id}")

    def get_analysis_status(self, analysis_id: str) -> Dict[str, Any]:
        """Get the status of an analysis (alias for get_analysis).

        Args:
            analysis_id: The analysis ID returned from a reanalyze request

        Returns:
            dict: Analysis status with 'status' field (queued, in-progress, completed)
        """
        return self.get_analysis(analysis_id)

    def wait_for_analysis(self, analysis_id: str, timeout: int = 60, poll_interval: int = 5) -> Optional[Dict[str, Any]]:
        """Poll analysis status until completed or timeout.

        Args:
            analysis_id: The analysis ID to poll
            timeout: Maximum seconds to wait (default 60)
            poll_interval: Seconds between polls (default 5)

        Returns:
            dict: The completed analysis result with stats, or None if timeout/error
        """
        import time
        elapsed = 0

        while elapsed < timeout:
            result = self.get_analysis(analysis_id)

            if "error" in result:
                logger.warning(f"Error polling analysis: {result['error']}")
                return None

            status = result.get("data", {}).get("attributes", {}).get("status", "")
            logger.debug(f"Analysis status: {status} (elapsed: {elapsed}s)")

            if status == "completed":
                logger.info(f"Analysis {analysis_id} completed after {elapsed}s")
                return result

            time.sleep(poll_interval)
            elapsed += poll_interval

        logger.warning(f"Analysis timed out after {timeout}s")
        return None

    @staticmethod
    def format_analysis_stats(stats: Dict[str, int]) -> str:
        """Format analysis stats into readable summary.

        Args:
            stats: Dict with keys like 'malicious', 'suspicious', 'harmless', 'undetected'

        Returns:
            str: Formatted summary string
        """
        if not stats:
            return "No analysis stats available"

        parts = []
        if stats.get("malicious", 0) > 0:
            parts.append(f"**{stats['malicious']} malicious**")
        if stats.get("suspicious", 0) > 0:
            parts.append(f"{stats['suspicious']} suspicious")
        if stats.get("harmless", 0) > 0:
            parts.append(f"{stats['harmless']} harmless")
        if stats.get("undetected", 0) > 0:
            parts.append(f"{stats['undetected']} undetected")

        total = sum(stats.values())
        return f"{', '.join(parts)} (total: {total} engines)"

    @staticmethod
    def get_threat_level(stats: Dict[str, int], is_file: bool = False) -> str:
        """Determine threat level based on detection stats.

        Args:
            stats: Dict with detection counts
            is_file: True if this is a file hash lookup (stricter thresholds)

        Returns:
            str: Threat level string
        """
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if is_file:
            if malicious > 10:
                return "MALWARE DETECTED"
            elif malicious > 0:
                return "HIGH RISK"
            elif suspicious > 3:
                return "SUSPICIOUS"
        else:
            if malicious > 5:
                return "HIGH RISK"
            elif malicious > 0 or suspicious > 3:
                return "SUSPICIOUS"

        return "CLEAN"

    def bulk_domain_lookup(self, domains: list, include_clean: bool = False) -> Dict[str, Any]:
        """Look up multiple domains in VirusTotal.

        Args:
            domains: List of domain names or dicts with 'domain' key
            include_clean: Whether to include clean domains in results

        Returns:
            dict: Summary with all domain results
        """
        from datetime import datetime

        results = {
            "success": True,
            "scan_time": datetime.utcnow().isoformat(),
            "domains_checked": 0,
            "high_risk": [],
            "medium_risk": [],
            "low_risk": [],
            "clean": [],
            "errors": [],
            "details": {},
        }

        for item in domains:
            # Handle both string domains and dicts with 'domain' key
            if isinstance(item, dict):
                domain = item.get("domain", "")
            else:
                domain = str(item)

            if not domain:
                continue

            results["domains_checked"] += 1

            try:
                data = self.lookup_domain(domain)

                if "error" in data:
                    results["errors"].append({
                        "domain": domain,
                        "error": data["error"],
                    })
                    results["details"][domain] = {"error": data["error"]}
                    continue

                # Extract reputation data
                attrs = data.get("data", {}).get("attributes", {})
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

                domain_result = {
                    "domain": domain,
                    "threat_level": threat_level,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "categories": attrs.get("categories", {}),
                    "registrar": attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date"),
                    "reputation": attrs.get("reputation", 0),
                    "vt_link": f"https://www.virustotal.com/gui/domain/{domain}",
                }

                results["details"][domain] = domain_result

                # Categorize by risk
                if threat_level == "HIGH":
                    results["high_risk"].append(domain_result)
                elif threat_level == "MEDIUM":
                    results["medium_risk"].append(domain_result)
                elif threat_level == "LOW":
                    results["low_risk"].append(domain_result)
                elif include_clean:
                    results["clean"].append(domain_result)

            except Exception as e:
                logger.error(f"VT bulk lookup error for {domain}: {e}")
                results["errors"].append({
                    "domain": domain,
                    "error": str(e),
                })

        logger.info(
            f"VT bulk scan complete: {results['domains_checked']} domains, "
            f"{len(results['high_risk'])} high risk, {len(results['medium_risk'])} medium risk"
        )

        return results

    def is_ioc_huntworthy(self, ioc: str, ioc_type: str = "domain") -> bool:
        """Check if an IOC has any malicious/suspicious detections on VT.

        Use this to filter out benign domains/IPs that appear in tippers as
        references (e.g., security vendor sites, news sites).

        Args:
            ioc: The IOC value (domain, IP, or hash)
            ioc_type: Type of IOC - "domain", "ip", or "hash"

        Returns:
            True if the IOC has any malicious/suspicious detections,
            False if it's clean or unknown.
        """
        try:
            if ioc_type == "domain":
                result = self.lookup_domain(ioc)
            elif ioc_type == "ip":
                result = self.lookup_ip(ioc)
            elif ioc_type == "hash":
                result = self.lookup_hash(ioc)
            else:
                return True  # Unknown type, assume huntworthy

            if "error" in result:
                # If VT doesn't know about it, it might be worth hunting
                return True

            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            # Huntworthy if any vendor flagged it
            return malicious > 0 or suspicious > 0

        except Exception as e:
            logger.debug(f"VT huntworthy check failed for {ioc}: {e}")
            return True  # On error, assume huntworthy to be safe

    def filter_huntworthy_iocs(
        self,
        domains: list = None,
        ips: list = None,
        hashes: list = None,
        max_checks: int = 50,
    ) -> dict:
        """Filter IOCs to only those with VT detections (worth hunting).

        Args:
            domains: List of domains to check
            ips: List of IPs to check
            hashes: List of hashes to check
            max_checks: Maximum total IOCs to check (to limit API calls)

        Returns:
            Dict with 'domains', 'ips', 'hashes' keys containing only huntworthy IOCs
        """
        result = {"domains": [], "ips": [], "hashes": []}

        if not self.is_configured():
            # If VT not configured, return all IOCs (can't filter)
            return {
                "domains": domains or [],
                "ips": ips or [],
                "hashes": hashes or [],
            }

        checks_done = 0

        # Check domains
        for domain in (domains or []):
            if checks_done >= max_checks:
                break
            if self.is_ioc_huntworthy(domain, "domain"):
                result["domains"].append(domain)
            checks_done += 1

        # Check IPs
        for ip in (ips or []):
            if checks_done >= max_checks:
                break
            if self.is_ioc_huntworthy(ip, "ip"):
                result["ips"].append(ip)
            checks_done += 1

        # Check hashes
        for hash_val in (hashes or []):
            if checks_done >= max_checks:
                break
            if self.is_ioc_huntworthy(hash_val, "hash"):
                result["hashes"].append(hash_val)
            checks_done += 1

        logger.info(
            f"VT huntworthy filter: {checks_done} IOCs checked, "
            f"{len(result['domains'])} domains, {len(result['ips'])} IPs, "
            f"{len(result['hashes'])} hashes are huntworthy"
        )

        return result


if __name__ == "__main__":
    # Quick test for VirusTotal client
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = VirusTotalClient()

    if not client.is_configured():
        print("ERROR: VIRUSTOTAL_API_KEY not configured")
        print("Set it in your .env file or environment")
        sys.exit(1)

    print("VirusTotal Client Test")
    print("=" * 50)

    # Test IP lookup (Google DNS - should be clean)
    print("\n1. Testing IP lookup (8.8.8.8)...")
    result = client.lookup_ip("8.8.8.8")
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print(f"   Stats: {client.format_analysis_stats(stats)}")
        print(f"   Threat Level: {client.get_threat_level(stats)}")

    # Test domain lookup
    print("\n2. Testing domain lookup (google.com)...")
    result = client.lookup_domain("google.com")
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print(f"   Stats: {client.format_analysis_stats(stats)}")
        print(f"   Threat Level: {client.get_threat_level(stats)}")

    # Test with a known malicious hash (EICAR test file)
    print("\n3. Testing hash lookup (EICAR test file)...")
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = client.lookup_hash(eicar_hash)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print(f"   Stats: {client.format_analysis_stats(stats)}")
        print(f"   Threat Level: {client.get_threat_level(stats, is_file=True)}")

    print("\n" + "=" * 50)
    print("Tests complete!")
