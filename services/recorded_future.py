"""RecordedFuture Threat Intelligence API Client.

Provides integration with RecordedFuture API for:
- IOC enrichment (IP, domain, hash, URL, CVE) via SOAR API
- Threat actor lookups and profiles
- Risk triage with context-aware scoring

API Documentation: https://api.recordedfuture.com/
"""

import logging
from typing import Any, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

# Risk score thresholds
RISK_CRITICAL = 90
RISK_HIGH = 65
RISK_MEDIUM = 25

RF_API_BASE_URL_DEFAULT = "https://api.recordedfuture.com"
TIMEOUT = 30


class RecordedFutureClient:
    """Client for interacting with the RecordedFuture Threat Intelligence API."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        """Initialize the RecordedFuture client.

        Args:
            api_key: RecordedFuture API token. If not provided, loads from config.
            base_url: API base URL. If not provided, loads from config or uses default.
        """
        config = get_config()

        if api_key is None:
            api_key = getattr(config, "recorded_future_api_key", None)

        if base_url is None:
            base_url = getattr(config, "recorded_future_api_base_url", None) or RF_API_BASE_URL_DEFAULT

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "accept": "application/json",
                "X-RFToken": self.api_key,
                "Content-Type": "application/json",
            })

    def is_configured(self) -> bool:
        """Check if the client has an API key configured."""
        return bool(self.api_key)

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Make authenticated request to RecordedFuture API.

        Args:
            endpoint: API endpoint path (without base URL)
            method: HTTP method (GET or POST)
            payload: Optional JSON payload for POST requests

        Returns:
            API response dictionary or error dict
        """
        if not self.api_key:
            return {"error": "RecordedFuture API key not configured"}

        url = f"{self.base_url}/{endpoint}"

        try:
            logger.debug(f"RecordedFuture {method} request to: {endpoint}")

            if method == "POST":
                response = self.session.post(url, json=payload, timeout=TIMEOUT)
            else:
                response = self.session.get(url, timeout=TIMEOUT)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                logger.error("RecordedFuture authentication failed")
                return {"error": "Invalid API token"}
            elif status_code == 403:
                logger.error("RecordedFuture access forbidden")
                return {"error": "Access forbidden - check API subscription"}
            elif status_code == 404:
                return {"error": "Resource not found"}
            elif status_code == 429:
                logger.warning("RecordedFuture rate limit exceeded")
                return {"error": "Rate limit exceeded"}
            else:
                logger.error(f"RecordedFuture API error: {status_code} for {method} {endpoint}")
                return {"error": f"API error: {status_code}"}

        except requests.exceptions.Timeout:
            logger.error("RecordedFuture request timed out")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error(f"RecordedFuture request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    def search_actor(
        self,
        name: str,
        limit: int = 100,
        offset: Optional[str] = None,
        category: Optional[str] = None,
    ) -> dict[str, Any]:
        """Search for threat actors by name.

        Args:
            name: Threat actor name to search for (e.g., "Fancy Bear", "APT28")
            limit: Maximum number of results (default: 100)
            offset: Pagination offset token for subsequent requests
            category: Filter by category (e.g., "Nation State Sponsored")

        Returns:
            API response with matching threat actors
        """
        name = name.strip()
        logger.info(f"Searching RecordedFuture for threat actor: {name}")

        payload: dict[str, Any] = {"name": name, "limit": limit}
        if offset:
            payload["offset"] = offset
        if category:
            payload["category"] = category

        return self._make_request("threat/actor/search", "POST", payload)

    def get_actor_details(self, actor_id: str) -> dict[str, Any]:
        """Get detailed information about a specific threat actor.

        Args:
            actor_id: RecordedFuture actor ID (e.g., "L37nw-")

        Returns:
            Detailed actor profile including description, risk, and sources
        """
        actor_id = actor_id.strip()
        logger.info(f"Getting RecordedFuture actor details: {actor_id}")
        return self._make_request(f"threat/actors/{actor_id}")

    def get_actor_indicators(self, actor_id: str) -> dict[str, Any]:
        """Get indicators of compromise (IOCs) for a threat actor.

        Note: This endpoint may require specific API subscription level.

        Args:
            actor_id: RecordedFuture actor ID

        Returns:
            Associated IOCs (IPs, domains, hashes, etc.)
        """
        actor_id = actor_id.strip()
        logger.info(f"Getting IOCs for actor: {actor_id}")
        return self._make_request(f"threat/actors/{actor_id}/indicators")

    # =========================================================================
    # SOAR Enrichment API - IOC Lookups
    # =========================================================================

    def enrich(
        self,
        ips: Optional[list[str]] = None,
        domains: Optional[list[str]] = None,
        hashes: Optional[list[str]] = None,
        urls: Optional[list[str]] = None,
        vulnerabilities: Optional[list[str]] = None,
        include_metadata: bool = False,
    ) -> dict[str, Any]:
        """Enrich IOCs with risk scores and intelligence.

        Batch lookup up to 1000 IOCs per request via SOAR API.

        Args:
            ips: List of IP addresses to enrich
            domains: List of domains to enrich
            hashes: List of file hashes (MD5, SHA1, SHA256) to enrich
            urls: List of URLs to enrich
            vulnerabilities: List of CVE identifiers to enrich
            include_metadata: Include explanatory metadata in response

        Returns:
            Enrichment results with risk scores and evidence rules
        """
        payload: dict[str, Any] = {}

        if ips:
            payload["ip"] = [ip.strip() for ip in ips]
        if domains:
            payload["domain"] = [d.strip().lower() for d in domains]
        if hashes:
            payload["hash"] = [h.strip().lower() for h in hashes]
        if urls:
            payload["url"] = [u.strip() for u in urls]
        if vulnerabilities:
            payload["vulnerability"] = [v.strip().upper() for v in vulnerabilities]

        if not payload:
            return {"error": "At least one IOC type must be provided"}

        total_iocs = sum(len(v) for v in payload.values())
        logger.info(f"Enriching {total_iocs} IOC(s) via RecordedFuture SOAR API")

        endpoint = "soar/v3/enrichment"
        if include_metadata:
            endpoint += "?metadata=true"

        return self._make_request(endpoint, "POST", payload)

    def enrich_domains(self, domains: list[str]) -> dict[str, Any]:
        """Enrich a list of domains with risk intelligence.

        Args:
            domains: List of domain names to enrich

        Returns:
            Enrichment results for each domain
        """
        return self.enrich(domains=domains)

    def enrich_ips(self, ips: list[str]) -> dict[str, Any]:
        """Enrich a list of IP addresses with risk intelligence.

        Args:
            ips: List of IP addresses to enrich

        Returns:
            Enrichment results for each IP
        """
        return self.enrich(ips=ips)

    def enrich_hashes(self, hashes: list[str]) -> dict[str, Any]:
        """Enrich a list of file hashes with risk intelligence.

        Args:
            hashes: List of file hashes (MD5, SHA1, SHA256)

        Returns:
            Enrichment results for each hash
        """
        return self.enrich(hashes=hashes)

    def enrich_urls(self, urls: list[str]) -> dict[str, Any]:
        """Enrich a list of URLs with risk intelligence.

        Args:
            urls: List of URLs to enrich

        Returns:
            Enrichment results for each URL
        """
        return self.enrich(urls=urls)

    # =========================================================================
    # SOAR Triage API - Risk Context Evaluation
    # =========================================================================

    def get_triage_contexts(self) -> dict[str, Any]:
        """Get available risk evaluation contexts.

        Returns:
            List of available triage contexts (e.g., phishing, malware, c2)
        """
        logger.info("Fetching available triage contexts")
        return self._make_request("soar/v3/triage/contexts")

    def triage(
        self,
        context: str,
        ips: Optional[list[str]] = None,
        domains: Optional[list[str]] = None,
        hashes: Optional[list[str]] = None,
        urls: Optional[list[str]] = None,
        threshold: int = 25,
        threshold_type: str = "min",
    ) -> dict[str, Any]:
        """Triage IOCs within a specific risk context.

        Evaluates IOCs against context-specific risk rules (phishing, malware, c2).

        Args:
            context: Risk context name (e.g., "phishing", "malware", "c2")
            ips: List of IP addresses
            domains: List of domains
            hashes: List of file hashes
            urls: List of URLs
            threshold: Risk score threshold (0-99)
            threshold_type: "min" (score >= threshold) or "max" (score <= threshold)

        Returns:
            Triage results with verdicts and risk summaries
        """
        payload: dict[str, Any] = {}

        if ips:
            payload["ip"] = [ip.strip() for ip in ips]
        if domains:
            payload["domain"] = [d.strip().lower() for d in domains]
        if hashes:
            payload["hash"] = [h.strip().lower() for h in hashes]
        if urls:
            payload["url"] = [u.strip() for u in urls]

        if not payload:
            return {"error": "At least one IOC type must be provided"}

        total_iocs = sum(len(v) for v in payload.values())
        logger.info(f"Triaging {total_iocs} IOC(s) in context '{context}'")

        endpoint = f"soar/v3/triage/contexts/{context}?threshold={threshold}&threshold_type={threshold_type}"
        return self._make_request(endpoint, "POST", payload)

    def triage_for_phishing(
        self,
        domains: Optional[list[str]] = None,
        urls: Optional[list[str]] = None,
        ips: Optional[list[str]] = None,
        threshold: int = 25,
    ) -> dict[str, Any]:
        """Triage IOCs specifically for phishing risk.

        Args:
            domains: List of domains to check
            urls: List of URLs to check
            ips: List of IPs to check
            threshold: Minimum risk score to flag (default: 25)

        Returns:
            Phishing-context triage results
        """
        return self.triage("phishing", ips=ips, domains=domains, urls=urls, threshold=threshold)

    # =========================================================================
    # Brand Impersonation / Domain Search
    # =========================================================================

    def search_brand_domains(
        self,
        brand: str,
        legitimate_domains: list[str] | None = None,
        min_risk_score: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search for domains containing brand name (brand impersonation detection).

        Uses RF Intelligence API to find domains that contain the brand keyword,
        which could be impersonation attempts like 'metlife-loan.com'.

        Args:
            brand: Brand name to search for (e.g., "metlife")
            legitimate_domains: List of legitimate domains to exclude
            min_risk_score: Minimum risk score to include (default: 0 = all)
            limit: Maximum results (default: 100)

        Returns:
            Dict with impersonation_domains list and metadata
        """
        brand_lower = brand.lower()
        legitimate_domains = [d.lower() for d in (legitimate_domains or [])]

        logger.info(f"Searching RecordedFuture for domains containing '{brand}'")

        # Use the Intelligence API v2 domain search
        # Search for domains containing the brand name
        endpoint = f"v2/domain/search?freetext={brand_lower}&risk[gte]={min_risk_score}&limit={limit}"

        result = self._make_request(endpoint)

        if "error" in result:
            return {
                "success": False,
                "brand": brand,
                "error": result["error"],
                "impersonation_domains": [],
            }

        # Extract domains from results
        data = result.get("data", {})
        results_list = data.get("results", [])

        suspicious_domains = []
        for item in results_list:
            entity = item.get("entity", {})
            domain = entity.get("name", "").lower()

            if not domain:
                continue

            # Skip if exact match or subdomain of legitimate domain
            is_legitimate = False
            for legit in legitimate_domains:
                if domain == legit or domain.endswith(f".{legit}"):
                    is_legitimate = True
                    break

            if is_legitimate:
                continue

            # Extract risk info
            risk = item.get("risk", {})
            risk_score = risk.get("score", 0)
            rules = [r.get("name") for r in risk.get("rules", [])]

            suspicious_domains.append({
                "domain": domain,
                "rf_risk_score": risk_score,
                "rf_risk_level": self.get_risk_level(risk_score),
                "rf_rules": rules,
                "rf_evidence_count": risk.get("evidenceCount", 0),
            })

        # Sort by risk score descending
        suspicious_domains.sort(key=lambda x: x.get("rf_risk_score", 0), reverse=True)

        logger.info(f"RF brand search found {len(suspicious_domains)} suspicious domains for '{brand}'")

        return {
            "success": True,
            "brand": brand,
            "impersonation_domains": suspicious_domains,
            "total_found": len(suspicious_domains),
            "api_total": data.get("total", len(results_list)),
        }

    # =========================================================================
    # Helper Methods
    # =========================================================================

    @staticmethod
    def get_risk_level(score: int) -> str:
        """Convert numeric risk score to risk level string.

        Args:
            score: Risk score (0-99)

        Returns:
            Risk level: "Critical", "High", "Medium", or "Low"
        """
        if score >= RISK_CRITICAL:
            return "Critical"
        elif score >= RISK_HIGH:
            return "High"
        elif score >= RISK_MEDIUM:
            return "Medium"
        return "Low"

    @staticmethod
    def extract_enrichment_results(response: dict) -> list[dict[str, Any]]:
        """Extract and normalize enrichment results from API response.

        Args:
            response: Raw API response from enrich() or triage()

        Returns:
            List of normalized IOC results with risk info
        """
        if "error" in response:
            return []

        results = []
        data = response.get("data", {}).get("results", [])

        for item in data:
            entity = item.get("entity", {})
            risk = item.get("risk", {})

            result = {
                "type": entity.get("type"),
                "value": entity.get("name"),
                "risk_score": risk.get("score", 0),
                "risk_level": RecordedFutureClient.get_risk_level(risk.get("score", 0)),
                "evidence_count": risk.get("evidenceCount", 0),
                "rules": [r.get("name") for r in risk.get("rules", [])],
                "criticality_label": risk.get("criticalityLabel"),
            }
            results.append(result)

        return results

    @staticmethod
    def filter_high_risk(results: list[dict], min_score: int = RISK_HIGH) -> list[dict]:
        """Filter enrichment results to only high-risk IOCs.

        Args:
            results: List of normalized enrichment results
            min_score: Minimum risk score to include (default: 65)

        Returns:
            Filtered list of high-risk IOCs
        """
        return [r for r in results if r.get("risk_score", 0) >= min_score]

    def lookup_actor_by_name(self, name: str) -> dict[str, Any]:
        """Look up a single threat actor by name.

        If the name matches exactly one actor, returns the full details.
        If multiple matches, returns the search results.

        Args:
            name: Threat actor name

        Returns:
            Actor details if single match, or search results if multiple
        """
        search_result = self.search_actor(name, limit=25)

        if "error" in search_result:
            return search_result

        data = search_result.get("data", [])
        if not data:
            return {"error": f"No threat actor found matching: {name}"}

        if len(data) == 1:
            actor = data[0]
            actor_name = actor.get("attributes", {}).get("name", "Unknown")
            logger.info(f"Single match found: {actor_name}")
            return {"match": "single", "actor": actor}

        # Multiple matches
        total = search_result.get("counts", {}).get("total", len(data))
        logger.info(f"Multiple matches found: {total}")
        return {
            "match": "multiple",
            "total": total,
            "actors": data,
        }

    @staticmethod
    def extract_actor_summary(actor: dict) -> dict[str, Any]:
        """Extract key information from an actor record.

        Args:
            actor: Actor data dictionary from API response

        Returns:
            Simplified actor summary
        """
        attrs = actor.get("attributes", {})
        categories = attrs.get("categories", [])

        return {
            "id": actor.get("id"),
            "name": attrs.get("name"),
            "type": actor.get("type"),
            "risk_score": attrs.get("risk_score"),
            "common_names": attrs.get("common_names", []),
            "aliases": attrs.get("alias", []),
            "categories": [c.get("name") for c in categories],
            "target_industries": attrs.get("target_industries", []),
            "target_countries": attrs.get("target_countries", []),
            "description": attrs.get("description"),
            "last_seen": attrs.get("last_seen"),
        }


# Singleton instance
_client: Optional[RecordedFutureClient] = None


def get_client() -> RecordedFutureClient:
    """Get the singleton RecordedFutureClient instance."""
    global _client
    if _client is None:
        _client = RecordedFutureClient()
    return _client


# =============================================================================
# Convenience Functions
# =============================================================================


def search_actor(name: str, limit: int = 100) -> dict[str, Any]:
    """Convenience function to search for threat actors."""
    return get_client().search_actor(name, limit)


def get_actor_details(actor_id: str) -> dict[str, Any]:
    """Convenience function to get actor details."""
    return get_client().get_actor_details(actor_id)


def lookup_actor(name: str) -> dict[str, Any]:
    """Convenience function to look up an actor by name."""
    return get_client().lookup_actor_by_name(name)


def enrich_domains(domains: list[str]) -> dict[str, Any]:
    """Convenience function to enrich domains."""
    return get_client().enrich_domains(domains)


def enrich_ips(ips: list[str]) -> dict[str, Any]:
    """Convenience function to enrich IP addresses."""
    return get_client().enrich_ips(ips)


def enrich_hashes(hashes: list[str]) -> dict[str, Any]:
    """Convenience function to enrich file hashes."""
    return get_client().enrich_hashes(hashes)


def triage_for_phishing(
    domains: Optional[list[str]] = None,
    urls: Optional[list[str]] = None,
    ips: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Convenience function to triage IOCs for phishing risk."""
    return get_client().triage_for_phishing(domains=domains, urls=urls, ips=ips)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    client = RecordedFutureClient()

    if not client.is_configured():
        print("ERROR: RECORDED_FUTURE_API_KEY not configured")
        print("Add RECORDED_FUTURE_API_KEY to your .env or .secrets.age file")
        sys.exit(1)

    print("RecordedFuture Client Test")
    print("=" * 60)

    # Test 1: Domain enrichment
    print("\n[1] Testing domain enrichment...")
    test_domains = ["google.com", "example.com"]
    result = client.enrich_domains(test_domains)

    if "error" in result:
        print(f"    Error: {result['error']}")
        print("    (This may require SOAR API subscription)")
    else:
        enriched = client.extract_enrichment_results(result)
        for item in enriched:
            print(f"    {item['value']}: Risk {item['risk_score']} ({item['risk_level']})")

    # Test 2: IP enrichment
    print("\n[2] Testing IP enrichment...")
    test_ips = ["8.8.8.8"]
    result = client.enrich_ips(test_ips)

    if "error" in result:
        print(f"    Error: {result['error']}")
    else:
        enriched = client.extract_enrichment_results(result)
        for item in enriched:
            print(f"    {item['value']}: Risk {item['risk_score']} ({item['risk_level']})")
            if item['rules']:
                print(f"      Rules: {', '.join(item['rules'][:3])}")

    # Test 3: Threat actor search
    print("\n[3] Testing threat actor search...")
    result = client.search_actor("APT28", limit=3)

    if "error" in result:
        print(f"    Error: {result['error']}")
    else:
        actors = result.get("data", [])
        total = result.get("counts", {}).get("total", 0)
        print(f"    Found {total} total matches, showing {len(actors)}")

        for actor in actors:
            summary = client.extract_actor_summary(actor)
            print(f"\n    Name: {summary['name']}")
            print(f"    ID: {summary['id']}")
            if summary["common_names"]:
                print(f"    AKA: {', '.join(summary['common_names'][:3])}")

    # Test 4: Triage contexts
    print("\n[4] Fetching available triage contexts...")
    result = client.get_triage_contexts()

    if "error" in result:
        print(f"    Error: {result['error']}")
    else:
        contexts = result.get("data", [])
        if contexts:
            print(f"    Available contexts: {contexts}")
        else:
            print("    No contexts returned (check API response structure)")

    print("\n" + "=" * 60)
    print("Test complete!")
