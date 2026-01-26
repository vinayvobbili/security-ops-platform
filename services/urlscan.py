"""URLScan.io Service - Domain scanning and parking detection.

This service provides:
- Domain scanning via urlscan.io API
- Parking detection using urlscan's page categorization
- Batch parking checks with caching

API Documentation: https://urlscan.io/docs/api/
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

# Request timeout
TIMEOUT = 30

# Parking-related categories from urlscan.io
PARKING_CATEGORIES = {
    'parked',
    'parking',
    'domain parking',
    'for sale',
    'placeholder',
    'coming soon',
    'under construction',
}

# Known parking service domains
PARKING_SERVICE_DOMAINS = {
    'sedoparking.com',
    'bodis.com',
    'parkingcrew.net',
    'parkingcrew.com',
    'above.com',
    'hugedomains.com',
    'afternic.com',
    'dan.com',
    'sav.com',
    'undeveloped.com',
    'domainmarket.com',
    'domainnamesales.com',
    'namecheap.com',  # Namecheap parking pages
    'registrar-servers.com',  # Namecheap infrastructure
}


class URLScanClient:
    """Client for URLScan.io API with parking detection capabilities."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the URLScan client.

        Args:
            api_key: Optional API key. If not provided, uses config.
                     Search API works without key, scan submission requires key.
        """
        if api_key is None:
            config = get_config()
            api_key = config.urlscan_api_key

        self.api_key = api_key
        self.base_url = "https://urlscan.io/api/v1"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SecurityResearch/1.0"
        })
        if self.api_key:
            self.session.headers["API-Key"] = self.api_key

        # Simple in-memory cache for parking results
        self._parking_cache: Dict[str, Tuple[Optional[bool], datetime]] = {}
        self._cache_ttl = timedelta(hours=24)

    def is_configured(self) -> bool:
        """Check if API key is configured (needed for scan submission)."""
        return bool(self.api_key)

    def search_domain(self, domain: str, size: int = 10) -> Dict[str, Any]:
        """Search for existing scans of a domain.

        This endpoint is free and doesn't require an API key.

        Args:
            domain: Domain to search for
            size: Maximum number of results

        Returns:
            Dictionary with search results
        """
        try:
            url = f"{self.base_url}/search/"
            params = {
                "q": f'page.domain:"{domain}"',
                "size": size,
            }

            response = self.session.get(url, params=params, timeout=TIMEOUT)

            if response.status_code == 429:
                logger.warning("URLScan rate limited")
                return {"success": False, "error": "Rate limited", "results": []}

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}", "results": []}

            data = response.json()
            return {
                "success": True,
                "total": data.get("total", 0),
                "results": data.get("results", []),
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"URLScan search error: {e}")
            return {"success": False, "error": str(e), "results": []}

    def submit_scan(self, url: str, visibility: str = "public") -> Dict[str, Any]:
        """Submit a URL for scanning.

        Requires API key.

        Args:
            url: URL to scan
            visibility: "public", "unlisted", or "private"

        Returns:
            Dictionary with scan submission result including uuid
        """
        if not self.api_key:
            return {"success": False, "error": "API key required for scan submission"}

        try:
            api_url = f"{self.base_url}/scan/"
            payload = {
                "url": url,
                "visibility": visibility,
            }

            response = self.session.post(api_url, json=payload, timeout=TIMEOUT)

            if response.status_code == 429:
                return {"success": False, "error": "Rate limited"}

            if response.status_code not in (200, 201):
                return {"success": False, "error": f"HTTP {response.status_code}: {response.text}"}

            data = response.json()
            return {
                "success": True,
                "uuid": data.get("uuid"),
                "result_url": data.get("result"),
                "api_url": data.get("api"),
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"URLScan submit error: {e}")
            return {"success": False, "error": str(e)}

    def get_scan_result(self, uuid: str) -> Dict[str, Any]:
        """Get results of a completed scan.

        Args:
            uuid: Scan UUID from submit_scan

        Returns:
            Dictionary with scan results
        """
        try:
            url = f"{self.base_url}/result/{uuid}/"
            response = self.session.get(url, timeout=TIMEOUT)

            if response.status_code == 404:
                return {"success": False, "error": "Scan not found or not yet complete"}

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}"}

            data = response.json()
            return {
                "success": True,
                "data": data,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"URLScan result error: {e}")
            return {"success": False, "error": str(e)}

    def _extract_parking_indicators(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract parking indicators from a scan result.

        Args:
            scan_result: Full scan result from urlscan.io

        Returns:
            Dictionary with parking analysis
        """
        indicators = {
            "is_parked": False,
            "confidence": "low",
            "reasons": [],
        }

        # Check verdicts/categories
        verdicts = scan_result.get("verdicts", {})

        # Check urlscan's own categorization
        urlscan_verdicts = verdicts.get("urlscan", {})
        categories = urlscan_verdicts.get("categories", [])

        for cat in categories:
            cat_lower = cat.lower()
            if any(parking_term in cat_lower for parking_term in PARKING_CATEGORIES):
                indicators["is_parked"] = True
                indicators["confidence"] = "high"
                indicators["reasons"].append(f"URLScan category: {cat}")

        # Check community verdicts
        community = verdicts.get("community", {})
        community_cats = community.get("categories", [])
        for cat in community_cats:
            cat_lower = cat.lower()
            if any(parking_term in cat_lower for parking_term in PARKING_CATEGORIES):
                indicators["is_parked"] = True
                indicators["confidence"] = "high"
                indicators["reasons"].append(f"Community category: {cat}")

        # Check page data for parking service indicators
        page = scan_result.get("page", {})
        page_domain = page.get("domain", "").lower()

        # Check if the page redirected to a known parking service
        lists = scan_result.get("lists", {})
        domains = lists.get("domains", [])

        for domain in domains:
            domain_lower = domain.lower()
            for parking_domain in PARKING_SERVICE_DOMAINS:
                if parking_domain in domain_lower:
                    indicators["is_parked"] = True
                    if indicators["confidence"] == "low":
                        indicators["confidence"] = "medium"
                    indicators["reasons"].append(f"Parking service detected: {parking_domain}")

        # Check page title for parking indicators
        task = scan_result.get("task", {})
        title = (page.get("title") or "").lower()
        parking_title_keywords = [
            "domain for sale", "buy this domain", "parked", "coming soon",
            "under construction", "domain parking", "make an offer",
            "this domain", "is for sale", "recently been registered"
        ]

        for keyword in parking_title_keywords:
            if keyword in title:
                indicators["is_parked"] = True
                if indicators["confidence"] == "low":
                    indicators["confidence"] = "medium"
                indicators["reasons"].append(f"Title contains: '{keyword}'")
                break

        return indicators

    def check_parking_status(self, domain: str, use_cache: bool = True) -> Optional[bool]:
        """Check if a domain is parked using urlscan.io data.

        Strategy:
        1. Check cache first
        2. Search for existing scans
        3. Analyze scan results for parking indicators
        4. If API key available and no recent scan, submit new scan

        Args:
            domain: Domain to check
            use_cache: Whether to use cached results

        Returns:
            True if parked, False if not parked, None if unable to determine
        """
        # Check cache
        if use_cache and domain in self._parking_cache:
            cached_result, cached_time = self._parking_cache[domain]
            if datetime.utcnow() - cached_time < self._cache_ttl:
                logger.debug(f"{domain}: Using cached parking status: {cached_result}")
                return cached_result

        # Search for existing scans
        search_result = self.search_domain(domain, size=5)

        if not search_result.get("success") or not search_result.get("results"):
            logger.debug(f"{domain}: No existing scans found")

            # If we have an API key, submit a new scan
            if self.api_key:
                return self._scan_and_check(domain)

            return None

        # Analyze existing scan results
        for result in search_result["results"]:
            scan_id = result.get("_id")
            if not scan_id:
                continue

            # Get full scan result
            full_result = self.get_scan_result(scan_id)
            if not full_result.get("success"):
                continue

            scan_data = full_result.get("data", {})
            parking_analysis = self._extract_parking_indicators(scan_data)

            if parking_analysis["is_parked"]:
                logger.info(f"{domain}: Detected as PARKED (confidence: {parking_analysis['confidence']}, reasons: {parking_analysis['reasons']})")
                self._parking_cache[domain] = (True, datetime.utcnow())
                return True

            # If high confidence it's NOT parked (has real content)
            if parking_analysis["confidence"] != "low":
                self._parking_cache[domain] = (False, datetime.utcnow())
                return False

        # If we checked scans but couldn't determine, return None
        logger.debug(f"{domain}: Unable to determine parking status from existing scans")
        return None

    def _scan_and_check(self, domain: str, wait_seconds: int = 30) -> Optional[bool]:
        """Submit a scan and wait for results.

        Args:
            domain: Domain to scan
            wait_seconds: How long to wait for scan completion

        Returns:
            True if parked, False if not, None if unable to determine
        """
        url = f"http://{domain}"
        submit_result = self.submit_scan(url, visibility="unlisted")

        if not submit_result.get("success"):
            logger.warning(f"Failed to submit scan for {domain}: {submit_result.get('error')}")
            return None

        uuid = submit_result.get("uuid")
        if not uuid:
            return None

        # Wait for scan to complete
        logger.debug(f"{domain}: Waiting {wait_seconds}s for scan completion...")
        time.sleep(wait_seconds)

        # Get result
        result = self.get_scan_result(uuid)
        if not result.get("success"):
            logger.debug(f"{domain}: Scan not complete yet")
            return None

        scan_data = result.get("data", {})
        parking_analysis = self._extract_parking_indicators(scan_data)

        is_parked = parking_analysis["is_parked"]
        self._parking_cache[domain] = (is_parked, datetime.utcnow())

        if is_parked:
            logger.info(f"{domain}: Detected as PARKED via new scan (reasons: {parking_analysis['reasons']})")
        else:
            logger.debug(f"{domain}: Detected as ACTIVE via new scan")

        return is_parked

    def check_parking_batch(
        self,
        domains: List[str],
        max_concurrent: int = 5,
        submit_new_scans: bool = False
    ) -> Dict[str, Optional[bool]]:
        """Check parking status for multiple domains.

        Note: This method only searches existing scans by default.
        Set submit_new_scans=True to submit scans for domains without results
        (requires API key and is slower due to rate limits).

        Args:
            domains: List of domains to check
            max_concurrent: Max concurrent requests (not used yet, for future)
            submit_new_scans: Whether to submit new scans for unknown domains

        Returns:
            Dictionary mapping domain -> parking status (True/False/None)
        """
        results = {}

        for domain in domains:
            # First check cache and existing scans
            status = self.check_parking_status(domain, use_cache=True)
            results[domain] = status

            # Small delay to avoid rate limiting
            time.sleep(0.5)

        return results
