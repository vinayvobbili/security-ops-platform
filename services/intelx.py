"""IntelligenceX Integration - Search dark web, Tor, I2P, and data leaks.

IntelligenceX is a search engine that indexes:
- Dark web (.onion sites via Tor)
- I2P network
- Public data leaks and breaches
- Paste sites (including deleted pastes)
- Public web sources

API Documentation: https://github.com/IntelligenceX/SDK
Free tier: Limited searches with public API key
Paid tier: Full access with personal API key from https://intelx.io/account?tab=developer
"""

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

# IntelligenceX API endpoints
DEFAULT_INTELX_API_BASE = "https://2.intelx.io"

# Public API key (limited functionality, use your own for better results)
PUBLIC_API_KEY = "9df61df0-84f7-4dc7-b34c-8ccfb8646571"

# Request timeout
TIMEOUT = 60

# Search types (buckets)
BUCKET_TYPES = {
    "darknet": 1,      # Tor/I2P dark web
    "pastes": 2,       # Paste sites
    "leaks": 3,        # Data leaks/breaches
    "web": 4,          # Public web
    "whois": 5,        # WHOIS history
    "documents": 6,    # Documents/files
}

# Media types
MEDIA_TYPES = {
    0: "all",
    1: "paste_document",
    2: "paste_user",
    3: "forum",
    4: "forum_board",
    5: "url",
    6: "url_pdf",
    7: "url_doc",
    8: "url_xls",
    9: "url_ppt",
    10: "url_image",
    13: "dumpster",
    14: "whois",
    18: "darknet_tor",
    19: "darknet_i2p",
    24: "leak_public",
    25: "leak_private",
}


class IntelligenceXClient:
    """Client for IntelligenceX API - searches dark web, leaks, and paste sites."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        """Initialize IntelligenceX client.

        Args:
            api_key: IntelligenceX API key. If not provided, uses public key (limited).
            base_url: API base URL. If not provided, uses default.
        """
        self.api_key = api_key or PUBLIC_API_KEY
        self.base_url = (base_url or DEFAULT_INTELX_API_BASE).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "x-key": self.api_key,
            "User-Agent": "Mozilla/5.0 (Security Research)",
        })
        self.is_public_key = (self.api_key == PUBLIC_API_KEY)

        if self.is_public_key:
            logger.warning(
                "Using IntelligenceX public API key - results will be limited. "
                "Get your own key at https://intelx.io/account?tab=developer"
            )
        else:
            logger.info(f"IntelligenceX client initialized with custom API key (base: {self.base_url})")

    def search(
        self,
        term: str,
        max_results: int = 100,
        buckets: Optional[List[str]] = None,
        timeout_secs: int = 30,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search IntelligenceX for a term.

        Args:
            term: Search term (domain, email, IP, etc.)
            max_results: Maximum results to return (default 100)
            buckets: List of bucket types to search (default: all)
                     Options: "darknet", "pastes", "leaks", "web", "whois", "documents"
            timeout_secs: How long to wait for results (default 30 seconds)
            date_from: Start date filter (YYYY-MM-DD)
            date_to: End date filter (YYYY-MM-DD)

        Returns:
            Dictionary with search results
        """
        try:
            # Step 1: Start the search
            search_id = self._start_search(term, max_results, buckets, date_from, date_to)
            if not search_id:
                return {"success": False, "error": "Failed to start search", "results": []}

            # Step 2: Poll for results
            results = self._get_results(search_id, timeout_secs)

            return {
                "success": True,
                "term": term,
                "search_id": search_id,
                "count": len(results),
                "results": results,
                "is_limited": self.is_public_key,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"IntelligenceX search error: {e}")
            return {"success": False, "error": str(e), "results": []}

    def _start_search(
        self,
        term: str,
        max_results: int,
        buckets: Optional[List[str]],
        date_from: Optional[str],
        date_to: Optional[str],
    ) -> Optional[str]:
        """Start an IntelligenceX search and return the search ID."""
        url = f"{self.base_url}/intelligent/search"

        # Build search request
        payload = {
            "term": term,
            "maxresults": max_results,
            "media": 0,  # All media types
            "sort": 2,   # Sort by date descending
            "terminate": [],
        }

        # Add bucket filter if specified
        if buckets:
            bucket_ids = [BUCKET_TYPES.get(b, 0) for b in buckets if b in BUCKET_TYPES]
            if bucket_ids:
                payload["buckets"] = bucket_ids

        # Add date filters
        if date_from:
            payload["datefrom"] = date_from
        if date_to:
            payload["dateto"] = date_to

        response = self.session.post(url, json=payload, timeout=TIMEOUT)

        if response.status_code == 402:
            logger.error("IntelligenceX API key limit reached or payment required")
            return None

        if response.status_code != 200:
            logger.error(f"IntelligenceX search failed: HTTP {response.status_code}")
            return None

        data = response.json()
        return data.get("id")

    def _get_results(self, search_id: str, timeout_secs: int) -> List[Dict[str, Any]]:
        """Poll for search results until complete or timeout."""
        url = f"{self.base_url}/intelligent/search/result"
        params = {"id": search_id}

        all_results = []
        start_time = time.time()

        while (time.time() - start_time) < timeout_secs:
            response = self.session.get(url, params=params, timeout=TIMEOUT)

            if response.status_code != 200:
                logger.warning(f"Failed to get results: HTTP {response.status_code}")
                break

            data = response.json()
            status = data.get("status", 0)
            records = data.get("records", [])

            # Process records
            for record in records:
                result = self._parse_record(record)
                if result:
                    all_results.append(result)

            # Check if search is complete
            # Status: 0 = in progress, 1 = complete, 2 = no results, 3 = ID invalid
            if status in [1, 2, 3]:
                break

            # Wait before polling again
            time.sleep(1)

        # Terminate the search to free resources
        self._terminate_search(search_id)

        return all_results

    def _parse_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single IntelligenceX record into a standardized format."""
        try:
            system_id = record.get("systemid", "")
            storage_id = record.get("storageid", "")
            media = record.get("media", 0)
            bucket = record.get("bucket", "")
            name = record.get("name", "")
            date = record.get("date", "")

            # Determine source type based on media
            source_type = MEDIA_TYPES.get(media, "unknown")

            # Determine if it's dark web content (Tor or I2P)
            is_darkweb = media in [18, 19] or bucket.startswith("darknet")

            return {
                "system_id": system_id,
                "storage_id": storage_id,
                "name": name,
                "date": date,
                "media_type": source_type,
                "bucket": bucket,
                "is_darkweb": is_darkweb,
                "intelx_url": f"https://intelx.io/?did={system_id}" if system_id else None,
                "source": "intelx",
            }
        except Exception as e:
            logger.error(f"Failed to parse IntelligenceX record: {e}")
            return None

    def _terminate_search(self, search_id: str):
        """Terminate a search to free server resources."""
        try:
            url = f"{self.base_url}/intelligent/search/terminate"
            self.session.get(url, params={"id": search_id}, timeout=10)
        except Exception as e:
            logger.debug(f"Failed to terminate search {search_id}: {e}")

    def search_darkweb_only(self, term: str, max_results: int = 100) -> Dict[str, Any]:
        """Search only dark web sources (Tor, I2P).

        Args:
            term: Search term (domain, email, etc.)
            max_results: Maximum results to return

        Returns:
            Dictionary with dark web search results
        """
        return self.search(term, max_results=max_results, buckets=["darknet"])

    def search_leaks_only(self, term: str, max_results: int = 100) -> Dict[str, Any]:
        """Search only data leak sources.

        Args:
            term: Search term (domain, email, etc.)
            max_results: Maximum results to return

        Returns:
            Dictionary with leak search results
        """
        return self.search(term, max_results=max_results, buckets=["leaks"])

    def search_pastes_only(self, term: str, max_results: int = 100) -> Dict[str, Any]:
        """Search only paste sites.

        Args:
            term: Search term (domain, email, etc.)
            max_results: Maximum results to return

        Returns:
            Dictionary with paste site results
        """
        return self.search(term, max_results=max_results, buckets=["pastes"])

    def get_phonebook(self, term: str, target: int = 1) -> Dict[str, Any]:
        """Search the phonebook for emails, domains, or URLs.

        Phonebook is a FREE feature that lists emails, subdomains, and URLs for a domain.

        Args:
            term: Domain to search
            target: 1=emails, 2=domains/subdomains, 3=URLs

        Returns:
            Dictionary with phonebook results
        """
        try:
            # Step 1: Start phonebook search
            url = f"{self.base_url}/phonebook/search"
            payload = {
                "term": term,
                "maxresults": 1000,
                "media": 0,
                "target": target,
                "terminate": [],
            }

            response = self.session.post(url, json=payload, timeout=TIMEOUT)

            if response.status_code == 401:
                # Phonebook is not available on free tier
                logger.debug("Phonebook not available (requires paid API key)")
                return {"success": False, "error": "Phonebook requires paid API key", "results": []}

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}", "results": []}

            data = response.json()
            search_id = data.get("id")

            if not search_id:
                return {"success": False, "error": "No search ID returned", "results": []}

            # Step 2: Get results
            results_url = f"{self.base_url}/phonebook/search/result"
            all_selectors = []
            start_time = time.time()

            while (time.time() - start_time) < 30:
                response = self.session.get(results_url, params={"id": search_id}, timeout=TIMEOUT)

                if response.status_code != 200:
                    break

                data = response.json()
                status = data.get("status", 0)
                selectors = data.get("selectors", [])

                for selector in selectors:
                    all_selectors.append({
                        "value": selector.get("selectorvalue", ""),
                        "type": selector.get("selectortype", 0),
                        "first_seen": selector.get("firstseen", ""),
                        "last_seen": selector.get("lastseen", ""),
                    })

                if status in [1, 2, 3]:
                    break

                time.sleep(0.5)

            target_names = {1: "emails", 2: "domains", 3: "urls"}
            return {
                "success": True,
                "term": term,
                "target": target_names.get(target, "unknown"),
                "count": len(all_selectors),
                "results": all_selectors,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"IntelligenceX phonebook error: {e}")
            return {"success": False, "error": str(e), "results": []}

    def search_domain(self, domain: str, max_results: int = 100) -> Dict[str, Any]:
        """Comprehensive search for a domain across all IntelligenceX sources.

        Does a single search and categorizes results by bucket type.
        This works with both free and paid API tiers.

        Args:
            domain: Domain to search for
            max_results: Maximum results to return

        Returns:
            Combined results from dark web, leaks, pastes, and phonebook
        """
        logger.info(f"Starting IntelligenceX search for {domain}")
        scan_time = datetime.now()

        results = {
            "success": True,
            "domain": domain,
            "scan_time": scan_time.isoformat(),
            "is_limited": self.is_public_key,
            "darkweb_findings": [],
            "leak_findings": [],
            "paste_findings": [],
            "other_findings": [],
            "phonebook_emails": [],
            "phonebook_subdomains": [],
            "total_findings": 0,
        }

        # Do a single general search (works on free tier)
        try:
            search_results = self.search(domain, max_results=max_results)
            if search_results.get("success"):
                # Categorize results by bucket
                for record in search_results.get("results", []):
                    bucket = record.get("bucket", "").lower()
                    is_darkweb = record.get("is_darkweb", False)

                    if is_darkweb or bucket.startswith("darknet"):
                        results["darkweb_findings"].append(record)
                    elif "leak" in bucket:
                        results["leak_findings"].append(record)
                    elif "paste" in bucket or bucket.startswith("dumpster"):
                        results["paste_findings"].append(record)
                    else:
                        results["other_findings"].append(record)
        except Exception as e:
            logger.error(f"IntelligenceX search failed: {e}")
            results["success"] = False
            results["error"] = str(e)

        # Phonebook searches (may not be available on free tier)
        try:
            email_results = self.get_phonebook(domain, target=1)
            if email_results.get("success"):
                results["phonebook_emails"] = email_results.get("results", [])
        except Exception as e:
            logger.debug(f"Phonebook email search failed: {e}")

        try:
            subdomain_results = self.get_phonebook(domain, target=2)
            if subdomain_results.get("success"):
                results["phonebook_subdomains"] = subdomain_results.get("results", [])
        except Exception as e:
            logger.debug(f"Phonebook subdomain search failed: {e}")

        # Calculate totals
        results["total_findings"] = (
            len(results["darkweb_findings"]) +
            len(results["leak_findings"]) +
            len(results["paste_findings"]) +
            len(results["other_findings"])
        )

        logger.info(
            f"IntelligenceX search complete: {results['total_findings']} findings "
            f"({len(results['darkweb_findings'])} dark web, "
            f"{len(results['leak_findings'])} leaks, "
            f"{len(results['paste_findings'])} pastes, "
            f"{len(results['other_findings'])} other)"
        )

        return results


# Singleton instance
_client: Optional[IntelligenceXClient] = None


def get_client(api_key: Optional[str] = None, base_url: Optional[str] = None) -> IntelligenceXClient:
    """Get the singleton IntelligenceX client instance.

    If api_key/base_url is not provided, attempts to load from config.
    """
    global _client
    if _client is None:
        # Auto-load from config if not provided
        config = get_config()
        if api_key is None:
            api_key = config.intelx_api_key
            if api_key:
                logger.info("IntelligenceX API key loaded from config")
        if base_url is None:
            base_url = config.intelx_api_base_url
        _client = IntelligenceXClient(api_key=api_key, base_url=base_url)
    return _client


def search_intelx(domain: str) -> Dict[str, Any]:
    """Convenience function to search IntelligenceX for a domain.

    Args:
        domain: Domain to search for

    Returns:
        Combined search results
    """
    return get_client().search_domain(domain)
