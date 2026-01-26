"""Data Leak Monitoring Service - Monitor for brand mentions in paste sites and code repos.

This service monitors CLEAR WEB sources for potential data leaks:
- URLScan.io - public scan results for phishing/malware
- GitHub Code Search - exposed credentials/configs in public repos
- Pastebin Search - paste site monitoring (via psbdmp.ws)
- LeakIX - exposed services and data leaks

For actual dark web (.onion) monitoring, see IntelligenceX integration.
"""

import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

# Request timeout
TIMEOUT = 30


class DarkWebMonitor:
    """Monitors paste sites, code repos, and public sources for data leaks and brand mentions."""

    def __init__(self, github_token: Optional[str] = None):
        """Initialize the dark web monitor.

        Args:
            github_token: Optional GitHub token for higher API rate limits
        """
        self.github_token = github_token
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Research)"
        })

    def search_urlscan(self, domain: str, days: int = 30) -> Dict[str, Any]:
        """Search URLScan.io for scans mentioning the domain.

        URLScan.io is free and indexes phishing sites, malware, etc.

        Args:
            domain: Domain to search for
            days: Number of days to look back

        Returns:
            Dictionary with search results
        """
        try:
            # Search for scans targeting this domain or lookalikes
            url = "https://urlscan.io/api/v1/search/"
            params = {
                "q": f'page.domain:"{domain}" OR page.domain:*{domain.split(".")[0]}*',
                "size": 100,
            }

            response = self.session.get(url, params=params, timeout=TIMEOUT)

            if response.status_code == 429:
                logger.warning("URLScan rate limited")
                return {"success": False, "error": "Rate limited", "results": []}

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}", "results": []}

            data = response.json()
            results = []

            cutoff_date = datetime.utcnow() - timedelta(days=days)

            for item in data.get("results", []):
                # Parse scan time
                scan_time_str = item.get("task", {}).get("time", "")
                try:
                    scan_time = datetime.fromisoformat(scan_time_str.replace("Z", "+00:00"))
                    if scan_time.replace(tzinfo=None) < cutoff_date:
                        continue
                except (ValueError, TypeError):
                    pass

                page = item.get("page", {})
                task = item.get("task", {})

                # Skip if it's the legitimate domain
                if page.get("domain") == domain:
                    continue

                results.append({
                    "url": page.get("url"),
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "scan_time": task.get("time"),
                    "scan_url": f"https://urlscan.io/result/{item.get('_id')}/",
                    "source": "urlscan.io",
                    "verdict": item.get("verdicts", {}).get("overall", {}).get("malicious", False),
                })

            logger.info(f"URLScan found {len(results)} results for {domain}")

            return {
                "success": True,
                "source": "urlscan.io",
                "count": len(results),
                "results": results,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"URLScan search error: {e}")
            return {"success": False, "error": str(e), "results": []}

    def search_github(self, domain: str, search_terms: Optional[List[str]] = None) -> Dict[str, Any]:
        """Search GitHub for exposed credentials or configs mentioning the domain.

        Args:
            domain: Domain to search for
            search_terms: Additional terms to search (e.g., ["password", "api_key"])

        Returns:
            Dictionary with search results
        """
        if search_terms is None:
            search_terms = ["password", "api_key", "secret", "credential", "token"]

        try:
            results = []
            headers = {}
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"

            # Search for domain + sensitive terms
            for term in search_terms[:3]:  # Limit to avoid rate limiting
                query = f'"{domain}" {term}'
                url = "https://api.github.com/search/code"
                params = {"q": query, "per_page": 10}

                response = self.session.get(url, params=params, headers=headers, timeout=TIMEOUT)

                if response.status_code == 403:
                    logger.warning("GitHub rate limited - consider adding token")
                    break

                if response.status_code != 200:
                    continue

                data = response.json()

                for item in data.get("items", []):
                    results.append({
                        "repo": item.get("repository", {}).get("full_name"),
                        "file": item.get("name"),
                        "path": item.get("path"),
                        "url": item.get("html_url"),
                        "search_term": term,
                        "source": "github",
                    })

            logger.info(f"GitHub found {len(results)} results for {domain}")

            return {
                "success": True,
                "source": "github",
                "count": len(results),
                "results": results,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub search error: {e}")
            return {"success": False, "error": str(e), "results": []}

    def _check_paste_exists(self, paste_id: str) -> bool:
        """Check if a Pastebin paste still exists.

        Args:
            paste_id: The Pastebin paste ID

        Returns:
            True if paste exists, False otherwise
        """
        try:
            url = f"https://pastebin.com/raw/{paste_id}"
            response = self.session.head(url, timeout=10, allow_redirects=True)
            # Pastebin returns 200 for existing, 404 for deleted
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def search_psbdmp(self, domain: str, verify_exists: bool = True, max_age_days: int = 0) -> Dict[str, Any]:
        """Search psbdmp.ws (Pastebin dump search) for mentions.

        This is a free paste site search engine. Note: pastes are often deleted
        quickly by Pastebin, so results may be stale.

        Args:
            domain: Domain to search for
            verify_exists: If True, check if each paste still exists (slower but more accurate,
                          adds ~1 second per paste). Default True for accuracy.
            max_age_days: Only include pastes from the last N days (0 = no age filter, default)

        Returns:
            Dictionary with search results
        """
        try:
            # psbdmp.ws API endpoint
            url = f"https://psbdmp.ws/api/v3/search/{domain}"

            response = self.session.get(url, timeout=TIMEOUT)

            if response.status_code != 200:
                # Try alternative: search page scraping
                return {"success": True, "source": "psbdmp", "count": 0, "results": [], "note": "API unavailable"}

            data = response.json()
            results = []
            skipped_old = 0
            skipped_deleted = 0

            cutoff_timestamp = None
            if max_age_days > 0:
                cutoff_timestamp = (datetime.utcnow() - timedelta(days=max_age_days)).timestamp()

            for item in data if isinstance(data, list) else []:
                paste_id = item.get("id")
                paste_time = item.get("time")

                # Filter by age if timestamp is valid
                if cutoff_timestamp and paste_time:
                    try:
                        if int(paste_time) < cutoff_timestamp:
                            skipped_old += 1
                            continue
                    except (ValueError, TypeError):
                        pass

                # Verify paste still exists (optional, slower)
                if verify_exists and paste_id:
                    if not self._check_paste_exists(paste_id):
                        skipped_deleted += 1
                        continue

                results.append({
                    "paste_id": paste_id,
                    "url": f"https://pastebin.com/{paste_id}",
                    "time": paste_time,
                    "source": "psbdmp",
                })

            logger.info(
                f"PSBDMP found {len(results)} valid results for {domain} "
                f"(skipped: {skipped_old} old, {skipped_deleted} deleted)"
            )

            return {
                "success": True,
                "source": "psbdmp",
                "count": len(results),
                "results": results,
                "skipped_old": skipped_old,
                "skipped_deleted": skipped_deleted,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"PSBDMP search error: {e}")
            return {"success": False, "error": str(e), "results": []}

    def search_leakix(self, domain: str) -> Dict[str, Any]:
        """Search LeakIX for exposed services and leaks.

        LeakIX is a free search engine for exposed services.

        Args:
            domain: Domain to search for

        Returns:
            Dictionary with search results
        """
        try:
            url = "https://leakix.net/api/subdomains"
            params = {"domain": domain}

            response = self.session.get(url, params=params, timeout=TIMEOUT)

            if response.status_code != 200:
                return {"success": True, "source": "leakix", "count": 0, "results": []}

            data = response.json()
            results = []

            for item in data if isinstance(data, list) else []:
                results.append({
                    "subdomain": item.get("subdomain"),
                    "ip": item.get("ip"),
                    "source": "leakix",
                })

            logger.info(f"LeakIX found {len(results)} results for {domain}")

            return {
                "success": True,
                "source": "leakix",
                "count": len(results),
                "results": results,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"LeakIX search error: {e}")
            return {"success": False, "error": str(e), "results": []}

    def search_all(self, domain: str) -> Dict[str, Any]:
        """Search all sources for mentions of a domain.

        Args:
            domain: Domain to search for

        Returns:
            Combined results from all sources
        """
        logger.info(f"Starting data leak search for {domain}")
        scan_time = datetime.now()

        results = {
            "success": True,
            "domain": domain,
            "scan_time": scan_time.isoformat(),
            "sources": {},
            "total_findings": 0,
            "high_risk_findings": [],
        }

        # Search each source
        sources = [
            ("urlscan", self.search_urlscan),
            ("github", self.search_github),
            ("psbdmp", self.search_psbdmp),
            ("leakix", self.search_leakix),
        ]

        for source_name, search_func in sources:
            try:
                source_result = search_func(domain)
                results["sources"][source_name] = source_result
                results["total_findings"] += source_result.get("count", 0)

                # Identify high-risk findings
                for finding in source_result.get("results", []):
                    # URLScan malicious verdicts
                    if finding.get("verdict") is True:
                        finding["risk"] = "high"
                        results["high_risk_findings"].append(finding)
                    # GitHub credential exposures
                    elif finding.get("search_term") in ["password", "secret", "credential"]:
                        finding["risk"] = "high"
                        results["high_risk_findings"].append(finding)

            except Exception as e:
                logger.error(f"Error searching {source_name}: {e}")
                results["sources"][source_name] = {"success": False, "error": str(e)}

        logger.info(
            f"Data leak search complete: {results['total_findings']} findings, "
            f"{len(results['high_risk_findings'])} high-risk"
        )

        return results


# Singleton instance
_monitor: Optional[DarkWebMonitor] = None


def get_monitor(github_token: Optional[str] = None) -> DarkWebMonitor:
    """Get the singleton DarkWebMonitor instance.

    If github_token is not provided, attempts to load from config.
    """
    global _monitor
    if _monitor is None:
        # Auto-load GitHub token from config if not provided
        if github_token is None:
            config = get_config()
            github_token = config.github_token
            if github_token:
                logger.info("GitHub token loaded from config - higher API rate limits enabled")
        _monitor = DarkWebMonitor(github_token=github_token)
    return _monitor


def search_dark_web(domain: str) -> Dict[str, Any]:
    """Convenience function to search dark web for a domain.

    Args:
        domain: Domain to search for

    Returns:
        Combined search results
    """
    return get_monitor().search_all(domain)
