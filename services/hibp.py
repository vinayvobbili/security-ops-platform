"""HaveIBeenPwned API Client.

Checks for breached credentials associated with your domain's email addresses.
Requires a HIBP API key (https://haveibeenpwned.com/API/Key).

Two modes of operation:
1. Domain Search (Enterprise) - Get all breached emails for domains you own
2. Email Pattern Check - Check common email patterns (admin@, info@, etc.)
"""

import logging
import time
from datetime import UTC, datetime
from typing import Any, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"

# Common email prefixes to check for a domain
COMMON_EMAIL_PREFIXES = [
    "admin", "administrator", "info", "contact", "support", "help",
    "sales", "billing", "accounts", "security", "hr", "jobs", "careers",
    "press", "media", "marketing", "webmaster", "postmaster", "hostmaster",
    "abuse", "noc", "ops", "it", "helpdesk", "service", "customerservice",
    "feedback", "enquiries", "inquiries", "hello", "office", "team",
]


class HIBPClient:
    """Client for HaveIBeenPwned API."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the HIBP client.

        Args:
            api_key: HIBP API key. If not provided, loads from config.
        """
        if api_key is None:
            config = get_config()
            api_key = getattr(config, 'hibp_api_key', None)

        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "IR-Domain-Monitoring",
        })
        if self.api_key:
            self.session.headers["hibp-api-key"] = self.api_key

        # Rate limiting: HIBP allows 10 requests per minute for regular API
        self.last_request_time = 0
        self.min_request_interval = 6.1  # seconds between requests

    def is_configured(self) -> bool:
        """Check if the client has an API key configured."""
        return bool(self.api_key)

    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            logger.debug(f"HIBP rate limit: sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _make_request(self, endpoint: str, params: Optional[dict] = None) -> dict[str, Any]:
        """Make authenticated request to HIBP API.

        Args:
            endpoint: API endpoint path
            params: Optional query parameters

        Returns:
            dict with response data or error
        """
        if not self.api_key:
            return {"error": "HIBP API key not configured"}

        self._rate_limit()

        url = f"{HIBP_API_BASE}/{endpoint}"

        try:
            logger.debug(f"HIBP request: {endpoint}")
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 404:
                # Not found = no breaches (good news)
                return {"success": True, "data": []}
            elif response.status_code == 401:
                return {"error": "Invalid HIBP API key"}
            elif response.status_code == 429:
                return {"error": "HIBP rate limit exceeded"}
            elif response.status_code == 403:
                return {"error": "HIBP API access forbidden - check subscription"}
            else:
                return {"error": f"HIBP API error: {response.status_code}"}

        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}
        except requests.exceptions.RequestException as e:
            logger.error(f"HIBP request failed: {e}")
            return {"error": str(e)}

    def check_email(self, email: str, truncate_response: bool = True) -> dict[str, Any]:
        """Check if an email address has been involved in breaches.

        Args:
            email: Email address to check
            truncate_response: If True, return only breach names (faster)

        Returns:
            dict with breach information
        """
        email = email.strip().lower()
        logger.info(f"HIBP checking email: {email}")

        params = {"truncateResponse": "true" if truncate_response else "false"}
        result = self._make_request(f"breachedaccount/{email}", params)

        if result.get("error"):
            return {
                "success": False,
                "email": email,
                "error": result["error"],
            }

        breaches = result.get("data", [])

        return {
            "success": True,
            "email": email,
            "breached": len(breaches) > 0,
            "breach_count": len(breaches),
            "breaches": breaches,
        }

    def check_domain_emails(
        self,
        domain: str,
        email_prefixes: Optional[list[str]] = None,
        max_checks: int = 20
    ) -> dict[str, Any]:
        """Check common email patterns for a domain.

        Args:
            domain: Domain to check (e.g., "example.com")
            email_prefixes: List of email prefixes to check. Defaults to common patterns.
            max_checks: Maximum number of emails to check (rate limit consideration)

        Returns:
            dict with results for all checked emails
        """
        if email_prefixes is None:
            email_prefixes = COMMON_EMAIL_PREFIXES[:max_checks]
        else:
            email_prefixes = email_prefixes[:max_checks]

        domain = domain.strip().lower()
        logger.info(f"HIBP checking {len(email_prefixes)} email patterns for {domain}")

        results = {
            "success": True,
            "domain": domain,
            "scan_time": datetime.now(UTC).isoformat(),
            "emails_checked": 0,
            "emails_breached": 0,
            "total_breaches": 0,
            "breached_emails": [],
            "clean_emails": [],
            "errors": [],
        }

        for prefix in email_prefixes:
            email = f"{prefix}@{domain}"
            result = self.check_email(email)
            results["emails_checked"] += 1

            if result.get("error"):
                results["errors"].append({
                    "email": email,
                    "error": result["error"],
                })
                # If we hit rate limit, stop
                if "rate limit" in result["error"].lower():
                    logger.warning("HIBP rate limit hit, stopping checks")
                    break
                continue

            if result.get("breached"):
                results["emails_breached"] += 1
                results["total_breaches"] += result["breach_count"]
                results["breached_emails"].append({
                    "email": email,
                    "breach_count": result["breach_count"],
                    "breaches": result["breaches"],
                })
            else:
                results["clean_emails"].append(email)

        logger.info(
            f"HIBP domain check complete: {results['emails_breached']}/{results['emails_checked']} "
            f"emails breached, {results['total_breaches']} total breaches"
        )

        return results

    def get_breach_details(self, breach_name: str) -> dict[str, Any]:
        """Get detailed information about a specific breach.

        Args:
            breach_name: Name of the breach (e.g., "Adobe")

        Returns:
            dict with breach details
        """
        result = self._make_request(f"breach/{breach_name}")

        if result.get("error"):
            return {"success": False, "error": result["error"]}

        return {
            "success": True,
            "breach": result.get("data", {}),
        }

    def get_all_breaches(self, domain: Optional[str] = None) -> dict[str, Any]:
        """Get list of all breaches in HIBP database.

        Args:
            domain: Optional - filter to breaches affecting this domain

        Returns:
            dict with list of breaches
        """
        params = {}
        if domain:
            params["domain"] = domain

        result = self._make_request("breaches", params)

        if result.get("error"):
            return {"success": False, "error": result["error"]}

        return {
            "success": True,
            "breaches": result.get("data", []),
            "count": len(result.get("data", [])),
        }

    def check_paste(self, email: str) -> dict[str, Any]:
        """Check if an email appears in any pastes.

        Note: Paste monitoring requires a higher subscription tier.

        Args:
            email: Email address to check

        Returns:
            dict with paste information
        """
        email = email.strip().lower()
        result = self._make_request(f"pasteaccount/{email}")

        if result.get("error"):
            return {"success": False, "email": email, "error": result["error"]}

        pastes = result.get("data", [])

        return {
            "success": True,
            "email": email,
            "paste_count": len(pastes),
            "pastes": pastes,
        }


# Singleton instance
_client: Optional[HIBPClient] = None


def get_client() -> HIBPClient:
    """Get the singleton HIBPClient instance."""
    global _client
    if _client is None:
        _client = HIBPClient()
    return _client


def check_email_breaches(email: str) -> dict[str, Any]:
    """Convenience function to check an email for breaches."""
    return get_client().check_email(email)


def check_domain_breaches(domain: str, max_checks: int = 20) -> dict[str, Any]:
    """Convenience function to check a domain's common emails for breaches."""
    return get_client().check_domain_emails(domain, max_checks=max_checks)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = HIBPClient()

    if not client.is_configured():
        print("ERROR: HIBP_API_KEY not configured")
        print("Get an API key at: https://haveibeenpwned.com/API/Key")
        print("Add HIBP_API_KEY to your .env or .secrets.age file")
        sys.exit(1)

    print("HaveIBeenPwned Client Test")
    print("=" * 50)

    # Test with a known breached email (test@example.com is commonly breached)
    print("\n1. Testing email check...")
    result = client.check_email("test@example.com")
    if result.get("error"):
        print(f"   Error: {result['error']}")
    else:
        print(f"   Breached: {result['breached']}")
        print(f"   Breach count: {result['breach_count']}")
        if result['breaches']:
            print(f"   Breaches: {', '.join(b.get('Name', str(b)) for b in result['breaches'][:5])}")

    print("\n" + "=" * 50)
    print("Test complete!")
