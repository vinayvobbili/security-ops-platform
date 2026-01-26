"""
Zscaler Internet Access (ZIA) API Client

A Python client for interacting with the Zscaler ZIA API.
Provides methods for URL lookup, sandbox reports, and security operations.
"""

import logging
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from my_config import get_config

CONFIG = get_config()
logger = logging.getLogger(__name__)


class ZscalerError(Exception):
    """Custom exception for Zscaler client errors with context and suggestions."""
    def __init__(self, status_code: int, endpoint: str, detail: str, suggestions: List[str]):
        self.status_code = status_code
        self.endpoint = endpoint
        self.detail = detail
        self.suggestions = suggestions
        message = (
            f"ZscalerError {status_code} on {endpoint}: {detail}\n"
            f"Suggestions:\n - " + "\n - ".join(suggestions)
        )
        super().__init__(message)


class ZscalerClient:
    """Client for interacting with the Zscaler ZIA API."""

    # Cloud name to base URL mapping
    CLOUD_URLS = {
        "zscaler": "https://zsapi.zscaler.net",
        "zscalerone": "https://zsapi.zscalerone.net",
        "zscalertwo": "https://zsapi.zscalertwo.net",
        "zscalerthree": "https://zsapi.zscalerthree.net",
        "zscloud": "https://zsapi.zscloud.net",
        "zscalerbeta": "https://zsapi.zscalerbeta.net",
        "zscalergov": "https://zsapi.zscalergov.net",
        "zscalerten": "https://zsapi.zscalerten.net",
    }

    def __init__(
            self,
            username: Optional[str] = None,
            password: Optional[str] = None,
            api_key: Optional[str] = None,
            base_url: Optional[str] = None,
            cloud: Optional[str] = None
    ):
        """
        Initialize the Zscaler ZIA API client.

        Args:
            username: ZIA admin username (if None, reads from config)
            password: ZIA admin password (if None, reads from config)
            api_key: ZIA API key (if None, reads from config)
            base_url: Base URL for the API (if None, derived from cloud or config)
            cloud: Cloud name (e.g., 'zscaler', 'zscalerone', 'zscloud')
        """
        self.username = username or CONFIG.zscaler_username
        self.password = password or CONFIG.zscaler_password
        self.api_key = api_key or CONFIG.zscaler_api_key

        # Determine base URL
        if base_url:
            self.base_url = base_url.rstrip('/')
        elif cloud and cloud.lower() in self.CLOUD_URLS:
            self.base_url = self.CLOUD_URLS[cloud.lower()]
        elif CONFIG.zscaler_base_url:
            self.base_url = CONFIG.zscaler_base_url.rstrip('/')
        else:
            # Default to zscalertwo cloud
            self.base_url = self.CLOUD_URLS["zscalertwo"]

        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'IR-ZscalerClient/1.0'
        })

        self._authenticated = False
        self._session_expires = None

        if not all([self.username, self.password, self.api_key]):
            logger.warning("Zscaler API credentials not fully configured")

    def is_configured(self) -> bool:
        """Check if the client is properly configured with credentials."""
        return bool(self.username and self.password and self.api_key)

    def _obfuscate_api_key(self) -> tuple[str, str]:
        """
        Obfuscate the API key using Zscaler's timestamp-based method.

        Returns:
            Tuple of (obfuscated_key, timestamp)
        """
        now = int(time.time() * 1000)
        timestamp = str(now)

        # Get the last 6 characters of timestamp
        n = timestamp[-6:]

        # Rearrange API key based on timestamp digits
        r = ""
        for i, char in enumerate(n):
            j = int(char)
            if j == 0:
                j = 10
            r += self.api_key[i:i+1] + self.api_key[j + i:j + i + 1]

        # Pad to ensure proper length
        r += self.api_key[len(r):len(self.api_key)]

        return r, timestamp

    def authenticate(self) -> bool:
        """
        Authenticate with the Zscaler ZIA API.

        Returns:
            True if authentication successful, False otherwise.
        """
        if not self.is_configured():
            logger.error("Cannot authenticate: credentials not configured")
            return False

        obfuscated_key, timestamp = self._obfuscate_api_key()

        payload = {
            "apiKey": obfuscated_key,
            "username": self.username,
            "password": self.password,
            "timestamp": timestamp
        }

        try:
            url = f"{self.base_url}/api/v1/authenticatedSession"
            logger.debug(f"Authenticating to Zscaler at {url}")

            response = self.session.post(url, json=payload)

            if response.status_code == 200:
                self._authenticated = True
                # Session typically valid for 30 minutes
                self._session_expires = time.time() + (25 * 60)
                logger.info("Zscaler authentication successful")
                return True
            else:
                logger.error(f"Zscaler authentication failed: {response.status_code} - {response.text}")
                self._authenticated = False
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Zscaler authentication error: {e}")
            return False

    def _ensure_authenticated(self) -> None:
        """Ensure we have a valid session, re-authenticating if needed."""
        if not self._authenticated or (self._session_expires and time.time() > self._session_expires):
            if not self.authenticate():
                raise ZscalerError(
                    401,
                    "/api/v1/authenticatedSession",
                    "Failed to authenticate with Zscaler",
                    [
                        "Verify username and password are correct",
                        "Check that API key is valid and not expired",
                        "Ensure the base URL matches your Zscaler cloud",
                        "Confirm API access is enabled for your account"
                    ]
                )

    def logout(self) -> bool:
        """
        End the authenticated session.

        Returns:
            True if logout successful.
        """
        if not self._authenticated:
            return True

        try:
            response = self.session.delete(f"{self.base_url}/api/v1/authenticatedSession")
            self._authenticated = False
            self._session_expires = None
            return response.status_code == 200
        except requests.exceptions.RequestException:
            self._authenticated = False
            return False

    def _make_request(
            self,
            method: str,
            endpoint: str,
            params: Optional[Dict[str, Any]] = None,
            json: Any = None,
            headers: Optional[Dict[str, str]] = None
    ) -> Any:
        """
        Make an HTTP request to the API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            params: Query parameters
            json: JSON body for POST requests
            headers: Additional headers

        Returns:
            Response data as dictionary

        Raises:
            ZscalerError: For API errors
        """
        self._ensure_authenticated()

        url = f"{self.base_url}{endpoint}"
        logger.debug(f"Making {method} request to {url} with params: {params}")

        request_headers = {}
        if headers:
            request_headers.update(headers)

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json,
                headers=request_headers
            )

            logger.debug(f"Response status: {response.status_code}")

            if response.status_code >= 400:
                body_preview = response.text[:500]
                logger.warning(f"API error {response.status_code} for {endpoint}: {body_preview}")

                if response.status_code == 401:
                    # Session expired, clear auth state
                    self._authenticated = False
                    suggestions = [
                        "Session may have expired - retrying will re-authenticate",
                        "Verify credentials are still valid",
                        "Check if account is locked"
                    ]
                    raise ZscalerError(401, endpoint, body_preview, suggestions)

                if response.status_code == 403:
                    suggestions = [
                        "Verify API access is enabled for your account",
                        "Check that your role has permission for this operation",
                        "Confirm you're using the correct cloud instance"
                    ]
                    raise ZscalerError(403, endpoint, body_preview, suggestions)

                if response.status_code == 429:
                    suggestions = [
                        "Rate limit exceeded - wait before retrying",
                        "Reduce request frequency",
                        "Consider implementing exponential backoff"
                    ]
                    raise ZscalerError(429, endpoint, body_preview, suggestions)

                suggestions = ["Check the API documentation for this endpoint"]
                raise ZscalerError(response.status_code, endpoint, body_preview, suggestions)

            response.raise_for_status()

            # Some endpoints return empty responses
            if not response.content:
                return {}

            return response.json()

        except ZscalerError:
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {endpoint}: {e}")
            raise ZscalerError(
                0, endpoint, str(e),
                ["Check network connectivity", "Verify the Zscaler base URL is correct"]
            )

    # =========================================================================
    # URL Lookup Methods
    # =========================================================================

    def url_lookup(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Look up the categorization of one or more URLs.

        Args:
            urls: List of URLs to look up (max 100)

        Returns:
            List of URL categorization results.
        """
        if not urls:
            return []

        # API limit is 100 URLs per request
        urls = urls[:100]

        return self._make_request('POST', '/api/v1/urlLookup', json=urls)

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Look up categorization for a single URL.

        Args:
            url: URL to look up

        Returns:
            URL categorization result.
        """
        results = self.url_lookup([url])
        return results[0] if results else {}

    # =========================================================================
    # Sandbox Methods
    # =========================================================================

    def get_sandbox_report(
            self,
            md5_hash: str,
            report_type: str = "full"
    ) -> Dict[str, Any]:
        """
        Get sandbox analysis report for a file by MD5 hash.

        Args:
            md5_hash: MD5 hash of the file
            report_type: 'full' or 'summary'

        Returns:
            Sandbox analysis report.
        """
        md5_hash = md5_hash.lower().strip()
        endpoint = f"/api/v1/sandbox/report/{md5_hash}"
        params = {"details": report_type}
        return self._make_request('GET', endpoint, params=params)

    def get_sandbox_quota(self) -> Dict[str, Any]:
        """
        Get sandbox submission quota information.

        Returns:
            Quota information including used/allowed submissions.
        """
        return self._make_request('GET', '/api/v1/sandbox/report/quota')

    # =========================================================================
    # URL Categories Methods
    # =========================================================================

    def get_url_categories(self, custom_only: bool = False) -> List[Dict[str, Any]]:
        """
        Get URL categories.

        Args:
            custom_only: If True, return only custom categories

        Returns:
            List of URL categories.
        """
        params = {}
        if custom_only:
            params['customOnly'] = 'true'

        return self._make_request('GET', '/api/v1/urlCategories', params=params)

    def get_url_category(self, category_id: str) -> Dict[str, Any]:
        """
        Get a specific URL category by ID.

        Args:
            category_id: Category ID

        Returns:
            URL category details.
        """
        return self._make_request('GET', f'/api/v1/urlCategories/{category_id}')

    # =========================================================================
    # Security Policy Methods
    # =========================================================================

    def get_security_policy_settings(self) -> Dict[str, Any]:
        """
        Get security policy settings.

        Returns:
            Security policy settings.
        """
        return self._make_request('GET', '/api/v1/security')

    def get_advanced_settings(self) -> Dict[str, Any]:
        """
        Get advanced security settings.

        Returns:
            Advanced security settings.
        """
        return self._make_request('GET', '/api/v1/advancedSettings')

    # =========================================================================
    # User and Group Methods
    # =========================================================================

    def get_users(
            self,
            search: Optional[str] = None,
            dept: Optional[str] = None,
            group: Optional[str] = None,
            page: int = 1,
            page_size: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get users.

        Args:
            search: Search string for username or email
            dept: Filter by department
            group: Filter by group
            page: Page number
            page_size: Results per page

        Returns:
            List of users.
        """
        params: Dict[str, Any] = {
            'page': page,
            'pageSize': min(page_size, 1000)
        }
        if search:
            params['search'] = search
        if dept:
            params['dept'] = dept
        if group:
            params['group'] = group

        return self._make_request('GET', '/api/v1/users', params=params)

    def get_user(self, user_id: int) -> Dict[str, Any]:
        """
        Get a specific user by ID.

        Args:
            user_id: User ID

        Returns:
            User details.
        """
        return self._make_request('GET', f'/api/v1/users/{user_id}')

    def get_departments(self) -> List[Dict[str, Any]]:
        """
        Get all departments.

        Returns:
            List of departments.
        """
        return self._make_request('GET', '/api/v1/departments')

    def get_groups(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get groups.

        Args:
            search: Search string for group name

        Returns:
            List of groups.
        """
        params = {}
        if search:
            params['search'] = search

        return self._make_request('GET', '/api/v1/groups', params=params)

    # =========================================================================
    # Blocklist Methods
    # =========================================================================

    def get_url_blocklist(self) -> Dict[str, Any]:
        """
        Get the URL blocklist.

        Returns:
            Blocklist configuration with URLs.
        """
        return self._make_request('GET', '/api/v1/security/advanced')

    def add_urls_to_blocklist(self, urls: List[str]) -> Dict[str, Any]:
        """
        Add URLs to the blocklist.

        Args:
            urls: List of URLs to block

        Returns:
            Updated blocklist.
        """
        current = self.get_url_blocklist()
        current_urls = current.get('blacklistUrls', [])

        # Add new URLs, avoiding duplicates
        updated_urls = list(set(current_urls + urls))

        payload = {
            'blacklistUrls': updated_urls
        }

        return self._make_request('PUT', '/api/v1/security/advanced', json=payload)

    def remove_urls_from_blocklist(self, urls: List[str]) -> Dict[str, Any]:
        """
        Remove URLs from the blocklist.

        Args:
            urls: List of URLs to unblock

        Returns:
            Updated blocklist.
        """
        current = self.get_url_blocklist()
        current_urls = current.get('blacklistUrls', [])

        # Remove specified URLs
        urls_to_remove = set(url.lower() for url in urls)
        updated_urls = [u for u in current_urls if u.lower() not in urls_to_remove]

        payload = {
            'blacklistUrls': updated_urls
        }

        return self._make_request('PUT', '/api/v1/security/advanced', json=payload)

    # =========================================================================
    # Web Application Control
    # =========================================================================

    def get_web_application_rules(self) -> List[Dict[str, Any]]:
        """
        Get web application control rules.

        Returns:
            List of web application rules.
        """
        return self._make_request('GET', '/api/v1/webApplicationRules')

    # =========================================================================
    # Firewall Methods
    # =========================================================================

    def get_firewall_rules(self) -> List[Dict[str, Any]]:
        """
        Get cloud firewall rules.

        Returns:
            List of firewall rules.
        """
        return self._make_request('GET', '/api/v1/firewallRules')

    def get_ip_destination_groups(self) -> List[Dict[str, Any]]:
        """
        Get IP destination groups.

        Returns:
            List of IP destination groups.
        """
        return self._make_request('GET', '/api/v1/ipDestinationGroups')

    def get_ip_source_groups(self) -> List[Dict[str, Any]]:
        """
        Get IP source groups.

        Returns:
            List of IP source groups.
        """
        return self._make_request('GET', '/api/v1/ipSourceGroups')

    # =========================================================================
    # Status and Activation
    # =========================================================================

    def get_status(self) -> Dict[str, Any]:
        """
        Get the current activation status.

        Returns:
            Status information.
        """
        return self._make_request('GET', '/api/v1/status')

    def activate_changes(self) -> Dict[str, Any]:
        """
        Activate pending configuration changes.

        Returns:
            Activation status.
        """
        return self._make_request('POST', '/api/v1/status/activate')

    # =========================================================================
    # Diagnostics
    # =========================================================================

    def diagnose_auth(self) -> Dict[str, Any]:
        """
        Run lightweight auth/permission diagnostics.

        Returns:
            Dict with results of minimal endpoint probes.
        """
        results: Dict[str, Any] = {}

        # First test authentication
        try:
            if self.authenticate():
                results['authentication'] = {'status': 'ok'}
            else:
                results['authentication'] = {'status': 'failed'}
                return results
        except Exception as e:
            results['authentication'] = {
                'status': 'error',
                'detail': str(e)
            }
            return results

        # Test various endpoints
        probes = [
            ('/api/v1/status', None),
            ('/api/v1/urlCategories', {'customOnly': 'true'}),
        ]

        for endpoint, params in probes:
            try:
                data = self._make_request('GET', endpoint, params=params)
                results[endpoint] = {
                    'status': 'ok',
                    'keys': list(data.keys())[:10] if isinstance(data, dict) else f'{len(data)} items'
                }
            except ZscalerError as ze:
                results[endpoint] = {
                    'status': f'error_{ze.status_code}',
                    'detail': ze.detail[:200]
                }
            except Exception as e:
                results[endpoint] = {
                    'status': 'error',
                    'detail': str(e)[:200]
                }

        return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = ZscalerClient()

    if not client.is_configured():
        print("ERROR: Zscaler API not configured")
        print("Ensure ZSCALER_USERNAME, ZSCALER_PASSWORD, and ZSCALER_API_KEY are set in .secrets.age")
        sys.exit(1)

    print("Zscaler Client Test")
    print("=" * 50)

    # Test authentication
    print("\n1. Testing authentication...")
    try:
        if client.authenticate():
            print("   Authentication successful!")
        else:
            print("   Authentication failed")
            sys.exit(1)
    except ZscalerError as e:
        print(f"   Error: {e.detail}")
        sys.exit(1)

    # Test URL lookup
    print("\n2. Testing URL lookup...")
    try:
        test_urls = ["google.com", "facebook.com"]
        results = client.url_lookup(test_urls)
        for result in results:
            url = result.get('url', 'Unknown')
            categories = result.get('urlClassifications', [])
            print(f"   {url}: {', '.join(categories) if categories else 'No categories'}")
    except ZscalerError as e:
        print(f"   Error: {e.detail}")

    # Test getting URL categories
    print("\n3. Testing URL categories...")
    try:
        categories = client.get_url_categories(custom_only=True)
        if isinstance(categories, list):
            print(f"   Found {len(categories)} custom categories")
            for cat in categories[:3]:
                print(f"   - {cat.get('configuredName', 'Unknown')}")
        else:
            print(f"   Response: {categories}")
    except ZscalerError as e:
        print(f"   Error: {e.detail}")

    # Test status
    print("\n4. Testing status...")
    try:
        status = client.get_status()
        print(f"   Status: {status}")
    except ZscalerError as e:
        print(f"   Error: {e.detail}")

    # Run diagnostics
    print("\n5. Running auth diagnostics...")
    diag = client.diagnose_auth()
    for endpoint, status in diag.items():
        print(f"   {endpoint}: {status.get('status', 'unknown')}")

    # Logout
    print("\n6. Logging out...")
    client.logout()
    print("   Done!")

    print("\n" + "=" * 50)
    print("Tests complete!")
