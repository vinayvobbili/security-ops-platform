"""
Abnormal Security API Client

A Python client for interacting with the Abnormal Security API.
Provides methods for retrieving and managing email threats.
"""

import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Literal

import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from my_config import get_config

CONFIG = get_config()
logger = logging.getLogger(__name__)


class AbnormalSecurityError(Exception):
    """Custom exception for Abnormal Security client errors with context and suggestions."""
    def __init__(self, status_code: int, endpoint: str, detail: str, suggestions: List[str]):
        self.status_code = status_code
        self.endpoint = endpoint
        self.detail = detail
        self.suggestions = suggestions
        message = (
            f"AbnormalSecurityError {status_code} on {endpoint}: {detail}\n"
            f"Suggestions:\n - " + "\n - ".join(suggestions)
        )
        super().__init__(message)


class AbnormalSecurityClient:
    """Client for interacting with the Abnormal Security API."""

    def __init__(self, api_token: Optional[str] = None, base_url: str = "https://api.abnormalplatform.com/v1"):
        """
        Initialize the Abnormal Security API client.

        Args:
            api_token: API authentication token (if None, reads from config)
            base_url: Base URL for the API (default: https://api.abnormalplatform.com/v1)
        """
        self.api_token = api_token or CONFIG.abnormal_security_api_key
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

        if self.api_token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'IR-AbnormalSecurityClient/1.0'
            })
        else:
            logger.warning("Abnormal Security API token not configured")

    def is_configured(self) -> bool:
        """Check if the client is properly configured with an API token."""
        return bool(self.api_token)

    def _make_request(
            self,
            method: str,
            endpoint: str,
            params: Optional[Dict[str, Any]] = None,
            json: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
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
            requests.exceptions.HTTPError: For HTTP errors
        """
        url = f"{self.base_url}{endpoint}"
        logger.debug(f"Making {method} request to {url} with params: {params}")

        request_headers = {}
        if headers:
            request_headers.update(headers)

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
            request_id = response.headers.get('X-Request-ID') or response.headers.get('x-request-id')
            if request_id:
                logger.warning("API error %s for %s (request_id=%s): %s", response.status_code, endpoint, request_id, body_preview)
            else:
                logger.warning("API error %s for %s: %s", response.status_code, endpoint, body_preview)
            if response.status_code == 403:
                suggestions: List[str] = []
                try:
                    detail_json = response.json()
                    detail_msg = detail_json.get('detail') or detail_json.get('message') or body_preview
                except (ValueError, requests.exceptions.JSONDecodeError):
                    detail_msg = body_preview
                if request_id:
                    detail_msg = f"{detail_msg} (request_id={request_id})"
                suggestions.append("Verify the API token has correct permissions (Threats & Cases scopes).")
                suggestions.append("Confirm Abnormal platform API access is enabled for your tenant/account.")
                suggestions.append("Double-check you are using the production token, not a UI session token.")
                suggestions.append("Remove or simplify filters to rule out filter-based permission issues.")
                suggestions.append("If recently rotated credentials, restart process to clear old token cache.")
                suggestions.append("Ensure base_url is correct; some tenants may use region-specific host.")
                if request_id:
                    suggestions.append(f"Provide request_id {request_id} to Abnormal support for faster tracing.")
                suggestions.append("Contact Abnormal support with the timestamp and request details if issue persists.")
                raise AbnormalSecurityError(403, endpoint, detail_msg, suggestions)
        response.raise_for_status()

        # Handle 202 responses that may not have JSON
        if response.status_code == 202:
            return response.json() if response.content else {}

        return response.json()

    def get_threats(
            self,
            filter_param: Optional[str] = None,
            page_size: int = 100,
            page_number: int = 1,
            source: Literal['all', 'advanced', 'attacks', 'borderline', 'spam'] = 'all',
            sender: Optional[str] = None,
            recipient: Optional[str] = None,
            subject: Optional[str] = None,
            topic: Optional[Literal[
                'Billing Account Update',
                'Covid-19 Related Attack',
                'Cryptocurrency',
                'Invoice',
                'Invoice Inquiry'
            ]] = None,
            attack_type: Optional[Literal[
                'Internal-to-Internal Attacks (Email Account Takeover)',
                'Spam',
                'Reconnaissance',
                'Scam',
                'Social Engineering (BEC)',
                'Phishing: Credential',
                'Invoice/Payment Fraud (BEC)',
                'Malware',
                'Extortion',
                'Phishing: Sensitive Data',
                'Other'
            ]] = None,
            attack_vector: Optional[Literal[
                'Link',
                'Attachment',
                'Text',
                'Others',
                'Attachment with Zipped File'
            ]] = None,
            attack_strategy: Optional[Literal[
                'Name Impersonation',
                'Internal Compromised Email Account',
                'External Compromised Email Account',
                'Spoofed Email',
                'Unknown Sender',
                'Covid 19 Related Attack'
            ]] = None,
            impersonated_party: Optional[Literal[
                'VIP',
                'Assistants',
                'Employee (other)',
                'Brand',
                'Known Partners',
                'Automated System (Internal)',
                'Automated System (External)',
                'Unknown Partner',
                'None / Others'
            ]] = None,
    ) -> Dict[str, Any]:
        """
        Get a list of threats from the Abnormal Security API.

        NOTE: This method performs a real network call. Ensure you have a valid
        production API token configured. The mock_data parameter is deprecated
        and ignored.

        Args:
            filter_param: Time-based filter (format: 'receivedTime gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ')
            page_size: Number of threats per page (default: 100, min: 1)
            page_number: Page number to retrieve (default: 1, min: 1)
            source: Detection source filter
            sender: Filter by sender name or email
            recipient: Filter by recipient name or email
            subject: Filter by email subject
            topic: Filter by email topic
            attack_type: Filter by attack type
            attack_vector: Filter by attack vector
            attack_strategy: Filter by strategy
            impersonated_party: Filter by impersonated party

        Returns:
            Dictionary containing paginated list of threats.
        """
        params = {
            'pageSize': page_size,
            'pageNumber': page_number,
            'source': source
        }

        # Add optional parameters if provided
        if filter_param:
            params['filter'] = filter_param
        if sender:
            params['sender'] = sender
        if recipient:
            params['recipient'] = recipient
        if subject:
            params['subject'] = subject
        if topic:
            params['topic'] = topic
        if attack_type:
            params['attackType'] = attack_type
        if attack_vector:
            params['attackVector'] = attack_vector
        if attack_strategy:
            params['attackStrategy'] = attack_strategy
        if impersonated_party:
            params['impersonatedParty'] = impersonated_party

        return self._make_request('GET', '/threats', params=params)

    def get_threat_details(
            self,
            threat_id: str,
            page_size: int = 100,
            page_number: int = 1,
    ) -> Dict[str, Any]:
        """
        Get detailed information about a specific threat (real API call).

        Args:
            threat_id: UUID of the threat
            page_size: Number of messages per page
            page_number: Page number

        Returns:
            Dictionary of threat details.
        """
        params = {
            'pageSize': page_size,
            'pageNumber': page_number
        }
        return self._make_request('GET', f'/threats/{threat_id}', params=params)

    def manage_threat(
            self,
            threat_id: str,
            action: Literal['remediate', 'unremediate'],
    ) -> Dict[str, Any]:
        """
        Remediate or unremediate a threat (real API call).

        Args:
            threat_id: UUID of the threat
            action: 'remediate' or 'unremediate'

        Returns:
            202 response body containing actionId and statusUrl (if synchronous JSON provided).
        """
        body = {'action': action}
        return self._make_request('POST', f'/threats/{threat_id}', json=body)

    def get_threats_by_timerange(
            self,
            start_time: datetime,
            end_time: datetime,
            **kwargs
    ) -> Dict[str, Any]:
        """Convenience wrapper around get_threats using a time range."""
        filter_str = (
            f"receivedTime gte {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"lte {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        return self.get_threats(filter_param=filter_str, **kwargs)

    def get_all_threats(
            self,
            filter_param: str,
            max_pages: Optional[int] = None,
            **kwargs
    ) -> List[Dict[str, Any]]:
        """Paginate through all threat pages until exhaustion or max_pages."""
        all_threats: List[Dict[str, Any]] = []
        page_number = 1
        while True:
            if max_pages and page_number > max_pages:
                break
            response = self.get_threats(filter_param=filter_param, page_number=page_number, **kwargs)
            threats = response.get('threats', [])
            all_threats.extend(threats)
            next_page = response.get('nextPageNumber')
            if not next_page:
                break
            page_number = next_page
        return all_threats

    def get_cases(
            self,
            filter_param: Optional[str] = None,
            page_size: int = 100,
            page_number: int = 1,
    ) -> Dict[str, Any]:
        """Retrieve Abnormal cases."""
        params: Dict[str, Any] = {
            'pageSize': page_size,
            'pageNumber': page_number
        }
        if filter_param:
            params['filter'] = filter_param
        return self._make_request('GET', '/cases', params=params)

    def get_case_details(
            self,
            case_id: str,
    ) -> Dict[str, Any]:
        """Get details for a single case."""
        return self._make_request('GET', f'/cases/{case_id}')

    def manage_case(
            self,
            case_id: str,
            action: str,
    ) -> Dict[str, Any]:
        """Update a case status."""
        body = {'action': action}
        return self._make_request('POST', f'/cases/{case_id}', json=body)

    def get_cases_by_timerange(
            self,
            start_time: datetime,
            end_time: datetime,
            filter_key: Literal['lastModifiedTime', 'createdTime', 'customerVisibleTime'] = 'lastModifiedTime',
            **kwargs
    ) -> Dict[str, Any]:
        """Wrapper around get_cases for a time window."""
        filter_str = (
            f"{filter_key} gte {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"lte {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        return self.get_cases(filter_param=filter_str, **kwargs)

    def get_all_cases(
            self,
            filter_param: str,
            max_pages: Optional[int] = None,
            **kwargs
    ) -> List[Dict[str, Any]]:
        """Paginate through all cases matching the filter."""
        all_cases: List[Dict[str, Any]] = []
        page_number = 1
        while True:
            if max_pages and page_number > max_pages:
                break
            response = self.get_cases(filter_param=filter_param, page_number=page_number, **kwargs)
            cases = response.get('cases', [])
            all_cases.extend(cases)
            next_page = response.get('nextPageNumber')
            if not next_page:
                break
            page_number = next_page
        return all_cases

    # =========================================================================
    # Abuse Mailbox Campaign Methods
    # =========================================================================

    def get_abuse_campaigns(
            self,
            filter_param: Optional[str] = None,
            page_size: int = 100,
            page_number: int = 1
    ) -> Dict[str, Any]:
        """Get abuse mailbox campaigns.

        Args:
            filter_param: Time-based filter (format: 'receivedTime gte YYYY-MM-DDTHH:MM:SSZ')
            page_size: Number of campaigns per page
            page_number: Page number to retrieve

        Returns:
            Dictionary containing paginated list of abuse campaigns.
        """
        params: Dict[str, Any] = {
            'pageSize': page_size,
            'pageNumber': page_number
        }
        if filter_param:
            params['filter'] = filter_param
        return self._make_request('GET', '/abusecampaigns', params=params)

    def get_abuse_campaign_details(self, campaign_id: str) -> Dict[str, Any]:
        """Get details of a specific abuse mailbox campaign.

        Args:
            campaign_id: The campaign ID

        Returns:
            Dictionary with campaign details.
        """
        return self._make_request('GET', f'/abusecampaigns/{campaign_id}')

    # =========================================================================
    # Vendor Methods
    # =========================================================================

    def get_vendors(
            self,
            page_size: int = 100,
            page_number: int = 1
    ) -> Dict[str, Any]:
        """Get list of vendors.

        Args:
            page_size: Number of vendors per page
            page_number: Page number to retrieve

        Returns:
            Dictionary containing paginated list of vendors.
        """
        params = {
            'pageSize': page_size,
            'pageNumber': page_number
        }
        return self._make_request('GET', '/vendors', params=params)

    def get_vendor_details(self, vendor_domain: str) -> Dict[str, Any]:
        """Get details of a specific vendor.

        Args:
            vendor_domain: The vendor's domain

        Returns:
            Dictionary with vendor details.
        """
        return self._make_request('GET', f'/vendors/{vendor_domain}')

    def get_vendor_activity(
            self,
            vendor_domain: str,
            page_size: int = 100,
            page_number: int = 1
    ) -> Dict[str, Any]:
        """Get activity for a specific vendor.

        Args:
            vendor_domain: The vendor's domain
            page_size: Number of activities per page
            page_number: Page number to retrieve

        Returns:
            Dictionary with vendor activity.
        """
        params = {
            'pageSize': page_size,
            'pageNumber': page_number
        }
        return self._make_request('GET', f'/vendors/{vendor_domain}/activity', params=params)

    def get_vendor_cases(
            self,
            filter_param: Optional[str] = None,
            page_size: int = 100,
            page_number: int = 1
    ) -> Dict[str, Any]:
        """Get vendor-related cases.

        Args:
            filter_param: Time-based filter
            page_size: Number of cases per page
            page_number: Page number to retrieve

        Returns:
            Dictionary containing paginated list of vendor cases.
        """
        params: Dict[str, Any] = {
            'pageSize': page_size,
            'pageNumber': page_number
        }
        if filter_param:
            params['filter'] = filter_param
        return self._make_request('GET', '/vendor-cases', params=params)

    def get_vendor_case_details(self, case_id: str) -> Dict[str, Any]:
        """Get details of a specific vendor case.

        Args:
            case_id: The vendor case ID

        Returns:
            Dictionary with vendor case details.
        """
        return self._make_request('GET', f'/vendor-cases/{case_id}')

    # =========================================================================
    # Employee Methods
    # =========================================================================

    def get_employee_identity_analysis(self, email_address: str) -> Dict[str, Any]:
        """Get identity analysis for an employee.

        Args:
            email_address: The employee's email address

        Returns:
            Dictionary with identity analysis data.
        """
        return self._make_request('GET', f'/employee/{email_address}/identity')

    def get_employee_information(self, email_address: str) -> Dict[str, Any]:
        """Get information about an employee.

        Args:
            email_address: The employee's email address

        Returns:
            Dictionary with employee information.
        """
        return self._make_request('GET', f'/employee/{email_address}')

    # =========================================================================
    # Threat Intel Feed
    # =========================================================================

    def get_threat_intel_feed(self) -> Dict[str, Any]:
        """Get the latest threat intelligence feed.

        Returns:
            Dictionary with threat intel data.
        """
        return self._make_request('GET', '/threat-intel')

    # =========================================================================
    # Diagnostics
    # =========================================================================

    def diagnose_auth(self) -> Dict[str, Any]:
        """Run lightweight auth/permission diagnostics.

        Returns:
            Dict with results of minimal endpoint probes.
        """
        results: Dict[str, Any] = {}
        probes = [
            ('/threats', {'pageSize': 1, 'pageNumber': 1, 'source': 'all'}),
            ('/cases', {'pageSize': 1, 'pageNumber': 1})
        ]
        for endpoint, params in probes:
            try:
                data = self._make_request('GET', endpoint, params=params)
                results[endpoint] = {
                    'status': 'ok',
                    'keys': list(data.keys())[:10]
                }
            except AbnormalSecurityError as ase:
                results[endpoint] = {
                    'status': 'forbidden',
                    'detail': ase.detail,
                    'suggestions': ase.suggestions
                }
            except requests.HTTPError as he:
                results[endpoint] = {
                    'status': f'http_error_{he.response.status_code}',
                    'detail': str(he)
                }
            except Exception as e:
                results[endpoint] = {
                    'status': 'error',
                    'detail': str(e)
                }
        return results


if __name__ == "__main__":
    # Quick test for Abnormal Security client
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = AbnormalSecurityClient()

    if not client.is_configured():
        print("ERROR: Abnormal Security API not configured")
        print("Ensure ABNORMAL_SECURITY_API_KEY is set in .secrets.age")
        sys.exit(1)

    print("Abnormal Security Client Test")
    print("=" * 50)

    # Define time range for tests
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=7)

    # Test fetching threats
    print("\n1. Testing threats fetch (last 7 days)...")
    try:
        result = client.get_threats_by_timerange(start_time, end_time, page_size=5)
        threats = result.get("threats", [])
        print(f"   Found {len(threats)} threats")
        for t in threats[:3]:
            print(f"   - {t.get('attackType', 'Unknown')}: {t.get('subject', 'N/A')[:40]}")
    except AbnormalSecurityError as e:
        print(f"   Error: {e.detail}")

    # Test fetching cases
    print("\n2. Testing cases fetch (last 7 days)...")
    try:
        result = client.get_cases_by_timerange(start_time, end_time, page_size=5)
        cases = result.get("cases", [])
        print(f"   Found {len(cases)} cases")
        for c in cases[:3]:
            print(f"   - Case #{c.get('caseId')}: {c.get('severity')} - {c.get('caseType')}")
    except AbnormalSecurityError as e:
        print(f"   Error: {e.detail}")

    # Run diagnostics
    print("\n3. Running auth diagnostics...")
    diag = client.diagnose_auth()
    for endpoint, status in diag.items():
        print(f"   {endpoint}: {status.get('status', 'unknown')}")

    print("\n" + "=" * 50)
    print("Tests complete!")
