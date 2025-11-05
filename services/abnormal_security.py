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

    def __init__(self, api_token: str, base_url: str = "https://api.abnormalplatform.com/v1"):
        """
        Initialize the Abnormal Security API client.

        Args:
            api_token: API authentication token
            base_url: Base URL for the API (default: https://api.abnormalplatform.com/v1)
        """
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'IR-AbnormalSecurityClient/1.0'
        })

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
                except Exception:
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
            mock_data: bool = False  # deprecated, kept for backward compatibility
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
            mock_data: Deprecated (ignored)

        Returns:
            Dictionary containing paginated list of threats.

        Example (will call real API, skipped in doctest):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> threats = client.get_threats(page_size=10)  # doctest: +SKIP
            >>> len(threats.get('threats', []))  # doctest: +SKIP
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
            mock_data: bool = False  # deprecated
    ) -> Dict[str, Any]:
        """
        Get detailed information about a specific threat (real API call).

        Args:
            threat_id: UUID of the threat
            page_size: Number of messages per page
            page_number: Page number
            mock_data: Deprecated (ignored)

        Returns:
            Dictionary of threat details.

        Example (skipped):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> detail = client.get_threat_details('threat-uuid')  # doctest: +SKIP
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
            mock_data: bool = False  # deprecated
    ) -> Dict[str, Any]:
        """
        Remediate or unremediate a threat (real API call).

        Args:
            threat_id: UUID of the threat
            action: 'remediate' or 'unremediate'
            mock_data: Deprecated (ignored)

        Returns:
            202 response body containing actionId and statusUrl (if synchronous JSON provided).

        Example (skipped):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> resp = client.manage_threat('threat-uuid', 'remediate')  # doctest: +SKIP
        """
        body = {'action': action}
        return self._make_request('POST', f'/threats/{threat_id}', json=body)

    def get_threats_by_timerange(
            self,
            start_time: datetime,
            end_time: datetime,
            **kwargs
    ) -> Dict[str, Any]:
        """
        Convenience wrapper around get_threats using a time range.

        Example (skipped):
            >>> from datetime import datetime, timedelta  # doctest: +SKIP
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> end = datetime.now(timezone.utc); start = end - timedelta(days=1)  # doctest: +SKIP
            >>> client.get_threats_by_timerange(start, end)  # doctest: +SKIP
        """
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
        """
        Paginate through all threat pages until exhaustion or max_pages.

        Example (skipped):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> all_threats = client.get_all_threats('receivedTime gte 2024-01-01T00:00:00Z lte 2024-01-02T00:00:00Z')  # doctest: +SKIP
        """
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
            mock_data: bool = False  # deprecated
    ) -> Dict[str, Any]:
        """
        Retrieve Abnormal cases (real API call).

        Example (skipped):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> client.get_cases(page_size=10)  # doctest: +SKIP
        """
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
            mock_data: bool = False  # deprecated
    ) -> Dict[str, Any]:
        """Get details for a single case (real API).

        Example (skipped):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> client.get_case_details('case-id')  # doctest: +SKIP
        """
        return self._make_request('GET', f'/cases/{case_id}')

    def manage_case(
            self,
            case_id: str,
            action: str,
            mock_data: bool = False  # deprecated
    ) -> Dict[str, Any]:
        """Update a case status (real API call).

        Example (skipped):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> client.manage_case('case-id', 'acknowledged')  # doctest: +SKIP
        """
        body = {'action': action}
        return self._make_request('POST', f'/cases/{case_id}', json=body)

    def get_cases_by_timerange(
            self,
            start_time: datetime,
            end_time: datetime,
            filter_key: Literal['lastModifiedTime', 'createdTime', 'customerVisibleTime'] = 'lastModifiedTime',
            **kwargs
    ) -> Dict[str, Any]:
        """Wrapper around get_cases for a time window.

        Example (skipped):
            >>> from datetime import datetime, timedelta  # doctest: +SKIP
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> end = datetime.now(timezone.utc); start = end - timedelta(days=1)  # doctest: +SKIP
            >>> client.get_cases_by_timerange(start, end)  # doctest: +SKIP
        """
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
        """Paginate through all cases matching the filter.

        Example (skipped):
            >>> client = AbnormalSecurityClient('real-token')  # doctest: +SKIP
            >>> client.get_all_cases('lastModifiedTime gte 2024-01-01T00:00:00Z lte 2024-01-02T00:00:00Z')  # doctest: +SKIP
        """
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


def main():
    """
    Main method for testing the Abnormal Security client.

    Examples of how to use the client with various methods.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if not CONFIG.abnormal_security_api_key:
        logger.error("ABNORMAL_SECURITY_API_KEY not found in configuration")
        logger.error("Please ensure your .secrets.age file contains the API key")
        return

    client = AbnormalSecurityClient(CONFIG.abnormal_security_api_key)

    logger.info("=" * 80)
    logger.info("Abnormal Security API Client - Test Suite")
    logger.info("=" * 80)

    # Define time range for tests (last 7 days)
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)

    # Test 1: Get recent threats
    logger.info("Test 1: Getting threats from the last 7 days...")
    try:
        threats_response = client.get_threats_by_timerange(
            start_time=start_time,
            end_time=end_time,
            page_size=10
        )

        threats = threats_response.get('threats', [])
        logger.info(f"Found {len(threats)} threats")

        if threats:
            logger.info(f"First threat ID: {threats[0].get('threatId', 'N/A')}")

            # Test 2: Get details for the first threat
            logger.info("Test 2: Getting details for first threat...")
            threat_id = threats[0].get('threatId')
            if threat_id:
                threat_details = client.get_threat_details(threat_id)
                logger.info("Retrieved threat details")
                logger.info(f"  Attack Type: {threat_details.get('attackType', 'N/A')}")
                logger.info(f"  Subject: {threat_details.get('subject', 'N/A')}")
                logger.info(f"  Sender: {threat_details.get('fromAddress', 'N/A')}")
    except AbnormalSecurityError as ase:
        logger.error(str(ase))
        logger.info("Running auth diagnostics after 403...")
        diag = client.diagnose_auth()
        logger.info(f"Diagnostics: {diag}")
    except Exception as e:
        logger.error(f"Error getting threats: {e}", exc_info=True)

    # Test 3: Get recent cases
    logger.info("Test 3: Getting cases from the last 7 days...")
    try:
        cases_response = client.get_cases_by_timerange(
            start_time=start_time,
            end_time=end_time,
            filter_key='lastModifiedTime',
            page_size=10
        )

        cases = cases_response.get('cases', [])
        logger.info(f"Found {len(cases)} cases")

        if cases:
            logger.info(f"First case ID: {cases[0].get('caseId', 'N/A')}")

            # Test 4: Get details for the first case
            logger.info("Test 4: Getting details for first case...")
            case_id = cases[0].get('caseId')
            if case_id:
                case_details = client.get_case_details(case_id)
                logger.info("Retrieved case details")
                logger.info(f"  Severity: {case_details.get('severity', 'N/A')}")
                logger.info(f"  Status: {case_details.get('status', 'N/A')}")
    except AbnormalSecurityError as ase:
        logger.error(str(ase))
        logger.info("Running auth diagnostics after 403 on cases...")
        diag = client.diagnose_auth()
        logger.info(f"Diagnostics: {diag}")
    except Exception as e:
        logger.error(f"Error getting cases: {e}", exc_info=True)

    # Test 5: Get threats with specific filters
    logger.info("Test 5: Getting threats with filters (attacks only)...")
    try:
        filter_str = (
            f"receivedTime gte {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"lte {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )

        filtered_threats = client.get_threats(
            filter_param=filter_str,
            source='attacks',
            page_size=5
        )

        attack_threats = filtered_threats.get('threats', [])
        logger.info(f"Found {len(attack_threats)} attack threats")
    except AbnormalSecurityError as ase:
        logger.error(str(ase))
    except Exception as e:
        logger.error(f"Error getting filtered threats: {e}", exc_info=True)

    logger.info("=" * 80)
    logger.info("Test suite completed")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
