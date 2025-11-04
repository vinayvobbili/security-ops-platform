"""
Abnormal Security API Client

A Python client for interacting with the Abnormal Security API.
Provides methods for retrieving and managing email threats.
"""

import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Literal

import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from my_config import get_config

CONFIG = get_config()
logger = logging.getLogger(__name__)


class AbnormalSecurityClient:
    """Client for interacting with the Abnormal Security API."""

    def __init__(self, api_token: str, base_url: str = "https://api.abnormalplatform.com"):
        """
        Initialize the Abnormal Security API client.

        Args:
            api_token: API authentication token
            base_url: Base URL for the API (default: https://api.abnormalplatform.com)
        """
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
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
            mock_data: bool = False
    ) -> Dict[str, Any]:
        """
        Get a list of threats.

        Args:
            filter_param: Time-based filter (format: 'receivedTime gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ')
            page_size: Number of threats per page (default: 100, min: 1)
            page_number: Page number to retrieve (default: 1, min: 1)
            source: Filter by detection source ('all', 'advanced', 'attacks', 'borderline', 'spam')
            sender: Filter by sender name or email
            recipient: Filter by recipient name or email
            subject: Filter by email subject
            topic: Filter by email topic
            attack_type: Filter by type of attack
            attack_vector: Filter by attack vector
            attack_strategy: Filter by attack strategy
            impersonated_party: Filter by impersonated party
            mock_data: Return test data if True

        Returns:
            Dictionary containing paginated list of threats

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> threats = client.get_threats(
            ...     filter_param='receivedTime gte 2024-01-01T00:00:00Z lte 2024-12-31T23:59:59Z',
            ...     page_size=50,
            ...     source='attacks'
            ... )
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

        headers = {'mock-data': str(mock_data)}

        return self._make_request('GET', '/v1/threats', params=params, headers=headers)

    def get_threat_details(
            self,
            threat_id: str,
            page_size: int = 100,
            page_number: int = 1,
            mock_data: bool = False
    ) -> Dict[str, Any]:
        """
        Get detailed information about a specific threat.

        Args:
            threat_id: UUID of the threat
            page_size: Number of messages per page (default: 100, min: 1)
            page_number: Page number (default: 1, min: 1) - currently limited to 10 results
            mock_data: Return test data if True

        Returns:
            Dictionary containing threat details including messages

        Note:
            Total results cannot exceed 2000 due to database limitations.
            Currently only 10 results for messages will show, full pagination support coming soon.

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> threat = client.get_threat_details('threat-uuid-here')
        """
        params = {
            'pageSize': page_size,
            'pageNumber': page_number
        }

        headers = {'mock-data': str(mock_data)}

        return self._make_request(
            'GET',
            f'/v1/threats/{threat_id}',
            params=params,
            headers=headers
        )

    def manage_threat(
            self,
            threat_id: str,
            action: Literal['remediate', 'unremediate'],
            mock_data: bool = False
    ) -> Dict[str, Any]:
        """
        Remediate or unremediate a threat.

        Args:
            threat_id: UUID of the threat
            action: Action to perform ('remediate' or 'unremediate')
            mock_data: Return test data if True

        Returns:
            Dictionary containing actionId and status URL (202 response)

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> response = client.manage_threat('threat-uuid', 'remediate')
            >>> action_id = response['actionId']
            >>> status_url = response['statusUrl']
        """
        body = {'action': action}
        headers = {'mock-data': str(mock_data)}

        return self._make_request(
            'POST',
            f'/v1/threats/{threat_id}',
            json=body,
            headers=headers
        )

    def get_threats_by_timerange(
            self,
            start_time: datetime,
            end_time: datetime,
            **kwargs
    ) -> Dict[str, Any]:
        """
        Convenience method to get threats within a time range.

        Args:
            start_time: Start datetime
            end_time: End datetime
            **kwargs: Additional arguments passed to get_threats()

        Returns:
            Dictionary containing paginated list of threats

        Example:
            >>> from datetime import datetime, timedelta
            >>> client = AbnormalSecurityClient('your-token')
            >>> end = datetime.now()
            >>> start = end - timedelta(days=7)
            >>> threats = client.get_threats_by_timerange(start, end, source='attacks')
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
        Get all threats across multiple pages.

        Args:
            filter_param: Time-based filter (required for pagination)
            max_pages: Maximum number of pages to retrieve (None for all)
            **kwargs: Additional arguments passed to get_threats()

        Returns:
            List of all threat dictionaries

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> all_threats = client.get_all_threats(
            ...     filter_param='receivedTime gte 2024-01-01T00:00:00Z lte 2024-12-31T23:59:59Z',
            ...     source='attacks'
            ... )
        """
        all_threats = []
        page_number = 1

        while True:
            if max_pages and page_number > max_pages:
                break

            response = self.get_threats(
                filter_param=filter_param,
                page_number=page_number,
                **kwargs
            )

            threats = response.get('threats', [])
            all_threats.extend(threats)

            # Check if there are more pages
            next_page = response.get('nextPageNumber')
            if not next_page:
                break

            page_number = next_page

        return all_threats

    # Cases API Methods

    def get_cases(
            self,
            filter_param: Optional[str] = None,
            page_size: int = 100,
            page_number: int = 1,
            mock_data: bool = False
    ) -> Dict[str, Any]:
        """
        Get a list of Abnormal cases.

        Args:
            filter_param: Time-based filter (format: '{FILTER_KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ')
                         Supported filter keys: 'lastModifiedTime', 'createdTime', 'customerVisibleTime'
            page_size: Number of cases per page (default: 100, min: 1)
            page_number: Page number to retrieve (default: 1, min: 1)
            mock_data: Return test data if True

        Returns:
            Dictionary containing paginated list of cases

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> cases = client.get_cases(
            ...     filter_param='lastModifiedTime gte 2024-01-01T00:00:00Z lte 2024-12-31T23:59:59Z',
            ...     page_size=50
            ... )
        """
        params: Dict[str, Any] = {
            'pageSize': page_size,
            'pageNumber': page_number
        }

        if filter_param:
            params['filter'] = filter_param

        headers = {'mock-data': str(mock_data)}

        return self._make_request('GET', '/v1/cases', params=params, headers=headers)

    def get_case_details(
            self,
            case_id: str,
            mock_data: bool = False
    ) -> Dict[str, Any]:
        """
        Get detailed information about a specific Abnormal case.

        Args:
            case_id: ID of the case
            mock_data: Return test data if True

        Returns:
            Dictionary containing case details

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> case = client.get_case_details('case-id-here')
        """
        headers = {'mock-data': str(mock_data)}

        return self._make_request(
            'GET',
            f'/v1/cases/{case_id}',
            headers=headers
        )

    def manage_case(
            self,
            case_id: str,
            action: str,
            mock_data: bool = False
    ) -> Dict[str, Any]:
        """
        Update the status of an Abnormal case.

        Args:
            case_id: ID of the case
            action: New case status (the specific status values depend on your Abnormal Security configuration)
            mock_data: Return test data if True

        Returns:
            Dictionary containing response (202 response)

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> response = client.manage_case('case-id', 'acknowledged')
        """
        body = {'action': action}
        headers = {'mock-data': str(mock_data)}

        return self._make_request(
            'POST',
            f'/v1/cases/{case_id}',
            json=body,
            headers=headers
        )

    def get_cases_by_timerange(
            self,
            start_time: datetime,
            end_time: datetime,
            filter_key: Literal['lastModifiedTime', 'createdTime', 'customerVisibleTime'] = 'lastModifiedTime',
            **kwargs
    ) -> Dict[str, Any]:
        """
        Convenience method to get cases within a time range.

        Args:
            start_time: Start datetime
            end_time: End datetime
            filter_key: Time field to filter on ('lastModifiedTime', 'createdTime', or 'customerVisibleTime')
            **kwargs: Additional arguments passed to get_cases()

        Returns:
            Dictionary containing paginated list of cases

        Example:
            >>> from datetime import datetime, timedelta
            >>> client = AbnormalSecurityClient('your-token')
            >>> end = datetime.now()
            >>> start = end - timedelta(days=7)
            >>> cases = client.get_cases_by_timerange(start, end, filter_key='lastModifiedTime')
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
        """
        Get all cases across multiple pages.

        Args:
            filter_param: Time-based filter (required for pagination)
            max_pages: Maximum number of pages to retrieve (None for all)
            **kwargs: Additional arguments passed to get_cases()

        Returns:
            List of all case dictionaries

        Example:
            >>> client = AbnormalSecurityClient('your-token')
            >>> all_cases = client.get_all_cases(
            ...     filter_param='lastModifiedTime gte 2024-01-01T00:00:00Z lte 2024-12-31T23:59:59Z'
            ... )
        """
        all_cases = []
        page_number = 1

        while True:
            if max_pages and page_number > max_pages:
                break

            response = self.get_cases(
                filter_param=filter_param,
                page_number=page_number,
                **kwargs
            )

            cases = response.get('cases', [])
            all_cases.extend(cases)

            # Check if there are more pages
            next_page = response.get('nextPageNumber')
            if not next_page:
                break

            page_number = next_page

        return all_cases


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
    except Exception as e:
        logger.error(f"Error getting filtered threats: {e}", exc_info=True)

    logger.info("=" * 80)
    logger.info("Test suite completed")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
