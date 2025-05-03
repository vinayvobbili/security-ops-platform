#!/usr/bin/env python3
"""
Cisco AMP API Client - A comprehensive Python client for interacting with the Cisco AMP API.
"""

import json
from typing import Dict, Any

import requests

from config import get_config

BASE_URI = "https://api.amp.cisco.com/v3"
API_TOKEN_URL = "https://visibility.amp.cisco.com/iroh/oauth2/token"

CONFIG = get_config()


class CiscoAMPClient:
    """
    A Python client for interacting with the Cisco AMP API.

    This client handles authentication and provides methods for interacting
    with various endpoints of the Cisco AMP API.
    """

    def __init__(self):
        """
        Initialize the Cisco AMP API client.

        Args:
        """

        self.client_id = CONFIG.cisco_amp_client_id
        self.client_secret = CONFIG.cisco_amp_client_secret
        self.token = self.authenticate()

    def authenticate(self) -> Dict[str, Any]:
        """
        Authenticate with the Cisco AMP API and obtain an access token.

        Returns:
            Dict containing the authentication response including access_token.
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        data = {
            "grant_type": "client_credentials"
        }

        response = requests.post(
            API_TOKEN_URL,
            auth=(self.client_id, self.client_secret),
            headers=headers,
            data=data
        )

        response.raise_for_status()
        result = response.json()

        return result.get("access_token")

    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get the headers required for authenticated requests.

        Returns:
            Dict containing required headers with authentication token.
        """
        if not self.token:
            self.authenticate()

        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json"
        }

    def _make_request(self, method: str, endpoint: str, params: Dict = None, data: Dict = None) -> Dict[str, Any]:
        """
        Make a request to the Cisco AMP API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint to call
            params: URL parameters
            data: Request body data

        Returns:
            Dict containing the API response.
        """
        url = f"{BASE_URI}{endpoint}"
        headers = self.get_auth_headers()

        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=data
            )

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                # Token might have expired, try to re-authenticate once
                self.authenticate()
                headers = self.get_auth_headers()
                response = requests.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    params=params,
                    json=data
                )
                response.raise_for_status()
                return response.json()
            else:
                raise

    # Computer endpoints
    def get_computers(self, params: Dict = None) -> Dict[str, Any]:
        """
        Get a list of computers.

        Args:
            params: Optional query parameters

        Returns:
            Dict containing computer data.
        """
        return self._make_request("GET", "/v1/computers", params=params)

    def get_computer(self, computer_guid: str) -> Dict[str, Any]:
        """
        Get details for a specific computer.

        Args:
            computer_guid: The GUID of the computer

        Returns:
            Dict containing computer details.
        """
        return self._make_request("GET", f"/v1/computers/{computer_guid}")

    def get_computer_trajectory(self, computer_guid: str, params: Dict = None) -> Dict[str, Any]:
        """
        Get trajectory events for a specific computer.

        Args:
            computer_guid: The GUID of the computer
            params: Optional query parameters

        Returns:
            Dict containing trajectory events.
        """
        return self._make_request("GET", f"/v1/computers/{computer_guid}/trajectory", params=params)

    # Group endpoints
    def get_groups(self) -> Dict[str, Any]:
        """
        Get a list of groups.

        Returns:
            Dict containing group data.
        """
        return self._make_request("GET", "/v1/groups")

    def get_group(self, group_guid: str) -> Dict[str, Any]:
        """
        Get details for a specific group.

        Args:
            group_guid: The GUID of the group

        Returns:
            Dict containing group details.
        """
        return self._make_request("GET", f"/v1/groups/{group_guid}")

    # Event endpoints
    def get_events(self, params: Dict = None) -> Dict[str, Any]:
        """
        Get events.

        Args:
            params: Optional query parameters for filtering events

        Returns:
            Dict containing event data.
        """
        return self._make_request("GET", "/v1/events", params=params)

    def get_event_types(self) -> Dict[str, Any]:
        """
        Get a list of event types.

        Returns:
            Dict containing event types.
        """
        return self._make_request("GET", "/v1/event_types")

    # File endpoints
    def get_file_lists(self) -> Dict[str, Any]:
        """
        Get all file lists.

        Returns:
            Dict containing file lists.
        """
        return self._make_request("GET", "/v1/file_lists")

    def get_file_list(self, file_list_guid: str) -> Dict[str, Any]:
        """
        Get a specific file list.

        Args:
            file_list_guid: The GUID of the file list

        Returns:
            Dict containing file list details.
        """
        return self._make_request("GET", f"/v1/file_lists/{file_list_guid}")

    def get_file_list_files(self, file_list_guid: str) -> Dict[str, Any]:
        """
        Get files in a specific file list.

        Args:
            file_list_guid: The GUID of the file list

        Returns:
            Dict containing files in the list.
        """
        return self._make_request("GET", f"/v1/file_lists/{file_list_guid}/files")

    def add_file_to_list(self, file_list_guid: str, sha256: str) -> Dict[str, Any]:
        """
        Add a file to a file list.

        Args:
            file_list_guid: The GUID of the file list
            sha256: SHA256 hash of the file

        Returns:
            Dict containing API response.
        """
        data = {"sha256": sha256}
        return self._make_request("POST", f"/v1/file_lists/{file_list_guid}/files", data=data)

    def delete_file_from_list(self, file_list_guid: str, sha256: str) -> Dict[str, Any]:
        """
        Delete a file from a file list.

        Args:
            file_list_guid: The GUID of the file list
            sha256: SHA256 hash of the file

        Returns:
            Dict containing API response.
        """
        return self._make_request("DELETE", f"/v1/file_lists/{file_list_guid}/files/{sha256}")

    # Policy endpoints
    def get_policies(self) -> Dict[str, Any]:
        """
        Get all policies.

        Returns:
            Dict containing policies.
        """
        return self._make_request("GET", "/v1/policies")

    def get_policy(self, policy_guid: str) -> Dict[str, Any]:
        """
        Get a specific policy.

        Args:
            policy_guid: The GUID of the policy

        Returns:
            Dict containing policy details.
        """
        return self._make_request("GET", f"/v1/policies/{policy_guid}")

    # Vulnerability endpoints
    def get_vulnerabilities(self, params: Dict = None) -> Dict[str, Any]:
        """
        Get vulnerability data.

        Args:
            params: Optional query parameters

        Returns:
            Dict containing vulnerability data.
        """
        return self._make_request("GET", "/v1/vulnerabilities", params=params)

    # Version endpoint
    def get_version(self) -> Dict[str, Any]:
        """
        Get the API version information.

        Returns:
            Dict containing version information.
        """
        return self._make_request("GET", "/v1/version")


if __name__ == "__main__":
    client = CiscoAMPClient()

    try:

        # Example of getting computers
        computers = client.get_computers()
        print(json.dumps(computers, indent=2))

    except Exception as e:
        print(f"Error: {e}")
