import json
from typing import Optional, Dict, Any

import requests


class CiscoSecureEndpointClient:
    def __init__(self, client_id: str, api_key: str, base_url: str = "https://api.amp.cisco.com/v1", token_url: str = "https://api.amp.cisco.com/v3/access_token"):
        """
        Initialize the Cisco Secure Endpoint API client.

        Args:
            client_id (str): Client ID for API authentication.
            api_key (str): API Key for API authentication.
            base_url (str): Base URL for the Cisco Secure Endpoint API.
            token_url (str): URL for the token endpoint.
        """
        self.base_url = base_url
        self.token_url = token_url
        self.client_id = client_id
        self.api_key = api_key
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        self._log_public_ip()
        self._authenticate()

    def _log_public_ip(self) -> None:
        """
        Log the current public IP address for debugging.
        """
        try:
            response = requests.get("https://api.ipify.org")
            response.raise_for_status()
            print(f"Current public IP: {response.text}")
        except requests.exceptions.RequestException as err:
            print(f"Failed to get public IP: {err}")

    def _authenticate(self) -> None:
        """
        Retrieve a bearer token and update headers.
        """
        token = self._get_bearer_token()
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        else:
            raise ValueError("Failed to authenticate: Could not obtain bearer token")

    def _get_bearer_token(self) -> Optional[str]:
        """
        Retrieve a bearer token using Client ID and API Key.

        Returns:
            Optional[str]: Bearer token if successful, None otherwise.
        """
        auth = (self.client_id, self.api_key)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        data = {"grant_type": "client_credentials"}

        print(f"Requesting token from: {self.token_url}")
        print(f"Headers: {headers}")
        print(f"Data: {data}")
        print(f"Auth: ({self.client_id}, [redacted])")

        try:
            response = requests.post(self.token_url, headers=headers, auth=auth, data=data)
            response.raise_for_status()
            return response.json().get("access_token")
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
            try:
                error_details = response.json()
                print(f"Error details: {json.dumps(error_details, indent=2)}")
            except ValueError:
                print(f"Raw response: {response.text}")
            return None
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
            return None

    def get_computer_details(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve computer details for a given hostname.

        Args:
            hostname (str): Hostname of the computer to query.

        Returns:
            Optional[Dict[str, Any]]: Computer details if found, None otherwise.
        """
        endpoint = f"{self.base_url}/computers"
        params = {"hostname": hostname}

        try:
            response = requests.get(endpoint, headers=self.headers, params=params)
            response.raise_for_status()

            data = response.json()
            computers = data.get("data", [])

            if not computers:
                print(f"No computers found for hostname: {hostname}")
                return None

            # Assuming the first match is the desired computer
            computer = computers[0]
            return computer

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
            return None
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
            return None
        except ValueError as json_err:
            print(f"JSON decode error: {json_err}")
            return None

    def check_isolation_status(self, computer: Dict[str, Any]) -> bool:
        """
        Check if the computer is network isolated.

        Args:
            computer (Dict[str, Any]): Computer details from API response.

        Returns:
            bool: True if isolated, False otherwise.
        """
        return computer.get("network_isolation", False)


def main():
    # Replace with your actual Client ID and API Key
    CLIENT_ID = "your_client_id_here"
    API_KEY = "your_api_key_here"

    # Initialize the client
    try:
        client = CiscoSecureEndpointClient(
            client_id=CLIENT_ID,
            api_key=API_KEY,
            token_url="https://visibility.amp.cisco.com/iroh/oauth2/token",  # Use for SecureX
            # token_url="https://api.amp.cisco.com/v3/access_token",  # Uncomment for Secure Endpoint
            # base_url="https://api.eu.amp.cisco.com/v1"  # Example for EU region
        )
    except ValueError as e:
        print(e)
        return

    # Specify the hostname to query
    hostname = "example-host"

    # Get computer details
    computer_details = client.get_computer_details(hostname)

    if computer_details:
        print("Computer Details:")
        print(json.dumps(computer_details, indent=2))

        # Check isolation status
        is_isolated = client.check_isolation_status(computer_details)
        print(f"Is {hostname} isolated? {'Yes' if is_isolated else 'No'}")
    else:
        print("Failed to retrieve computer details.")


if __name__ == "__main__":
    main()
