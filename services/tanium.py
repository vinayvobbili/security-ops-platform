#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers

Usage:
    client = TaniumClient("https://tanium-server.com", "api-token")
    computers = client.get_computers()
"""

import requests
from dataclasses import dataclass
from typing import List, Optional

from config import get_config

CONFIG = get_config()


@dataclass
class Computer:
    id: str
    name: str
    os: Optional[str] = None
    ip: Optional[str] = None
    online: bool = False
    tags: List[str] = None


class TaniumClient:
    def __init__(self, server_url: str, token: str = None):
        self.server_url = server_url.rstrip('/')
        self.token = token
        # Use 'session' header for Tanium API Gateway (GraphQL), as required
        self.headers = {'session': token} if token else {}

    def login(self, username: str, password: str):
        print("WARNING: login() is not supported for GraphQL API. Use an API token and the session header.")
        raise NotImplementedError("Session login is not supported for Tanium API Gateway/GraphQL. Use an API token.")

    def query(self, gql: str):
        r = requests.post(f"{self.server_url}/plugin/products/gateway/graphql",
                          json={'query': gql}, headers=self.headers)
        try:
            r.raise_for_status()
            return r.json()
        except requests.exceptions.HTTPError as e:
            if r.status_code == 401:
                print("ERROR: Unauthorized (401). Please check your Tanium API token or login credentials.")
            else:
                print(f"HTTP error: {e}\nResponse: {r.text}")
            raise
        except requests.exceptions.JSONDecodeError:
            print(f"Non-JSON response received: {r.text}")
            raise

    def get_computers(self, limit: int = 10) -> List[Computer]:
        computers = []
        cursor = None
        count = 0

        while True:
            after = f'(after: "{cursor}")' if cursor else ""
            gql = f"""
            {{
                endpoints{after} {{
                    pageInfo {{ endCursor hasNextPage }}
                    edges {{
                        node {{
                            id
                            name
                            ipAddress
                            ipAddresses
                            macAddresses
                            lastLoggedInUser
                            isVirtual
                            isEncrypted
                            serialNumber
                            manufacturer
                            model
                        }}
                    }}
                }}
            }}
            """

            data = self.query(gql)['data']['endpoints']

            for edge in data['edges']:
                node = edge['node']
                computers.append(Computer(
                    id=node.get('id', ""),
                    name=node.get('name'),
                    os=node.get('os'),
                    ip=node.get('ipAddress'),
                    online=node.get('isVirtual', False),
                    tags=node.get('macAddresses', []),  # Use macAddresses as a sample list field
                ))
                count += 1
                if count >= limit:
                    return computers

            if not data['pageInfo']['hasNextPage']:
                break
            cursor = data['pageInfo']['endCursor']

        return computers

    def get_computer(self, name: str):
        """
        Fetch details for a specific computer by name.
        :param name: The computer name to search for.
        :return: The computer details as a dict, or None if not found.
        """
        computers = self.get_computers(limit=500)
        for c in computers:
            if c.name == name:
                return c.__dict__
        return None

    def introspect_endpoint_fields(self):
        """
        Query the GraphQL schema to list all available fields for the Endpoint type.
        """
        introspection_query = '''
        { __type(name: "Endpoint") {
            name
            fields { name type { name kind ofType { name kind } } }
        }}
        '''
        result = self.query(introspection_query)
        fields = result.get('data', {}).get('__type', {}).get('fields', [])
        print("Available fields for Endpoint:")
        for field in fields:
            print(f"- {field['name']}")
        return fields


def validateToken(ts: str, token: str):
    """
    Example function of how to validate that an API token is able
    to hit the Tanium server and get a 200 response.

    parameter ts is the Tanium server to use.
    Example: 'https://MyTaniumServer.com'
    parameter token is the api token string generated from the ts gui.
    """
    r = requests.post(f"{ts}/api/v2/session/validate",
                      json={'session': token},
                      headers={'session': token}
                      )
    # status_code should be 200 on successful validation of token.
    print(f"Status code from validating token: {r.status_code}.")


def query_with_session(ts: str, api_gateway_url: str, session_token: str, gql_query: str):
    """
    Makes a POST request to the Tanium API Gateway GraphQL endpoint using the session token in the 'session' header.
    :param ts: The Tanium server URL (e.g., 'https://my-company.cloud.tanium.com')
    :param api_gateway_url: The API Gateway GraphQL endpoint (e.g., 'https://my-company-API.cloud.tanium.com/plugin/products/gateway/graphql')
    :param session_token: The session token string (e.g., 'token-RedactedApiKey')
    :param gql_query: The GraphQL query string (e.g., '{ now }')
    :return: The response JSON or error message
    """
    headers = {
        'Content-type': 'application/json',
        'session': session_token,
        'tanium_server': ts
    }
    body = {'query': gql_query}
    r = requests.post(api_gateway_url, json=body, headers=headers)
    print(f"Status code: {r.status_code}")
    try:
        print(r.json())
        return r.json()
    except Exception:
        print(r.text)
        return r.text


# Example usage
if __name__ == "__main__":
    client = TaniumClient("https://metportal-api.cloud.tanium.com", CONFIG.tanium_api_token)
    computers = client.get_computers()

    # Print the raw details of each computer (as dict)
    for c in computers:
        print(c.__dict__)

    # Fetch and print details for a specific computer
    specific_name = "US4DC8974.internal.company.com"
    details = client.get_computer(specific_name)
    print(f"Details for {specific_name}: {details}")

    # Introspect and print all available fields for the Endpoint type
    print("\n--- Available fields for Endpoint ---")
    client.introspect_endpoint_fields()
    print("\nTo fetch more data points, add the desired field names to your GraphQL query in get_computers or get_computer.")
