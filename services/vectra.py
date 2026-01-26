"""
Vectra AI API Client

Provides integration with Vectra AI NDR platform for threat detection and response.
Supports querying detections, entities (hosts/accounts), and assignments.
"""

import base64
import logging
from typing import Optional, Dict, Any, List

import requests

from my_config import get_config

logger = logging.getLogger(__name__)


class VectraClient:
    """Client for interacting with the Vectra AI API."""

    def __init__(self):
        self.config = get_config()
        self._base_url = self.config.vectra_api_base_url
        self._client_id = self.config.vectra_client_id
        self._api_key = self.config.vectra_api_key
        self._access_token: Optional[str] = None
        self.timeout = 30

        # Build the full base URL if needed
        if self._base_url and not self._base_url.startswith("http"):
            self._base_url = f"https://{self._base_url}"

        if not self._base_url or not self._client_id or not self._api_key:
            logger.warning("Vectra API not fully configured (missing URL, client ID, or API key)")

    def is_configured(self) -> bool:
        """Check if the client is properly configured."""
        return bool(self._base_url and self._client_id and self._api_key)

    def _get_access_token(self) -> Optional[str]:
        """Get OAuth2 access token using client credentials with Basic auth."""
        if not self.is_configured():
            return None

        if self._access_token:
            return self._access_token

        try:
            auth_url = f"{self._base_url}/oauth2/token"

            # Vectra requires Basic auth header with client_id:client_secret
            auth_string = base64.b64encode(
                f"{self._client_id}:{self._api_key}".encode()
            ).decode()

            headers = {
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            data = "grant_type=client_credentials"

            logger.debug(f"Requesting Vectra access token from {auth_url}")
            response = requests.post(auth_url, headers=headers, data=data, timeout=self.timeout)
            response.raise_for_status()

            token_data = response.json()
            self._access_token = token_data.get("access_token")
            logger.info("Successfully obtained Vectra access token")
            return self._access_token

        except requests.exceptions.HTTPError as e:
            logger.error(f"Vectra authentication failed: {e.response.status_code}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Vectra authentication request failed: {e}")
            return None

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make authenticated request to Vectra API.

        Args:
            endpoint: API endpoint path (e.g., "/api/v3.3/detections")
            method: HTTP method
            params: Query parameters
            data: Request body for POST/PUT
        """
        if not self.is_configured():
            return {"error": "Vectra API not configured (missing URL, client ID, or API key)"}

        token = self._get_access_token()
        if not token:
            return {"error": "Failed to obtain Vectra access token"}

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        url = f"{self._base_url}{endpoint}"

        try:
            logger.debug(f"Making Vectra {method} request to: {endpoint}")

            if method == "GET":
                response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=self.timeout)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data, timeout=self.timeout)
            elif method == "PATCH":
                response = requests.patch(url, headers=headers, json=data, timeout=self.timeout)
            else:
                return {"error": f"Unsupported HTTP method: {method}"}

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                # Token might be expired, clear it and retry once
                self._access_token = None
                token = self._get_access_token()
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    try:
                        if method == "GET":
                            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
                        else:
                            response = requests.post(url, headers=headers, json=data, timeout=self.timeout)
                        response.raise_for_status()
                        return response.json()
                    except requests.exceptions.RequestException:
                        pass
                return {"error": "Vectra authentication failed - invalid credentials"}
            elif status_code == 404:
                return {"error": "Resource not found in Vectra"}
            elif status_code == 429:
                return {"error": "Vectra API rate limit exceeded"}
            else:
                logger.error(f"Vectra API error: {status_code}")
                return {"error": f"Vectra API error: {status_code}"}

        except requests.exceptions.Timeout:
            logger.error("Vectra API request timed out")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error(f"Vectra request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    # =========================================================================
    # Detection Methods
    # =========================================================================

    def get_detections(
        self,
        limit: int = 50,
        state: Optional[str] = None,
        threat_gte: Optional[int] = None,
        certainty_gte: Optional[int] = None,
        tags: Optional[str] = None,
        detection_type: Optional[str] = None,
        is_triaged: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get detections from Vectra.

        Args:
            limit: Maximum number of detections to return (default 50)
            state: Filter by state (active, inactive)
            threat_gte: Minimum threat score (0-100)
            certainty_gte: Minimum certainty score (0-100)
            tags: Comma-separated tags to filter by
            detection_type: Filter by detection type
            is_triaged: Filter by triage status

        Returns:
            dict: Vectra API response with detections list
        """
        params = {"page_size": limit}

        if state:
            params["state"] = state
        if threat_gte is not None:
            params["threat_gte"] = threat_gte
        if certainty_gte is not None:
            params["certainty_gte"] = certainty_gte
        if tags:
            params["tags"] = tags
        if detection_type:
            params["detection_type"] = detection_type
        if is_triaged is not None:
            params["is_triaged"] = str(is_triaged).lower()

        logger.info(f"Fetching Vectra detections with params: {params}")
        return self._make_request("/api/v3.3/detections", params=params)

    def get_detection_by_id(self, detection_id: int) -> Dict[str, Any]:
        """Get a specific detection by ID.

        Args:
            detection_id: The detection ID

        Returns:
            dict: Detection details
        """
        logger.info(f"Fetching Vectra detection ID: {detection_id}")
        return self._make_request(f"/api/v3.3/detections/{detection_id}")

    def get_high_threat_detections(self, min_threat: int = 50, limit: int = 20) -> Dict[str, Any]:
        """Get high-threat detections.

        Args:
            min_threat: Minimum threat score (default 50)
            limit: Maximum results to return

        Returns:
            dict: High-threat detections
        """
        return self.get_detections(limit=limit, threat_gte=min_threat, state="active")

    def mark_detection_as_fixed(self, detection_id: int) -> Dict[str, Any]:
        """Mark a detection as fixed/resolved.

        Args:
            detection_id: The detection ID to mark as fixed

        Returns:
            dict: Updated detection or error
        """
        logger.info(f"Marking Vectra detection {detection_id} as fixed")
        return self._make_request(
            f"/api/v3.3/detections/{detection_id}",
            method="PATCH",
            data={"state": "fixed"}
        )

    # =========================================================================
    # Entity Methods (Hosts and Accounts)
    # =========================================================================

    def get_entities(
        self,
        entity_type: Optional[str] = None,
        limit: int = 50,
        threat_gte: Optional[int] = None,
        certainty_gte: Optional[int] = None,
        is_prioritized: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get entities (hosts or accounts) from Vectra.

        Args:
            entity_type: Type of entity (host, account)
            limit: Maximum number to return
            threat_gte: Minimum threat score
            certainty_gte: Minimum certainty score
            is_prioritized: Filter by prioritization status

        Returns:
            dict: Vectra entities response
        """
        params = {"page_size": limit}

        if entity_type:
            params["type"] = entity_type
        if threat_gte is not None:
            params["threat_gte"] = threat_gte
        if certainty_gte is not None:
            params["certainty_gte"] = certainty_gte
        if is_prioritized is not None:
            params["is_prioritized"] = str(is_prioritized).lower()

        logger.info(f"Fetching Vectra entities with params: {params}")
        return self._make_request("/api/v3.3/entities", params=params)

    def get_entity_by_id(self, entity_id: int) -> Dict[str, Any]:
        """Get a specific entity by ID.

        Args:
            entity_id: The entity ID

        Returns:
            dict: Entity details
        """
        logger.info(f"Fetching Vectra entity ID: {entity_id}")
        return self._make_request(f"/api/v3.3/entities/{entity_id}")

    def search_entity_by_name(self, name: str, entity_type: Optional[str] = None) -> Dict[str, Any]:
        """Search for an entity by hostname or account name.

        Args:
            name: Hostname or account name to search
            entity_type: Optional type filter (host, account)

        Returns:
            dict: Matching entities
        """
        params = {"name": name, "page_size": 20}
        if entity_type:
            params["type"] = entity_type

        logger.info(f"Searching Vectra for entity: {name}")
        return self._make_request("/api/v3.3/entities", params=params)

    def search_entity_by_ip(self, ip_address: str) -> Dict[str, Any]:
        """Search for an entity by IP address.

        Args:
            ip_address: IP address to search

        Returns:
            dict: Matching entities
        """
        params = {"last_source": ip_address, "page_size": 20}
        logger.info(f"Searching Vectra for entity by IP: {ip_address}")
        return self._make_request("/api/v3.3/entities", params=params)

    def get_prioritized_entities(self, limit: int = 20) -> Dict[str, Any]:
        """Get prioritized entities requiring attention.

        Args:
            limit: Maximum results to return

        Returns:
            dict: Prioritized entities
        """
        return self.get_entities(limit=limit, is_prioritized=True)

    # =========================================================================
    # Assignment Methods
    # =========================================================================

    def get_assignments(self, limit: int = 50, resolved: Optional[bool] = None) -> Dict[str, Any]:
        """Get assignments from Vectra.

        Args:
            limit: Maximum number to return
            resolved: Filter by resolved status

        Returns:
            dict: Vectra assignments response
        """
        params = {"page_size": limit}

        if resolved is not None:
            params["resolved"] = str(resolved).lower()

        logger.info(f"Fetching Vectra assignments")
        return self._make_request("/api/v3.3/assignments", params=params)

    def get_assignment_by_id(self, assignment_id: int) -> Dict[str, Any]:
        """Get a specific assignment by ID.

        Args:
            assignment_id: The assignment ID

        Returns:
            dict: Assignment details
        """
        logger.info(f"Fetching Vectra assignment ID: {assignment_id}")
        return self._make_request(f"/api/v3.3/assignments/{assignment_id}")

    # =========================================================================
    # Utility Methods
    # =========================================================================

    @staticmethod
    def get_threat_level(threat_score: int, certainty_score: int) -> str:
        """Determine threat level based on scores.

        Args:
            threat_score: Threat score (0-100)
            certainty_score: Certainty score (0-100)

        Returns:
            str: Threat level string
        """
        combined = (threat_score + certainty_score) / 2

        if threat_score >= 80 or combined >= 70:
            return "CRITICAL"
        elif threat_score >= 50 or combined >= 50:
            return "HIGH"
        elif threat_score >= 25 or combined >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def format_detection_summary(detection: Dict[str, Any]) -> str:
        """Format a detection into a summary string.

        Args:
            detection: Detection data from API

        Returns:
            str: Formatted summary
        """
        det_id = detection.get("id", "Unknown")
        det_type = detection.get("detection_type", "Unknown")
        threat = detection.get("threat", 0)
        certainty = detection.get("certainty", 0)
        state = detection.get("state", "unknown")
        summary = detection.get("summary", {})

        return (
            f"**Detection #{det_id}** - {det_type}\n"
            f"  Threat: {threat} | Certainty: {certainty} | State: {state}\n"
            f"  Summary: {summary.get('description', 'N/A')}"
        )

    @staticmethod
    def format_entity_summary(entity: Dict[str, Any]) -> str:
        """Format an entity into a summary string.

        Args:
            entity: Entity data from API

        Returns:
            str: Formatted summary
        """
        entity_id = entity.get("id", "Unknown")
        name = entity.get("name", "Unknown")
        entity_type = entity.get("type", "unknown")
        threat = entity.get("threat", 0)
        certainty = entity.get("certainty", 0)
        last_source = entity.get("last_source", "N/A")
        detection_count = entity.get("detection_count", 0)

        return (
            f"**{entity_type.title()} #{entity_id}** - {name}\n"
            f"  Threat: {threat} | Certainty: {certainty}\n"
            f"  Last Source: {last_source} | Detections: {detection_count}"
        )


if __name__ == "__main__":
    # Quick test for Vectra client
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = VectraClient()

    if not client.is_configured():
        print("ERROR: Vectra API not configured")
        print("Ensure VECTRA_API_BASE_URL, VECTRA_CLIENT_ID, and VECTRA_API_KEY are set")
        sys.exit(1)

    print("Vectra Client Test")
    print("=" * 50)

    # Test fetching detections
    print("\n1. Testing detection fetch...")
    result = client.get_detections(limit=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        detections = result.get("results", [])
        print(f"   Found {len(detections)} detections")
        for det in detections[:3]:
            print(f"   - Detection #{det.get('id')}: {det.get('detection_type')}")

    # Test fetching entities
    print("\n2. Testing entity fetch...")
    result = client.get_entities(limit=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        entities = result.get("results", [])
        print(f"   Found {len(entities)} entities")
        for ent in entities[:3]:
            print(f"   - {ent.get('type', 'Entity')} #{ent.get('id')}: {ent.get('name')}")

    print("\n" + "=" * 50)
    print("Tests complete!")
