"""
DFIR-IRIS API Client

Provides integration with DFIR-IRIS for incident response case management.
Supports creating cases, adding IOCs, assets, notes, and timeline events.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

import requests
import urllib3

from my_config import get_config

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class DFIRIrisClient:
    """Client for interacting with DFIR-IRIS API."""

    # Severity levels (DFIR-IRIS uses 1-5)
    SEVERITY_INFORMATIONAL = 1
    SEVERITY_LOW = 2
    SEVERITY_MEDIUM = 3
    SEVERITY_HIGH = 4
    SEVERITY_CRITICAL = 5

    # Case status
    STATUS_OPEN = "Open"
    STATUS_IN_PROGRESS = "In progress"
    STATUS_CONTAINMENT = "Containment"
    STATUS_ERADICATION = "Eradication"
    STATUS_RECOVERY = "Recovery"
    STATUS_POST_INCIDENT = "Post-Incident"
    STATUS_CLOSED = "Closed"

    # IOC types
    IOC_TYPES = {
        "ip": "ip-dst",
        "ip-src": "ip-src",
        "ip-dst": "ip-dst",
        "domain": "domain",
        "url": "url",
        "hash": "hash",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "email": "email-dst",
        "filename": "filename",
        "hostname": "hostname",
        "user-agent": "user-agent",
        "registry": "regkey",
    }

    def __init__(self):
        self.config = get_config()
        self.base_url = self.config.dfir_iris_url
        self.api_key = self.config.dfir_iris_api_key
        self.timeout = 30
        self.verify_ssl = False  # Self-signed cert by default

        if self.base_url:
            self.base_url = self.base_url.rstrip('/')

        if not self.api_key:
            logger.warning("DFIR-IRIS API key not configured")

    def is_configured(self) -> bool:
        """Check if the client is properly configured."""
        return bool(self.api_key and self.base_url)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to DFIR-IRIS API."""
        if not self.is_configured():
            return {"error": "DFIR-IRIS is not configured (missing URL or API key)"}

        url = f"{self.base_url}/api/v2/{endpoint}"
        headers = self._get_headers()

        try:
            logger.debug(f"DFIR-IRIS {method} request to: {endpoint}")

            if method == "POST":
                response = requests.post(
                    url, headers=headers, json=data,
                    timeout=self.timeout, verify=self.verify_ssl
                )
            elif method == "PUT":
                response = requests.put(
                    url, headers=headers, json=data,
                    timeout=self.timeout, verify=self.verify_ssl
                )
            elif method == "DELETE":
                response = requests.delete(
                    url, headers=headers,
                    timeout=self.timeout, verify=self.verify_ssl
                )
            else:
                response = requests.get(
                    url, headers=headers, params=params,
                    timeout=self.timeout, verify=self.verify_ssl
                )

            response.raise_for_status()

            if response.text:
                result = response.json()
                # DFIR-IRIS wraps responses in a 'data' key
                if isinstance(result, dict) and 'data' in result:
                    return result['data']
                return result
            return {"success": True}

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            error_detail = ""
            try:
                error_json = e.response.json()
                error_detail = error_json.get("message", str(e))
            except Exception:
                error_detail = e.response.text[:200] if e.response.text else str(e)

            if status_code == 401:
                return {"error": "Invalid DFIR-IRIS API key or unauthorized"}
            elif status_code == 403:
                return {"error": f"Forbidden: {error_detail}"}
            elif status_code == 404:
                return {"error": "Resource not found in DFIR-IRIS"}
            elif status_code == 400:
                return {"error": f"Bad request: {error_detail}"}
            else:
                logger.error(f"DFIR-IRIS API error: {status_code} - {error_detail}")
                return {"error": f"DFIR-IRIS API error ({status_code}): {error_detail}"}

        except requests.exceptions.Timeout:
            logger.error("DFIR-IRIS API request timed out")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error(f"DFIR-IRIS request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    def get_api_version(self) -> Dict[str, Any]:
        """Get DFIR-IRIS API version info."""
        if not self.is_configured():
            return {"error": "DFIR-IRIS is not configured"}

        try:
            url = f"{self.base_url}/api/versions"
            response = requests.get(
                url, headers=self._get_headers(),
                timeout=self.timeout, verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List all cases.

        Args:
            limit: Maximum number of cases to return

        Returns:
            List of cases or error
        """
        # DFIR-IRIS uses /manage/ endpoints, not /api/v2/
        if not self.is_configured():
            return {"error": "DFIR-IRIS is not configured (missing URL or API key)"}

        url = f"{self.base_url}/manage/cases/list"
        headers = self._get_headers()

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "success":
                return result.get("data", [])[:limit]
            return {"error": result.get("message", "Unknown error")}
        except Exception as e:
            return {"error": str(e)}

    def get_case(self, case_id: int) -> Dict[str, Any]:
        """Get case details by ID.

        Args:
            case_id: DFIR-IRIS case ID

        Returns:
            Case data or error
        """
        if not self.is_configured():
            return {"error": "DFIR-IRIS is not configured (missing URL or API key)"}

        url = f"{self.base_url}/manage/cases/list"
        headers = self._get_headers()

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "success":
                cases = result.get("data", [])
                for case in cases:
                    if case.get("case_id") == case_id:
                        return case
                return {"error": f"Case {case_id} not found"}
            return {"error": result.get("message", "Unknown error")}
        except Exception as e:
            return {"error": str(e)}

    def create_case(
        self,
        name: str,
        description: str,
        customer_id: int = 1,
        classification_id: int = 1,
        soc_id: str = "",
        severity_id: int = SEVERITY_MEDIUM,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new case.

        Args:
            name: Case name/title
            description: Case description
            customer_id: Customer ID (default: 1 for default customer)
            classification_id: Classification ID (default: 1)
            soc_id: External SOC reference ID
            severity_id: Severity level (1-5)
            tags: List of tags

        Returns:
            Created case data or error
        """
        case_data = {
            "case_name": name,
            "case_description": description,
            "case_customer": customer_id,
            "classification_id": classification_id,
            "case_soc_id": soc_id,
            "severity_id": severity_id,
        }

        if tags:
            case_data["case_tags"] = ",".join(tags)

        # Use /manage/cases/add endpoint
        if not self.is_configured():
            return {"error": "DFIR-IRIS is not configured (missing URL or API key)"}

        url = f"{self.base_url}/manage/cases/add"
        headers = self._get_headers()

        try:
            response = requests.post(url, headers=headers, json=case_data, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "success":
                result = result.get("data", {})
            else:
                return {"error": result.get("message", "Unknown error")}
        except requests.exceptions.HTTPError as e:
            error_detail = ""
            try:
                error_detail = e.response.json().get("message", str(e))
            except:
                error_detail = str(e)
            return {"error": f"HTTP error: {error_detail}"}
        except Exception as e:
            return {"error": str(e)}

        if isinstance(result, dict) and "error" not in result:
            logger.info(f"Created DFIR-IRIS case: {result.get('case_id')} - {name}")

        return result

    def update_case(
        self,
        case_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        severity_id: Optional[int] = None,
        status_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Update an existing case.

        Args:
            case_id: Case ID to update
            name: New case name (optional)
            description: New description (optional)
            severity_id: New severity (optional)
            status_id: New status ID (optional)

        Returns:
            Updated case data or error
        """
        update_data = {}

        if name is not None:
            update_data["case_name"] = name
        if description is not None:
            update_data["case_description"] = description
        if severity_id is not None:
            update_data["severity_id"] = severity_id
        if status_id is not None:
            update_data["status_id"] = status_id

        if not update_data:
            return {"error": "No update fields provided"}

        return self._make_request(f"cases/{case_id}", method="PUT", data=update_data)

    def close_case(self, case_id: int) -> Dict[str, Any]:
        """Close a case.

        Args:
            case_id: Case ID to close

        Returns:
            Updated case data or error
        """
        return self._make_request(
            f"cases/{case_id}",
            method="PUT",
            data={"status_id": 9}  # 9 = Closed in DFIR-IRIS
        )

    def add_ioc(
        self,
        case_id: int,
        ioc_value: str,
        ioc_type: str,
        ioc_description: str = "",
        ioc_tlp_id: int = 2,  # TLP:AMBER
        ioc_tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add an IOC to a case.

        Args:
            case_id: Case ID
            ioc_value: IOC value (IP, domain, hash, etc.)
            ioc_type: IOC type (ip, domain, hash, url, etc.)
            ioc_description: Description of the IOC
            ioc_tlp_id: TLP level (1=WHITE, 2=GREEN, 3=AMBER, 4=RED)
            ioc_tags: List of tags

        Returns:
            Created IOC data or error
        """
        # Normalize IOC type
        ioc_type_normalized = self.IOC_TYPES.get(ioc_type.lower(), ioc_type)

        ioc_data = {
            "ioc_value": ioc_value,
            "ioc_type_id": self._get_ioc_type_id(ioc_type_normalized),
            "ioc_description": ioc_description,
            "ioc_tlp_id": ioc_tlp_id,
            "ioc_tags": ",".join(ioc_tags) if ioc_tags else "",
        }

        # Use /case/ioc/add?cid=X endpoint
        if not self.is_configured():
            return {"error": "DFIR-IRIS is not configured (missing URL or API key)"}

        url = f"{self.base_url}/case/ioc/add?cid={case_id}"
        headers = self._get_headers()

        try:
            response = requests.post(url, headers=headers, json=ioc_data, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "success":
                result = result.get("data", {})
                logger.info(f"Added IOC to case {case_id}: {ioc_type}={ioc_value}")
            else:
                return {"error": result.get("message", "Unknown error")}
        except Exception as e:
            return {"error": str(e)}

        return result

    def _get_ioc_type_id(self, ioc_type: str) -> int:
        """Map IOC type string to DFIR-IRIS type ID."""
        # Common mappings - these may vary by DFIR-IRIS configuration
        type_map = {
            "ip-dst": 76,
            "ip-src": 78,
            "domain": 20,
            "url": 141,
            "md5": 91,
            "sha1": 113,
            "sha256": 114,
            "email-dst": 22,
            "filename": 46,
            "hostname": 64,
            "hash": 91,  # default to MD5
        }
        return type_map.get(ioc_type, 107)  # 107 = "other"

    def get_iocs(self, case_id: int) -> Dict[str, Any]:
        """Get all IOCs for a case.

        Args:
            case_id: Case ID

        Returns:
            List of IOCs or error
        """
        return self._make_request(f"cases/{case_id}/iocs")

    def add_note(
        self,
        case_id: int,
        note_title: str,
        note_content: str,
        group_id: int = 1,
    ) -> Dict[str, Any]:
        """Add a note to a case.

        Args:
            case_id: Case ID
            note_title: Note title
            note_content: Note content (supports markdown)
            group_id: Note group ID (default: 1)

        Returns:
            Created note data or error
        """
        note_data = {
            "note_title": note_title,
            "note_content": note_content,
            "group_id": group_id,
        }

        return self._make_request(
            f"cases/{case_id}/notes",
            method="POST",
            data=note_data
        )

    def add_asset(
        self,
        case_id: int,
        asset_name: str,
        asset_type_id: int = 1,  # 1 = Account
        asset_description: str = "",
        asset_ip: str = "",
        asset_compromised: bool = False,
    ) -> Dict[str, Any]:
        """Add an asset to a case.

        Args:
            case_id: Case ID
            asset_name: Asset name (hostname, username, etc.)
            asset_type_id: Asset type ID
            asset_description: Description
            asset_ip: IP address if applicable
            asset_compromised: Whether the asset is compromised

        Returns:
            Created asset data or error
        """
        asset_data = {
            "asset_name": asset_name,
            "asset_type_id": asset_type_id,
            "asset_description": asset_description,
            "asset_ip": asset_ip,
            "asset_compromised": asset_compromised,
        }

        return self._make_request(
            f"cases/{case_id}/assets",
            method="POST",
            data=asset_data
        )

    def add_timeline_event(
        self,
        case_id: int,
        event_title: str,
        event_date: str,
        event_content: str = "",
        event_category_id: int = 5,  # 5 = Legitimate
    ) -> Dict[str, Any]:
        """Add a timeline event to a case.

        Args:
            case_id: Case ID
            event_title: Event title
            event_date: Event date/time (ISO format)
            event_content: Event description
            event_category_id: Event category ID

        Returns:
            Created event data or error
        """
        event_data = {
            "event_title": event_title,
            "event_date": event_date,
            "event_content": event_content,
            "event_category_id": event_category_id,
            "event_in_graph": True,
            "event_in_summary": True,
        }

        return self._make_request(
            f"cases/{case_id}/timeline/events",
            method="POST",
            data=event_data
        )

    def get_timeline(self, case_id: int) -> Dict[str, Any]:
        """Get timeline events for a case.

        Args:
            case_id: Case ID

        Returns:
            List of timeline events or error
        """
        return self._make_request(f"cases/{case_id}/timeline/events")

    def create_alert(
        self,
        title: str,
        description: str,
        source: str,
        source_ref: str,
        severity_id: int = SEVERITY_MEDIUM,
        status_id: int = 2,  # 2 = New
        customer_id: int = 1,
        iocs: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """Create an alert in DFIR-IRIS.

        Args:
            title: Alert title
            description: Alert description
            source: Source of the alert (e.g., "Pokedex", "CrowdStrike")
            source_ref: Unique reference from source system
            severity_id: Severity level (1-5)
            status_id: Alert status ID
            customer_id: Customer ID
            iocs: List of IOC dicts with 'ioc_value' and 'ioc_type'

        Returns:
            Created alert data or error
        """
        alert_data = {
            "alert_title": title,
            "alert_description": description,
            "alert_source": source,
            "alert_source_ref": source_ref,
            "alert_severity_id": severity_id,
            "alert_status_id": status_id,
            "alert_customer_id": customer_id,
        }

        if iocs:
            alert_data["alert_iocs"] = [
                {
                    "ioc_value": ioc.get("ioc_value"),
                    "ioc_type_id": self._get_ioc_type_id(ioc.get("ioc_type", "other")),
                    "ioc_description": ioc.get("description", ""),
                    "ioc_tlp_id": 2,
                }
                for ioc in iocs
            ]

        result = self._make_request("alerts", method="POST", data=alert_data)

        if isinstance(result, dict) and "error" not in result:
            logger.info(f"Created DFIR-IRIS alert: {title}")

        return result


# Formatting helpers
def format_case_summary(case: Dict) -> str:
    """Format a case for display."""
    if isinstance(case, dict) and "error" in case:
        return f"Error: {case['error']}"

    severity_map = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

    case_id = case.get("case_id", "Unknown")
    name = case.get("case_name", "Untitled")
    description = case.get("case_description", "")[:200]
    status = case.get("status", {}).get("status_name", "Unknown") if isinstance(case.get("status"), dict) else case.get("status_name", "Unknown")
    severity = severity_map.get(case.get("severity_id", 3), "Unknown")
    soc_id = case.get("case_soc_id", "N/A")
    opened = case.get("open_date", "Unknown")
    owner = case.get("owner", {}).get("user_name", "Unassigned") if isinstance(case.get("owner"), dict) else "Unassigned"

    return f"""## DFIR-IRIS Case #{case_id}
**Name:** {name}
**Status:** {status}
**Severity:** {severity}
**SOC ID:** {soc_id}
**Owner:** {owner}
**Opened:** {opened}
**Description:** {description}
"""


def format_case_list(cases: List[Dict]) -> str:
    """Format a list of cases for display."""
    if not cases:
        return "No cases found."

    if isinstance(cases, dict) and "error" in cases:
        return f"Error: {cases['error']}"

    lines = [f"## DFIR-IRIS Cases ({len(cases)} found)", ""]

    severity_emoji = {1: "⚪", 2: "🟢", 3: "🟡", 4: "🟠", 5: "🔴"}

    for case in cases:
        case_id = case.get("case_id", "?")
        name = case.get("case_name", "Untitled")[:50]
        status = case.get("status", {}).get("status_name", "?") if isinstance(case.get("status"), dict) else case.get("status_name", "?")
        severity = case.get("severity_id", 3)

        emoji = severity_emoji.get(severity, "⚪")
        lines.append(f"- {emoji} **#{case_id}** [{status}] {name}")

    return "\n".join(lines)
