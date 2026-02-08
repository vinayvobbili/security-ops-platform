"""
TheHive API Client

Provides integration with TheHive 5 API for case management.
Supports creating cases, adding observables, updating cases, and searching.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

import requests

from my_config import get_config

logger = logging.getLogger(__name__)


class TheHiveClient:
    """Client for interacting with TheHive 5 API."""

    # Severity levels
    SEVERITY_LOW = 1
    SEVERITY_MEDIUM = 2
    SEVERITY_HIGH = 3
    SEVERITY_CRITICAL = 4

    # TLP levels
    TLP_CLEAR = 0
    TLP_GREEN = 1
    TLP_AMBER = 2
    TLP_AMBER_STRICT = 3
    TLP_RED = 4

    # PAP levels
    PAP_CLEAR = 0
    PAP_GREEN = 1
    PAP_AMBER = 2
    PAP_RED = 3

    # Case status
    STATUS_NEW = "New"
    STATUS_IN_PROGRESS = "InProgress"
    STATUS_RESOLVED = "Resolved"
    STATUS_CLOSED = "Closed"

    # Observable data types
    OBSERVABLE_TYPES = {
        "ip": "ip",
        "domain": "domain",
        "url": "url",
        "hash": "hash",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "email": "mail",
        "filename": "filename",
        "hostname": "hostname",
        "user-agent": "user-agent",
        "registry": "registry",
    }

    def __init__(self):
        self.config = get_config()
        self.base_url = self.config.thehive_url
        self.api_key = self.config.thehive_api_key
        self.org = self.config.thehive_org
        self.timeout = 30

        if self.base_url:
            # Remove trailing slash
            self.base_url = self.base_url.rstrip('/')

        if not self.api_key:
            logger.warning("TheHive API key not configured")

    def is_configured(self) -> bool:
        """Check if the client is properly configured."""
        return bool(self.api_key and self.base_url)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.org:
            headers["X-Organisation"] = self.org
        return headers

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to TheHive API."""
        if not self.is_configured():
            return {"error": "TheHive is not configured (missing URL or API key)"}

        url = f"{self.base_url}/api/v1/{endpoint}"
        headers = self._get_headers()

        try:
            logger.debug(f"TheHive {method} request to: {endpoint}")

            if method == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=self.timeout)
            elif method == "PATCH":
                response = requests.patch(url, headers=headers, json=data, timeout=self.timeout)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=self.timeout)
            else:
                response = requests.get(url, headers=headers, params=params, timeout=self.timeout)

            response.raise_for_status()

            if response.text:
                return response.json()
            return {"success": True}

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            error_detail = ""
            try:
                error_detail = e.response.json().get("message", str(e))
            except Exception:
                error_detail = e.response.text[:200] if e.response.text else str(e)

            if status_code == 401:
                return {"error": "Invalid TheHive API key or unauthorized"}
            elif status_code == 403:
                return {"error": f"Forbidden: {error_detail}"}
            elif status_code == 404:
                return {"error": "Resource not found in TheHive"}
            elif status_code == 400:
                return {"error": f"Bad request: {error_detail}"}
            else:
                logger.error(f"TheHive API error: {status_code} - {error_detail}")
                return {"error": f"TheHive API error ({status_code}): {error_detail}"}

        except requests.exceptions.Timeout:
            logger.error("TheHive API request timed out")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error(f"TheHive request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    def get_status(self) -> Dict[str, Any]:
        """Get TheHive server status."""
        # Status endpoint doesn't require v1 prefix
        if not self.is_configured():
            return {"error": "TheHive is not configured"}

        try:
            url = f"{self.base_url}/api/status"
            response = requests.get(url, headers=self._get_headers(), timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def create_case(
        self,
        title: str,
        description: str,
        severity: int = SEVERITY_MEDIUM,
        tlp: int = TLP_AMBER,
        pap: int = PAP_AMBER,
        tags: Optional[List[str]] = None,
        tasks: Optional[List[Dict]] = None,
        custom_fields: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Create a new case in TheHive.

        Args:
            title: Case title
            description: Case description (supports markdown)
            severity: Severity level (1-4)
            tlp: TLP level (0-4)
            pap: PAP level (0-3)
            tags: List of tags
            tasks: List of task definitions
            custom_fields: Custom field values

        Returns:
            Created case data or error
        """
        case_data = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
            "tags": tags or [],
            "flag": False,
        }

        if tasks:
            case_data["tasks"] = tasks

        if custom_fields:
            case_data["customFields"] = custom_fields

        result = self._make_request("case", method="POST", data=case_data)

        if "error" not in result and "_id" in result:
            logger.info(f"Created TheHive case: {result.get('_id')} - {title}")

        return result

    def get_case(self, case_id: str) -> Dict[str, Any]:
        """Get case details by ID.

        Args:
            case_id: TheHive case ID (e.g., '~123456')

        Returns:
            Case data or error
        """
        return self._make_request(f"case/{case_id}")

    def update_case(
        self,
        case_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[int] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Update an existing case.

        Args:
            case_id: TheHive case ID
            title: New title (optional)
            description: New description (optional)
            severity: New severity (optional)
            status: New status (optional)
            tags: New tags (optional)
            custom_fields: Custom field updates (optional)

        Returns:
            Updated case data or error
        """
        update_data = {}

        if title is not None:
            update_data["title"] = title
        if description is not None:
            update_data["description"] = description
        if severity is not None:
            update_data["severity"] = severity
        if status is not None:
            update_data["status"] = status
        if tags is not None:
            update_data["tags"] = tags
        if custom_fields is not None:
            update_data["customFields"] = custom_fields

        if not update_data:
            return {"error": "No update fields provided"}

        result = self._make_request(f"case/{case_id}", method="PATCH", data=update_data)

        # PATCH returns 204 No Content on success - fetch the updated case
        if result.get("success") or not result.get("error"):
            return self.get_case(case_id)

        return result

    def close_case(
        self,
        case_id: str,
        resolution_status: str = "TruePositive",
        summary: str = "",
        impact_status: str = "NoImpact"
    ) -> Dict[str, Any]:
        """Close a case.

        Args:
            case_id: TheHive case ID
            resolution_status: Resolution status (TruePositive, FalsePositive, Indeterminate, etc.)
            summary: Closing summary
            impact_status: Impact status (NoImpact, WithImpact, NotApplicable)

        Returns:
            Updated case data or error
        """
        close_data = {
            "status": "Resolved",
            "resolutionStatus": resolution_status,
            "summary": summary,
            "impactStatus": impact_status,
        }
        return self._make_request(f"case/{case_id}", method="PATCH", data=close_data)

    def add_observable(
        self,
        case_id: str,
        data_type: str,
        value: str,
        message: str = "",
        tlp: int = TLP_AMBER,
        ioc: bool = False,
        sighted: bool = False,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add an observable (IOC) to a case.

        Args:
            case_id: TheHive case ID
            data_type: Observable type (ip, domain, hash, url, etc.)
            value: Observable value
            message: Description of the observable
            tlp: TLP level
            ioc: Whether this is an IOC
            sighted: Whether this has been sighted
            tags: List of tags

        Returns:
            Created observable data or error
        """
        # Normalize data type
        data_type_normalized = self.OBSERVABLE_TYPES.get(data_type.lower(), data_type)

        observable_data = {
            "dataType": data_type_normalized,
            "data": value,
            "message": message,
            "tlp": tlp,
            "ioc": ioc,
            "sighted": sighted,
            "tags": tags or [],
        }

        result = self._make_request(
            f"case/{case_id}/observable",
            method="POST",
            data=observable_data
        )

        if "error" not in result:
            logger.info(f"Added observable to case {case_id}: {data_type}={value}")

        return result

    def add_task(
        self,
        case_id: str,
        title: str,
        description: str = "",
        status: str = "Waiting",
        flag: bool = False,
    ) -> Dict[str, Any]:
        """Add a task to a case.

        Args:
            case_id: TheHive case ID
            title: Task title
            description: Task description
            status: Task status (Waiting, InProgress, Completed, Cancel)
            flag: Whether to flag the task

        Returns:
            Created task data or error
        """
        task_data = {
            "title": title,
            "description": description,
            "status": status,
            "flag": flag,
        }

        return self._make_request(f"case/{case_id}/task", method="POST", data=task_data)

    def add_comment(self, case_id: str, message: str) -> Dict[str, Any]:
        """Add a comment/log to a case.

        Args:
            case_id: TheHive case ID
            message: Comment text (supports markdown)

        Returns:
            Created comment data or error
        """
        comment_data = {
            "message": message,
        }

        return self._make_request(
            f"case/{case_id}/comment",
            method="POST",
            data=comment_data
        )

    def search_cases(
        self,
        query: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[int] = None,
        tags: Optional[List[str]] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Search for cases.

        Args:
            query: Search query string
            status: Filter by status
            severity: Filter by severity
            tags: Filter by tags
            limit: Maximum results to return

        Returns:
            List of matching cases or error dict
        """
        if not self.is_configured():
            return {"error": "TheHive is not configured (missing URL or API key)"}

        # Use /api/case endpoint (TheHive 5 compatible)
        url = f"{self.base_url}/api/case"
        headers = self._get_headers()

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            cases = response.json()

            # Apply filters in Python (TheHive 5 /api/case doesn't support query params well)
            if query:
                query_lower = query.lower()
                cases = [c for c in cases if query_lower in c.get("title", "").lower()]

            if status:
                cases = [c for c in cases if c.get("status") == status]

            if severity:
                cases = [c for c in cases if c.get("severity") == severity]

            if tags:
                cases = [c for c in cases if any(t in c.get("tags", []) for t in tags)]

            # Sort by creation date descending and limit
            cases = sorted(cases, key=lambda x: x.get("createdAt", 0), reverse=True)[:limit]

            return cases

        except requests.exceptions.HTTPError as e:
            return {"error": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def get_case_observables(self, case_id: str) -> Dict[str, Any]:
        """Get all observables for a case.

        Args:
            case_id: TheHive case ID

        Returns:
            List of observables or error
        """
        query_body = {
            "query": {
                "_parent": {"_type": "case", "_id": case_id}
            }
        }

        return self._make_request(
            f"case/{case_id}/observable",
            method="GET"
        )

    def create_alert(
        self,
        title: str,
        description: str,
        source: str,
        source_ref: str,
        severity: int = SEVERITY_MEDIUM,
        tlp: int = TLP_AMBER,
        pap: int = PAP_AMBER,
        alert_type: str = "external",
        tags: Optional[List[str]] = None,
        observables: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """Create an alert in TheHive.

        Args:
            title: Alert title
            description: Alert description
            source: Alert source (e.g., "Pokedex", "CrowdStrike")
            source_ref: Unique reference from source system
            severity: Severity level
            tlp: TLP level
            pap: PAP level
            alert_type: Type of alert
            tags: List of tags
            observables: List of observable dicts with dataType, data, message

        Returns:
            Created alert data or error
        """
        alert_data = {
            "title": title,
            "description": description,
            "source": source,
            "sourceRef": source_ref,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
            "type": alert_type,
            "tags": tags or [],
        }

        if observables:
            alert_data["observables"] = observables

        result = self._make_request("alert", method="POST", data=alert_data)

        if "error" not in result and "_id" in result:
            logger.info(f"Created TheHive alert: {result.get('_id')} - {title}")

        return result

    def promote_alert_to_case(self, alert_id: str) -> Dict[str, Any]:
        """Promote an alert to a case.

        Args:
            alert_id: TheHive alert ID

        Returns:
            Created case data or error
        """
        return self._make_request(f"alert/{alert_id}/case", method="POST", data={})


# Formatting helpers
def format_case_summary(case: Dict) -> str:
    """Format a case for display."""
    if "error" in case:
        return f"Error: {case['error']}"

    severity_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    tlp_map = {0: "CLEAR", 1: "GREEN", 2: "AMBER", 3: "AMBER+STRICT", 4: "RED"}

    case_id = case.get("_id", "Unknown")
    # TheHive 5 uses caseId, older versions use number
    case_number = case.get("caseId") or case.get("number", "N/A")
    title = case.get("title", "Untitled")
    status = case.get("status", "Unknown")
    severity = severity_map.get(case.get("severity", 2), "Unknown")
    tlp = tlp_map.get(case.get("tlp", 2), "Unknown")
    tags = ", ".join(case.get("tags", [])) or "None"
    created = case.get("_createdAt", "Unknown")
    owner = case.get("owner", "Unassigned")

    return f"""## TheHive Case #{case_number}
**ID:** {case_id}
**Title:** {title}
**Status:** {status}
**Severity:** {severity}
**TLP:** {tlp}
**Owner:** {owner}
**Tags:** {tags}
**Created:** {created}
"""


def format_case_list(cases: List[Dict]) -> str:
    """Format a list of cases for display."""
    if not cases:
        return "No cases found."

    lines = [f"## TheHive Cases ({len(cases)} found)", ""]

    for case in cases:
        # TheHive 5 uses caseId, older versions use number
        case_number = case.get("caseId") or case.get("number", "N/A")
        title = case.get("title", "Untitled")[:50]
        status = case.get("status", "?")
        severity = case.get("severity", 2)

        severity_emoji = {1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴"}.get(severity, "⚪")

        lines.append(f"- {severity_emoji} **#{case_number}** [{status}] {title}")

    return "\n".join(lines)
