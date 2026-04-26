"""
XSIAM (Cortex XDR/XSIAM) API Client

Provides integration with Palo Alto Networks XSIAM using Advanced API key
authentication: the request is signed with a per-call nonce + timestamp,
hashed (SHA256) together with the API key, and sent in the Authorization
header.
"""

import hashlib
import logging
import secrets
import string
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)


class XsiamClient:
    """Client for interacting with the Palo Alto Cortex XSIAM/XDR API."""

    def __init__(self):
        self.config = get_config()
        self.api_key = self.config.xsiam_prod_api_key
        self.api_key_id = self.config.xsiam_prod_api_auth_id
        self.base_url = self.config.xsiam_prod_api_base_url
        self.ui_base_url = self._derive_ui_base_url()
        self.timeout = 60

        if not self.api_key:
            logger.warning("XSIAM API key not configured")
        if not self.api_key_id:
            logger.warning("XSIAM API key id not configured")
        if not self.base_url:
            logger.warning("XSIAM API base URL not configured")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key_id and self.base_url)

    def _derive_ui_base_url(self) -> Optional[str]:
        """UI base URL is the API base with the `api-` host prefix stripped.
        Override via XSIAM_PROD_UI_BASE_URL if the host pattern differs.
        """
        override = self.config.xsiam_prod_ui_base_url
        if override:
            return override.rstrip("/")
        if not self.base_url:
            return None
        return self.base_url.replace("//api-", "//", 1).rstrip("/")

    def case_url(self, case_id) -> Optional[str]:
        if not self.ui_base_url or case_id in (None, ""):
            return None
        return f"{self.ui_base_url}/case?caseId={case_id}"

    def _build_auth_headers(self) -> Dict[str, str]:
        """Build XSIAM advanced-auth headers (nonce + timestamp + SHA256 hash)."""
        nonce = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(64)
        )
        timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
        auth_key = f"{self.api_key}{nonce}{timestamp}".encode("utf-8")
        api_key_hash = hashlib.sha256(auth_key).hexdigest()
        return {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self.api_key_id),
            "Authorization": api_key_hash,
            "Content-Type": "application/json",
        }

    def _make_request(
        self,
        path: str,
        method: str = "POST",
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make an authenticated request to the XSIAM API.

        Args:
            path: API path (with or without leading slash).
            method: HTTP method (XSIAM endpoints are mostly POST).
            json_data: JSON body.
            params: Query string parameters.
        """
        if not self.is_configured():
            return {"error": "XSIAM API not configured (missing key, key id, or base URL)"}

        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        headers = self._build_auth_headers()

        try:
            logger.debug("XSIAM %s %s", method, path)
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data if method != "GET" else None,
                params=params,
                timeout=self.timeout,
            )
            response.raise_for_status()
            if response.text:
                return response.json()
            return {"success": True}

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            error_msg = e.response.text or str(e)
            if status_code == 401:
                return {"error": "Invalid XSIAM credentials or expired signature"}
            if status_code == 402:
                return {"error": "License does not cover this XSIAM API"}
            if status_code == 403:
                return {"error": "Access denied - insufficient XSIAM permissions"}
            if status_code == 404:
                return {"error": "XSIAM endpoint not found"}
            if status_code == 429:
                return {"error": "XSIAM API rate limit exceeded"}
            if status_code >= 500:
                return {"error": f"XSIAM server error: {status_code}"}
            logger.error("XSIAM API error: %s - %s", status_code, error_msg)
            return {"error": f"XSIAM API error ({status_code}): {error_msg}"}

        except requests.exceptions.Timeout:
            logger.error("XSIAM API request timed out")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error("XSIAM request failed: %s", e)
            return {"error": f"Request failed: {e}"}

    # ==================== Public methods ====================

    def validate_auth(self) -> Dict[str, Any]:
        """Hit /api_keys/validate/ to confirm credentials and signing work."""
        return self._make_request("api_keys/validate/", method="POST", json_data={})

    @staticmethod
    def _build_request_data(
        filters: Optional[list] = None,
        search_from: int = 0,
        search_to: int = 100,
        sort: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Compose XSIAM's standard `request_data` envelope."""
        rd: Dict[str, Any] = {"search_from": search_from, "search_to": search_to}
        if filters:
            rd["filters"] = filters
        if sort:
            rd["sort"] = sort
        return rd

    @staticmethod
    def _time_filter(field: str, hours: int) -> Dict[str, Any]:
        """`field` >= now - hours, in epoch milliseconds."""
        cutoff_ms = int(
            (datetime.now(timezone.utc).timestamp() - hours * 3600) * 1000
        )
        return {"field": field, "operator": "gte", "value": cutoff_ms}

    def get_incidents(
        self,
        hours: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List incidents, optionally filtered by recency/status."""
        filters = []
        if hours and hours > 0:
            filters.append(self._time_filter("creation_time", hours))
        if status:
            filters.append({"field": "status", "operator": "in", "value": [status]})
        rd = self._build_request_data(
            filters=filters or None,
            search_to=max(1, min(limit, 100)),
            sort={"field": "creation_time", "keyword": "desc"},
        )
        return self._make_request(
            "public_api/v1/incidents/get_incidents/",
            method="POST",
            json_data={"request_data": rd},
        )

    def get_incident_extra_data(
        self, incident_id: str, alerts_limit: int = 50
    ) -> Dict[str, Any]:
        """Single incident with related alerts, artifacts, and network artifacts."""
        return self._make_request(
            "public_api/v1/incidents/get_incident_extra_data/",
            method="POST",
            json_data={
                "request_data": {
                    "incident_id": str(incident_id),
                    "alerts_limit": alerts_limit,
                }
            },
        )

    def update_incident(
        self,
        incident_id: str,
        status: Optional[str] = None,
        assigned_user_mail: Optional[str] = None,
        severity: Optional[str] = None,
        resolve_comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update incident fields. Only provided fields are sent."""
        update_data: Dict[str, Any] = {}
        if status:
            update_data["status"] = status
        if assigned_user_mail:
            update_data["assigned_user_mail"] = assigned_user_mail
        if severity:
            update_data["severity"] = severity
        if resolve_comment:
            update_data["resolve_comment"] = resolve_comment
        return self._make_request(
            "public_api/v1/incidents/update_incident/",
            method="POST",
            json_data={
                "request_data": {
                    "incident_id": str(incident_id),
                    "update_data": update_data,
                }
            },
        )

    def get_alerts(
        self,
        hours: Optional[int] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Query alerts via /public_api/v1/alerts/get_alerts_multi_events/."""
        filters = []
        if hours and hours > 0:
            filters.append(self._time_filter("creation_time", hours))
        if severity:
            filters.append(
                {"field": "severity", "operator": "in", "value": [severity]}
            )
        rd = self._build_request_data(
            filters=filters or None,
            search_to=max(1, min(limit, 100)),
            sort={"field": "creation_time", "keyword": "desc"},
        )
        return self._make_request(
            "public_api/v1/alerts/get_alerts_multi_events/",
            method="POST",
            json_data={"request_data": rd},
        )

    def get_endpoint(
        self,
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        endpoint_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Look up endpoints by hostname, IP, or endpoint_id."""
        filters = []
        if hostname:
            filters.append(
                {"field": "hostname", "operator": "in", "value": [hostname]}
            )
        if ip:
            filters.append({"field": "ip_list", "operator": "in", "value": [ip]})
        if endpoint_id:
            filters.append(
                {"field": "endpoint_id_list", "operator": "in", "value": [endpoint_id]}
            )
        if not filters:
            return {"error": "Provide at least one of hostname, ip, or endpoint_id"}
        return self._make_request(
            "public_api/v1/endpoints/get_endpoint/",
            method="POST",
            json_data={"request_data": {"filters": filters}},
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    client = XsiamClient()
    if not client.is_configured():
        print("XSIAM not configured - set XSIAM_PROD_API_AUTH_ID, XSIAM_PROD_API_KEY, XSIAM_PROD_API_BASE_URL")
        raise SystemExit(1)
    print(client.validate_auth())
