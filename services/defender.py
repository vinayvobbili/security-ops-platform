"""Microsoft Defender (XDR / Defender for Endpoint) API client.

Authenticates to Microsoft Graph via OAuth2 client credentials and exposes
read methods for the artifacts that map to "detection content":

  - Custom detection rules  (Graph beta: /security/rules/detectionRules)
  - Threat Intelligence indicators  (Graph v1.0: /security/tiIndicators)

Required Azure app registration permissions (application, admin-consented):
  - CustomDetection.Read.All        (custom detection rules)
  - ThreatIndicators.Read.All       (TI indicators)

Required env vars (see my_config.py):
  - DEFENDER_TENANT_ID
  - DEFENDER_CLIENT_ID
  - DEFENDER_CLIENT_SECRET
"""

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
DEFAULT_SCOPE = "https://graph.microsoft.com/.default"


class DefenderClient:
    """Client for Microsoft Defender via Microsoft Graph."""

    def __init__(self):
        self.config = get_config()
        self.tenant_id = self.config.defender_tenant_id
        self.client_id = self.config.defender_client_id
        self.client_secret = self.config.defender_client_secret
        self.timeout = 30
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    def is_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        resp = requests.post(
            TOKEN_URL_TEMPLATE.format(tenant=self.tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": DEFAULT_SCOPE,
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expires_at = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{GRAPH_BASE}{path}"
        headers = {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code >= 400:
                return {"error": f"HTTP {resp.status_code}: {resp.text[:300]}"}
            return resp.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    def _paginate(self, path: str, params: Optional[Dict[str, Any]] = None,
                  max_pages: int = 20) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        page = self._get(path, params=params)
        if "error" in page:
            logger.warning("Defender %s failed: %s", path, page["error"])
            return items
        items.extend(page.get("value", []))

        next_link = page.get("@odata.nextLink")
        pages_seen = 1
        while next_link and pages_seen < max_pages:
            try:
                resp = requests.get(
                    next_link,
                    headers={"Authorization": f"Bearer {self._get_token()}",
                             "Accept": "application/json"},
                    timeout=self.timeout,
                )
                if resp.status_code >= 400:
                    logger.warning("Defender pagination HTTP %s: %s",
                                   resp.status_code, resp.text[:300])
                    break
                page = resp.json()
            except requests.RequestException as e:
                logger.warning("Defender pagination error: %s", e)
                break
            items.extend(page.get("value", []))
            next_link = page.get("@odata.nextLink")
            pages_seen += 1

        return items

    def list_custom_detection_rules(self) -> Dict[str, Any]:
        """Custom detection rules (scheduled KQL hunting queries with alert templates).

        Endpoint is in /beta — Microsoft has not yet promoted it to v1.0.
        """
        if not self.is_configured():
            return {"error": "Defender not configured"}
        rules = self._paginate("/beta/security/rules/detectionRules")
        return {"rules": rules}

    def list_indicators(self, top: int = 500) -> Dict[str, Any]:
        """Threat Intelligence indicators (file hashes, IPs, URLs, domains)."""
        if not self.is_configured():
            return {"error": "Defender not configured"}
        indicators = self._paginate(
            "/v1.0/security/tiIndicators",
            params={"$top": min(top, 1000)},
        )
        return {"indicators": indicators}
