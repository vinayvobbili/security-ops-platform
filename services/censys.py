"""Censys Platform API client — internet-exposure counts for CAPD reachability.

A vendor-independent second source alongside Shodan (``services.shodan_monitor``)
for the CAPD scorecard's "external reachability" category. Censys and Shodan scan
the internet independently, so corroborating the two reduces the chance a single
scanner's blind spot under- or over-states our exposure.

Auth: the Censys **Platform API** uses a Personal Access Token (the ``censys_``
prefixed key) as an HTTP Bearer token, and every data call must carry an
``organization_id`` (Censys account/billing org). Both ``CENSYS_API_KEY`` and
``CENSYS_ORG_ID`` are therefore required — without the org id the Platform
rejects search with HTTP 403. Counts draw on the account's query allowance, so we
only call this when fully configured and only with the primary CVE.

Note: this is the new ``api.platform.censys.io`` API, NOT the legacy Search v2
(``search.censys.io``) ID+secret API.
"""

import logging
from typing import Any, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

CENSYS_PLATFORM_BASE = "https://api.platform.censys.io/v3"
# CenQL field that filters hosts by CVE id. Confirm against a live call once the
# org id is provisioned — the Platform rejected our pre-org probes with 403
# (auth/entitlement) before any field validation could run.
CENSYS_CVE_FIELD = "host.services.vulnerabilities.cve_id"


class CensysClient:
    """Client for the Censys Platform API (global host search)."""

    def __init__(self, api_key: Optional[str] = None, org_id: Optional[str] = None):
        """Initialize the Censys Platform client.

        Args:
            api_key: Censys Personal Access Token. If None, loads from config.
            org_id: Censys organization id. If None, loads from config.
        """
        if api_key is None or org_id is None:
            config = get_config()
            api_key = api_key or getattr(config, "censys_api_key", None)
            org_id = org_id or getattr(config, "censys_org_id", None)

        self.api_key = api_key
        self.org_id = org_id
        self.session = requests.Session()

    def is_configured(self) -> bool:
        """True only when BOTH the PAT and the organization id are present —
        the Platform data API rejects search without an org id."""
        return bool(self.api_key and self.org_id)

    def _headers(self) -> dict[str, str]:
        return {
            "accept": "application/json",
            "authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }

    def count(self, query: str) -> dict[str, Any]:
        """Count internet-exposed hosts matching a Censys CenQL host query.

        Issues ``POST /v3/global/search/query`` with ``page_size=1`` (we only need
        the count, not the hits) and reads the total out of the response. Returns
        ``{"success": True, "total": <int>}`` or ``{"success": False, "error": ...}``.
        """
        if not self.is_configured():
            return {"success": False, "error": "Censys API key / org id not configured"}

        url = f"{CENSYS_PLATFORM_BASE}/global/search/query"
        try:
            resp = self.session.post(
                url,
                headers=self._headers(),
                params={"organization_id": self.org_id},
                json={"page_size": 1, "query": query},
                timeout=30,
            )
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Request timed out"}
        except requests.exceptions.RequestException as e:
            logger.error("Censys request failed: %s", e)
            return {"success": False, "error": str(e)}

        if resp.status_code == 401:
            return {"success": False, "error": "Invalid Censys API token"}
        if resp.status_code == 403:
            return {"success": False, "error": "Censys token lacks API access for this org"}
        if resp.status_code == 429:
            return {"success": False, "error": "Censys rate limit / query quota exceeded"}
        if resp.status_code != 200:
            return {"success": False, "error": f"Censys API error: {resp.status_code}"}

        try:
            data = resp.json()
        except ValueError:
            return {"success": False, "error": "Censys returned non-JSON response"}

        total = _extract_total(data)
        if total is None:
            return {"success": False, "error": "Censys response had no result count"}
        return {"success": True, "total": int(total)}


def _extract_total(data: dict[str, Any]) -> Optional[int]:
    """Pull a result-count integer out of a Platform search response, tolerant of
    the exact key name (``total``/``total_results``/``count``) wherever it sits in
    the top level or under ``result``. Returns None if no count field is present."""
    candidates = ("total", "total_results", "total_hits", "count", "result_count")
    for container in (data, data.get("result") if isinstance(data.get("result"), dict) else None):
        if not isinstance(container, dict):
            continue
        for key in candidates:
            val = container.get(key)
            if isinstance(val, (int, float)):
                return int(val)
            if isinstance(val, dict) and isinstance(val.get("value"), (int, float)):
                return int(val["value"])  # some APIs nest {"value": N, "relation": "eq"}
    return None


_client: Optional[CensysClient] = None


def get_client() -> CensysClient:
    """Get the singleton CensysClient instance."""
    global _client
    if _client is None:
        _client = CensysClient()
    return _client


if __name__ == "__main__":
    import sys

    client = get_client()
    print("Censys Platform Client Test")
    print("=" * 50)
    if not client.is_configured():
        print("Not configured (need CENSYS_API_KEY and CENSYS_ORG_ID).")
        sys.exit(1)

    print("Testing count (Log4Shell)...")
    res = client.count(f'{CENSYS_CVE_FIELD}: "CVE-2021-44228"')
    print(res)
    print("\n" + "=" * 50)
    print("Test complete!")
