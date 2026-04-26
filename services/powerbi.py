"""Power BI REST API client — MSAL auth (cert or secret) + DAX query execution."""

import logging
import time
from pathlib import Path
from typing import Optional

import msal
import requests
from requests.exceptions import ChunkedEncodingError, ConnectionError, Timeout

from my_config import get_config

logger = logging.getLogger(__name__)

# Power BI REST API base
_PBI_API = "https://api.powerbi.com/v1.0/myorg"


class PowerBIClient:
    """Thin wrapper around the Power BI REST API (read-only).

    Supports two authentication modes:
      1. Certificate-based (preferred): POWER_BI_CERT_PATH + POWER_BI_CERT_THUMBPRINT
      2. Client secret fallback: POWER_BI_CLIENT_SECRET
    """

    def __init__(self):
        cfg = get_config()
        self.tenant_id = cfg.power_bi_tenant_id
        self.client_id = cfg.power_bi_client_id
        self.client_secret = cfg.power_bi_client_secret
        self.workspace_id = cfg.power_bi_workspace_id
        self.default_dataset_id = cfg.power_bi_dataset_id
        cert_path = cfg.power_bi_cert_path
        cert_thumbprint = cfg.power_bi_cert_thumbprint

        missing = []
        if not self.tenant_id:
            missing.append("POWER_BI_TENANT_ID")
        if not self.client_id:
            missing.append("POWER_BI_CLIENT_ID")
        if missing:
            raise RuntimeError(f"Power BI config missing: {', '.join(missing)}")

        # Build MSAL credential — cert takes priority over client secret
        if cert_path and cert_thumbprint:
            pem_path = Path(cert_path)
            if not pem_path.is_absolute():
                pem_path = Path(__file__).parent.parent / "data" / "transient" / cert_path
            if not pem_path.exists():
                raise RuntimeError(f"Power BI cert not found: {pem_path}")
            private_key = pem_path.read_text()
            credential = {
                "private_key": private_key,
                "thumbprint": cert_thumbprint,
            }
            logger.info("Power BI auth: certificate (thumbprint=%s...)", cert_thumbprint[:8])
        elif self.client_secret:
            credential = self.client_secret
            logger.info("Power BI auth: client secret")
        else:
            raise RuntimeError(
                "Power BI auth requires either POWER_BI_CERT_PATH + POWER_BI_CERT_THUMBPRINT "
                "or POWER_BI_CLIENT_SECRET"
            )

        self._app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential=credential,
        )
        self._token_cache: Optional[str] = None

    def _get_token(self) -> str:
        """Acquire an access token (cached by MSAL)."""
        result = self._app.acquire_token_for_client(
            scopes=["https://analysis.windows.net/powerbi/api/.default"]
        )
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            raise RuntimeError(f"MSAL token acquisition failed: {error}")
        return result["access_token"]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}"}

    # ── Discovery ──

    def list_datasets(self, workspace_id: str | None = None) -> list[dict]:
        """List datasets in a workspace (or 'My Workspace' if no workspace_id)."""
        ws = workspace_id or self.workspace_id
        if ws:
            url = f"{_PBI_API}/groups/{ws}/datasets"
        else:
            url = f"{_PBI_API}/datasets"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])

    def get_tables(self, dataset_id: str, workspace_id: str | None = None) -> list[dict]:
        """Get tables in a dataset (push datasets only — returns 404 for import-mode datasets).
        For import-mode datasets, use get_dataset_info or run an INFORMATION_SCHEMA DAX query."""
        ws = workspace_id or self.workspace_id
        if ws:
            url = f"{_PBI_API}/groups/{ws}/datasets/{dataset_id}/tables"
        else:
            url = f"{_PBI_API}/datasets/{dataset_id}/tables"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.json().get("value", [])

    # ── Refresh History ──

    def get_last_refresh(self, dataset_id: str, workspace_id: str | None = None) -> dict | None:
        """Get the most recent refresh entry for a dataset.

        Returns {"startTime": ..., "endTime": ..., "status": ...} or None.
        """
        ws = workspace_id or self.workspace_id
        if ws:
            url = f"{_PBI_API}/groups/{ws}/datasets/{dataset_id}/refreshes?$top=1"
        else:
            url = f"{_PBI_API}/datasets/{dataset_id}/refreshes?$top=1"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=15)
            if resp.ok:
                entries = resp.json().get("value", [])
                return entries[0] if entries else None
        except Exception:
            pass
        return None

    # ── DAX Execution ──

    def execute_dax(
        self, dataset_id: str, dax_query: str, workspace_id: str | None = None
    ) -> dict:
        """Execute a DAX query and return the parsed result.

        Returns:
            {
                "columns": ["Col1", "Col2", ...],
                "rows": [{"Col1": val, "Col2": val}, ...],
                "row_count": int
            }
        """
        ws = workspace_id or self.workspace_id
        if ws:
            url = f"{_PBI_API}/groups/{ws}/datasets/{dataset_id}/executeQueries"
        else:
            url = f"{_PBI_API}/datasets/{dataset_id}/executeQueries"

        payload = {
            "queries": [{"query": dax_query}],
            "serializerSettings": {"includeNulls": True},
        }
        last_exc = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    url, json=payload, headers=self._headers(), timeout=120
                )
                break
            except (ChunkedEncodingError, ConnectionError, Timeout) as exc:
                last_exc = exc
                logger.warning("DAX request attempt %d failed: %s", attempt + 1, exc)
                if attempt < 2:
                    time.sleep(1 * (attempt + 1))
        else:
            return {"error": f"DAX connection failed after 3 attempts: {last_exc}", "columns": [], "rows": [], "row_count": 0}

        if not resp.ok:
            try:
                body = resp.json()
                error_detail = body.get("error", {}).get("message", resp.text)
            except Exception:
                error_detail = resp.text[:500]
            return {"error": f"DAX error ({resp.status_code}): {error_detail}", "columns": [], "rows": [], "row_count": 0}

        data = resp.json()
        table = data["results"][0]["tables"][0]
        rows = table.get("rows", [])
        columns = [col["name"] for col in table.get("columns", [])] if "columns" in table else (
            list(rows[0].keys()) if rows else []
        )
        return {"columns": columns, "rows": rows, "row_count": len(rows)}
