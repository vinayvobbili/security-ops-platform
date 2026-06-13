"""Self-contained XSIAM API helper for the detection-content CI pipeline.

This module is committed INTO the detection-content repo and executed by the
GitLab runner — it cannot import the IR application, so it carries its own
minimal Cortex XSIAM client (advanced API-key signing + the three calls the
pipeline needs: start an XQL query, fetch results, insert a correlation rule).

Credentials come from CI/CD variables (set them on the project, masked):
    XSIAM_API_KEY        the Advanced API key
    XSIAM_API_KEY_ID     the key id (x-xdr-auth-id)
    XSIAM_BASE_URL       e.g. https://api-<tenant>.xdr.<region>.paloaltonetworks.com

Only `requests` is required (`pip install requests`).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import string
import time
from typing import Any, Dict, List, Optional

import requests

_TIMEOUT = 60

_SEVERITY_ENUM = {
    "informational": "SEV_010_INFO",
    "low": "SEV_020_LOW",
    "medium": "SEV_030_MEDIUM",
    "high": "SEV_040_HIGH",
    "critical": "SEV_050_CRITICAL",
}

# Tenant/version dependent — mirrors services/xsiam.py CORRELATION_INSERT_PATH.
CORRELATION_INSERT_PATH = "public_api/v1/correlations/insert/"


class XsiamCI:
    """Minimal XSIAM client scoped to what the CI pipeline needs."""

    def __init__(self):
        self.api_key = (os.environ.get("XSIAM_API_KEY") or "").strip()
        self.api_key_id = (os.environ.get("XSIAM_API_KEY_ID") or "").strip()
        self.base_url = (os.environ.get("XSIAM_BASE_URL") or "").strip().rstrip("/")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key_id and self.base_url)

    def missing(self) -> List[str]:
        return [k for k, v in (
            ("XSIAM_API_KEY", self.api_key),
            ("XSIAM_API_KEY_ID", self.api_key_id),
            ("XSIAM_BASE_URL", self.base_url),
        ) if not v]

    def _headers(self) -> Dict[str, str]:
        nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        timestamp = int(time.time()) * 1000
        api_key_hash = hashlib.sha256(
            f"{self.api_key}{nonce}{timestamp}".encode("utf-8")
        ).hexdigest()
        return {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self.api_key_id),
            "Authorization": api_key_hash,
            "Content-Type": "application/json",
        }

    def _post(self, path: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            r = requests.post(url, headers=self._headers(),
                              json={"request_data": request_data}, timeout=_TIMEOUT)
            if r.status_code == 401:
                return {"error": "Invalid XSIAM credentials or expired signature (401)"}
            if r.status_code == 403:
                return {"error": "Access denied — insufficient XSIAM permissions (403)"}
            if r.status_code == 404:
                return {"error": f"XSIAM endpoint not found (404): {path}"}
            r.raise_for_status()
            return r.json() if r.text else {"success": True}
        except requests.exceptions.HTTPError as e:
            return {"error": f"XSIAM API error ({e.response.status_code}): {e.response.text[:300]}"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}

    # ── read-only XQL validation ──────────────────────────────────────────────
    def validate_xql(self, xql: str, window_hours: int = 1, max_wait: float = 60.0) -> Dict[str, Any]:
        """Run `xql` read-only over a short window to confirm it parses."""
        xql = (xql or "").strip()
        if not xql:
            return {"error": "Empty XQL"}
        now_ms = int(time.time() * 1000)
        started = self._post("public_api/v1/xql/start_xql_query/", {
            "query": xql, "tenants": [],
            "_time": {"from": now_ms - window_hours * 3600 * 1000, "to": now_ms},
        })
        if "error" in started:
            return {"error": started["error"]}
        query_id = started.get("reply")
        if not query_id:
            return {"error": f"No query id returned ({started})"}
        deadline = time.monotonic() + max_wait
        while True:
            res = self._post("public_api/v1/xql/get_query_results/", {
                "query_id": query_id, "pending_flag": True, "format": "json",
            })
            if "error" in res:
                return {"error": res["error"]}
            reply = res.get("reply") or {}
            if reply.get("status") != "PENDING":
                return {"ok": True, "results": reply.get("number_of_results", 0)}
            if time.monotonic() >= deadline:
                return {"error": f"XQL still PENDING after {max_wait:.0f}s"}
            time.sleep(3.0)

    # ── the one write op ──────────────────────────────────────────────────────
    def create_correlation_rule(self, manifest: Dict[str, Any], apply: bool = False) -> Dict[str, Any]:
        """Validate the manifest's XQL, then (only if apply=True) create the rule.

        With apply=False this returns what WOULD be created and writes nothing.
        """
        name = (manifest.get("name") or "").strip()
        xql = (manifest.get("xql") or manifest.get("xql_query") or "").strip()
        if not name:
            return {"error": "manifest missing 'name'"}
        if not xql:
            return {"error": "manifest missing 'xql'"}

        validation = self.validate_xql(xql)
        if "error" in validation:
            return {"error": f"XQL did not validate: {validation['error']}", "validated": False}

        rule = {
            "name": name,
            "description": manifest.get("description") or name,
            "severity": _SEVERITY_ENUM.get(str(manifest.get("severity", "medium")).lower(), "SEV_030_MEDIUM"),
            "xql_query": xql,
            "search_window": manifest.get("search_window") or "24_HOURS",
            "mitre_tactics": manifest.get("mitre_tactics") or [],
            "mitre_techniques": manifest.get("mitre_techniques") or [],
            "enabled": bool(manifest.get("enabled", True)),
        }
        if not apply:
            return {"dry_run": True, "validation": validation, "would_create": rule}

        res = self._post(CORRELATION_INSERT_PATH, rule)
        if "error" in res:
            return {"error": res["error"], "created": False, "validation": validation}
        return {"ok": True, "created": True, "validation": validation, "reply": res.get("reply", res)}


def load_manifests(path: str) -> List[Dict[str, Any]]:
    """Load every compiled-detection manifest (*.json) under `path`."""
    import glob
    import json

    out = []
    for f in sorted(glob.glob(os.path.join(path, "*.json"))):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            data["_file"] = f
            out.append(data)
        except (OSError, ValueError) as e:
            print(f"  ! skipping {f}: {e}")
    return out
