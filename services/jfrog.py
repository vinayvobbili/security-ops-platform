"""
JFrog Platform client — Artifactory (artifact repository) + Xray (security scanning).

Authentication is a scoped JFrog access token used as a Bearer token
(`JFROG_TOKEN`); `JFROG_TOKEN_ID` is the token's identifier, kept for
reference/revocation but not needed to authenticate. `JFROG_API_URL` is the
platform base (e.g. https://jfrog-artifactory.the-company.com) — Artifactory lives
under /artifactory and Xray under /xray.

The JFrog host is corp-internal and not reachable from the isolated lab net
without the corp-egress SOCKS proxy, so this client routes through it exactly
like the other corp-internal clients. the corporate proxy on the egress host intercepts TLS, so cert
verification is disabled when proxied.

Errors are returned, not raised: API methods return a dict with an "error" key
(and store the message on `last_error`) so callers can degrade gracefully —
matching services/veracode.py.

CVE→artifact exposure (`exposure()`) is answered ON DEMAND via the Xray
Vulnerabilities Report API (create → poll → fetch → delete), filtered by the
CVE(s) of interest. This is the direct, always-fresh path — no local crawl/cache.
It requires the access token to carry the Xray "Manage Reports" permission; until
that is granted the report endpoints return 403 and `exposure()` degrades to a
clear "not authorized" result. NOTE: the report request/response shapes below are
written to the documented API and must be validated against the live instance
once the permission is in place (see _create_vuln_report / _read_report_rows).
"""

import logging
import os
import time
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

# Corp-egress SOCKS failover front (primary → local fallback),
# same default the corp-internal clients use. Override with CORP_PROXY.
DEFAULT_CORP_SOCKS_PROXY = "socks5h://localhost:1079"

TIMEOUT = 60

# Exposure is scoped to the leadership-relevant severities; lower the floor here
# if a future caller needs Medium/Low.
_EXPOSURE_SEVERITIES = ["High", "Critical"]
# Bounds for polling a report to completion (Xray builds it async).
_REPORT_POLL_INTERVAL = 3
_REPORT_POLL_MAX_WAIT = 120

# Negative cache: once the Reports API 403s (token lacks Manage-Reports), skip the
# report dance — including the repo listing — for this long so we don't hammer
# JFrog on every tipper while the permission is pending. Auto-recovers within the
# TTL after the grant. Epoch seconds; 0 = not currently known-unauthorized.
_REPORTS_UNAUTHORIZED_TTL = 1800
_reports_unauthorized_until = 0.0


class JFrogClient:
    """Client for the JFrog Artifactory and Xray REST APIs."""

    def __init__(
        self,
        token: Optional[str] = None,
        api_url: Optional[str] = None,
        token_id: Optional[str] = None,
    ):
        config = get_config()
        self.token = token or getattr(config, "jfrog_token", None)
        self.token_id = token_id or getattr(config, "jfrog_token_id", None)
        self.api_url = (api_url or getattr(config, "jfrog_api_url", None) or "").rstrip("/")
        # The configured URL may be the host root, or include a path suffix like
        # /artifactory or /artifactory/api. Normalize to scheme://host so we can
        # build both the Artifactory (/artifactory/api/...) and Xray (/xray/...)
        # product paths from one root regardless of how JFROG_API_URL is written.
        parts = urlsplit(self.api_url)
        self.host_root = f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""
        self.last_error: Optional[str] = None

        self.session = requests.Session()
        self.session.verify = os.getenv("DISABLE_SSL_VERIFY", "").lower() != "true"

        # JFrog is corp-internal — route through the corp-egress SOCKS proxy.
        # the corporate proxy on the egress host intercepts TLS, so disable verify when proxied.
        proxy = (getattr(config, "corp_proxy", None) or "").strip() or DEFAULT_CORP_SOCKS_PROXY
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.verify = False
            logger.info("JFrog: using proxy %s", proxy)

        if self.token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
            })
        else:
            logger.warning("JFrog token not configured (JFROG_TOKEN)")

    def is_configured(self) -> bool:
        """True when we have both an access token and a resolvable host."""
        return bool(self.token and self.host_root)

    # ---- core request helper -------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """
        Make an authenticated request. `path` is appended to the host root and
        must include the product segment, e.g. '/artifactory/api/...' or
        '/xray/api/v1/...'.

        Returns the parsed JSON body on success, or {"error": "..."} on failure.
        Sets `self.last_error` on failure.
        """
        if not self.is_configured():
            self.last_error = "JFrog not configured (missing JFROG_TOKEN / JFROG_API_URL)"
            return {"error": self.last_error}

        url = f"{self.host_root}{path}"
        kwargs.setdefault("timeout", TIMEOUT)
        self.last_error = None
        try:
            resp = self.session.request(method, url, **kwargs)
            resp.raise_for_status()
            if not resp.content:
                return {}
            ctype = resp.headers.get("Content-Type", "")
            return resp.json() if "json" in ctype else resp.text
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response is not None else None
            if code in (401, 403):
                self.last_error = "JFrog auth failed (check JFROG_TOKEN / permissions)"
            else:
                body = (e.response.text if e.response is not None else "") or str(e)
                self.last_error = f"JFrog HTTP {code}: {body[:200]}"
            logger.warning("JFrog %s %s failed: %s", method, path, self.last_error)
            return {"error": self.last_error, "status_code": code}
        except requests.RequestException as e:
            self.last_error = str(e)
            logger.warning("JFrog %s %s failed: %s", method, path, e)
            return {"error": self.last_error}

    # ---- connectivity --------------------------------------------------------

    def ping(self) -> bool:
        """True if Artifactory answers its health ping (returns the text 'OK')."""
        # This endpoint emits text/plain; override the default Accept: application/json
        # (which the server rejects with 406 for a text response).
        result = self._request(
            "GET", "/artifactory/api/system/ping", headers={"Accept": "text/plain"}
        )
        return isinstance(result, str) and result.strip().upper() == "OK"

    # ---- Artifactory: artifact repository ------------------------------------

    def list_repositories(self, repo_type: Optional[str] = None) -> Any:
        """
        List configured repositories.

        repo_type: optional filter — 'local', 'remote', 'virtual', or 'federated'.
        Returns a list of {key, type, url, packageType, ...} dicts, or {"error": ...}.
        """
        params = {"type": repo_type} if repo_type else None
        return self._request("GET", "/artifactory/api/repositories", params=params)

    def search_aql(self, aql: str) -> Any:
        """
        Run an Artifactory Query Language search. `aql` is the full AQL string,
        e.g. 'items.find({"repo":"libs-release-local","name":{"$match":"*.jar"}})'.
        Returns the parsed {"results": [...], "range": {...}} body.
        """
        return self._request(
            "POST",
            "/artifactory/api/search/aql",
            data=aql,
            headers={"Content-Type": "text/plain"},
        )

    def file_info(self, repo: str, path: str) -> Any:
        """
        Storage metadata (size, checksums, timestamps) for a single artifact.
        repo: repository key; path: path within the repo.
        """
        return self._request("GET", f"/artifactory/api/storage/{repo}/{path.lstrip('/')}")

    def file_stats(self, repo: str, path: str) -> Any:
        """Download/usage stats for a single artifact (downloadCount, lastDownloaded)."""
        return self._request(
            "GET", f"/artifactory/api/storage/{repo}/{path.lstrip('/')}", params={"stats": ""}
        )

    # ---- Xray: security scanning ---------------------------------------------

    def xray_artifact_summary(
        self, paths: Optional[list[str]] = None, checksums: Optional[list[str]] = None
    ) -> Any:
        """
        Xray vulnerability + license summary for one or more artifacts.

        Provide repo paths (e.g. 'default/libs-release-local/foo/bar-1.0.jar') and/or
        SHA-256 checksums. Returns {"artifacts": [{general, issues, licenses}, ...]}.
        """
        body: dict[str, list[str]] = {}
        if paths:
            body["paths"] = paths
        if checksums:
            body["checksums"] = checksums
        if not body:
            self.last_error = "xray_artifact_summary needs paths and/or checksums"
            return {"error": self.last_error}
        return self._request("POST", "/xray/api/v1/summary/artifact", json=body)

    def xray_violations(self, filters: Optional[dict[str, Any]] = None,
                        page_num: int = 1, num_rows: int = 100) -> Any:
        """
        List Xray violations (security + license policy breaches).

        filters: optional Xray violation filter dict (e.g.
            {"violation_type": "security", "min_severity": "High",
             "created_from": "2026-01-01T00:00:00Z"}).
        Returns {"total_violations": N, "violations": [...]}.
        """
        body = {
            "filters": filters or {},
            "pagination": {"order_by": "created", "direction": "desc",
                           "page_num": page_num, "num_of_rows": num_rows},
        }
        return self._request("POST", "/xray/api/v1/violations", json=body)

    # ---- CVE→artifact exposure (on-demand via the Xray Reports API) -----------

    def exposure(self, cve_ids: Optional[list[str]] = None,
                 severities: Optional[list[str]] = None) -> dict:
        """Which of our artifacts carry a component affected by the given CVE(s).

        Answered on demand: builds a one-shot Xray Vulnerabilities Report filtered
        to these CVE(s) (High/Critical by default), reads the impacted artifacts
        out of it, then deletes the report. Always fresh — no local cache.

        Requires the token's Xray "Manage Reports" permission; without it the
        report endpoints 403 and this returns an unauthorized result that callers
        treat as "not checked".

        Returns a JSON-friendly dict mirroring the Veracode SCA service:
        ``{checked_at, configured, cves: {CVE: [exposures]},
        affected_artifact_count, exposed, summary_text, error?}``.
        """
        cves = sorted({str(c).upper().strip() for c in (cve_ids or [])
                       if c and str(c).upper().startswith("CVE-")})
        result: dict = {
            "checked_at": int(time.time()),
            "configured": self.is_configured(),
            "cves": {},
            "affected_artifact_count": 0,
            "exposed": False,
        }
        if not self.is_configured():
            result["error"] = "JFrog not configured"
            result["summary_text"] = self._summary_text(result)
            return result
        if not cves:
            result["summary_text"] = self._summary_text(result)
            return result

        # Short-circuit while the Reports API is known-unauthorized — no network
        # calls at all, so a pending permission costs nothing per tipper.
        if time.time() < _reports_unauthorized_until:
            result["error"] = (
                "JFrog Xray Reports API not authorized for this token — grant it "
                "the Xray 'Manage Reports' permission to enable CVE exposure lookups."
            )
            result["summary_text"] = self._summary_text(result)
            return result

        rows = self._report_exposure(cves, severities or _EXPOSURE_SEVERITIES)
        if isinstance(rows, dict) and "error" in rows:
            result["error"] = rows["error"]
            result["summary_text"] = self._summary_text(result)
            return result

        affected = set()
        for row in rows:
            cve = row.get("cve")
            if not cve:
                continue
            result["cves"].setdefault(cve, []).append({
                "artifact": row.get("artifact"),
                "repo": row.get("repo"),
                "component": row.get("component"),
                "version": row.get("version"),
                "severity": row.get("severity"),
                "fix_versions": row.get("fix_versions"),
            })
            affected.add(row.get("artifact"))
        result["affected_artifact_count"] = len(affected)
        result["exposed"] = bool(affected)
        result["summary_text"] = self._summary_text(result)
        return result

    def cve_exposure(self, cve_ids: list[str]) -> dict:
        """Thin wrapper over :meth:`exposure` for callers that only have CVEs."""
        return self.exposure(cve_ids=cve_ids)

    def _report_exposure(self, cves: list[str], severities: list[str]) -> Any:
        """Run a vulnerabilities report per CVE and return flat exposure rows.

        The vulnerabilities-report `cve` filter is a SINGLE string (verified
        against jfrog-client-go's VulnerabilitiesFilter), so we run one report per
        CVE and tag its rows with that CVE. The repo resource scope is computed
        once and reused across CVEs. Returns a list of {cve, artifact, repo,
        component, version, severity, fix_versions} dicts, or {"error": ...} on an
        auth/setup failure (403 = missing perm).
        """
        resources = self._all_repo_resources()
        if isinstance(resources, dict):  # error listing repos
            return resources
        all_rows: list[dict] = []
        for cve in cves:
            rid = self._create_vuln_report(cve, severities, resources)
            if isinstance(rid, dict):  # error
                # Auth failure → abort the whole lookup (negative cache armed).
                if rid.get("status_code") == 403:
                    return rid
                continue  # other create error for this CVE — skip it
            try:
                if self._await_report(rid):
                    all_rows.extend(self._read_report_rows(rid, cve))
            finally:
                self._delete_report(rid)
        return all_rows

    def _create_vuln_report(self, cve: str, severities: list[str],
                            resources: list[dict]) -> Any:
        """Create an Xray Vulnerabilities Report scoped to a single CVE.

        Request shape verified against jfrog-client-go's
        VulnerabilitiesReportRequestParams: name / resources.repositories[].name /
        filters.cve (single string) / filters.severities (list).
        Returns the report id (int) or {"error": ...}.
        """
        body = {
            "name": f"ir-exposure-{int(time.time())}",
            "resources": {"repositories": resources},
            "filters": {
                "cve": cve,
                "severities": severities,
            },
        }
        created = self._request("POST", "/xray/api/v1/reports/vulnerabilities", json=body)
        if isinstance(created, dict) and "error" in created:
            if created.get("status_code") == 403:
                global _reports_unauthorized_until
                _reports_unauthorized_until = time.time() + _REPORTS_UNAUTHORIZED_TTL
                created["error"] = (
                    "JFrog Xray Reports API not authorized for this token — grant it "
                    "the Xray 'Manage Reports' permission to enable CVE exposure lookups."
                )
                self.last_error = created["error"]
            return created
        rid = created.get("report_id") if isinstance(created, dict) else None
        if not rid:
            self.last_error = f"Xray report not created: {str(created)[:200]}"
            return {"error": self.last_error}
        return rid

    def _all_repo_resources(self) -> Any:
        """Repository resource list for a report scope (local repos = what we host).

        Returns a list of {"name": <repo-key>} dicts, or the {"error": ...} dict
        from list_repositories if that call failed (so a 403 propagates).
        """
        repos = self.list_repositories(repo_type="local")
        if isinstance(repos, list):
            return [{"name": r.get("key")} for r in repos if r.get("key")]
        if isinstance(repos, dict) and "error" in repos:
            return repos
        return []

    def _await_report(self, rid: int) -> bool:
        """Poll a report until it is completed (or timeout). True if completed."""
        waited = 0
        while waited < _REPORT_POLL_MAX_WAIT:
            status = self._request("GET", f"/xray/api/v1/reports/{rid}")
            state = (status.get("status") if isinstance(status, dict) else "") or ""
            if state.lower() in ("completed", "complete"):
                return True
            if state.lower() in ("failed", "error", "aborted"):
                self.last_error = f"Xray report {rid} status={state}"
                return False
            time.sleep(_REPORT_POLL_INTERVAL)
            waited += _REPORT_POLL_INTERVAL
        self.last_error = f"Xray report {rid} not ready after {_REPORT_POLL_MAX_WAIT}s"
        return False

    def _read_report_rows(self, rid: int, cve: str) -> list[dict]:
        """Read a completed single-CVE vulnerabilities report into exposure rows.

        Row schema verified against jfrog-client-go's Row struct: impacted_artifact
        / vulnerable_component ('<type>://<name>:<version>', so version is parsed
        out, not a separate field) / fixed_versions (list) / severity. The report
        is filtered to one CVE, so every row is tagged with `cve`.
        """
        out: list[dict] = []
        page = 1
        while True:
            body = {"pagination": {"order_by": "severity", "direction": "desc",
                                   "page_num": page, "num_of_rows": 100}}
            data = self._request(
                "POST", f"/xray/api/v1/reports/vulnerabilities/{rid}", json=body)
            if not isinstance(data, dict) or "error" in data:
                break
            rows = data.get("rows") or []
            if not rows:
                break
            for r in rows:
                comp_raw = r.get("vulnerable_component") or ""
                name, ver = self._split_component(comp_raw) if comp_raw else ("", "")
                art = r.get("impacted_artifact") or ""
                fixes = r.get("fixed_versions") or []
                out.append({
                    "cve": cve,
                    "artifact": art,
                    "repo": self._repo_from_artifact_path(art),
                    "component": name or comp_raw,
                    "version": ver,
                    "severity": r.get("severity"),
                    "fix_versions": ", ".join(fixes) if isinstance(fixes, list) else str(fixes or ""),
                })
            total = data.get("total_rows") or 0
            if page * 100 >= total:
                break
            page += 1
        return out

    def _delete_report(self, rid: int) -> None:
        """Best-effort cleanup of a one-shot report."""
        self._request("DELETE", f"/xray/api/v1/reports/{rid}")

    @staticmethod
    def _repo_from_artifact_path(path: str) -> str:
        """Repository key from an Xray artifact path 'default/<repo>/<path...>'."""
        parts = [p for p in str(path).split("/") if p]
        return parts[1] if len(parts) > 1 else (parts[0] if parts else "")

    @staticmethod
    def _split_component(comp: str) -> tuple[str, str]:
        """Split a component token into (name, version).

        Xray formats these as '<type>://<name>:<version>', e.g.
        'go://golang.org/x/crypto:0.27.0', 'gav://com.fasterxml:jackson:2.9.8',
        or 'npm://lodash:4.17.0'. Returns (name, "") when there's no version.
        """
        s = str(comp)
        if "://" in s:
            s = s.split("://", 1)[1]
        if ":" in s:
            name, version = s.rsplit(":", 1)
            return name, version
        return s, ""

    @staticmethod
    def _summary_text(result: dict) -> str:
        if result.get("error"):
            return f"JFrog Xray check unavailable: {result['error']}"
        n = result.get("affected_artifact_count", 0)
        if not n:
            return ("No artifacts in JFrog carry a High/Critical component matching "
                    "this tipper's CVE(s) per Xray.")
        return (f"{n} artifact{'' if n == 1 else 's'} in JFrog carry a High/Critical "
                f"component affected by this tipper's CVE(s) per Xray.")


_client: Optional[JFrogClient] = None


def get_client() -> JFrogClient:
    """Module-level singleton accessor."""
    global _client
    if _client is None:
        _client = JFrogClient()
    return _client


def exposure(cve_ids: Optional[list[str]] = None,
             severities: Optional[list[str]] = None) -> dict:
    """Convenience wrapper: which artifacts are exposed to these CVE(s) per Xray."""
    return get_client().exposure(cve_ids=cve_ids, severities=severities)


def cve_exposure(cve_ids: list[str]) -> dict:
    """Convenience wrapper: which artifacts are exposed to these CVE(s) per Xray."""
    return get_client().cve_exposure(cve_ids)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    client = JFrogClient()

    if not client.is_configured():
        print("ERROR: JFrog not configured.")
        print("Ensure JFROG_API_URL, JFROG_TOKEN_ID, and JFROG_TOKEN are set in .secrets.age")
        raise SystemExit(1)

    print(f"JFrog host: {client.host_root}  (configured: {client.api_url})")
    print(f"Token id: {client.token_id}")

    print("\n1. Ping Artifactory ...")
    print(f"   reachable: {client.ping()}")

    print("\n2. List repositories ...")
    repos = client.list_repositories()
    if isinstance(repos, dict) and "error" in repos:
        print(f"   error: {repos['error']}")
    elif isinstance(repos, list):
        print(f"   {len(repos)} repositories")

    print("\n3. CVE exposure (on-demand Reports API) ...")
    exp = client.exposure(cve_ids=["CVE-2024-45337"])
    print(f"   {exp['summary_text']}")
    if exp.get("error"):
        print(f"   (error: {exp['error']})")
