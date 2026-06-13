"""
Veracode REST API client.

Provides integration with the Veracode Application Security platform, focused on
Software Composition Analysis (SCA): mapping a CVE (or an affected open-source
package) to the applications in our portfolio that actually carry the
vulnerable component.

Authentication uses Veracode's OAuth2 client-credentials flow: the client id +
secret are exchanged (HTTP Basic) at the token endpoint for a short-lived bearer
token, which is then sent as ``Authorization: Bearer <token>`` on each REST call.
The token is cached in-memory until shortly before it expires.

API docs: https://docs.veracode.com/r/c_rest_api_intro
"""

import logging
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from my_config import get_config

logger = logging.getLogger(__name__)

TIMEOUT = 60
# The portfolio is multi-thousand apps, so we never iterate per-app findings.
# Instead one Analytics "FINDINGS" report (scan_type=SCA) returns every open SCA
# finding across all applications in a single async job; we page its results.
_REPORT_MAX_PAGES = 400          # safety bound on report result pages (~170 today)
_REPORT_POLL_SECONDS = 5         # delay between generation status polls
_REPORT_POLL_MAX_WAIT = 600      # give up generating a report after this long
# The Analytics report requires last_updated_start_date within the last 0-6
# months, so the index is a rolling window: every app scanned in that window is
# covered (anything not scanned in 6 months is stale). Stay just inside the cap.
_REPORT_WINDOW_DAYS = 179
# The CVE->apps index is a full-portfolio report (~240k rows, ~6 min build), so
# it lives in a SQLite table refreshed by a background job and is reused within
# this TTL. Consumers only ever READ it — a stale/missing index triggers an
# async refresh, never an inline build.
_INDEX_TTL_SECONDS = 24 * 60 * 60  # 24 hours
_INDEX_DB_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "transient" / "veracode_sca_index.db"
)

# Package ecosystems recognized in purls / "name@version" tokens, used to strip
# a purl or ecosystem prefix down to the bare component name for matching.
_PURL_ECOSYSTEMS = {
    "npm", "pypi", "pip", "maven", "gem", "rubygems", "nuget", "golang", "go",
    "cargo", "crates", "composer", "packagist", "cocoapods", "swift", "hex",
    "pub", "conan", "generic",
}

# Veracode numeric severity (0-5) -> label, used across SCA + SAST findings.
_SEVERITY_LABELS = {
    0: "Informational",
    1: "Very Low",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Very High",
}

# Module-level guards so concurrent enrichers (tipper threads, advisory poller,
# web requests) never start more than one rebuild at a time.
_index_lock = threading.Lock()       # held for the duration of a build
_refresh_flag_lock = threading.Lock()
_refresh_in_progress = False


def severity_label(value: Any) -> str:
    """Map a Veracode numeric severity to its human label (pass-through if unknown)."""
    try:
        return _SEVERITY_LABELS.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value) if value not in (None, "") else "Unknown"


class VeracodeClient:
    """Client for the Veracode REST API (HMAC-authenticated)."""

    def __init__(
        self,
        api_id: Optional[str] = None,
        api_secret: Optional[str] = None,
        base_url: Optional[str] = None,
        token_url: Optional[str] = None,
    ):
        config = get_config()
        self.api_id = api_id or getattr(config, "veracode_client_id", None)
        self.api_secret = api_secret or getattr(config, "veracode_client_secret", None)
        self.base_url = (
            base_url
            or getattr(config, "veracode_api_base_url", None)
            or "https://api.veracode.com"
        ).rstrip("/")
        # OAuth2 token endpoint (Veracode Identity service). Derived from the API
        # host for the commercial region; override with VERACODE_TOKEN_URL for
        # the EU (veracode.eu) / US (veracode.us) regions or a fronting gateway.
        self.token_url = (
            token_url
            or getattr(config, "veracode_token_url", None)
            or f"{self.base_url}/api/authn/v2/oauth2/token"
        )
        self.timeout = TIMEOUT
        self.last_error: Optional[str] = None
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

        if not self.api_id:
            logger.warning("Veracode client id not configured")
        if not self.api_secret:
            logger.warning("Veracode client secret not configured")

    def is_configured(self) -> bool:
        return bool(self.api_id and self.api_secret and self.token_url)

    # ── Auth (OAuth2 client-credentials) ──────────────────────────────────────

    def _bearer_token(self) -> Optional[str]:
        """Return a cached bearer token, fetching a new one when expired.

        Exchanges client id/secret (HTTP Basic) for a token at the token
        endpoint with ``grant_type=client_credentials``. Raises on transport
        errors so the caller's ``except requests.RequestException`` can handle it.
        """
        now = time.time()
        # Refresh a minute early to avoid using a token that expires mid-request.
        if self._token and now < (self._token_expiry - 60):
            return self._token
        resp = requests.post(
            self.token_url,
            auth=HTTPBasicAuth(self.api_id, self.api_secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        payload = resp.json() if resp.text else {}
        self._token = payload.get("access_token")
        try:
            ttl = float(payload.get("expires_in", 3600))
        except (TypeError, ValueError):
            ttl = 3600.0
        self._token_expiry = now + ttl
        return self._token

    # ── Low-level request ─────────────────────────────────────────────────────

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET an API path, returning parsed JSON or ``{"error": ...}``."""
        if not self.is_configured():
            return {"error": "Veracode API not configured (missing client id/secret/token URL)"}

        url = f"{self.base_url}{path}"
        try:
            token = self._bearer_token()
            if not token:
                self.last_error = "Veracode OAuth token request returned no access_token"
                logger.warning("Veracode: %s", self.last_error)
                return {"error": self.last_error}
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            resp = requests.get(url, headers=headers, params=params or {}, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json() if resp.text else {}
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response is not None else None
            if code in (401, 403):
                self.last_error = "Veracode auth failed (check client id/secret)"
            else:
                self.last_error = f"Veracode HTTP {code}: {(e.response.text or str(e))[:200]}"
            logger.warning("Veracode GET %s failed: %s", path, self.last_error)
            return {"error": self.last_error}
        except requests.RequestException as e:
            self.last_error = str(e)
            logger.warning("Veracode GET %s failed: %s", path, e)
            return {"error": str(e)}

    def _get_paginated(
        self, path: str, params: Optional[Dict[str, Any]] = None, max_pages: int = 100
    ) -> List[Dict[str, Any]]:
        """Walk a HAL-paginated collection endpoint, returning all embedded items.

        Veracode wraps collections as ``{"_embedded": {<key>: [...]}, "page": {...}}``.
        We don't know the embed key up front, so we take the first list found.
        """
        params = dict(params or {})
        params.setdefault("size", 500)
        items: List[Dict[str, Any]] = []
        page = 0
        while page < max_pages:
            params["page"] = page
            data = self._get(path, params)
            if "error" in data:
                break
            embedded = data.get("_embedded") or {}
            page_items: List[Dict[str, Any]] = []
            for value in embedded.values():
                if isinstance(value, list):
                    page_items = value
                    break
            items.extend(page_items)
            page_info = data.get("page") or {}
            total_pages = page_info.get("total_pages")
            if not page_items or (total_pages is not None and page + 1 >= total_pages):
                break
            page += 1
        return items

    # ── High-level API ────────────────────────────────────────────────────────

    def list_applications(self) -> List[Dict[str, Any]]:
        """Return all application profiles (guid + name + business criticality).

        Used by the connectors health probe; the CVE index no longer iterates
        applications (it uses the Analytics report instead).
        """
        apps = self._get_paginated("/appsec/v1/applications", max_pages=20)
        out = []
        for app in apps:
            profile = app.get("profile") or {}
            out.append(
                {
                    "guid": app.get("guid"),
                    "name": profile.get("name") or app.get("guid"),
                    "business_criticality": profile.get("business_criticality"),
                }
            )
        return out

    # ── SCA findings via the Analytics Reporting API ──────────────────────────

    def _post(self, path: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        """POST JSON to an API path, returning parsed JSON or ``{"error": ...}``."""
        if not self.is_configured():
            return {"error": "Veracode API not configured"}
        url = f"{self.base_url}{path}"
        try:
            token = self._bearer_token()
            if not token:
                return {"error": "Veracode OAuth token request returned no access_token"}
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            resp = requests.post(url, headers=headers, json=json_body, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json() if resp.text else {}
        except requests.RequestException as e:
            self.last_error = str(e)
            logger.warning("Veracode POST %s failed: %s", path, e)
            return {"error": str(e)}

    def _generate_sca_report(self) -> Optional[str]:
        """Create one Analytics FINDINGS report (SCA, open) over the whole portfolio
        and return its id once generated. Returns None on failure (sets last_error).

        Avoids per-application iteration entirely — one async report covers all
        ~4k apps. The window is the last ~6 months (the API's hard cap on
        last_updated_start_date).
        """
        start_date = (datetime.now(timezone.utc) - timedelta(days=_REPORT_WINDOW_DAYS)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        body = {
            "report_type": "FINDINGS",
            "scan_type": ["SCA"],
            "status": "open",
            "last_updated_start_date": start_date,
        }
        created = self._post("/appsec/v1/analytics/report", body)
        emb = created.get("_embedded") or {}
        rid = emb.get("id") or created.get("id")
        if "error" in created or not rid:
            self.last_error = created.get("error") or "report creation returned no id"
            logger.warning("Veracode: SCA report not created: %s", self.last_error)
            return None

        waited, status = 0, ""
        while waited <= _REPORT_POLL_MAX_WAIT:
            data = self._get(f"/appsec/v1/analytics/report/{rid}", {"page": 0, "size": 1})
            emb = data.get("_embedded") or {}
            status = str(emb.get("status") or data.get("status") or "").upper()
            if status == "COMPLETED":
                return rid
            if "ERROR" in status or "FAIL" in status:
                self.last_error = f"Veracode report status {status}"
                return None
            time.sleep(_REPORT_POLL_SECONDS)
            waited += _REPORT_POLL_SECONDS
        self.last_error = f"Veracode report not ready after {_REPORT_POLL_MAX_WAIT}s (status={status})"
        logger.warning(self.last_error)
        return None

    def _iter_report_pages(self, rid: str):
        """Yield each page's list of finding rows for a generated report.

        The report's own page size (~2.5k) is used — the ``size`` param is
        ignored server-side — so we page by index and stop at total_pages.
        """
        page = 0
        while page < _REPORT_MAX_PAGES:
            data = self._get(f"/appsec/v1/analytics/report/{rid}", {"page": page})
            emb = data.get("_embedded") or {}
            findings = emb.get("findings") or []
            if "error" in data:
                break
            yield findings
            meta = emb.get("page_metadata") or data.get("page_metadata") or {}
            total_pages = meta.get("total_pages")
            if not findings:
                break
            if total_pages is not None and page + 1 >= total_pages:
                break
            page += 1

    # ── CVE -> affected applications index ─────────────────────────────────────

    @staticmethod
    def _cve_from_finding(finding: Dict[str, Any]) -> Optional[str]:
        name = finding.get("cve_id") or finding.get("cve_name")
        if not name:
            return None
        name = str(name).upper().strip()
        return name if name.startswith("CVE-") else None

    @staticmethod
    def _component_name(finding: Dict[str, Any]) -> str:
        return (
            finding.get("component_name")
            or finding.get("filename")
            or finding.get("component_file_path")
            or "unknown component"
        )

    @staticmethod
    def _normalize_package_name(raw: Optional[str]) -> str:
        """Reduce a package reference to a bare, lowercased name for matching.

        Handles purls (``pkg:npm/left-pad@1.3.0``), ``name@version`` tokens
        (``left-pad@1.3.0``), scoped npm names (``@scope/pkg``), ``ecosystem:name``
        prefixes (``npm:left-pad``), Maven ``group:artifact`` coordinates (kept
        whole), and the versioned archive filenames Veracode indexes Java/.NET
        components as (``log4j-core-2.17.1.jar`` -> ``log4j-core``). Returns ""
        when nothing usable remains.
        """
        if not raw:
            return ""
        s = str(raw).strip().lower()
        # purl: pkg:<eco>/<namespace>?/<name>@<version>?<qualifiers>
        if s.startswith("pkg:"):
            s = s[4:].split("?", 1)[0].split("#", 1)[0]
            if "/" in s:
                eco, rest = s.split("/", 1)
                if eco in _PURL_ECOSYSTEMS:
                    s = rest
        # strip a trailing @version (but keep a leading @scope, so at > 0 only)
        at = s.rfind("@")
        if at > 0:
            s = s[:at]
        # strip an "<eco>:" prefix like "npm:left-pad" (Maven group:artifact kept)
        if ":" in s:
            head, tail = s.split(":", 1)
            if head in _PURL_ECOSYSTEMS:
                s = tail
        s = s.strip().strip("/")
        # Veracode indexes Java/.NET components as versioned archive filenames
        # (log4j-core-2.17.1.jar, jackson-databind-2.13.3.jar). Drop a known
        # archive extension, then a trailing dotted ``-<version>`` segment, so a
        # tipper/advisory's bare ``log4j-core`` matches. The dotted-version
        # requirement keeps real hyphenated names (utf-8, utils-terminal) intact.
        for ext in (".jar", ".war", ".ear", ".aar"):
            if s.endswith(ext):
                s = s[: -len(ext)]
                break
        s = re.sub(r"-\d[0-9a-z]*(?:\.[0-9a-z]+)+$", "", s)
        return s.strip()

    def build_sca_index(self, force: bool = False) -> Dict[str, Any]:
        """Rebuild the SQLite CVE->apps index from a fresh portfolio SCA report.

        Streams the report pages into the ``sca_exposure`` table inside a single
        transaction, so readers keep seeing the previous index until commit.
        Heavy (~6 min); call it from a background refresh, not a request path.
        Guarded by _index_lock; honours the TTL unless ``force``.

        Returns the index meta dict (see ``_index_meta``).
        """
        with _index_lock:
            meta = self._index_meta()
            if not force and meta.get("built_at") and (time.time() - meta["built_at"]) < _INDEX_TTL_SECONDS:
                return meta
            if not self.is_configured():
                return {"built_at": 0, "error": "not configured"}

            rid = self._generate_sca_report()
            if not rid:
                # Keep any existing index rather than wiping it on a transient failure.
                return self._index_meta() or {"built_at": 0, "error": self.last_error or "report failed"}

            conn = self._connect()
            try:
                self._init_schema(conn)
                cur = conn.cursor()
                cur.execute("BEGIN")
                cur.execute("DELETE FROM sca_exposure")
                finding_count, cves, apps, components = 0, set(), set(), set()
                for findings in self._iter_report_pages(rid):
                    batch = []
                    for f in findings:
                        # Retain every SCA finding — not just CVE-bearing ones — so
                        # the index also answers package-name lookups (cve_id may be
                        # NULL for component findings without an assigned CVE).
                        cve = self._cve_from_finding(f)
                        real_comp = (
                            f.get("component_name") or f.get("filename")
                            or f.get("component_file_path")
                        )
                        comp_norm = self._normalize_package_name(real_comp) if real_comp else ""
                        if not cve and not comp_norm:
                            continue
                        finding_count += 1
                        if cve:
                            cves.add(cve)
                        if comp_norm:
                            components.add(comp_norm)
                        apps.add(f.get("app_id") or f.get("app_name"))
                        batch.append((
                            cve, f.get("app_id"), f.get("app_name"),
                            self._component_name(f), f.get("component_version"),
                            severity_label(f.get("severity")), f.get("business_unit"),
                            comp_norm,
                        ))
                    if batch:
                        cur.executemany(
                            "INSERT INTO sca_exposure "
                            "(cve_id, app_id, app_name, component, version, severity_label, "
                            "business_unit, component_norm) "
                            "VALUES (?,?,?,?,?,?,?,?)", batch,
                        )
                built_at = time.time()
                for k, v in (("built_at", built_at), ("finding_count", finding_count),
                             ("app_count", len(apps)), ("distinct_cves", len(cves)),
                             ("distinct_components", len(components))):
                    cur.execute("INSERT OR REPLACE INTO sca_meta (key, value) VALUES (?, ?)", (k, str(v)))
                conn.commit()
                logger.info("Veracode SCA index built: %d findings, %d apps, %d CVEs, %d components",
                            finding_count, len(apps), len(cves), len(components))
                return self._index_meta()
            except Exception as e:
                conn.rollback()
                self.last_error = str(e)
                logger.warning("Veracode SCA index build failed: %s", e)
                return self._index_meta() or {"built_at": 0, "error": str(e)}
            finally:
                conn.close()

    def exposure(
        self,
        cve_ids: Optional[List[str]] = None,
        packages: Optional[List[str]] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Which applications are exposed to the given CVE(s) and/or package(s).

        Two correlation axes against the same cached SQLite index:
          * ``cve_ids`` — apps carrying a component affected by that CVE;
          * ``packages`` — apps carrying that named open-source package (purl or
            ``name@version``), matched on the component name of an *open SCA
            finding*. A miss means no open finding references the package — it is
            NOT proof the package is absent from every app's full SBOM.

        Reads the cached index — never builds inline. A missing index kicks a
        background refresh and returns ``indexing: True``; a stale index is served
        as-is while a background refresh runs. Returns a JSON-friendly dict:
        ``{checked_at, configured, cves: {CVE: [exposures]},
        packages: {token: [exposures]}, affected_app_count, exposed, indexing,
        index_built_at, summary_text, error?}``.
        """
        cves = sorted({str(c).upper().strip() for c in (cve_ids or []) if c and str(c).upper().startswith("CVE-")})
        # normalized package name -> the original token the caller passed, so
        # results are reported against what the tipper/advisory actually said.
        pkg_map: Dict[str, str] = {}
        for p in packages or []:
            norm = self._normalize_package_name(p)
            if norm:
                pkg_map.setdefault(norm, str(p))

        result: Dict[str, Any] = {
            "checked_at": int(time.time()),
            "configured": self.is_configured(),
            "cves": {},
            "packages": {},
            "affected_app_count": 0,
            "exposed": False,
        }
        if not self.is_configured():
            result["error"] = "Veracode API not configured"
            result["summary_text"] = self._summary_text(result)
            return result
        if not cves and not pkg_map:
            result["summary_text"] = self._summary_text(result)
            return result

        if force_refresh:
            self.build_sca_index(force=True)

        meta = self._index_meta()
        built_at = meta.get("built_at") or 0
        if not built_at:
            # No index yet — start one in the background, don't block the caller.
            self.ensure_fresh_async()
            result["indexing"] = True
            result["error"] = "Veracode SCA index is building; results available shortly"
            result["summary_text"] = self._summary_text(result)
            return result
        if (time.time() - built_at) > _INDEX_TTL_SECONDS:
            self.ensure_fresh_async()  # serve stale now, refresh for next time

        affected = set()
        if cves:
            for row in self._query_exposure(cves):
                result["cves"].setdefault(row["cve_id"], []).append({
                    "application": row["app_name"],
                    "app_id": row["app_id"],
                    "component": row["component"],
                    "version": row["version"],
                    "severity_label": row["severity_label"],
                    "business_unit": row["business_unit"],
                })
                affected.add(row["app_id"] or row["app_name"])
        if pkg_map:
            for row in self._query_component_exposure(list(pkg_map)):
                label = pkg_map.get(row["component_norm"], row["component_norm"])
                result["packages"].setdefault(label, []).append({
                    "application": row["app_name"],
                    "app_id": row["app_id"],
                    "component": row["component"],
                    "version": row["version"],
                    "severity_label": row["severity_label"],
                    "business_unit": row["business_unit"],
                    "cve_id": row["cve_id"],
                })
                affected.add(row["app_id"] or row["app_name"])
        result["affected_app_count"] = len(affected)
        result["exposed"] = bool(affected)
        result["index_built_at"] = built_at
        result["summary_text"] = self._summary_text(result)
        return result

    def cve_exposure(self, cve_ids: List[str], force_refresh: bool = False) -> Dict[str, Any]:
        """Which applications are exposed to the given CVE(s) per Veracode SCA.

        Thin wrapper over :meth:`exposure` (CVE axis only); kept for callers that
        only have CVEs (e.g. the advisory poller).
        """
        return self.exposure(cve_ids=cve_ids, force_refresh=force_refresh)

    def component_exposure(self, packages: List[str], force_refresh: bool = False) -> Dict[str, Any]:
        """Which applications carry the named open-source package(s) per Veracode SCA.

        Thin wrapper over :meth:`exposure` (package axis only).
        """
        return self.exposure(packages=packages, force_refresh=force_refresh)

    @staticmethod
    def _summary_text(result: Dict[str, Any]) -> str:
        if result.get("indexing"):
            return "Veracode SCA index is building — check back in a few minutes."
        if result.get("error"):
            return f"Veracode check unavailable: {result['error']}"
        n = result.get("affected_app_count", 0)
        if not n:
            return (
                "No applications in the Veracode portfolio carry a component matching "
                "this tipper's CVE(s)/package(s) per open SCA findings."
            )
        axes = []
        if result.get("cves"):
            axes.append("CVE")
        if result.get("packages"):
            axes.append("named package")
        axis = " / ".join(axes) or "component"
        return (
            f"{n} application{'' if n == 1 else 's'} carry an open-source component "
            f"matching this tipper's {axis} per Veracode SCA."
        )

    # ── SQLite index store + background refresh ────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        _INDEX_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(_INDEX_DB_PATH), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # readers never block the build
        return conn

    @staticmethod
    def _init_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sca_exposure ("
            "cve_id TEXT, app_id INTEGER, app_name TEXT, component TEXT, "
            "version TEXT, severity_label TEXT, business_unit TEXT, component_norm TEXT)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sca_cve ON sca_exposure(cve_id)")
        # Backfill the normalized-component column for indexes created before the
        # package-name lookup path existed (next rebuild repopulates the values).
        cols = {r[1] for r in conn.execute("PRAGMA table_info(sca_exposure)")}
        if "component_norm" not in cols:
            conn.execute("ALTER TABLE sca_exposure ADD COLUMN component_norm TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sca_component ON sca_exposure(component_norm)")
        conn.execute("CREATE TABLE IF NOT EXISTS sca_meta (key TEXT PRIMARY KEY, value TEXT)")

    def _index_meta(self) -> Dict[str, Any]:
        try:
            conn = self._connect()
            try:
                self._init_schema(conn)
                rows = conn.execute("SELECT key, value FROM sca_meta").fetchall()
            finally:
                conn.close()
        except sqlite3.Error as e:
            logger.debug("Veracode index meta read failed: %s", e)
            return {}
        m = {r["key"]: r["value"] for r in rows}
        out: Dict[str, Any] = {}
        if "built_at" in m:
            try:
                out["built_at"] = float(m["built_at"])
            except (TypeError, ValueError):
                out["built_at"] = 0
        for k in ("finding_count", "app_count", "distinct_cves", "distinct_components"):
            if k in m:
                try:
                    out[k] = int(m[k])
                except (TypeError, ValueError):
                    pass
        return out

    def _query_exposure(self, cves: List[str]) -> List[sqlite3.Row]:
        if not cves:
            return []
        try:
            conn = self._connect()
            try:
                self._init_schema(conn)
                placeholders = ",".join("?" * len(cves))
                # DISTINCT collapses the same component/version reported across
                # multiple scans or branches of one app into a single row.
                return conn.execute(
                    "SELECT DISTINCT cve_id, app_id, app_name, component, version, severity_label, business_unit "
                    f"FROM sca_exposure WHERE cve_id IN ({placeholders}) "
                    "ORDER BY cve_id, app_name, component",
                    cves,
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as e:
            logger.warning("Veracode exposure query failed: %s", e)
            return []

    def _query_component_exposure(self, norms: List[str]) -> List[sqlite3.Row]:
        """Rows whose normalized component name matches any of ``norms``."""
        if not norms:
            return []
        try:
            conn = self._connect()
            try:
                self._init_schema(conn)
                placeholders = ",".join("?" * len(norms))
                return conn.execute(
                    "SELECT DISTINCT cve_id, app_id, app_name, component, version, "
                    "severity_label, business_unit, component_norm "
                    f"FROM sca_exposure WHERE component_norm IN ({placeholders}) "
                    "ORDER BY component_norm, app_name, version",
                    norms,
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as e:
            logger.warning("Veracode component exposure query failed: %s", e)
            return []

    def ensure_fresh_async(self) -> None:
        """Trigger a background rebuild if the index is missing or older than TTL.
        Non-blocking and idempotent (one refresh at a time)."""
        meta = self._index_meta()
        built_at = meta.get("built_at") or 0
        if built_at and (time.time() - built_at) < _INDEX_TTL_SECONDS:
            return
        self._start_background_refresh()

    def _start_background_refresh(self) -> None:
        global _refresh_in_progress
        with _refresh_flag_lock:
            if _refresh_in_progress:
                return
            _refresh_in_progress = True

        def _run():
            global _refresh_in_progress
            try:
                self.build_sca_index(force=True)
            except Exception as e:
                logger.warning("Veracode background index refresh failed: %s", e)
            finally:
                with _refresh_flag_lock:
                    _refresh_in_progress = False

        threading.Thread(target=_run, daemon=True, name="veracode-sca-index-refresh").start()


# Module-level singleton, mirroring how other services are consumed.
_client: Optional[VeracodeClient] = None


def get_client() -> VeracodeClient:
    global _client
    if _client is None:
        _client = VeracodeClient()
    return _client


def exposure(
    cve_ids: Optional[List[str]] = None,
    packages: Optional[List[str]] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """Convenience wrapper: apps exposed to these CVE(s) and/or named package(s)."""
    return get_client().exposure(cve_ids=cve_ids, packages=packages, force_refresh=force_refresh)


def cve_exposure(cve_ids: List[str], force_refresh: bool = False) -> Dict[str, Any]:
    """Convenience wrapper: which apps are exposed to these CVE(s) per Veracode SCA."""
    return get_client().cve_exposure(cve_ids, force_refresh=force_refresh)


def component_exposure(packages: List[str], force_refresh: bool = False) -> Dict[str, Any]:
    """Convenience wrapper: which apps carry these named package(s) per Veracode SCA."""
    return get_client().component_exposure(packages, force_refresh=force_refresh)


def refresh_index(force: bool = True) -> Dict[str, Any]:
    """Rebuild the SCA index now (blocking). For the scheduled background job."""
    return get_client().build_sca_index(force=force)


def ensure_fresh_async() -> None:
    """Kick a background index refresh if stale/missing (non-blocking)."""
    get_client().ensure_fresh_async()
