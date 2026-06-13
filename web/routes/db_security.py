"""Database Security dashboard routes.

Two modes:

1. **Sidecar mode** — when the ir-dbsec container (port 8027) is healthy, `/db-security`
   renders an iframe to the reverse-proxied sidecar UI at `/db-sec-app/ui`, and the
   vendor deploy portal at `/db-security/deploy` handles zip uploads, activation, and
   rollback (same pattern as the AIDRT portal).

2. **Fallback/demo mode** — when the sidecar is not reachable (e.g. before the first
   vendor zip has been activated), the page falls back to the in-repo Flask demo
   dashboard built from hardcoded sample data.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Blueprint, jsonify, render_template, request, Response

from my_config import get_config
from src.utils.logging_utils import log_web_activity
from web.routes._vendor_logs import register_vendor_logs
from web.auth.helpers import login_required
from web.auth.rbac import require_capability, DEPLOY_SIDECAR

logger = logging.getLogger(__name__)

db_security_bp = Blueprint("db_security", __name__)

# ---------------------------------------------------------------------------
# Sidecar config
# ---------------------------------------------------------------------------

DBSEC_BASE = "http://127.0.0.1:8027"
PROXY_PREFIX = "/db-sec-app"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}

_EXTERNAL = Path("/home/vinay/security-ops-platform/external")
ACTIVE_DIR = _EXTERNAL / "dbsec"
STAGING_DIR = _EXTERNAL / "dbsec_staging"
BACKUPS_DIR = _EXTERNAL / "dbsec_backups"
AUDIT_LOG = _EXTERNAL / "dbsec_audit.jsonl"

MAX_BACKUPS = 5
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
SERVICE_NAME = "ir-dbsec"
DOCKER_IMAGE = "ir-dbsec"
DOCKER_TAG_CURRENT = "current"
VERSION_ID_RE = re.compile(r"^v\d{8}_\d{6}_[a-f0-9]{6}$")

register_vendor_logs(db_security_bp, "db-security", SERVICE_NAME, "DB Security")

# Cache sidecar-up detection for 10s so the page route doesn't probe on every hit.
_SIDECAR_CACHE = {"healthy": False, "checked_at": 0.0}
_SIDECAR_TTL = 10.0


# ---------------------------------------------------------------------------
# Demo data (fallback mode only)
# ---------------------------------------------------------------------------

_DEMO_DATABASES = [
    {"name": "PROD-SQL-01", "engine": "SQL Server 2022", "env": "Production", "owner": "App Team A",
     "encryption": "TDE", "last_patched": "2026-03-15", "audit_enabled": True, "public_access": False,
     "score": 92, "findings": 1},
    {"name": "PROD-PG-CORE", "engine": "PostgreSQL 16", "env": "Production", "owner": "Platform",
     "encryption": "AES-256", "last_patched": "2026-03-28", "audit_enabled": True, "public_access": False,
     "score": 97, "findings": 0},
    {"name": "PROD-ORACLE-FIN", "engine": "Oracle 19c", "env": "Production", "owner": "Finance",
     "encryption": "TDE", "last_patched": "2026-02-10", "audit_enabled": True, "public_access": False,
     "score": 78, "findings": 3},
    {"name": "PROD-MYSQL-WEB", "engine": "MySQL 8.0", "env": "Production", "owner": "Web Team",
     "encryption": "At-rest", "last_patched": "2026-03-20", "audit_enabled": True, "public_access": False,
     "score": 88, "findings": 2},
    {"name": "DEV-PG-SANDBOX", "engine": "PostgreSQL 15", "env": "Development", "owner": "Dev Team",
     "encryption": "None", "last_patched": "2026-01-05", "audit_enabled": False, "public_access": True,
     "score": 34, "findings": 7},
    {"name": "STG-SQL-02", "engine": "SQL Server 2019", "env": "Staging", "owner": "QA",
     "encryption": "TDE", "last_patched": "2026-03-01", "audit_enabled": False, "public_access": False,
     "score": 65, "findings": 4},
    {"name": "PROD-COSMOS-API", "engine": "CosmosDB", "env": "Production", "owner": "API Team",
     "encryption": "AES-256", "last_patched": "N/A (managed)", "audit_enabled": True, "public_access": False,
     "score": 95, "findings": 0},
    {"name": "PROD-REDIS-CACHE", "engine": "Redis 7", "env": "Production", "owner": "Platform",
     "encryption": "In-transit", "last_patched": "2026-03-22", "audit_enabled": False, "public_access": False,
     "score": 71, "findings": 2},
    {"name": "DEV-MONGO-ML", "engine": "MongoDB 7", "env": "Development", "owner": "Data Science",
     "encryption": "None", "last_patched": "2025-12-18", "audit_enabled": False, "public_access": True,
     "score": 28, "findings": 9},
    {"name": "PROD-SQL-LEGACY", "engine": "SQL Server 2016", "env": "Production", "owner": "Legacy Apps",
     "encryption": "None", "last_patched": "2025-11-30", "audit_enabled": True, "public_access": False,
     "score": 41, "findings": 8},
]

_DEMO_AUDIT_EVENTS = [
    {"ts": "2026-04-02 09:14", "db": "PROD-SQL-01", "user": "svc_deploy", "action": "SCHEMA ALTER",
     "detail": "Added column user_preferences to tbl_accounts", "severity": "medium"},
    {"ts": "2026-04-02 08:47", "db": "PROD-ORACLE-FIN", "user": "dba_john", "action": "GRANT PRIVILEGE",
     "detail": "Granted SELECT on fin_transactions to rpt_readonly", "severity": "low"},
    {"ts": "2026-04-02 07:30", "db": "DEV-PG-SANDBOX", "user": "dev_sarah", "action": "BULK EXPORT",
     "detail": "Exported 45K rows from customer_data (PII flagged)", "severity": "high"},
    {"ts": "2026-04-01 23:15", "db": "PROD-SQL-LEGACY", "user": "svc_etl", "action": "LOGIN FAILURE",
     "detail": "5 consecutive failed auth attempts from <internal-host>", "severity": "critical"},
    {"ts": "2026-04-01 21:02", "db": "PROD-PG-CORE", "user": "app_service", "action": "QUERY",
     "detail": "Long-running query (12 min) on idx_orders — possible table scan", "severity": "low"},
    {"ts": "2026-04-01 18:33", "db": "PROD-MYSQL-WEB", "user": "admin_mike", "action": "CONFIG CHANGE",
     "detail": "Disabled slow_query_log (re-enable after maintenance)", "severity": "medium"},
    {"ts": "2026-04-01 16:45", "db": "PROD-COSMOS-API", "user": "svc_api", "action": "THROUGHPUT CHANGE",
     "detail": "RU scaled from 4000 to 8000 — auto-scale trigger", "severity": "low"},
    {"ts": "2026-04-01 14:10", "db": "DEV-MONGO-ML", "user": "dev_raj", "action": "DROP COLLECTION",
     "detail": "Dropped training_data_v2 collection (47 GB)", "severity": "medium"},
]

_DEMO_PRIV_ACCOUNTS = [
    {"user": "dba_john", "role": "DBA", "databases": "PROD-ORACLE-FIN, PROD-SQL-01", "mfa": True,
     "last_review": "2026-03-01", "last_login": "2026-04-02 08:47"},
    {"user": "admin_mike", "role": "SysAdmin", "databases": "PROD-MYSQL-WEB, STG-SQL-02", "mfa": True,
     "last_review": "2026-02-15", "last_login": "2026-04-01 18:33"},
    {"user": "svc_deploy", "role": "Service (DDL)", "databases": "PROD-SQL-01, STG-SQL-02", "mfa": False,
     "last_review": "2026-01-20", "last_login": "2026-04-02 09:14"},
    {"user": "svc_etl", "role": "Service (ETL)", "databases": "PROD-SQL-LEGACY, PROD-PG-CORE", "mfa": False,
     "last_review": "2025-12-10", "last_login": "2026-04-01 23:15"},
    {"user": "dba_ops_team", "role": "DBA (shared)", "databases": "All Production", "mfa": True,
     "last_review": "2026-03-20", "last_login": "2026-03-31 11:00"},
]


def _compute_kpis(databases):
    total = len(databases)
    compliant = sum(1 for d in databases if d["score"] >= 80)
    critical = sum(d["findings"] for d in databases if d["score"] < 50)
    total_findings = sum(d["findings"] for d in databases)
    unencrypted = sum(1 for d in databases if d["encryption"] == "None")
    no_audit = sum(1 for d in databases if not d["audit_enabled"])
    public = sum(1 for d in databases if d["public_access"])
    avg_score = round(sum(d["score"] for d in databases) / total) if total else 0
    return {
        "total_dbs": total,
        "compliant": compliant,
        "compliant_pct": round(compliant / total * 100) if total else 0,
        "critical_findings": critical,
        "total_findings": total_findings,
        "unencrypted": unencrypted,
        "no_audit": no_audit,
        "public_access": public,
        "avg_score": avg_score,
    }


# ---------------------------------------------------------------------------
# Deploy portal helpers (mirrors ai_drt.py)
# ---------------------------------------------------------------------------

def _now_utc_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _new_version_id(digest_hex: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"v{ts}_{digest_hex[:6]}"


def _audit(action: str, version_id: str | None, extra: dict | None = None):
    entry = {
        "ts": _now_utc_iso(),
        "action": action,
        "version_id": version_id,
        "client_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "user_agent": request.headers.get("User-Agent", ""),
    }
    if extra:
        entry.update(extra)
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _read_audit(limit: int = 30):
    if not AUDIT_LOG.exists():
        return []
    lines = AUDIT_LOG.read_text().splitlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return list(reversed(out))


def _dir_info(path: Path) -> dict | None:
    if not path.is_dir():
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    return {
        "id": path.name,
        "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00", "Z"),
        "size_bytes": sum(f.stat().st_size for f in path.rglob("*") if f.is_file()),
    }


def _service_status() -> dict:
    try:
        r = requests.get(f"{DBSEC_BASE}/status", timeout=3)
        if r.ok:
            try:
                return {"healthy": True, **r.json()}
            except Exception:
                return {"healthy": True}
        return {"healthy": False, "http_status": r.status_code}
    except Exception as e:
        return {"healthy": False, "error": str(e)}


def _sidecar_is_up() -> bool:
    """Fast cached check used by the page route to decide iframe vs fallback."""
    now = time.time()
    if now - _SIDECAR_CACHE["checked_at"] < _SIDECAR_TTL:
        return _SIDECAR_CACHE["healthy"]
    try:
        # Any 2xx on the root or a /status endpoint counts as up. A fresh vendor
        # zip may not have /status, so we probe / as well.
        r = requests.get(f"{DBSEC_BASE}/", timeout=1.5)
        healthy = r.ok
    except Exception:
        healthy = False
    _SIDECAR_CACHE["healthy"] = healthy
    _SIDECAR_CACHE["checked_at"] = now
    return healthy


def _docker_build(src_dir: Path, version_id: str, timeout_s: int = 300) -> dict:
    if not (src_dir / "Dockerfile").is_file():
        return {"ok": False, "error": "Dockerfile missing in source directory"}
    tag = f"{DOCKER_IMAGE}:{version_id}"
    try:
        result = subprocess.run(
            ["docker", "build", "-t", tag, str(src_dir)],
            capture_output=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"docker build timed out after {timeout_s}s"}
    ok = result.returncode == 0
    tail = (result.stdout[-800:] + result.stderr[-800:]).decode(errors="ignore")
    return {"ok": ok, "returncode": result.returncode, "tag": tag, "tail": tail}


def _docker_tag(source: str, target: str) -> dict:
    try:
        result = subprocess.run(
            ["docker", "tag", source, target],
            capture_output=True, timeout=10,
        )
        return {"ok": result.returncode == 0, "stderr": result.stderr.decode(errors="ignore")}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "docker tag timed out"}


def _docker_image_exists(tag: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _restart_service_and_wait(timeout_s: int = 30) -> dict:
    try:
        subprocess.run(
            ["systemctl", "--user", "restart", SERVICE_NAME],
            check=True, capture_output=True, timeout=15,
        )
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": f"systemctl restart failed: {e.stderr.decode(errors='ignore')}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "systemctl restart timed out"}

    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            r = requests.get(f"{DBSEC_BASE}/", timeout=2)
            if r.ok:
                return {"ok": True, "http_status": r.status_code}
        except Exception as e:
            last_err = str(e)
        time.sleep(1)
    return {"ok": False, "error": f"service did not come up in {timeout_s}s; last error: {last_err}"}


def _safe_extract_zip(zip_path: Path, dest: Path):
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        total_uncompressed = sum(zi.file_size for zi in zf.infolist())
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(f"zip expands to {total_uncompressed} bytes — limit is {MAX_UNCOMPRESSED_BYTES}")
        for zi in zf.infolist():
            name = zi.filename
            if name.startswith(("/", "\\")) or ".." in Path(name).parts or ":" in name:
                raise ValueError(f"zip entry has unsafe path: {name}")
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"zip entry escapes destination: {name}")
        zf.extractall(dest)


def _find_package_root(extract_dir: Path) -> Path:
    """Accept either a flat package at root or one nested in a single top-level folder.

    Same shape as the AIDRT deploy portal: main.py + frontend/index.html at root.
    """
    if (extract_dir / "main.py").is_file() and (extract_dir / "frontend" / "index.html").is_file():
        return extract_dir
    children = [c for c in extract_dir.iterdir() if c.is_dir()]
    if len(children) == 1:
        inner = children[0]
        if (inner / "main.py").is_file() and (inner / "frontend" / "index.html").is_file():
            return inner
    raise ValueError(
        "Zip is missing the expected DB Security structure — need main.py and frontend/index.html at the root "
        "(or nested inside a single top-level folder)."
    )


def _validate_package(pkg_root: Path):
    required = [
        pkg_root / "main.py",
        pkg_root / "frontend" / "index.html",
        pkg_root / "requirements.txt",
    ]
    missing = [str(p.relative_to(pkg_root)) for p in required if not p.exists()]
    if missing:
        raise ValueError(f"Package missing required files: {', '.join(missing)}")


def _prune_old_backups():
    if not BACKUPS_DIR.exists():
        return
    backups = sorted((p for p in BACKUPS_DIR.iterdir() if p.is_dir()), key=lambda p: p.name)
    for old in backups[:-MAX_BACKUPS]:
        shutil.rmtree(old, ignore_errors=True)
        subprocess.run(
            ["docker", "rmi", "-f", f"{DOCKER_IMAGE}:{old.name}"],
            capture_output=True, timeout=10,
        )


# ---------------------------------------------------------------------------
# Routes: page (iframe or fallback) + proxy
# ---------------------------------------------------------------------------

@db_security_bp.route("/db-security")
@log_web_activity
def db_security_page():
    if _sidecar_is_up():
        return render_template("db_security_live.html")
    return render_template("db_security.html")


@db_security_bp.route("/db-security/deploy")
@log_web_activity
def db_security_deploy_page():
    return render_template("db_security_deploy.html")


@db_security_bp.route("/api/db-security/active-version", methods=["GET"])
def db_security_active_version():
    """Read-only: what version is currently live? Powers the dashboard version badge."""
    meta_path = ACTIVE_DIR / ".deploy_meta.json"
    activated_at = None
    if ACTIVE_DIR.is_dir():
        activated_at = datetime.fromtimestamp(ACTIVE_DIR.stat().st_mtime, tz=timezone.utc)\
            .isoformat(timespec="seconds").replace("+00:00", "Z")
    if not meta_path.is_file():
        return jsonify({"version_id": None, "activated_at": activated_at})
    try:
        meta = json.loads(meta_path.read_text())
    except Exception:
        return jsonify({"version_id": None, "activated_at": activated_at})
    return jsonify({
        "version_id": meta.get("version_id"),
        "uploaded_at": meta.get("uploaded_at"),
        "sha256_short": (meta.get("sha256") or "")[:7],
        "activated_at": activated_at,
    })


@db_security_bp.route("/api/db-security/overview")
@log_web_activity
def api_overview():
    """Fallback demo-data endpoint used by the in-repo dashboard when the sidecar isn't running."""
    kpis = _compute_kpis(_DEMO_DATABASES)
    return jsonify({
        "demo": True,
        "databases": _DEMO_DATABASES,
        "kpis": kpis,
        "audit_events": _DEMO_AUDIT_EVENTS,
        "privileged_accounts": _DEMO_PRIV_ACCOUNTS,
    })


@db_security_bp.route(f"{PROXY_PREFIX}/", defaults={"path": ""}, methods=["GET", "POST"])
@db_security_bp.route(f"{PROXY_PREFIX}/<path:path>", methods=["GET", "POST"])
@login_required
def db_security_proxy(path):
    upstream_url = f"{DBSEC_BASE}/{path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}

    upstream = requests.request(
        method=request.method,
        url=upstream_url,
        headers=headers,
        params=request.args,
        data=request.get_data(),
        timeout=120,
        allow_redirects=False,
    )

    body = upstream.content
    content_type = upstream.headers.get("Content-Type", "")
    if "text/html" in content_type.lower():
        # AIDRT-style hook (for vendor packages that expose a configurable API const).
        body = body.replace(b"const API = ''", f"const API = '{PROXY_PREFIX}'".encode())
        # Vendor's dbsec frontend hardcodes fetch('/api/...') instead of using a
        # configurable API base. Rewrite those so they hit the proxied sidecar
        # instead of the Flask host.
        body = body.replace(b"fetch('/api/", f"fetch('{PROXY_PREFIX}/api/".encode())
        body = body.replace(b'fetch("/api/', f'fetch("{PROXY_PREFIX}/api/'.encode())

    out_headers = [(k, v) for k, v in upstream.headers.items()
                   if k.lower() not in HOP_BY_HOP]
    return Response(body, status=upstream.status_code, headers=out_headers)


# ---------------------------------------------------------------------------
# Routes: deploy API
# ---------------------------------------------------------------------------

@db_security_bp.route("/api/db-security/versions", methods=["GET"])
@login_required
def db_security_versions():
    active_info = _dir_info(ACTIVE_DIR)
    staged = sorted(
        (d for d in STAGING_DIR.iterdir() if d.is_dir()),
        key=lambda p: p.name, reverse=True,
    ) if STAGING_DIR.exists() else []
    backups = sorted(
        (d for d in BACKUPS_DIR.iterdir() if d.is_dir()),
        key=lambda p: p.name, reverse=True,
    ) if BACKUPS_DIR.exists() else []
    return jsonify({
        "active": active_info,
        "staged": [_dir_info(p) for p in staged],
        "backups": [_dir_info(p) for p in backups],
        "service": _service_status(),
        "audit_recent": _read_audit(limit=20),
    })


@db_security_bp.route("/api/db-security/upload", methods=["POST"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_security')
def db_security_upload():
    f = request.files.get("zip")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "No 'zip' file in request"}), 400
    if not f.filename.lower().endswith(".zip"):
        return jsonify({"ok": False, "error": "File must be a .zip"}), 400

    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    tmp_zip = STAGING_DIR / f"_upload_{os.getpid()}_{int(time.time())}.zip"
    try:
        f.save(str(tmp_zip))

        h = hashlib.sha256()
        with tmp_zip.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()

        version_id = _new_version_id(digest)
        extract_dir = STAGING_DIR / version_id
        if extract_dir.exists():
            shutil.rmtree(extract_dir)

        try:
            _safe_extract_zip(tmp_zip, extract_dir)
            pkg_root = _find_package_root(extract_dir)
            _validate_package(pkg_root)

            if pkg_root != extract_dir:
                tmp_flat = STAGING_DIR / f"_flat_{version_id}"
                shutil.move(str(pkg_root), str(tmp_flat))
                shutil.rmtree(extract_dir)
                shutil.move(str(tmp_flat), str(extract_dir))

            meta = {
                "version_id": version_id,
                "uploaded_at": _now_utc_iso(),
                "original_filename": f.filename,
                "sha256": digest,
                "size_bytes": tmp_zip.stat().st_size,
            }
            (extract_dir / ".deploy_meta.json").write_text(json.dumps(meta, indent=2))
        except Exception:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise

        _audit("upload", version_id, {"filename": f.filename, "sha256": digest, "size_bytes": tmp_zip.stat().st_size})
        return jsonify({"ok": True, "version_id": version_id, "sha256": digest})

    except (zipfile.BadZipFile, ValueError) as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"Upload failed: {e}"}), 500
    finally:
        if tmp_zip.exists():
            tmp_zip.unlink()


@db_security_bp.route("/api/db-security/activate", methods=["POST"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_security')
def db_security_activate():
    data = request.get_json(silent=True) or request.form
    version_id = (data.get("version_id") or "").strip()
    if not VERSION_ID_RE.match(version_id):
        return jsonify({"ok": False, "error": "Invalid version_id"}), 400
    staged_src = STAGING_DIR / version_id
    if not staged_src.is_dir():
        return jsonify({"ok": False, "error": f"Staged version {version_id} not found"}), 404

    # Reuse Dockerfile / .dockerignore from the current active dir if the vendor
    # didn't ship them. On first-ever activate neither exists — the package must
    # include them or the build will fail with a clear error.
    for support_file in ("Dockerfile", ".dockerignore"):
        if not (staged_src / support_file).exists() and (ACTIVE_DIR / support_file).exists():
            shutil.copy2(ACTIVE_DIR / support_file, staged_src / support_file)

    build = _docker_build(staged_src, version_id)
    if not build["ok"]:
        _audit("activate_failed", version_id, {"stage": "build", "tail": build.get("tail", "")})
        return jsonify({"ok": False, "error": "Docker build failed", "build": build}), 500

    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    backup_id = _new_version_id(version_id[-6:])
    backup_dest = BACKUPS_DIR / backup_id

    try:
        if ACTIVE_DIR.exists():
            shutil.move(str(ACTIVE_DIR), str(backup_dest))
        shutil.move(str(staged_src), str(ACTIVE_DIR))
    except Exception as e:
        _audit("activate_failed", version_id, {"stage": "swap", "error": str(e)})
        return jsonify({"ok": False, "error": f"Source swap failed after successful build: {e}"}), 500

    if _docker_image_exists(f"{DOCKER_IMAGE}:{DOCKER_TAG_CURRENT}"):
        _docker_tag(f"{DOCKER_IMAGE}:{DOCKER_TAG_CURRENT}", f"{DOCKER_IMAGE}:{backup_id}")

    tag_result = _docker_tag(f"{DOCKER_IMAGE}:{version_id}", f"{DOCKER_IMAGE}:{DOCKER_TAG_CURRENT}")
    if not tag_result["ok"]:
        _audit("activate_failed", version_id, {"stage": "tag", "error": tag_result.get("stderr", "")})
        return jsonify({"ok": False, "error": "Failed to tag image as :current", "tag": tag_result}), 500

    restart = _restart_service_and_wait()
    _prune_old_backups()
    # Bust the sidecar-up cache so the next /db-security hit flips to the iframe immediately.
    _SIDECAR_CACHE["checked_at"] = 0.0
    _audit("activate", version_id, {"backup_id": backup_id, "build_returncode": build["returncode"], "restart": restart})

    return jsonify({
        "ok": restart["ok"],
        "version_id": version_id,
        "backup_id": backup_id,
        "build": {"tag": build["tag"], "returncode": build["returncode"]},
        "restart": restart,
    })


@db_security_bp.route("/api/db-security/rollback", methods=["POST"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_security')
def db_security_rollback():
    data = request.get_json(silent=True) or request.form
    backup_id = (data.get("backup_id") or "").strip()
    if not VERSION_ID_RE.match(backup_id):
        return jsonify({"ok": False, "error": "Invalid backup_id"}), 400
    backup_src = BACKUPS_DIR / backup_id
    if not backup_src.is_dir():
        return jsonify({"ok": False, "error": f"Backup {backup_id} not found"}), 404
    if not _docker_image_exists(f"{DOCKER_IMAGE}:{backup_id}"):
        return jsonify({
            "ok": False,
            "error": f"Docker image {DOCKER_IMAGE}:{backup_id} not found — image may have been pruned. Re-upload and activate.",
        }), 404

    rollback_backup_id = _new_version_id(backup_id[-6:])
    rollback_backup_dest = BACKUPS_DIR / rollback_backup_id

    try:
        if ACTIVE_DIR.exists():
            shutil.move(str(ACTIVE_DIR), str(rollback_backup_dest))
        shutil.move(str(backup_src), str(ACTIVE_DIR))
    except Exception as e:
        _audit("rollback_failed", backup_id, {"stage": "swap", "error": str(e)})
        return jsonify({"ok": False, "error": f"Source swap failed: {e}"}), 500

    if _docker_image_exists(f"{DOCKER_IMAGE}:{DOCKER_TAG_CURRENT}"):
        _docker_tag(f"{DOCKER_IMAGE}:{DOCKER_TAG_CURRENT}", f"{DOCKER_IMAGE}:{rollback_backup_id}")

    tag_result = _docker_tag(f"{DOCKER_IMAGE}:{backup_id}", f"{DOCKER_IMAGE}:{DOCKER_TAG_CURRENT}")
    if not tag_result["ok"]:
        _audit("rollback_failed", backup_id, {"stage": "tag", "error": tag_result.get("stderr", "")})
        return jsonify({"ok": False, "error": "Failed to re-tag image", "tag": tag_result}), 500

    restart = _restart_service_and_wait()
    _prune_old_backups()
    _SIDECAR_CACHE["checked_at"] = 0.0
    _audit("rollback", backup_id, {"new_backup_id": rollback_backup_id, "restart": restart})
    return jsonify({"ok": restart["ok"], "rolled_back_to": backup_id, "restart": restart})


@db_security_bp.route("/api/db-security/staged/<version_id>", methods=["DELETE"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_security')
def db_security_delete_staged(version_id):
    if not VERSION_ID_RE.match(version_id):
        return jsonify({"ok": False, "error": "Invalid version_id"}), 400
    target = STAGING_DIR / version_id
    if not target.is_dir():
        return jsonify({"ok": False, "error": "Not found"}), 404
    shutil.rmtree(target)
    _audit("staged_delete", version_id)
    return jsonify({"ok": True})
