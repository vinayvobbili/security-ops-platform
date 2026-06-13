"""DB Config — vendor sidecar at ir-db-config.service on :8034.

Database configuration / hardening posture: CIS benchmark drift, required-setting
checks, default-account review, port exposure, backup/retention policy. Sibling
to /db-security (which is about encryption, audit trails, and privileged access)
— this one is about the config knobs themselves.

Two modes (same pattern as db_security.py):

1. **Sidecar mode** — when the ir-db-config container is healthy, `/db-config`
   renders an iframe to the proxied sidecar UI at `/db-config-app/`, and
   `/db-config/deploy` hosts the vendor deploy portal.

2. **Seed/demo mode** — before the first vendor zip is activated, the page
   falls back to an in-repo demo dashboard built from synthetic sample data.

Expected vendor package shape:
    main.py
    frontend/index.html
    requirements.txt
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
from web.auth.helpers import login_required
from web.auth.rbac import require_capability, DEPLOY_SIDECAR

logger = logging.getLogger(__name__)

db_config_bp = Blueprint("db_config", __name__)

DBCFG_BASE = "http://127.0.0.1:8034"
PROXY_PREFIX = "/db-config-app"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}

_EXTERNAL = Path("/home/vinay/security-ops-platform/external")
ACTIVE_DIR = _EXTERNAL / "db_config"
STAGING_DIR = _EXTERNAL / "db_config_staging"
BACKUPS_DIR = _EXTERNAL / "db_config_backups"
AUDIT_LOG = _EXTERNAL / "db_config_audit.jsonl"

MAX_BACKUPS = 5
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
SERVICE_NAME = "ir-db-config"
DOCKER_IMAGE = "ir-db-config"
DOCKER_TAG_CURRENT = "current"
VERSION_ID_RE = re.compile(r"^v\d{8}_\d{6}_[a-f0-9]{6}$")

_SIDECAR_CACHE = {"healthy": False, "checked_at": 0.0}
_SIDECAR_TTL = 10.0


# ---------------------------------------------------------------------------
# Demo data (seed/fallback mode — used until vendor ships real code)
# ---------------------------------------------------------------------------

_DEMO_DATABASES = [
    {"name": "PROD-SQL-01", "engine": "SQL Server 2022", "env": "Production", "benchmark": "CIS MSSQL 1.4.0",
     "pass": 58, "fail": 3, "warn": 2, "compliance": 92, "last_scan": "2026-04-17 05:00"},
    {"name": "PROD-PG-CORE", "engine": "PostgreSQL 16", "env": "Production", "benchmark": "CIS PostgreSQL 1.2.0",
     "pass": 62, "fail": 0, "warn": 1, "compliance": 98, "last_scan": "2026-04-17 05:00"},
    {"name": "PROD-ORACLE-FIN", "engine": "Oracle 19c", "env": "Production", "benchmark": "CIS Oracle 3.0.0",
     "pass": 71, "fail": 5, "warn": 4, "compliance": 88, "last_scan": "2026-04-17 05:00"},
    {"name": "PROD-MYSQL-WEB", "engine": "MySQL 8.0", "env": "Production", "benchmark": "CIS MySQL 1.0.0",
     "pass": 48, "fail": 1, "warn": 3, "compliance": 94, "last_scan": "2026-04-17 05:00"},
    {"name": "STG-SQL-02", "engine": "SQL Server 2019", "env": "Staging", "benchmark": "CIS MSSQL 1.4.0",
     "pass": 52, "fail": 6, "warn": 5, "compliance": 83, "last_scan": "2026-04-17 05:00"},
    {"name": "DEV-PG-SANDBOX", "engine": "PostgreSQL 15", "env": "Development", "benchmark": "CIS PostgreSQL 1.2.0",
     "pass": 34, "fail": 18, "warn": 11, "compliance": 54, "last_scan": "2026-04-16 05:00"},
    {"name": "PROD-SQL-LEGACY", "engine": "SQL Server 2016", "env": "Production", "benchmark": "CIS MSSQL 1.4.0",
     "pass": 31, "fail": 22, "warn": 8, "compliance": 49, "last_scan": "2026-04-17 05:00"},
    {"name": "DEV-MONGO-ML", "engine": "MongoDB 7", "env": "Development", "benchmark": "CIS MongoDB 1.2.0",
     "pass": 22, "fail": 15, "warn": 8, "compliance": 48, "last_scan": "2026-04-17 05:00"},
]

_DEMO_FINDINGS = [
    {"db": "PROD-SQL-LEGACY", "check": "Ensure 'sa' account is disabled", "benchmark": "CIS MSSQL 4.1",
     "severity": "critical", "state": "FAIL", "remediation": "ALTER LOGIN [sa] DISABLE"},
    {"db": "PROD-SQL-LEGACY", "check": "Ensure 'Cross DB Ownership Chaining' is disabled",
     "benchmark": "CIS MSSQL 2.9", "severity": "high", "state": "FAIL",
     "remediation": "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;"},
    {"db": "PROD-SQL-LEGACY", "check": "Ensure 'CLR Enabled' is disabled",
     "benchmark": "CIS MSSQL 2.6", "severity": "high", "state": "FAIL",
     "remediation": "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;"},
    {"db": "DEV-MONGO-ML", "check": "Ensure authorization is enabled",
     "benchmark": "CIS MongoDB 2.1", "severity": "critical", "state": "FAIL",
     "remediation": "Set security.authorization: enabled in mongod.conf"},
    {"db": "DEV-MONGO-ML", "check": "Ensure TLS/SSL is configured for all inbound connections",
     "benchmark": "CIS MongoDB 2.5", "severity": "high", "state": "FAIL",
     "remediation": "Configure net.tls.mode: requireTLS in mongod.conf"},
    {"db": "DEV-PG-SANDBOX", "check": "Ensure log_connections is enabled",
     "benchmark": "CIS PostgreSQL 6.7", "severity": "medium", "state": "FAIL",
     "remediation": "ALTER SYSTEM SET log_connections = on; SELECT pg_reload_conf();"},
    {"db": "DEV-PG-SANDBOX", "check": "Ensure password_encryption is set to scram-sha-256",
     "benchmark": "CIS PostgreSQL 4.3", "severity": "high", "state": "FAIL",
     "remediation": "ALTER SYSTEM SET password_encryption = 'scram-sha-256';"},
    {"db": "PROD-ORACLE-FIN", "check": "Ensure 'SEC_CASE_SENSITIVE_LOGON' is set to TRUE",
     "benchmark": "CIS Oracle 3.1.3", "severity": "medium", "state": "WARN",
     "remediation": "ALTER SYSTEM SET SEC_CASE_SENSITIVE_LOGON = TRUE SCOPE=BOTH;"},
    {"db": "STG-SQL-02", "check": "Ensure 'Remote Access' is disabled",
     "benchmark": "CIS MSSQL 2.17", "severity": "medium", "state": "FAIL",
     "remediation": "EXEC sp_configure 'remote access', 0; RECONFIGURE;"},
    {"db": "PROD-SQL-01", "check": "Ensure 'Database Mail XPs' is disabled when not in use",
     "benchmark": "CIS MSSQL 2.1", "severity": "low", "state": "WARN",
     "remediation": "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE;"},
]

_DEMO_DRIFT = [
    {"ts": "2026-04-16 22:18", "db": "PROD-SQL-01", "setting": "trustworthy",
     "before": "OFF", "after": "ON", "actor": "svc_deploy", "risk": "medium"},
    {"ts": "2026-04-16 14:42", "db": "PROD-ORACLE-FIN", "setting": "SEC_CASE_SENSITIVE_LOGON",
     "before": "TRUE", "after": "FALSE", "actor": "dba_john", "risk": "high"},
    {"ts": "2026-04-16 11:05", "db": "PROD-MYSQL-WEB", "setting": "local_infile",
     "before": "OFF", "after": "ON", "actor": "admin_mike", "risk": "medium"},
    {"ts": "2026-04-15 18:30", "db": "PROD-PG-CORE", "setting": "ssl",
     "before": "on", "after": "on", "actor": "auto-baseline", "risk": "none"},
    {"ts": "2026-04-15 09:11", "db": "STG-SQL-02", "setting": "xp_cmdshell",
     "before": "disabled", "after": "enabled", "actor": "etl_runner", "risk": "critical"},
]


def _compute_kpis(databases):
    total = len(databases)
    total_pass = sum(d["pass"] for d in databases)
    total_fail = sum(d["fail"] for d in databases)
    total_warn = sum(d["warn"] for d in databases)
    total_checks = total_pass + total_fail + total_warn
    compliant = sum(1 for d in databases if d["compliance"] >= 90)
    avg_compliance = round(sum(d["compliance"] for d in databases) / total) if total else 0
    return {
        "total_dbs": total,
        "compliant": compliant,
        "compliant_pct": round(compliant / total * 100) if total else 0,
        "avg_compliance": avg_compliance,
        "total_checks": total_checks,
        "fail": total_fail,
        "warn": total_warn,
        "pass": total_pass,
    }


# ---------------------------------------------------------------------------
# Deploy portal helpers (mirrors db_security.py)
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
        r = requests.get(f"{DBCFG_BASE}/", timeout=3)
        if r.ok:
            return {"healthy": True, "http_status": r.status_code}
        return {"healthy": False, "http_status": r.status_code}
    except Exception as e:
        return {"healthy": False, "error": str(e)}


def _sidecar_is_up() -> bool:
    now = time.time()
    if now - _SIDECAR_CACHE["checked_at"] < _SIDECAR_TTL:
        return _SIDECAR_CACHE["healthy"]
    try:
        r = requests.get(f"{DBCFG_BASE}/", timeout=1.5)
        healthy = r.ok
    except Exception:
        healthy = False
    _SIDECAR_CACHE["healthy"] = healthy
    _SIDECAR_CACHE["checked_at"] = now
    return healthy


def _docker_build(src_dir: Path, version_id: str, timeout_s: int = 600) -> dict:
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


def _restart_service_and_wait(timeout_s: int = 60) -> dict:
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
            r = requests.get(f"{DBCFG_BASE}/", timeout=2)
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
    if (extract_dir / "main.py").is_file() and (extract_dir / "frontend" / "index.html").is_file():
        return extract_dir
    children = [c for c in extract_dir.iterdir() if c.is_dir()]
    if len(children) == 1:
        inner = children[0]
        if (inner / "main.py").is_file() and (inner / "frontend" / "index.html").is_file():
            return inner
    raise ValueError(
        "Zip is missing the expected DB Config structure — need main.py and frontend/index.html at the root "
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
# Routes: page (iframe or seed fallback) + proxy
# ---------------------------------------------------------------------------

@db_config_bp.route("/db-config")
@log_web_activity
def db_config_page():
    if _sidecar_is_up():
        return render_template("db_config_live.html")
    return render_template("db_config.html")


@db_config_bp.route("/db-config/deploy")
@log_web_activity
def db_config_deploy_page():
    return render_template("db_config_deploy.html")


@db_config_bp.route("/api/db-config/active-version", methods=["GET"])
def db_config_active_version():
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


@db_config_bp.route("/api/db-config/overview")
@log_web_activity
def api_overview():
    return jsonify({
        "demo": True,
        "databases": _DEMO_DATABASES,
        "kpis": _compute_kpis(_DEMO_DATABASES),
        "findings": _DEMO_FINDINGS,
        "drift_events": _DEMO_DRIFT,
    })


@db_config_bp.route(f"{PROXY_PREFIX}/", defaults={"path": ""}, methods=["GET", "POST"])
@db_config_bp.route(f"{PROXY_PREFIX}/<path:path>", methods=["GET", "POST"])
@login_required
def db_config_proxy(path):
    upstream_url = f"{DBCFG_BASE}/{path}"
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
        body = body.replace(b"const API = ''", f"const API = '{PROXY_PREFIX}'".encode())
        body = body.replace(b"fetch('/api/", f"fetch('{PROXY_PREFIX}/api/".encode())
        body = body.replace(b'fetch("/api/', f'fetch("{PROXY_PREFIX}/api/'.encode())

    out_headers = [(k, v) for k, v in upstream.headers.items()
                   if k.lower() not in HOP_BY_HOP]
    return Response(body, status=upstream.status_code, headers=out_headers)


# ---------------------------------------------------------------------------
# Routes: deploy API
# ---------------------------------------------------------------------------

@db_config_bp.route("/api/db-config/versions", methods=["GET"])
@login_required
def db_config_versions():
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


@db_config_bp.route("/api/db-config/upload", methods=["POST"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_config')
def db_config_upload():
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


@db_config_bp.route("/api/db-config/activate", methods=["POST"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_config')
def db_config_activate():
    data = request.get_json(silent=True) or request.form
    version_id = (data.get("version_id") or "").strip()
    if not VERSION_ID_RE.match(version_id):
        return jsonify({"ok": False, "error": "Invalid version_id"}), 400
    staged_src = STAGING_DIR / version_id
    if not staged_src.is_dir():
        return jsonify({"ok": False, "error": f"Staged version {version_id} not found"}), 404

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
    _SIDECAR_CACHE["checked_at"] = 0.0
    _audit("activate", version_id, {"backup_id": backup_id, "build_returncode": build["returncode"], "restart": restart})

    return jsonify({
        "ok": restart["ok"],
        "version_id": version_id,
        "backup_id": backup_id,
        "build": {"tag": build["tag"], "returncode": build["returncode"]},
        "restart": restart,
    })


@db_config_bp.route("/api/db-config/rollback", methods=["POST"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_config')
def db_config_rollback():
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


@db_config_bp.route("/api/db-config/staged/<version_id>", methods=["DELETE"])
@require_capability(DEPLOY_SIDECAR, sidecar='db_config')
def db_config_delete_staged(version_id):
    if not VERSION_ID_RE.match(version_id):
        return jsonify({"ok": False, "error": "Invalid version_id"}), 400
    target = STAGING_DIR / version_id
    if not target.is_dir():
        return jsonify({"ok": False, "error": "Not found"}), 404
    shutil.rmtree(target)
    _audit("staged_delete", version_id)
    return jsonify({"ok": True})
