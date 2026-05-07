"""Data Security Posture Management (DSPM) — vendor sidecar at ir-dspm.service on :8033.

Two modes (same pattern as db_security.py):

1. **Sidecar mode** — when the ir-dspm container is healthy, `/dspm` renders an iframe
   to the reverse-proxied sidecar UI at `/dspm-app/`, and `/dspm/deploy` hosts the
   token-gated vendor deploy portal (zip upload → stage → activate → rollback).

2. **Seed/demo mode** — before the first vendor zip has been activated, the page
   falls back to an in-repo demo dashboard rendered from synthetic sample data,
   so stakeholders have something to look at while the vendor finishes the code.

Expected vendor package shape (enforced by `_validate_package`):
    main.py
    frontend/index.html
    requirements.txt
"""

import hashlib
import hmac
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
from flask import Blueprint, abort, jsonify, render_template, request, Response

from my_config import get_config
from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)

dspm_bp = Blueprint("dspm", __name__)

DSPM_BASE = "http://127.0.0.1:8033"
PROXY_PREFIX = "/dspm-app"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}

_EXTERNAL = Path("/home/vinay/security-ops-platform/external")
ACTIVE_DIR = _EXTERNAL / "dspm"
STAGING_DIR = _EXTERNAL / "dspm_staging"
BACKUPS_DIR = _EXTERNAL / "dspm_backups"
AUDIT_LOG = _EXTERNAL / "dspm_audit.jsonl"

MAX_BACKUPS = 5
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
SERVICE_NAME = "ir-dspm"
DOCKER_IMAGE = "ir-dspm"
DOCKER_TAG_CURRENT = "current"
VERSION_ID_RE = re.compile(r"^v\d{8}_\d{6}_[a-f0-9]{6}$")

_SIDECAR_CACHE = {"healthy": False, "checked_at": 0.0}
_SIDECAR_TTL = 10.0


# ---------------------------------------------------------------------------
# Demo data (seed/fallback mode only — used until vendor ships real code)
# ---------------------------------------------------------------------------

_DEMO_ASSETS = [
    {"name": "prod-customer-docs", "type": "S3 Bucket", "location": "AWS us-east-1", "owner": "Platform",
     "classification": "PII", "records": 2_400_000, "public": False, "encryption": "KMS",
     "last_scan": "2026-04-17 06:12", "score": 94, "findings": 1},
    {"name": "finance-reports-share", "type": "SharePoint", "location": "M365 — Finance", "owner": "Finance",
     "classification": "PCI", "records": 38_500, "public": False, "encryption": "MIP",
     "last_scan": "2026-04-17 06:12", "score": 82, "findings": 3},
    {"name": "mktg-assets-public", "type": "S3 Bucket", "location": "AWS us-east-1", "owner": "Marketing",
     "classification": "Public", "records": 0, "public": True, "encryption": "AES-256",
     "last_scan": "2026-04-17 06:12", "score": 88, "findings": 2},
    {"name": "hr-case-files", "type": "Azure Blob", "location": "Azure eastus2", "owner": "HR",
     "classification": "PII + PHI", "records": 540_000, "public": False, "encryption": "CMK",
     "last_scan": "2026-04-17 06:12", "score": 76, "findings": 4},
    {"name": "legacy-etl-dump", "type": "File Share", "location": "On-prem — NAS03", "owner": "Data Eng",
     "classification": "PII", "records": 1_100_000, "public": False, "encryption": "None",
     "last_scan": "2026-04-16 03:00", "score": 38, "findings": 9},
    {"name": "claims-archive-2018", "type": "S3 Bucket", "location": "AWS us-west-2", "owner": "Claims",
     "classification": "PHI", "records": 890_000, "public": False, "encryption": "AES-256",
     "last_scan": "2026-04-17 06:12", "score": 71, "findings": 5},
    {"name": "card-vault-prod", "type": "Oracle DB", "location": "On-prem — VLT01", "owner": "Payments",
     "classification": "PCI", "records": 4_200_000, "public": False, "encryption": "TDE",
     "last_scan": "2026-04-17 06:12", "score": 97, "findings": 0},
    {"name": "dev-sandbox-dumps", "type": "S3 Bucket", "location": "AWS us-east-1", "owner": "Dev",
     "classification": "PII (test)", "records": 45_000, "public": True, "encryption": "None",
     "last_scan": "2026-04-17 06:12", "score": 22, "findings": 11},
    {"name": "analytics-lake-bronze", "type": "Databricks", "location": "Azure eastus2", "owner": "Analytics",
     "classification": "Mixed", "records": 120_000_000, "public": False, "encryption": "CMK",
     "last_scan": "2026-04-17 06:12", "score": 85, "findings": 2},
    {"name": "support-ticket-exports", "type": "GCS Bucket", "location": "GCP us-central1", "owner": "Support",
     "classification": "PII", "records": 210_000, "public": False, "encryption": "Google-managed",
     "last_scan": "2026-04-17 06:12", "score": 79, "findings": 3},
]

_DEMO_ALERTS = [
    {"ts": "2026-04-17 08:42", "asset": "legacy-etl-dump", "type": "UNENCRYPTED_PII",
     "detail": "1.1M records classified as PII on share with no encryption at rest", "severity": "critical"},
    {"ts": "2026-04-17 07:15", "asset": "dev-sandbox-dumps", "type": "PUBLIC_EXPOSURE",
     "detail": "Bucket ACL allows s3:GetObject for everyone; 45K PII (test) records present", "severity": "critical"},
    {"ts": "2026-04-17 06:58", "asset": "hr-case-files", "type": "OVER_PERMISSIONED",
     "detail": "148 users have read access — baseline is 12", "severity": "high"},
    {"ts": "2026-04-17 05:30", "asset": "claims-archive-2018", "type": "STALE_ACCESS",
     "detail": "Service principal svc_archive_reader unused for 180+ days still retains access", "severity": "medium"},
    {"ts": "2026-04-16 22:14", "asset": "analytics-lake-bronze", "type": "CLASSIFICATION_DRIFT",
     "detail": "New table bronze.cc_raw matches PCI pattern but not tagged", "severity": "high"},
    {"ts": "2026-04-16 18:03", "asset": "finance-reports-share", "type": "EXTERNAL_SHARE",
     "detail": "File shared externally with 3 vendor addresses (@pwc.com, @deloitte.com)", "severity": "medium"},
    {"ts": "2026-04-16 14:25", "asset": "prod-customer-docs", "type": "BULK_DOWNLOAD",
     "detail": "svc_export_runner downloaded 42GB in 18 minutes (baseline: 2GB/day)", "severity": "medium"},
    {"ts": "2026-04-16 09:10", "asset": "mktg-assets-public", "type": "CLASSIFICATION_UPGRADE",
     "detail": "Auto-classifier flagged 3 files as Internal in a Public bucket", "severity": "low"},
]

_DEMO_CLASSIFICATIONS = [
    {"label": "PCI", "assets": 2, "records": 4_238_500, "color": "#991b1b"},
    {"label": "PII", "assets": 4, "records": 3_755_000, "color": "#b45309"},
    {"label": "PHI", "assets": 2, "records": 1_430_000, "color": "#6d28d9"},
    {"label": "Internal", "assets": 3, "records": 120_000_000, "color": "#1e40af"},
    {"label": "Public", "assets": 1, "records": 0, "color": "#475569"},
]


def _compute_kpis(assets):
    total = len(assets)
    public = sum(1 for a in assets if a["public"])
    unencrypted = sum(1 for a in assets if a["encryption"] == "None")
    total_records = sum(a["records"] for a in assets)
    total_findings = sum(a["findings"] for a in assets)
    critical = sum(a["findings"] for a in assets if a["score"] < 50)
    avg_score = round(sum(a["score"] for a in assets) / total) if total else 0
    return {
        "total_assets": total,
        "public_exposure": public,
        "unencrypted": unencrypted,
        "total_records": total_records,
        "total_findings": total_findings,
        "critical_findings": critical,
        "avg_score": avg_score,
    }


# ---------------------------------------------------------------------------
# Deploy portal helpers (mirrors db_security.py)
# ---------------------------------------------------------------------------

def _now_utc_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _new_version_id(digest_hex: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"v{ts}_{digest_hex[:6]}"


def _require_token():
    expected = get_config().data_security_upload_token
    if not expected:
        abort(500, description="Upload token not configured on server")
    provided = (
        request.headers.get("X-Upload-Token")
        or request.form.get("token")
        or (request.get_json(silent=True) or {}).get("token", "")
    )
    if not provided or not hmac.compare_digest(str(provided), str(expected)):
        abort(401, description="Invalid or missing upload token")


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
        r = requests.get(f"{DSPM_BASE}/", timeout=3)
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
        r = requests.get(f"{DSPM_BASE}/", timeout=1.5)
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
            r = requests.get(f"{DSPM_BASE}/", timeout=2)
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

    Same shape as the AISPM/DB-Security deploy portals: main.py + frontend/index.html.
    """
    if (extract_dir / "main.py").is_file() and (extract_dir / "frontend" / "index.html").is_file():
        return extract_dir
    children = [c for c in extract_dir.iterdir() if c.is_dir()]
    if len(children) == 1:
        inner = children[0]
        if (inner / "main.py").is_file() and (inner / "frontend" / "index.html").is_file():
            return inner
    raise ValueError(
        "Zip is missing the expected DSPM structure — need main.py and frontend/index.html at the root "
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

@dspm_bp.route("/dspm")
@log_web_activity
def dspm_page():
    if _sidecar_is_up():
        return render_template("dspm_live.html")
    return render_template("dspm.html")


@dspm_bp.route("/dspm/deploy")
@log_web_activity
def dspm_deploy_page():
    return render_template("dspm_deploy.html")


@dspm_bp.route("/api/dspm/active-version", methods=["GET"])
def dspm_active_version():
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


@dspm_bp.route("/api/dspm/overview")
@log_web_activity
def api_overview():
    """Seed/demo endpoint used by the in-repo dashboard when the sidecar isn't running."""
    return jsonify({
        "demo": True,
        "assets": _DEMO_ASSETS,
        "kpis": _compute_kpis(_DEMO_ASSETS),
        "alerts": _DEMO_ALERTS,
        "classifications": _DEMO_CLASSIFICATIONS,
    })


@dspm_bp.route(f"{PROXY_PREFIX}/", defaults={"path": ""}, methods=["GET", "POST"])
@dspm_bp.route(f"{PROXY_PREFIX}/<path:path>", methods=["GET", "POST"])
def dspm_proxy(path):
    upstream_url = f"{DSPM_BASE}/{path}"
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

@dspm_bp.route("/api/dspm/versions", methods=["GET"])
def dspm_versions():
    _require_token()
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


@dspm_bp.route("/api/dspm/upload", methods=["POST"])
def dspm_upload():
    _require_token()
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


@dspm_bp.route("/api/dspm/activate", methods=["POST"])
def dspm_activate():
    _require_token()
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


@dspm_bp.route("/api/dspm/rollback", methods=["POST"])
def dspm_rollback():
    _require_token()
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


@dspm_bp.route("/api/dspm/staged/<version_id>", methods=["DELETE"])
def dspm_delete_staged(version_id):
    _require_token()
    if not VERSION_ID_RE.match(version_id):
        return jsonify({"ok": False, "error": "Invalid version_id"}), 400
    target = STAGING_DIR / version_id
    if not target.is_dir():
        return jsonify({"ok": False, "error": "Not found"}), 404
    shutil.rmtree(target)
    _audit("staged_delete", version_id)
    return jsonify({"ok": True})
