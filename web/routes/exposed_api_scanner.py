"""Exposed API Scanner — reverse-proxy to the standalone scanner sidecar (ir-exposed-api-scanner.service on :8028).

Vendor ships a Flask web UI (web_app.py + templates/index.html + requirements.txt).
The sidecar runs the app via waitress on port 8000 inside the container; we map
that to 127.0.0.1:8028 on the host and expose it externally through the Flask
reverse proxy at /exposed-api-scanner-app/*.

Same deploy-portal shape as db-security: token-gated upload → stage → activate,
with rollback to the last 5 backups.
"""

import hashlib
import hmac
import json
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

exposed_api_scanner_bp = Blueprint("exposed_api_scanner", __name__)

SCANNER_BASE = "http://127.0.0.1:8028"
PROXY_PREFIX = "/exposed-api-scanner-app"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}

_EXTERNAL = Path("/home/vinay/security-ops-platform/external")
ACTIVE_DIR = _EXTERNAL / "exposed_api_scanner"
STAGING_DIR = _EXTERNAL / "exposed_api_scanner_staging"
BACKUPS_DIR = _EXTERNAL / "exposed_api_scanner_backups"
AUDIT_LOG = _EXTERNAL / "exposed_api_scanner_audit.jsonl"

MAX_BACKUPS = 5
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
SERVICE_NAME = "ir-exposed-api-scanner"
DOCKER_IMAGE = "ir-exposed-api-scanner"
DOCKER_TAG_CURRENT = "current"
VERSION_ID_RE = re.compile(r"^v\d{8}_\d{6}_[a-f0-9]{6}$")


def _now_utc_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _new_version_id(digest_hex: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"v{ts}_{digest_hex[:6]}"


def _require_token():
    expected = get_config().scanner_upload_token
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
        r = requests.get(f"{SCANNER_BASE}/health", timeout=3)
        if r.ok:
            try:
                return {"healthy": True, **r.json()}
            except Exception:
                return {"healthy": True}
        return {"healthy": False, "http_status": r.status_code}
    except Exception as e:
        return {"healthy": False, "error": str(e)}


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
            r = requests.get(f"{SCANNER_BASE}/", timeout=2)
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
    """Vendor ships web_app.py + templates/index.html + requirements.txt at root.

    Accept either a flat package at root or one nested inside a single top-level folder.
    """
    if ((extract_dir / "web_app.py").is_file()
            and (extract_dir / "templates" / "index.html").is_file()):
        return extract_dir
    children = [c for c in extract_dir.iterdir() if c.is_dir()]
    if len(children) == 1:
        inner = children[0]
        if ((inner / "web_app.py").is_file()
                and (inner / "templates" / "index.html").is_file()):
            return inner
    raise ValueError(
        "Zip is missing the expected Exposed API Scanner structure — need web_app.py and "
        "templates/index.html at the root (or nested inside a single top-level folder)."
    )


def _validate_package(pkg_root: Path):
    required = [
        pkg_root / "web_app.py",
        pkg_root / "templates" / "index.html",
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
# Routes: page + proxy
# ---------------------------------------------------------------------------

@exposed_api_scanner_bp.route("/exposed-api-scanner")
@log_web_activity
def exposed_api_scanner_page():
    return render_template("exposed_api_scanner.html")


@exposed_api_scanner_bp.route("/exposed-api-scanner/deploy")
@log_web_activity
def exposed_api_scanner_deploy_page():
    return render_template("exposed_api_scanner_deploy.html")


@exposed_api_scanner_bp.route("/api/exposed-api-scanner/active-version", methods=["GET"])
def exposed_api_scanner_active_version():
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


@exposed_api_scanner_bp.route(f"{PROXY_PREFIX}/", defaults={"path": ""}, methods=["GET", "POST"])
@exposed_api_scanner_bp.route(f"{PROXY_PREFIX}/<path:path>", methods=["GET", "POST"])
def exposed_api_scanner_proxy(path):
    upstream_url = f"{SCANNER_BASE}/{path}"
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
        # Vendor's frontend hardcodes fetch('/api/...') — rewrite so requests
        # hit the proxied sidecar instead of the Flask host app.
        body = body.replace(b"const API = ''", f"const API = '{PROXY_PREFIX}'".encode())
        body = body.replace(b"fetch('/api/", f"fetch('{PROXY_PREFIX}/api/".encode())
        body = body.replace(b'fetch("/api/', f'fetch("{PROXY_PREFIX}/api/'.encode())

    out_headers = [(k, v) for k, v in upstream.headers.items()
                   if k.lower() not in HOP_BY_HOP]
    return Response(body, status=upstream.status_code, headers=out_headers)


# ---------------------------------------------------------------------------
# Routes: deploy API
# ---------------------------------------------------------------------------

@exposed_api_scanner_bp.route("/api/exposed-api-scanner/versions", methods=["GET"])
def exposed_api_scanner_versions():
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


@exposed_api_scanner_bp.route("/api/exposed-api-scanner/upload", methods=["POST"])
def exposed_api_scanner_upload():
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


@exposed_api_scanner_bp.route("/api/exposed-api-scanner/activate", methods=["POST"])
def exposed_api_scanner_activate():
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
    _audit("activate", version_id, {"backup_id": backup_id, "build_returncode": build["returncode"], "restart": restart})

    return jsonify({
        "ok": restart["ok"],
        "version_id": version_id,
        "backup_id": backup_id,
        "build": {"tag": build["tag"], "returncode": build["returncode"]},
        "restart": restart,
    })


@exposed_api_scanner_bp.route("/api/exposed-api-scanner/rollback", methods=["POST"])
def exposed_api_scanner_rollback():
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
    _audit("rollback", backup_id, {"new_backup_id": rollback_backup_id, "restart": restart})
    return jsonify({"ok": restart["ok"], "rolled_back_to": backup_id, "restart": restart})


@exposed_api_scanner_bp.route("/api/exposed-api-scanner/staged/<version_id>", methods=["DELETE"])
def exposed_api_scanner_delete_staged(version_id):
    _require_token()
    if not VERSION_ID_RE.match(version_id):
        return jsonify({"ok": False, "error": "Invalid version_id"}), 400
    target = STAGING_DIR / version_id
    if not target.is_dir():
        return jsonify({"ok": False, "error": "Not found"}), 404
    shutil.rmtree(target)
    _audit("staged_delete", version_id)
    return jsonify({"ok": True})
