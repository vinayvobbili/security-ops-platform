"""Refresh the trusted internal mirror for Claude Code setup.

Pulls latest Node.js LTS archives (Windows zip, macOS arm64/x64 tarballs, Linux
x64 tarball) and the latest @anthropic-ai/claude-code npm tarball into
``data/transient/cc_mirror/``. Verifies upstream SHA-256 from the official
``SHASUMS256.txt`` for Node and from npm's published integrity hash for Claude
Code. Writes a ``manifest.json`` the Flask route consumes.

Atomic publish: downloads land in a sibling ``.staging`` dir; on success the
two dirs swap so the served files never appear half-written.

Run manually::

    python scripts/refresh_cc_mirror.py

Suggested cron (Sundays 3 AM, after the lab-vm2 backup at 2 AM)::

    0 3 * * 0 cd /home/vinay/security-ops-platform && /home/vinay/security-ops-platform/.venv/bin/python \
        scripts/refresh_cc_mirror.py >> data/transient/logs/cc_mirror.log 2>&1
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MIRROR_DIR = REPO_ROOT / "data" / "transient" / "cc_mirror"
STAGING_DIR = MIRROR_DIR.with_suffix(".staging")
CORP_CA_SRC = REPO_ROOT / "data" / "transient" / "certs" / "corp-ca-bundle.pem"

NODE_INDEX_URL = "https://nodejs.org/dist/index.json"
NPM_REGISTRY_BASE = "https://registry.npmjs.org/@anthropic-ai"
CC_WRAPPER_PKG = "claude-code"

# (upstream_name_template, published_filename)
NODE_ARTIFACTS = [
    ("node-{ver}-win-x64.zip", "node-v22-win-x64.zip"),
    ("node-{ver}-darwin-arm64.tar.gz", "node-v22-darwin-arm64.tar.gz"),
    ("node-{ver}-darwin-x64.tar.gz", "node-v22-darwin-x64.tar.gz"),
    ("node-{ver}-linux-x64.tar.xz", "node-v22-linux-x64.tar.xz"),
]

# Claude Code 2.x publishes per-platform native binaries as optionalDependencies.
# Mirror the four that cover virtually everyone here so the mirror install is
# truly self-contained (no fallback to npm registry for the native binary).
CC_PLATFORM_PKGS = [
    ("claude-code-darwin-arm64", "anthropic-ai-claude-code-darwin-arm64.tgz"),
    ("claude-code-darwin-x64", "anthropic-ai-claude-code-darwin-x64.tgz"),
    ("claude-code-linux-x64", "anthropic-ai-claude-code-linux-x64.tgz"),
    ("claude-code-win32-x64", "anthropic-ai-claude-code-win32-x64.tgz"),
]


def _http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ir-cc-mirror/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _http_get_json(url: str) -> dict:
    return json.loads(_http_get(url))


def _http_download(url: str, dest: Path, timeout: int = 600) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "ir-cc-mirror/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out, length=1024 * 1024)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _latest_node_lts() -> str:
    """Return the latest Node v22 LTS version string like 'v22.10.0'."""
    index = _http_get_json(NODE_INDEX_URL)
    for entry in index:
        ver = entry["version"]
        if ver.startswith("v22.") and entry.get("lts"):
            return ver
    raise RuntimeError("No v22 LTS release found in nodejs.org index")


def _parse_shasums(text: str) -> dict[str, str]:
    """Parse a SHASUMS256.txt body into {filename: sha256_hex}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition("  ")
        if digest and name:
            out[name] = digest
    return out


def _fetch_node(staging: Path) -> dict[str, dict]:
    ver = _latest_node_lts()
    print(f"[node] latest LTS: {ver}", flush=True)
    base = f"https://nodejs.org/dist/{ver}"
    shasums_raw = _http_get(f"{base}/SHASUMS256.txt").decode("utf-8")
    expected = _parse_shasums(shasums_raw)

    files: dict[str, dict] = {}
    for upstream_tpl, published in NODE_ARTIFACTS:
        upstream_name = upstream_tpl.format(ver=ver)
        upstream_url = f"{base}/{upstream_name}"
        want_sha = expected.get(upstream_name)
        if not want_sha:
            raise RuntimeError(f"No SHA-256 in SHASUMS256.txt for {upstream_name}")
        dest = staging / published
        print(f"[node] {upstream_name} -> {dest.name}", flush=True)
        _http_download(upstream_url, dest)
        got_sha = _sha256(dest)
        if got_sha != want_sha:
            raise RuntimeError(
                f"SHA-256 mismatch for {upstream_name}: want {want_sha}, got {got_sha}"
            )
        size = dest.stat().st_size
        files[published] = {
            "size_bytes": size,
            "size_human": _human_size(size),
            "sha256": got_sha,
            "upstream": upstream_url,
        }
    return files, ver


def _fetch_npm_pkg(pkg: str, published: str, staging: Path, want_version: str | None = None) -> tuple[dict, str]:
    """Fetch one @anthropic-ai/* npm package. If ``want_version`` is given, pin
    to it; otherwise use dist-tags.latest. Verifies sha512 integrity from the
    registry metadata.
    """
    meta = _http_get_json(f"{NPM_REGISTRY_BASE}/{pkg}")
    version = want_version or meta["dist-tags"]["latest"]
    if version not in meta["versions"]:
        raise RuntimeError(f"{pkg}@{version} not found in registry")
    dist = meta["versions"][version]["dist"]
    tarball_url = dist["tarball"]
    integrity = dist.get("integrity", "")
    print(f"[npm] @anthropic-ai/{pkg}@{version}", flush=True)

    dest = staging / published
    _http_download(tarball_url, dest)

    if integrity.startswith("sha512-"):
        expected = base64.b64decode(integrity.split("-", 1)[1])
        got = hashlib.sha512(dest.read_bytes()).digest()
        if got != expected:
            raise RuntimeError(f"SHA-512 mismatch for {pkg}@{version}")
    else:
        print(f"[npm] WARNING: no sha512 integrity for {pkg}@{version}", flush=True)

    size = dest.stat().st_size
    return {
        published: {
            "size_bytes": size,
            "size_human": _human_size(size),
            "sha256": _sha256(dest),
            "upstream": tarball_url,
        }
    }, version


def _fetch_claude_code(staging: Path) -> tuple[dict[str, dict], str]:
    """Fetch wrapper + all mirrored platform binaries at one pinned version."""
    files, wrapper_ver = _fetch_npm_pkg(
        CC_WRAPPER_PKG, "anthropic-ai-claude-code.tgz", staging
    )
    for pkg, published in CC_PLATFORM_PKGS:
        platform_files, _ = _fetch_npm_pkg(pkg, published, staging, want_version=wrapper_ver)
        files.update(platform_files)
    return files, wrapper_ver


def _copy_corp_ca(staging: Path) -> dict[str, dict]:
    published = "corp-ca-bundle.pem"
    dest = staging / published
    if not CORP_CA_SRC.exists():
        print(f"[ca] skip — {CORP_CA_SRC} missing", flush=True)
        return {}
    shutil.copy2(CORP_CA_SRC, dest)
    size = dest.stat().st_size
    return {
        published: {
            "size_bytes": size,
            "size_human": _human_size(size),
            "sha256": _sha256(dest),
            "upstream": f"file://{CORP_CA_SRC}",
        }
    }


def _atomic_swap(staging: Path, live: Path) -> None:
    """Replace ``live`` with ``staging`` atomically."""
    backup = live.with_suffix(".old")
    if backup.exists():
        shutil.rmtree(backup)
    if live.exists():
        live.rename(backup)
    try:
        staging.rename(live)
    except Exception:
        if backup.exists():
            backup.rename(live)
        raise
    if backup.exists():
        shutil.rmtree(backup)


def main() -> int:
    start = time.time()
    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    try:
        node_files, node_version = _fetch_node(STAGING_DIR)
        cc_files, cc_version = _fetch_claude_code(STAGING_DIR)
        ca_files = _copy_corp_ca(STAGING_DIR)

        manifest = {
            "refreshed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "node_version": node_version,
            "claude_code_version": cc_version,
            "files": {**node_files, **cc_files, **ca_files},
        }
        (STAGING_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2))
        _atomic_swap(STAGING_DIR, MIRROR_DIR)

        elapsed = time.time() - start
        print(
            f"[done] refreshed {len(manifest['files'])} files in "
            f"{elapsed:.1f}s -> {MIRROR_DIR}",
            flush=True,
        )
        return 0
    except Exception as exc:
        print(f"[fail] {exc!r}", file=sys.stderr, flush=True)
        if STAGING_DIR.exists():
            shutil.rmtree(STAGING_DIR)
        return 1


if __name__ == "__main__":
    sys.exit(main())
