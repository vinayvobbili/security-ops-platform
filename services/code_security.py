"""Code Security Scanner — agentic repo vulnerability scanning (adapter).

The scan ENGINE lives in the standalone, model-agnostic `refutescan` package
(a two-LLM, refute-first scanner: a fast navigator casts a wide net of candidate
findings via read-only repo tools; a skeptical judge refutes each against the
real code slice before it surfaces; every scan runs jailed in an ephemeral docker
sandbox). This module is the thin adapter around it:

  • injects the LLMs — a local LLM (create_llm) navigates and enumerates the
    candidate findings, and a second create_llm pass with structured output acts
    as the refute judge;
  • keeps the SQLite audit trail, the background worker, the slot semaphore, and
    the submit/get_scan/list_recent API the web route consumes;
  • maps the platform's env config (CODE_SECURITY_SANDBOX, CODE_SEC_SANDBOX_IMAGE,
    CODE_SECURITY_ALLOWED_ROOTS, …) onto refutescan's ScanConfig.

Slice 1 is READ-ONLY: it scans and reports — no writes, PRs, or patches. Long
scans run in a background worker thread; the page polls for progress.

`refutescan` is a published public PyPI package; install it into the app's venv.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from refutescan import (
    ScanConfig,
    VULN_CLASSES,
    derive_title as _derive_title,
    looks_like_git_url as _looks_like_git_url,
    scan as _refute_scan,
)

logger = logging.getLogger(__name__)

# Re-exported for the web route / methodology modal (the taxonomy the scanner
# hunts). Sourced from refutescan so the page and the engine never drift.
VULN_CLASSES = VULN_CLASSES

_DB = Path(__file__).resolve().parent.parent / "data" / "code_security.db"

# Scans are heavy — a full repo walk plus dozens of LLM calls. Run them strictly
# one at a time; extra submissions sit in their worker thread (status=queued)
# until the slot frees.
_MAX_CONCURRENT = 1
_slots = threading.BoundedSemaphore(_MAX_CONCURRENT)

# Per-candidate judge deadline — also passed to the judge LLM as its request timeout.
_JUDGE_TIMEOUT = 60.0


def _scan_config() -> ScanConfig:
    """Build refutescan's config from the environment.

    Defaults preserve the prior behavior: docker sandbox when available (auto),
    the prebuilt image `ir-code-sec-sandbox:current`, and local scans confined to
    /home/vinay unless overridden.
    """
    roots_spec = os.environ.get("CODE_SECURITY_ALLOWED_ROOTS", "/home/vinay")
    allowed_roots = [
        Path(os.path.expanduser(p)).resolve()
        for p in roots_spec.split(":") if p.strip()
    ]
    return ScanConfig(
        sandbox=os.environ.get("CODE_SECURITY_SANDBOX", "auto").strip().lower(),
        sandbox_image=os.environ.get("CODE_SEC_SANDBOX_IMAGE", "ir-code-sec-sandbox:current"),
        sandbox_memory=os.environ.get("CODE_SEC_SANDBOX_MEMORY", "2g"),
        sandbox_cpus=os.environ.get("CODE_SEC_SANDBOX_CPUS", "2"),
        judge_timeout=_JUDGE_TIMEOUT,
        allowed_roots=allowed_roots,
    )


# ── Model injection (the LLMs behind refutescan's provider seam) ─────────────────

def _navigator_factory():
    """Wide-net navigator = a local LLM (a tool-caller). Returns a chat model."""
    from my_bot.utils.llm_factory import create_llm
    return create_llm(temperature=0)


def _judge_factory():
    """Refute judge = a second create_llm pass with structured output. Returns a
    callable (prompt, schema) -> validated pydantic instance, fresh per candidate."""
    from my_bot.utils.llm_factory import create_llm, structured_output

    def judge(prompt: str, schema):
        m = create_llm(temperature=0, timeout=int(_JUDGE_TIMEOUT))
        return structured_output(m, schema).invoke(prompt)

    return judge


# ── Persistence ─────────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    _DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id            TEXT PRIMARY KEY,
                created_at    TEXT NOT NULL,
                completed_at  TEXT,
                actor         TEXT,
                title         TEXT,
                source_kind   TEXT,           -- path | git
                source_label  TEXT,           -- repo path or URL (display)
                branch        TEXT,
                options_json  TEXT,
                status        TEXT NOT NULL,   -- queued | running | done | error
                phase         TEXT,
                map_json      TEXT,
                findings_json TEXT,
                culled_json   TEXT,
                summary_json  TEXT,
                error         TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)")
        conn.commit()


def _reconcile_orphans() -> None:
    """On process start no worker drives previously in-flight scans — mark any
    leftover queued/running rows interrupted so history never shows a zombie."""
    try:
        with _connect() as conn:
            conn.execute(
                "UPDATE scans SET status='error', phase='Interrupted', "
                "error='Interrupted by a server restart — re-run the scan.', "
                "completed_at=? WHERE status IN ('queued','running')",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
            )
            conn.commit()
    except Exception:
        logger.exception("[code-sec] orphan reconcile failed")


_init_db()
_reconcile_orphans()


def _update(scan_id: str, **cols) -> None:
    if not cols:
        return
    sets = ", ".join(f"{k} = ?" for k in cols)
    vals = list(cols.values()) + [scan_id]
    try:
        with _connect() as conn:
            conn.execute(f"UPDATE scans SET {sets} WHERE id = ?", vals)
            conn.commit()
    except Exception:
        logger.exception("[code-sec] failed to update scan %s", scan_id)


def _row_to_scan(row: sqlite3.Row) -> Dict[str, Any]:
    def _j(v):
        if not v:
            return None
        try:
            return json.loads(v)
        except Exception:
            return None

    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
        "actor": row["actor"],
        "title": row["title"],
        "source_kind": row["source_kind"],
        "source_label": row["source_label"],
        "branch": row["branch"],
        "options": _j(row["options_json"]) or {},
        "status": row["status"],
        "phase": row["phase"],
        "map": _j(row["map_json"]),
        "findings": _j(row["findings_json"]),
        "culled": _j(row["culled_json"]),
        "summary": _j(row["summary_json"]),
        "error": row["error"],
    }


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    try:
        with _connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_scan(row) if row else None
    except Exception:
        logger.exception("[code-sec] get_scan failed")
        return None


def list_recent(limit: int = 25) -> List[Dict[str, Any]]:
    """Compact recent-scans list for the history rail (no heavy result blobs)."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, actor, title, source_label, status, phase, summary_json "
                "FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    except Exception:
        logger.exception("[code-sec] list_recent failed")
        return []

    out = []
    for r in rows:
        summary = {}
        try:
            summary = json.loads(r["summary_json"]) if r["summary_json"] else {}
        except Exception:
            summary = {}
        out.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "actor": r["actor"],
            "title": r["title"] or "Untitled scan",
            "source_label": r["source_label"],
            "status": r["status"],
            "phase": r["phase"],
            "total_findings": (summary or {}).get("total_findings"),
            "max_severity": (summary or {}).get("max_severity"),
        })
    return out


# ── Orchestration ───────────────────────────────────────────────────────────────

def submit(source: str, branch: str = "", title: str = "", actor: str = "anonymous",
           options: Optional[dict] = None) -> str:
    """Create a scan and kick off the background worker. Returns scan_id."""
    options = options or {}
    source = (source or "").strip()
    scan_id = uuid.uuid4().hex[:16]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_kind = "git" if _looks_like_git_url(source) else "path"
    title = (title or "").strip() or _derive_title(source)

    with _connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, created_at, actor, title, source_kind, source_label, "
            "branch, options_json, status, phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'Queued')",
            (scan_id, now, actor, title, source_kind, source, branch or "", json.dumps(options)),
        )
        conn.commit()

    logger.info("[CODE-SEC] user=%s action=submit scan=%s kind=%s src=%s",
                actor, scan_id, source_kind, source[:120])

    t = threading.Thread(target=_run_scan, args=(scan_id, source, branch),
                         name=f"code-sec-{scan_id}", daemon=True)
    t.start()
    return scan_id


def _run_scan(scan_id: str, source: str, branch: str) -> None:
    """Background worker: acquire the slot, run refutescan, persist the result."""
    acquired = False
    try:
        _update(scan_id, status="queued", phase="Waiting for a scan slot")
        _slots.acquire()
        acquired = True
        _update(scan_id, status="running", phase="Starting")

        def _progress(phase: str) -> None:
            _update(scan_id, phase=phase)

        result = _refute_scan(
            source,
            navigator_factory=_navigator_factory,
            judge_factory=_judge_factory,
            branch=branch,
            config=_scan_config(),
            progress=_progress,
        )

        _update(scan_id, status="done", phase="Complete",
                map_json=json.dumps(result.code_map),
                findings_json=json.dumps(result.findings),
                culled_json=json.dumps(result.culled),
                summary_json=json.dumps(result.summary),
                completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("[CODE-SEC] scan=%s done findings=%d culled=%d max_sev=%s sandbox=%s",
                    scan_id, len(result.findings), len(result.culled),
                    result.summary.get("max_severity"), result.sandboxed)
    except Exception as e:
        logger.exception("[code-sec] scan %s failed", scan_id)
        _update(scan_id, status="error", phase="Failed",
                error=f"{type(e).__name__}: {e}",
                completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    finally:
        if acquired:
            _slots.release()
