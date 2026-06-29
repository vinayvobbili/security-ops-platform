"""SQLite store for the Active-Threat Intake queue.

The adversary-centric sibling to the cs-advisories (asset-centric) queue. Where
``github_advisories_db`` pivots on a vulnerable *package*, this pivots on an
*adversary* — an actor, a campaign, or a bundle of in-the-wild IOCs that has no
CVE. One row == one active threat ingested from a pasted report (slice 1) or,
later, an auto-pull from Recorded Future.

Schema mirrors the cs-advisories conventions: ``uid = "{source}:{source_id}"``,
ISO-8601 Z timestamps, a status lifecycle, JSON-encoded list columns decoded on
read. Read paths never raise; mutation paths use the commit/rollback context
manager.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DB_DIR = Path(__file__).resolve().parent.parent / "data" / "transient" / "active_threats"
DB_PATH = DB_DIR / "active_threats.db"

# Status lifecycle for an active threat as it moves through the desk.
STATUSES = ("new", "under_review", "hunting", "blocked", "closed")
# Coarse threat families used for the type chip + filtering.
THREAT_TYPES = (
    "ransomware", "phishing", "malware", "apt", "infostealer",
    "botnet", "vulnerability_exploitation", "fraud", "other",
)
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Columns stored as JSON text and decoded to Python lists on read.
_JSON_COLS = ("iocs", "ttps", "recommended_actions", "aliases")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def make_uid(source: str, source_id: str) -> str:
    return f"{source}:{source_id}"


@contextmanager
def get_connection():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS active_threats (
    uid                 TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    source_id           TEXT NOT NULL,
    title               TEXT NOT NULL DEFAULT '',
    actor               TEXT NOT NULL DEFAULT '',
    campaign            TEXT NOT NULL DEFAULT '',
    threat_type         TEXT NOT NULL DEFAULT 'other',
    severity            TEXT NOT NULL DEFAULT 'medium',
    summary             TEXT NOT NULL DEFAULT '',
    iocs                TEXT NOT NULL DEFAULT '[]',
    ttps                TEXT NOT NULL DEFAULT '[]',
    recommended_actions TEXT NOT NULL DEFAULT '[]',
    aliases             TEXT NOT NULL DEFAULT '[]',
    raw_report          TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'new',
    notes               TEXT NOT NULL DEFAULT '',
    created_by          TEXT NOT NULL DEFAULT '',
    first_seen_at       TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL DEFAULT '',
    updated_at          TEXT NOT NULL DEFAULT ''
);
"""


_META_SCHEMA = """
CREATE TABLE IF NOT EXISTS active_threats_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
"""


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(_SCHEMA)
        conn.execute(_META_SCHEMA)
        # Forward-compatible: add columns that later slices introduce without a
        # destructive migration (enrichment verdicts, hunt/block ledgers).
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(active_threats)").fetchall()}
        for name, ddl in (
            ("enrichment", "ALTER TABLE active_threats ADD COLUMN enrichment TEXT NOT NULL DEFAULT '{}'"),
            ("hunt_job_id", "ALTER TABLE active_threats ADD COLUMN hunt_job_id TEXT NOT NULL DEFAULT ''"),
            ("hunt_status", "ALTER TABLE active_threats ADD COLUMN hunt_status TEXT NOT NULL DEFAULT ''"),
            ("hunt_result", "ALTER TABLE active_threats ADD COLUMN hunt_result TEXT NOT NULL DEFAULT '{}'"),
            ("block_status", "ALTER TABLE active_threats ADD COLUMN block_status TEXT NOT NULL DEFAULT ''"),
            ("block_result", "ALTER TABLE active_threats ADD COLUMN block_result TEXT NOT NULL DEFAULT '{}'"),
        ):
            if name not in cols:
                conn.execute(ddl)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    for col in _JSON_COLS:
        raw = d.get(col)
        try:
            d[col] = json.loads(raw) if raw else []
        except (json.JSONDecodeError, TypeError):
            d[col] = []
    for jcol in ("enrichment", "hunt_result", "block_result"):
        raw = d.get(jcol)
        if raw is not None:
            try:
                d[jcol] = json.loads(raw) if raw else {}
            except (json.JSONDecodeError, TypeError):
                d[jcol] = {}
    return d


def _json(val: Any) -> str:
    try:
        return json.dumps(val or [], ensure_ascii=False)
    except (TypeError, ValueError):
        return "[]"


def upsert_threat(rec: dict[str, Any], *, initial_status: str = "new") -> bool:
    """Insert a normalized active-threat record if its uid is new.

    Returns True iff a new row was inserted. Re-ingesting the same uid is a
    no-op (the desk owns the live row's status/notes), matching the
    cs-advisories upsert contract.
    """
    source = (rec.get("source") or "").strip()
    source_id = (rec.get("source_id") or "").strip()
    if not source or not source_id:
        return False
    uid = make_uid(source, source_id)
    now = _now_iso()
    status = rec.get("status") or initial_status
    with get_connection() as conn:
        if conn.execute("SELECT 1 FROM active_threats WHERE uid = ?", (uid,)).fetchone():
            return False
        conn.execute(
            """INSERT INTO active_threats
               (uid, source, source_id, title, actor, campaign, threat_type,
                severity, summary, iocs, ttps, recommended_actions, aliases,
                raw_report, status, notes, created_by, first_seen_at,
                created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                uid, source, source_id,
                (rec.get("title") or "").strip(),
                (rec.get("actor") or "").strip(),
                (rec.get("campaign") or "").strip(),
                (rec.get("threat_type") or "other").strip(),
                (rec.get("severity") or "medium").strip(),
                (rec.get("summary") or "").strip(),
                _json(rec.get("iocs")),
                _json(rec.get("ttps")),
                _json(rec.get("recommended_actions")),
                _json(rec.get("aliases")),
                rec.get("raw_report") or "",
                status,
                rec.get("notes") or "",
                (rec.get("created_by") or "").strip(),
                now, now, now,
            ),
        )
    return True


def list_threats(*, include_closed: bool = True, limit: int = 500) -> list[dict[str, Any]]:
    """Newest-first list for the queue page. Never raises — returns []."""
    try:
        with get_connection() as conn:
            if include_closed:
                rows = conn.execute(
                    "SELECT * FROM active_threats ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM active_threats WHERE status != 'closed' "
                    "ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [d for d in (_row_to_dict(r) for r in rows) if d]
    except Exception:
        return []


def get_threat(key: str) -> dict[str, Any] | None:
    """Fetch by uid OR by source_id (the URL-friendly key). Never raises."""
    if not key:
        return None
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM active_threats WHERE uid = ? OR source_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (key, key),
            ).fetchone()
        return _row_to_dict(row)
    except Exception:
        return None


def set_status(uid: str, status: str) -> bool:
    if status not in STATUSES:
        return False
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE active_threats SET status = ?, updated_at = ? WHERE uid = ? OR source_id = ?",
            (status, _now_iso(), uid, uid),
        )
        return cur.rowcount > 0


def save_notes(uid: str, notes: str) -> bool:
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE active_threats SET notes = ?, updated_at = ? WHERE uid = ? OR source_id = ?",
            (notes or "", _now_iso(), uid, uid),
        )
        return cur.rowcount > 0


def save_enrichment(uid: str, enrichment: dict[str, Any]) -> bool:
    """Persist the IOC-reputation enrichment blob (slice 2) for a threat.

    Stored as JSON in the ``enrichment`` column; decoded back to a dict on read
    by ``_row_to_dict``. Used both for the in-progress ``status='running'``
    marker and the final verdict set, so the detail page can poll.
    """
    try:
        payload = json.dumps(enrichment or {}, ensure_ascii=False)
    except (TypeError, ValueError):
        payload = "{}"
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE active_threats SET enrichment = ?, updated_at = ? WHERE uid = ? OR source_id = ?",
            (payload, _now_iso(), uid, uid),
        )
        return cur.rowcount > 0


def get_enrichment(key: str) -> dict[str, Any]:
    """Read just the enrichment blob for polling. Never raises — returns {}."""
    t = get_threat(key)
    if not t:
        return {}
    enr = t.get("enrichment")
    return enr if isinstance(enr, dict) else {}


def save_hunt(uid: str, hunt_status: str, hunt_result: dict[str, Any] | None = None,
              hunt_job_id: str | None = None) -> bool:
    """Persist the telemetry-hunt state (slice 3) for a threat.

    ``hunt_status`` is the lifecycle marker (running / done / error) the detail
    page polls on; ``hunt_result`` is the normalized HuntResult blob.
    """
    sets = ["hunt_status = ?", "updated_at = ?"]
    vals: list[Any] = [hunt_status or "", _now_iso()]
    if hunt_result is not None:
        try:
            payload = json.dumps(hunt_result or {}, ensure_ascii=False)
        except (TypeError, ValueError):
            payload = "{}"
        sets.append("hunt_result = ?")
        vals.append(payload)
    if hunt_job_id is not None:
        sets.append("hunt_job_id = ?")
        vals.append(hunt_job_id)
    vals.extend([uid, uid])
    with get_connection() as conn:
        cur = conn.execute(
            f"UPDATE active_threats SET {', '.join(sets)} WHERE uid = ? OR source_id = ?",
            vals,
        )
        return cur.rowcount > 0


def get_hunt(key: str) -> dict[str, Any]:
    """Read the hunt blob + status for polling. Never raises — returns {}."""
    t = get_threat(key)
    if not t:
        return {}
    res = t.get("hunt_result")
    res = res if isinstance(res, dict) else {}
    status = t.get("hunt_status") or res.get("status") or ""
    if status and "status" not in res:
        res = {**res, "status": status}
    return res


def save_block(uid: str, block_status: str, block_result: dict[str, Any] | None = None) -> bool:
    """Persist the containment-block state (slice 4) for a threat.

    ``block_status`` is the lifecycle marker (blocking / blocked / partial /
    error) the detail page polls on; ``block_result`` is the per-IOC outcome
    plus the XSOAR ticket the block flow opened.
    """
    sets = ["block_status = ?", "updated_at = ?"]
    vals: list[Any] = [block_status or "", _now_iso()]
    if block_result is not None:
        try:
            payload = json.dumps(block_result or {}, ensure_ascii=False)
        except (TypeError, ValueError):
            payload = "{}"
        sets.append("block_result = ?")
        vals.append(payload)
    vals.extend([uid, uid])
    with get_connection() as conn:
        cur = conn.execute(
            f"UPDATE active_threats SET {', '.join(sets)} WHERE uid = ? OR source_id = ?",
            vals,
        )
        return cur.rowcount > 0


def get_block(key: str) -> dict[str, Any]:
    """Read the block blob + status for polling. Never raises — returns {}."""
    t = get_threat(key)
    if not t:
        return {}
    res = t.get("block_result")
    res = res if isinstance(res, dict) else {}
    status = t.get("block_status") or res.get("status") or ""
    if status and "status" not in res:
        res = {**res, "status": status}
    return res


def get_meta(key: str, default: str = "") -> str:
    """Read a small key/value cursor (e.g. the RF feed high-water marks).

    Used by the slice-5 Recorded Future poller to remember how far it has
    ingested so a re-poll only fetches newer items. Never raises.
    """
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM active_threats_meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default
    except Exception:
        return default


def set_meta(key: str, value: str) -> bool:
    """Upsert a key/value cursor. Never raises."""
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO active_threats_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value or ""),
            )
        return True
    except Exception:
        return False


def status_counts() -> dict[str, int]:
    out = {s: 0 for s in STATUSES}
    try:
        with get_connection() as conn:
            for r in conn.execute(
                "SELECT status, COUNT(*) c FROM active_threats GROUP BY status"
            ).fetchall():
                out[r["status"]] = r["c"]
    except Exception:
        pass
    out["total"] = sum(out.get(s, 0) for s in STATUSES)
    return out


def severity_counts(*, open_only: bool = True) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    try:
        clause = "WHERE status != 'closed'" if open_only else ""
        with get_connection() as conn:
            for r in conn.execute(
                f"SELECT severity, COUNT(*) c FROM active_threats {clause} GROUP BY severity"
            ).fetchall():
                if r["severity"] in out:
                    out[r["severity"]] = r["c"]
    except Exception:
        pass
    return out


def ioc_total(*, open_only: bool = True) -> int:
    """Count distinct IOC values across the (open) queue — a KPI for the rail."""
    seen: set[str] = set()
    for t in list_threats(include_closed=not open_only):
        if open_only and t.get("status") == "closed":
            continue
        for ioc in t.get("iocs") or []:
            v = (ioc.get("value") if isinstance(ioc, dict) else str(ioc)) or ""
            if v:
                seen.add(v.strip().lower())
    return len(seen)


# Initialize on import (matches the pattern used by the other *_db.py modules).
init_db()
