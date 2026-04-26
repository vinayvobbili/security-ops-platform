"""
Tanium Installed Software Inventory — SQLite-backed cache.

A daily job calls sync_inventory() to pull every endpoint's Installed
Applications sensor into a local SQLite DB. Queries against the cache
take ~100ms instead of ~5 minutes for a live fleet scan, which lets the
CVE exposure correlator run per-tipper without blocking.

Schema:
  installed_software(host, os, source, app, app_lower, version, synced_at)
  sync_meta(id, started_at, finished_at, row_count, duration_sec, instances, status)

find_software_matches(keywords) does case-insensitive substring match
via LIKE on an indexed column. Multiple keywords are OR'd.
"""

import logging
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional

from services.tanium import TaniumClient

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).resolve().parent.parent / "data" / "transient"
DB_PATH = DB_DIR / "tanium_software_inventory.sqlite3"

# Staleness threshold for the correlator's "fresh enough" check
DEFAULT_STALE_HOURS = 36

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS installed_software (
        host       TEXT NOT NULL,
        os         TEXT,
        source     TEXT NOT NULL,
        app        TEXT NOT NULL,
        app_lower  TEXT NOT NULL,
        version    TEXT,
        synced_at  REAL NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_installed_app_lower ON installed_software(app_lower)",
    "CREATE INDEX IF NOT EXISTS idx_installed_host ON installed_software(host)",
    """
    CREATE TABLE IF NOT EXISTS sync_meta (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at    REAL NOT NULL,
        finished_at   REAL,
        row_count     INTEGER,
        duration_sec  REAL,
        instances     TEXT,
        status        TEXT
    )
    """,
)


@contextmanager
def _conn():
    """Short-lived read/write connection with WAL mode."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init_db() -> None:
    with _conn() as c:
        for stmt in _SCHEMA_STATEMENTS:
            c.execute(stmt)


# ---- sync ------------------------------------------------------------------

def sync_inventory(tanium_client: Optional[TaniumClient] = None) -> dict:
    """Full-fleet Tanium installed-software sync into SQLite.

    Per-instance transactions: each successful instance is committed before
    the next starts, so a Cloud success isn't lost when On-Prem fails. The
    table is wiped per-instance (via DELETE WHERE source=?) so partial
    results from an earlier failed run on the same instance get cleaned up.
    Returns {row_count, duration_sec, instances, instance_results, status}.
    """
    init_db()
    started = time.time()
    client = tanium_client or TaniumClient()
    instance_names = [i.name for i in client.instances]
    if not client.instances:
        raise RuntimeError("No Tanium instances available — cannot sync inventory")

    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO sync_meta (started_at, instances, status) VALUES (?, ?, 'running')",
        (started, ",".join(instance_names)),
    )
    sync_id = cursor.lastrowid
    conn.commit()

    insert_sql = (
        "INSERT INTO installed_software "
        "(host, os, source, app, app_lower, version, synced_at) VALUES (?,?,?,?,?,?,?)"
    )
    BATCH_SIZE = 5000

    instance_results: dict = {}
    total_rows = 0
    failed: list = []

    try:
        for instance in client.instances:
            i_started = time.time()
            i_rows = 0
            batch: list = []
            now = time.time()
            try:
                cursor.execute("BEGIN")
                cursor.execute("DELETE FROM installed_software WHERE source = ?", (instance.name,))
                logger.info(f"[inventory sync] pulling from {instance.name}...")
                for row in instance.iter_installed_software():
                    batch.append((
                        row['host'], row['os'], row['source'],
                        row['app'], row['app'].lower(), row['version'], now,
                    ))
                    if len(batch) >= BATCH_SIZE:
                        cursor.executemany(insert_sql, batch)
                        i_rows += len(batch)
                        batch = []
                if batch:
                    cursor.executemany(insert_sql, batch)
                    i_rows += len(batch)
                conn.commit()
                total_rows += i_rows
                instance_results[instance.name] = {
                    "rows": i_rows, "duration_sec": time.time() - i_started, "status": "ok"
                }
                logger.info(
                    f"[inventory sync] {instance.name}: {i_rows} rows in "
                    f"{time.time() - i_started:.1f}s"
                )
            except Exception as inst_err:
                conn.rollback()
                failed.append((instance.name, inst_err))
                instance_results[instance.name] = {
                    "rows": 0,
                    "duration_sec": time.time() - i_started,
                    "status": "failed",
                    "error": f"{type(inst_err).__name__}: {inst_err}",
                }
                logger.error(f"[inventory sync] {instance.name} FAILED: {inst_err}")

        # Determine overall status: ok = all good; partial = some succeeded, some failed; failed = none succeeded
        ok_count = sum(1 for r in instance_results.values() if r["status"] == "ok")
        if ok_count == len(client.instances):
            overall = "ok"
        elif ok_count > 0:
            overall = "partial"
        else:
            overall = "failed"

        duration = time.time() - started
        cursor.execute(
            "UPDATE sync_meta SET finished_at=?, row_count=?, duration_sec=?, status=? WHERE id=?",
            (time.time(), total_rows, duration, overall, sync_id),
        )
        conn.commit()

        if failed:
            try:
                from src.components.cve_exposure.alerts import notify_dev_space
                fail_lines = "\n".join(f"- **{n}**: `{e}`" for n, e in failed)
                notify_dev_space(
                    "tanium_inventory_sync_partial",
                    f"Tanium inventory sync — {len(failed)} instance(s) failed",
                    f"Some instances failed; the cache holds whatever succeeded "
                    f"({ok_count}/{len(client.instances)} instances, {total_rows} rows).\n\n"
                    f"{fail_lines}",
                )
            except Exception as alert_err:
                logger.debug("alert suppressed: %s", alert_err)

        logger.info(
            f"[inventory sync] {overall.upper()}: {total_rows} rows total in {duration:.1f}s "
            f"({ok_count}/{len(client.instances)} instances)"
        )
        return {
            "row_count": total_rows,
            "duration_sec": duration,
            "instances": instance_names,
            "instance_results": instance_results,
            "status": overall,
        }
    finally:
        conn.close()


# ---- query -----------------------------------------------------------------

def find_software_matches(keywords: List[str]) -> List[dict]:
    """Return installed-software rows matching any keyword (case-insensitive substring).

    Each row: {host, os, source, app, version}. Empty list if no keywords given
    or cache is empty. Caller is responsible for checking cache freshness via
    get_sync_status() if that matters.
    """
    if not keywords:
        return []
    clean = [k.lower().strip() for k in keywords if k and k.strip()]
    if not clean:
        return []

    init_db()
    clauses = " OR ".join(["app_lower LIKE ?"] * len(clean))
    params = [f"%{k}%" for k in clean]
    with _conn() as c:
        rows = c.execute(
            f"SELECT host, os, source, app, version FROM installed_software WHERE {clauses}",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def get_sync_status() -> Optional[dict]:
    """Return the latest sync_meta row, or None if no sync has ever run."""
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT id, started_at, finished_at, row_count, duration_sec, instances, status "
            "FROM sync_meta ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


def is_cache_fresh(stale_hours: int = DEFAULT_STALE_HOURS) -> bool:
    """True if the last successful sync finished within `stale_hours`."""
    status = get_sync_status()
    if not status or status.get("status") != "ok" or not status.get("finished_at"):
        return False
    return (time.time() - status["finished_at"]) < stale_hours * 3600
