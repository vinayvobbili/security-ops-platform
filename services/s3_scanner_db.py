"""S3 Scanner Database.

SQLite database for persisting scan results, comparison diffs, and scan history.
Follows existing IR patterns: WAL mode, context manager, JSON serialization.
"""

import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).parent.parent / "data" / "s3_scanner"
DB_PATH = DB_DIR / "s3_scanner.db"

DB_DIR.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables and indexes if they don't exist."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS s3_scans (
                scan_id         TEXT PRIMARY KEY,
                timestamp       TEXT,
                total           INTEGER,
                "pass"          INTEGER,
                fail            INTEGER,
                error           INTEGER,
                info            INTEGER,
                buckets_scanned TEXT,
                ip_address      TEXT
            );

            CREATE TABLE IF NOT EXISTS s3_scan_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                target          TEXT,
                bucket          TEXT,
                check_name      TEXT,
                status          TEXT,
                detail          TEXT,
                http_status     INTEGER,
                evidence        TEXT,
                FOREIGN KEY (scan_id) REFERENCES s3_scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_s3_results_scan ON s3_scan_results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_s3_scans_ts ON s3_scans(timestamp);
        """)
    logger.info("S3 scanner database initialized")


def save_scan(report_dict: dict, ip_address: str = None) -> str:
    """Persist a full scan report to the database.

    Args:
        report_dict: Output from scan report with summary and results.
        ip_address: Client IP that initiated the scan.

    Returns:
        The generated scan_id.
    """
    scan_id = str(uuid.uuid4())
    summary = report_dict.get("summary", {})
    results = report_dict.get("results", [])

    # Extract unique bucket names from results
    buckets = sorted({r.get("bucket", "") for r in results if r.get("bucket")})

    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            'INSERT INTO s3_scans '
            '(scan_id, timestamp, total, "pass", fail, error, info, buckets_scanned, ip_address) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                scan_id,
                report_dict.get("timestamp"),
                summary.get("total", 0),
                summary.get("pass", 0),
                summary.get("fail", 0),
                summary.get("error", 0),
                summary.get("info", 0),
                json.dumps(buckets),
                ip_address,
            )
        )

        cursor.executemany(
            "INSERT INTO s3_scan_results "
            "(scan_id, target, bucket, check_name, status, detail, http_status, evidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    r.get("target"),
                    r.get("bucket"),
                    r.get("check") or r.get("check_name"),
                    r.get("status"),
                    r.get("detail"),
                    r.get("http_status"),
                    json.dumps(r.get("evidence")) if r.get("evidence") is not None else None,
                )
                for r in results
            ]
        )

    logger.info(f"Saved scan {scan_id}: {len(results)} results across {len(buckets)} buckets")
    return scan_id


def get_scan_history(limit: int = 50) -> list[dict]:
    """Get recent scan runs.

    Returns:
        List of scan metadata dicts, most recent first.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, timestamp, total, "pass", fail,
                   error, info, buckets_scanned, ip_address
            FROM s3_scans
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        return [
            {
                "scan_id": r["scan_id"],
                "timestamp": r["timestamp"],
                "total": r["total"],
                "pass_count": r["pass"],
                "fail": r["fail"],
                "error": r["error"],
                "info": r["info"],
                "buckets_scanned": json.loads(r["buckets_scanned"]) if r["buckets_scanned"] else [],
                "ip_address": r["ip_address"],
            }
            for r in rows
        ]


def get_scan(scan_id: str) -> dict | None:
    """Load a full scan report by ID.

    Reconstructs the dict shape:
        {timestamp, summary: {total, pass, fail, error, info}, results: [...]}

    Returns:
        Reconstructed report dict, or None if scan_id not found.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT scan_id, timestamp, total, "pass", fail,
                   error, info, buckets_scanned
            FROM s3_scans
            WHERE scan_id = ?
        """, (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            return None

        cursor.execute("""
            SELECT target, bucket, check_name, status, detail, http_status, evidence
            FROM s3_scan_results
            WHERE scan_id = ?
        """, (scan_id,))
        result_rows = cursor.fetchall()

        results = []
        for r in result_rows:
            entry = {
                "target": r["target"],
                "bucket": r["bucket"],
                "check": r["check_name"],
                "status": r["status"],
                "detail": r["detail"],
                "http_status": r["http_status"],
                "evidence": json.loads(r["evidence"]) if r["evidence"] else None,
            }
            results.append(entry)

        return {
            "timestamp": scan_row["timestamp"],
            "summary": {
                "total": scan_row["total"],
                "pass": scan_row["pass"],
                "fail": scan_row["fail"],
                "error": scan_row["error"],
                "info": scan_row["info"],
            },
            "results": results,
        }


def get_scan_diff(scan_id_a: str, scan_id_b: str) -> dict:
    """Compare two scans and return new failures, resolved issues, and unchanged count.

    Args:
        scan_id_a: The older (baseline) scan ID.
        scan_id_b: The newer scan ID.

    Returns:
        Dict with new_failures, resolved, unchanged_count, scan_a metadata, scan_b metadata.
    """
    def _load_results(conn, scan_id):
        cursor = conn.cursor()
        cursor.execute("""
            SELECT target, bucket, check_name, status, detail
            FROM s3_scan_results
            WHERE scan_id = ?
        """, (scan_id,))
        rows = cursor.fetchall()
        keyed = {}
        for r in rows:
            key = f"{r['target']}|{r['bucket']}|{r['check_name']}"
            keyed[key] = {
                "target": r["target"],
                "bucket": r["bucket"],
                "check_name": r["check_name"],
                "status": r["status"],
                "detail": r["detail"],
            }
        return keyed

    def _load_scan_meta(conn, scan_id):
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, timestamp, total, "pass", fail,
                   error, info
            FROM s3_scans
            WHERE scan_id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "scan_id": row["scan_id"],
            "timestamp": row["timestamp"],
            "total": row["total"],
            "pass_count": row["pass"],
            "fail": row["fail"],
            "error": row["error"],
            "info": row["info"],
        }

    with get_connection() as conn:
        results_a = _load_results(conn, scan_id_a)
        results_b = _load_results(conn, scan_id_b)
        meta_a = _load_scan_meta(conn, scan_id_a)
        meta_b = _load_scan_meta(conn, scan_id_b)

    fail_statuses = {"fail", "error"}
    all_keys = set(results_a.keys()) | set(results_b.keys())

    new_failures = []
    resolved = []
    unchanged_count = 0

    for key in sorted(all_keys):
        entry_a = results_a.get(key)
        entry_b = results_b.get(key)

        status_a = entry_a["status"] if entry_a else None
        status_b = entry_b["status"] if entry_b else None

        # Determine the reference entry for target/bucket/check_name
        ref = entry_b or entry_a

        if status_a == status_b:
            unchanged_count += 1
            continue

        was_failing = status_a in fail_statuses if status_a else False
        now_failing = status_b in fail_statuses if status_b else False

        if now_failing and not was_failing:
            new_failures.append({
                "target": ref["target"],
                "bucket": ref["bucket"],
                "check_name": ref["check_name"],
                "old_status": status_a,
                "new_status": status_b,
                "old_detail": entry_a["detail"] if entry_a else None,
                "new_detail": entry_b["detail"] if entry_b else None,
            })
        elif was_failing and not now_failing:
            resolved.append({
                "target": ref["target"],
                "bucket": ref["bucket"],
                "check_name": ref["check_name"],
                "old_status": status_a,
                "new_status": status_b,
                "old_detail": entry_a["detail"] if entry_a else None,
                "new_detail": entry_b["detail"] if entry_b else None,
            })
        else:
            # Status changed but not a failure transition (e.g. pass -> info)
            unchanged_count += 1

    return {
        "new_failures": new_failures,
        "resolved": resolved,
        "unchanged_count": unchanged_count,
        "scan_a": meta_a,
        "scan_b": meta_b,
    }


def get_bucket_object_counts(buckets: list[str]) -> dict[str, dict]:
    """Get the latest deep-scan object counts for given bucket names.

    Looks up the most recent 'Object Enumeration' result for each bucket
    and extracts the object_count from its evidence JSON.

    Returns:
        {bucket_name: {"object_count": N, "total_size_human": "...", "scan_id": "...", "timestamp": "..."}}
    """
    if not buckets:
        return {}

    placeholders = ",".join("?" for _ in buckets)
    with get_connection() as conn:
        cursor = conn.cursor()
        # For each bucket, get the most recent Object Enumeration result
        cursor.execute(f"""
            SELECT r.bucket, r.evidence, r.scan_id, s.timestamp
            FROM s3_scan_results r
            JOIN s3_scans s ON s.scan_id = r.scan_id
            WHERE r.bucket IN ({placeholders})
              AND r.check_name = 'Object Enumeration'
              AND r.evidence IS NOT NULL
            ORDER BY s.timestamp DESC
        """, buckets)

        result = {}
        for row in cursor.fetchall():
            b = row["bucket"]
            if b in result:
                continue  # already have the latest
            try:
                ev = json.loads(row["evidence"])
                result[b] = {
                    "object_count": ev.get("object_count", 0),
                    "total_size_human": ev.get("total_size_human", ""),
                    "scan_id": row["scan_id"],
                    "timestamp": row["timestamp"],
                }
            except (json.JSONDecodeError, TypeError):
                pass
        return result


# Initialize DB on import
init_db()
