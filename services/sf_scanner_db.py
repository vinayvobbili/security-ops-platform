"""Salesforce Scanner Database.

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

DB_DIR = Path(__file__).parent.parent / "data" / "salesforce_scanner"
DB_PATH = DB_DIR / "sf_scanner.db"

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
            CREATE TABLE IF NOT EXISTS sf_scans (
                scan_id         TEXT PRIMARY KEY,
                timestamp       TEXT,
                dual_vantage    INTEGER DEFAULT 0,
                total           INTEGER,
                "pass"          INTEGER,
                fail            INTEGER,
                error           INTEGER,
                info            INTEGER,
                unreachable     INTEGER,
                sites_scanned   TEXT,
                ip_address      TEXT
            );

            CREATE TABLE IF NOT EXISTS sf_scan_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                site            TEXT,
                base_url        TEXT,
                check_name      TEXT,
                status          TEXT,
                detail          TEXT,
                http_status     INTEGER,
                sample_records  TEXT,
                pii_fields      TEXT,
                vantage         TEXT,
                field_inventory TEXT,
                FOREIGN KEY (scan_id) REFERENCES sf_scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_sf_results_scan ON sf_scan_results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_sf_scans_ts ON sf_scans(timestamp);
        """)
        # Migration: add ip_address column if missing
        cursor = conn.execute("PRAGMA table_info(sf_scans)")
        columns = {row["name"] for row in cursor.fetchall()}
        if "ip_address" not in columns:
            conn.execute("ALTER TABLE sf_scans ADD COLUMN ip_address TEXT")
    logger.info("Salesforce scanner database initialized")


def save_scan(report_dict: dict, dual_vantage: bool = False, ip_address: str = None) -> str:
    """Persist a full scan report to the database.

    Args:
        report_dict: Output from ScanReport.to_dict() with summary and results.
        dual_vantage: Whether the scan was run from two vantage points.
        ip_address: Client IP that initiated the scan.

    Returns:
        The generated scan_id.
    """
    scan_id = str(uuid.uuid4())
    summary = report_dict.get("summary", {})
    results = report_dict.get("results", [])

    # Extract unique site keys from results
    sites = sorted({r.get("site", "") for r in results if r.get("site")})

    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            'INSERT INTO sf_scans '
            '(scan_id, timestamp, dual_vantage, total, "pass", fail, error, info, unreachable, sites_scanned, ip_address) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                scan_id,
                report_dict.get("timestamp"),
                int(dual_vantage),
                summary.get("total", 0),
                summary.get("pass", 0),
                summary.get("fail", 0),
                summary.get("error", 0),
                summary.get("info", 0),
                summary.get("unreachable", 0),
                json.dumps(sites),
                ip_address,
            )
        )

        cursor.executemany(
            "INSERT INTO sf_scan_results "
            "(scan_id, site, base_url, check_name, status, detail, http_status, "
            "sample_records, pii_fields, vantage, field_inventory) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    r.get("site"),
                    r.get("base_url"),
                    r.get("check") or r.get("check_name"),
                    r.get("status"),
                    r.get("detail"),
                    r.get("http_status"),
                    json.dumps(r.get("sample_records")) if r.get("sample_records") is not None else None,
                    json.dumps(r.get("pii_fields")) if r.get("pii_fields") is not None else None,
                    r.get("vantage"),
                    json.dumps(r.get("field_inventory")) if r.get("field_inventory") is not None else None,
                )
                for r in results
            ]
        )

    logger.info(f"Saved scan {scan_id}: {len(results)} results across {len(sites)} sites")
    return scan_id


def get_scan_history(limit: int = 50) -> list[dict]:
    """Get recent scan runs.

    Returns:
        List of scan metadata dicts, most recent first.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, timestamp, dual_vantage, total, "pass", fail,
                   error, info, unreachable, sites_scanned, ip_address
            FROM sf_scans
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        return [
            {
                "scan_id": r["scan_id"],
                "timestamp": r["timestamp"],
                "dual_vantage": bool(r["dual_vantage"]),
                "total": r["total"],
                "pass_count": r["pass"],
                "fail": r["fail"],
                "error": r["error"],
                "info": r["info"],
                "unreachable": r["unreachable"],
                "sites_scanned": json.loads(r["sites_scanned"]) if r["sites_scanned"] else [],
                "ip_address": r["ip_address"],
            }
            for r in rows
        ]


def get_scan(scan_id: str) -> dict | None:
    """Load a full scan report by ID.

    Reconstructs the dict shape matching ScanReport.to_dict():
        {timestamp, summary: {total, pass, fail, error, info, unreachable}, results: [...]}

    Returns:
        Reconstructed report dict, or None if scan_id not found.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT scan_id, timestamp, dual_vantage, total, "pass", fail,
                   error, info, unreachable, sites_scanned
            FROM sf_scans
            WHERE scan_id = ?
        """, (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            return None

        cursor.execute("""
            SELECT site, base_url, check_name, status, detail, http_status,
                   sample_records, pii_fields, vantage, field_inventory
            FROM sf_scan_results
            WHERE scan_id = ?
        """, (scan_id,))
        result_rows = cursor.fetchall()

        results = []
        for r in result_rows:
            entry = {
                "site": r["site"],
                "base_url": r["base_url"],
                "check": r["check_name"],
                "status": r["status"],
                "detail": r["detail"],
                "http_status": r["http_status"],
                "sample_records": json.loads(r["sample_records"]) if r["sample_records"] else None,
                "pii_fields": json.loads(r["pii_fields"]) if r["pii_fields"] else None,
                "vantage": r["vantage"],
                "field_inventory": json.loads(r["field_inventory"]) if r["field_inventory"] else None,
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
                "unreachable": scan_row["unreachable"],
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
            SELECT site, base_url, check_name, status, detail, vantage
            FROM sf_scan_results
            WHERE scan_id = ?
        """, (scan_id,))
        rows = cursor.fetchall()
        keyed = {}
        for r in rows:
            key = f"{r['site']}|{r['base_url']}|{r['check_name']}|{r['vantage'] or ''}"
            keyed[key] = {
                "site": r["site"],
                "base_url": r["base_url"],
                "check_name": r["check_name"],
                "vantage": r["vantage"],
                "status": r["status"],
                "detail": r["detail"],
            }
        return keyed

    def _load_scan_meta(conn, scan_id):
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, timestamp, dual_vantage, total, "pass", fail,
                   error, info, unreachable
            FROM sf_scans
            WHERE scan_id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "scan_id": row["scan_id"],
            "timestamp": row["timestamp"],
            "dual_vantage": bool(row["dual_vantage"]),
            "total": row["total"],
            "pass_count": row["pass"],
            "fail": row["fail"],
            "error": row["error"],
            "info": row["info"],
            "unreachable": row["unreachable"],
        }

    with get_connection() as conn:
        results_a = _load_results(conn, scan_id_a)
        results_b = _load_results(conn, scan_id_b)
        meta_a = _load_scan_meta(conn, scan_id_a)
        meta_b = _load_scan_meta(conn, scan_id_b)

    fail_statuses = {"fail", "error", "unreachable"}
    all_keys = set(results_a.keys()) | set(results_b.keys())

    new_failures = []
    resolved = []
    unchanged_count = 0

    for key in sorted(all_keys):
        entry_a = results_a.get(key)
        entry_b = results_b.get(key)

        status_a = entry_a["status"] if entry_a else None
        status_b = entry_b["status"] if entry_b else None

        # Determine the reference entry for site/base_url/check_name/vantage
        ref = entry_b or entry_a

        if status_a == status_b:
            unchanged_count += 1
            continue

        was_failing = status_a in fail_statuses if status_a else False
        now_failing = status_b in fail_statuses if status_b else False

        if now_failing and not was_failing:
            new_failures.append({
                "site": ref["site"],
                "base_url": ref["base_url"],
                "check_name": ref["check_name"],
                "vantage": ref["vantage"],
                "old_status": status_a,
                "new_status": status_b,
                "old_detail": entry_a["detail"] if entry_a else None,
                "new_detail": entry_b["detail"] if entry_b else None,
            })
        elif was_failing and not now_failing:
            resolved.append({
                "site": ref["site"],
                "base_url": ref["base_url"],
                "check_name": ref["check_name"],
                "vantage": ref["vantage"],
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


# Initialize DB on import
init_db()
