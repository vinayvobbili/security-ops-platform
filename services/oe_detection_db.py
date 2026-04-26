"""OE Detection Database.

SQLite database for persisting scan results, risk scores, signals, and alerts.
Follows existing IR patterns: WAL mode, context manager, _date_filter_sql.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).parent.parent / "data" / "oe_detection"
DB_PATH = DB_DIR / "oe_detection.db"

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
            CREATE TABLE IF NOT EXISTS oe_scans (
                scan_id         TEXT PRIMARY KEY,
                started_at      TEXT NOT NULL,
                completed_at    TEXT,
                employee_count  INTEGER DEFAULT 0,
                dry_run         INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS oe_signals (
                signal_id       TEXT PRIMARY KEY,
                scan_id         TEXT NOT NULL,
                employee_id     TEXT NOT NULL,
                rule_id         TEXT NOT NULL,
                domain          TEXT NOT NULL,
                weight          INTEGER DEFAULT 0,
                description     TEXT,
                evidence        TEXT,
                timestamp       TEXT,
                source_tool     TEXT,
                FOREIGN KEY (scan_id) REFERENCES oe_scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS oe_scores (
                score_id            TEXT PRIMARY KEY,
                scan_id             TEXT NOT NULL,
                employee_id         TEXT NOT NULL,
                employee_name       TEXT,
                raw_score           REAL DEFAULT 0,
                normalized_score    REAL DEFAULT 0,
                risk_level          TEXT DEFAULT 'low',
                domains_hit         TEXT,
                correlation_multiplier REAL DEFAULT 1.0,
                narrative           TEXT,
                calculated_at       TEXT,
                FOREIGN KEY (scan_id) REFERENCES oe_scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS oe_alerts (
                alert_id        TEXT PRIMARY KEY,
                score_id        TEXT NOT NULL,
                dispatched_to   TEXT,
                dispatched_at   TEXT,
                FOREIGN KEY (score_id) REFERENCES oe_scores(score_id)
            );

            CREATE INDEX IF NOT EXISTS idx_oe_scores_scan ON oe_scores(scan_id);
            CREATE INDEX IF NOT EXISTS idx_oe_scores_employee ON oe_scores(employee_id);
            CREATE INDEX IF NOT EXISTS idx_oe_scores_calculated ON oe_scores(calculated_at);
            CREATE INDEX IF NOT EXISTS idx_oe_signals_scan ON oe_signals(scan_id);
            CREATE INDEX IF NOT EXISTS idx_oe_signals_employee ON oe_signals(employee_id);
            CREATE INDEX IF NOT EXISTS idx_oe_scans_started ON oe_scans(started_at);
        """)
    logger.info("OE detection database initialized")


def _date_filter_sql(alias, start_date, end_date):
    """Build date filter SQL fragments and params."""
    prefix = f"{alias}." if alias else ""
    sql = ""
    params = []
    if start_date:
        sql += f" AND {prefix}calculated_at >= ?"
        params.append(start_date)
    if end_date:
        sql += f" AND {prefix}calculated_at <= ?"
        params.append(end_date + "T23:59:59")
    return sql, params


def save_scan_result(scan_id: str, started_at: datetime, scores: list, dry_run: bool) -> None:
    """Bulk insert results from a scan run.

    Args:
        scan_id: Unique scan identifier
        started_at: When the scan started
        scores: List of RiskScore objects
        dry_run: Whether this was a dry run
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Insert scan metadata
        cursor.execute(
            "INSERT OR REPLACE INTO oe_scans (scan_id, started_at, completed_at, employee_count, dry_run) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, started_at.isoformat(), datetime.utcnow().isoformat(), len(scores), int(dry_run))
        )

        for score in scores:
            # Insert score
            cursor.execute(
                "INSERT OR REPLACE INTO oe_scores "
                "(score_id, scan_id, employee_id, employee_name, raw_score, normalized_score, "
                "risk_level, domains_hit, correlation_multiplier, narrative, calculated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    score.score_id, scan_id, score.employee_id, score.employee_name,
                    score.raw_score, score.normalized_score, score.risk_level.value,
                    json.dumps(list(score.domains_hit)), score.correlation_multiplier,
                    score.narrative, score.calculated_at.isoformat()
                )
            )

            # Insert signals
            for signal in score.signals:
                cursor.execute(
                    "INSERT OR REPLACE INTO oe_signals "
                    "(signal_id, scan_id, employee_id, rule_id, domain, weight, "
                    "description, evidence, timestamp, source_tool) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        signal.signal_id, scan_id, signal.employee_id, signal.rule_id,
                        signal.domain.value, signal.weight, signal.description,
                        json.dumps(signal.evidence), signal.timestamp.isoformat(),
                        signal.source_tool
                    )
                )

    logger.info(f"Saved scan {scan_id}: {len(scores)} scores")


def get_latest_scores(start_date=None, end_date=None) -> list[dict]:
    """Get the latest score per employee within date range.

    Returns list of dicts with employee scores, sorted by normalized_score desc.
    """
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        date_sql, date_params = _date_filter_sql("s", start_date, end_date)

        cursor.execute(f"""
            SELECT s.score_id, s.scan_id, s.employee_id, s.employee_name,
                   s.raw_score, s.normalized_score, s.risk_level,
                   s.domains_hit, s.correlation_multiplier, s.narrative,
                   s.calculated_at,
                   (SELECT COUNT(*) FROM oe_signals g
                    WHERE g.scan_id = s.scan_id AND g.employee_id = s.employee_id) as signal_count
            FROM oe_scores s
            INNER JOIN (
                SELECT employee_id, MAX(calculated_at) as max_calc
                FROM oe_scores
                WHERE 1=1 {date_sql}
                GROUP BY employee_id
            ) latest ON s.employee_id = latest.employee_id AND s.calculated_at = latest.max_calc
            WHERE 1=1 {date_sql}
            ORDER BY s.normalized_score DESC
        """, date_params + date_params)

        rows = cursor.fetchall()
        return [
            {
                "score_id": r["score_id"],
                "scan_id": r["scan_id"],
                "employee_id": r["employee_id"],
                "employee_name": r["employee_name"],
                "raw_score": r["raw_score"],
                "normalized_score": r["normalized_score"],
                "risk_level": r["risk_level"],
                "domains_hit": json.loads(r["domains_hit"]) if r["domains_hit"] else [],
                "correlation_multiplier": r["correlation_multiplier"],
                "narrative": r["narrative"],
                "calculated_at": r["calculated_at"],
                "signal_count": r["signal_count"],
            }
            for r in rows
        ]


def get_employee_history(employee_id: str) -> list[dict]:
    """Get score trend over time for an employee."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.score_id, s.scan_id, s.normalized_score, s.risk_level,
                   s.domains_hit, s.correlation_multiplier, s.narrative, s.calculated_at,
                   (SELECT COUNT(*) FROM oe_signals g
                    WHERE g.scan_id = s.scan_id AND g.employee_id = s.employee_id) as signal_count
            FROM oe_scores s
            WHERE s.employee_id = ?
            ORDER BY s.calculated_at DESC
            LIMIT 50
        """, (employee_id,))

        rows = cursor.fetchall()
        return [
            {
                "score_id": r["score_id"],
                "scan_id": r["scan_id"],
                "normalized_score": r["normalized_score"],
                "risk_level": r["risk_level"],
                "domains_hit": json.loads(r["domains_hit"]) if r["domains_hit"] else [],
                "correlation_multiplier": r["correlation_multiplier"],
                "narrative": r["narrative"],
                "calculated_at": r["calculated_at"],
                "signal_count": r["signal_count"],
            }
            for r in rows
        ]


def get_signal_details(score_id: str) -> list[dict]:
    """Get all signals for a specific score."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()

        # Get scan_id and employee_id from the score
        cursor.execute(
            "SELECT scan_id, employee_id FROM oe_scores WHERE score_id = ?",
            (score_id,)
        )
        score_row = cursor.fetchone()
        if not score_row:
            return []

        cursor.execute("""
            SELECT signal_id, rule_id, domain, weight, description,
                   evidence, timestamp, source_tool
            FROM oe_signals
            WHERE scan_id = ? AND employee_id = ?
            ORDER BY weight DESC
        """, (score_row["scan_id"], score_row["employee_id"]))

        rows = cursor.fetchall()
        return [
            {
                "signal_id": r["signal_id"],
                "rule_id": r["rule_id"],
                "domain": r["domain"],
                "weight": r["weight"],
                "description": r["description"],
                "evidence": json.loads(r["evidence"]) if r["evidence"] else {},
                "timestamp": r["timestamp"],
                "source_tool": r["source_tool"],
            }
            for r in rows
        ]


def get_scan_history(limit: int = 20) -> list[dict]:
    """Get recent scan runs."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, started_at, completed_at, employee_count, dry_run
            FROM oe_scans
            ORDER BY started_at DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        return [
            {
                "scan_id": r["scan_id"],
                "started_at": r["started_at"],
                "completed_at": r["completed_at"],
                "employee_count": r["employee_count"],
                "dry_run": bool(r["dry_run"]),
            }
            for r in rows
        ]


def get_summary_stats(start_date=None, end_date=None) -> dict:
    """Get card-level aggregates for the dashboard."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        date_sql, date_params = _date_filter_sql("s", start_date, end_date)

        # Total unique employees scanned
        cursor.execute(f"""
            SELECT COUNT(DISTINCT s.employee_id) as total
            FROM oe_scores s WHERE 1=1 {date_sql}
        """, date_params)
        total_scanned = cursor.fetchone()["total"]

        # Risk level distribution (latest score per employee)
        cursor.execute(f"""
            SELECT s.risk_level, COUNT(*) as cnt
            FROM oe_scores s
            INNER JOIN (
                SELECT employee_id, MAX(calculated_at) as max_calc
                FROM oe_scores
                WHERE 1=1 {date_sql}
                GROUP BY employee_id
            ) latest ON s.employee_id = latest.employee_id AND s.calculated_at = latest.max_calc
            WHERE 1=1 {date_sql}
            GROUP BY s.risk_level
        """, date_params + date_params)
        risk_distribution = {r["risk_level"]: r["cnt"] for r in cursor.fetchall()}

        # Last scan timestamp
        cursor.execute("SELECT MAX(completed_at) as last_scan FROM oe_scans")
        row = cursor.fetchone()
        last_scan = row["last_scan"] if row else None

        # Active rules count (from latest scan signals)
        cursor.execute(f"""
            SELECT COUNT(DISTINCT g.rule_id) as rule_count
            FROM oe_signals g
            INNER JOIN oe_scans sc ON g.scan_id = sc.scan_id
            WHERE sc.scan_id = (SELECT scan_id FROM oe_scans ORDER BY started_at DESC LIMIT 1)
        """)
        row = cursor.fetchone()
        active_rules = row["rule_count"] if row else 0

        # Top domains hit
        cursor.execute(f"""
            SELECT g.domain, COUNT(*) as cnt
            FROM oe_signals g
            INNER JOIN oe_scores s ON g.scan_id = s.scan_id AND g.employee_id = s.employee_id
            INNER JOIN (
                SELECT employee_id, MAX(calculated_at) as max_calc
                FROM oe_scores
                WHERE 1=1 {date_sql}
                GROUP BY employee_id
            ) latest ON s.employee_id = latest.employee_id AND s.calculated_at = latest.max_calc
            WHERE 1=1 {date_sql}
            GROUP BY g.domain
            ORDER BY cnt DESC
        """, date_params + date_params)
        top_domains = {r["domain"]: r["cnt"] for r in cursor.fetchall()}

        # Total scans
        cursor.execute("SELECT COUNT(*) as cnt FROM oe_scans")
        total_scans = cursor.fetchone()["cnt"]

        return {
            "total_scanned": total_scanned,
            "risk_distribution": risk_distribution,
            "last_scan": last_scan,
            "active_rules": active_rules,
            "top_domains": top_domains,
            "total_scans": total_scans,
        }


# Initialize DB on import
init_db()
