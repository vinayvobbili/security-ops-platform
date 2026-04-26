"""
XSOAR Ticket Timeline Database

SQLite-backed storage for historical XSOAR ticket data, powering
the animated bar chart race on the meaningful-metrics page.
"""

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent / 'data' / 'xsoar_timeline' / 'xsoar_timeline.db'

SEVERITY_DISPLAY = {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}


def get_db_path() -> Path:
    return DB_PATH


@contextmanager
def get_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
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
    """Initialize database schema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS xsoar_tickets (
                id TEXT PRIMARY KEY,
                name TEXT,
                created_date TEXT NOT NULL,
                closed_date TEXT,
                occurred_date TEXT,
                modified_date TEXT,
                severity INTEGER,
                severity_display TEXT,
                security_category TEXT,
                category_short TEXT,
                affected_region TEXT,
                affected_country TEXT,
                status INTEGER,
                type TEXT,
                owner TEXT,
                close_reason TEXT,
                close_notes TEXT,
                closing_user TEXT,
                impact TEXT,
                detection_source TEXT,
                source_brand TEXT,
                source_instance TEXT,
                hostname TEXT,
                username TEXT,
                email TEXT,
                automation_level TEXT,
                escalation_state TEXT,
                details TEXT,
                user_notes TEXT,
                phase TEXT,
                open_duration INTEGER,
                resolution_time_hours REAL,
                raw_json TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Migration: add columns if missing (for existing DBs)
        cursor.execute("PRAGMA table_info(xsoar_tickets)")
        existing_cols = {r['name'] for r in cursor.fetchall()}

        new_columns = {
            'name': 'TEXT',
            'occurred_date': 'TEXT',
            'modified_date': 'TEXT',
            'owner': 'TEXT',
            'close_reason': 'TEXT',
            'close_notes': 'TEXT',
            'closing_user': 'TEXT',
            'impact': 'TEXT',
            'detection_source': 'TEXT',
            'source_brand': 'TEXT',
            'source_instance': 'TEXT',
            'hostname': 'TEXT',
            'username': 'TEXT',
            'email': 'TEXT',
            'automation_level': 'TEXT',
            'details': 'TEXT',
            'user_notes': 'TEXT',
            'escalation_state': 'TEXT',
            'phase': 'TEXT',
            'open_duration': 'INTEGER',
            'raw_json': 'TEXT',
        }
        for col_name, col_type in new_columns.items():
            if col_name not in existing_cols:
                cursor.execute(f"ALTER TABLE xsoar_tickets ADD COLUMN {col_name} {col_type}")

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_created_date ON xsoar_tickets(created_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_severity ON xsoar_tickets(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_security_category ON xsoar_tickets(security_category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_affected_region ON xsoar_tickets(affected_region)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_type ON xsoar_tickets(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_status ON xsoar_tickets(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_owner ON xsoar_tickets(owner)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_detection_source ON xsoar_tickets(detection_source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_xt_impact ON xsoar_tickets(impact)")

        # One-time data migrations
        _migrate_normalize_data(conn)
        _migrate_backfill_details(conn)


def _migrate_normalize_data(conn):
    """Normalize dirty data in existing records (idempotent)."""
    cursor = conn.cursor()

    # Check if migration already ran
    cursor.execute("SELECT value FROM sync_metadata WHERE key = 'data_normalized_v1'")
    if cursor.fetchone():
        return

    logger.info("Running data normalization migration...")

    # --- Category: strip Cat-N / CAT-N prefixes, empty → Unknown ---
    cursor.execute("UPDATE xsoar_tickets SET category_short = 'Unknown' WHERE category_short IS NULL OR TRIM(category_short) = ''")
    # Cat-7 Investigation → Investigation, CAT-4 Inappropriate Usage → Inappropriate Usage, etc.
    cursor.execute("""
        UPDATE xsoar_tickets
        SET category_short = TRIM(SUBSTR(category_short, INSTR(category_short, ' ') + 1))
        WHERE LOWER(category_short) GLOB 'cat[-][0-9]*'
    """)

    # --- Region: normalize case and junk values ---
    region_updates = {
        'GLOBAL': 'Global', 'Global': 'Global',
        'AMERICAS': 'Americas',
        'ASIA': 'APAC',
        'Not Found': 'Unknown', 'Select': 'Unknown',
    }
    for old, new in region_updates.items():
        cursor.execute("UPDATE xsoar_tickets SET affected_region = ? WHERE affected_region = ?", (new, old))
    # Empty / whitespace-only / newlines → Unknown
    cursor.execute("UPDATE xsoar_tickets SET affected_region = 'Unknown' WHERE affected_region IS NULL OR TRIM(affected_region) = ''")
    # Catch any remaining non-canonical values (newlines, typos, etc.)
    cursor.execute("""
        UPDATE xsoar_tickets SET affected_region = 'Unknown'
        WHERE affected_region NOT IN ('Global', 'Americas', 'APAC', 'EMEA', 'LATAM', 'Unknown')
    """)

    # --- Impact: case normalization, empty → Unknown ---
    impact_updates = {
        'ignore': 'Ignore', 'confirmed': 'Confirmed',
    }
    for old, new in impact_updates.items():
        cursor.execute("UPDATE xsoar_tickets SET impact = ? WHERE impact = ?", (new, old))
    cursor.execute("UPDATE xsoar_tickets SET impact = 'Unknown' WHERE impact IS NULL OR TRIM(impact) = ''")

    # Mark migration as done
    cursor.execute("INSERT OR REPLACE INTO sync_metadata (key, value) VALUES ('data_normalized_v1', 'done')")
    logger.info("Data normalization migration complete.")


def _migrate_backfill_details(conn):
    """Backfill the details column from raw_json for existing rows (idempotent)."""
    import json

    cursor = conn.cursor()

    cursor.execute("SELECT value FROM sync_metadata WHERE key = 'details_backfill_v1'")
    if cursor.fetchone():
        return

    logger.info("Backfilling details column from raw_json...")

    rows = cursor.execute(
        "SELECT id, raw_json FROM xsoar_tickets WHERE raw_json IS NOT NULL AND raw_json != ''"
    ).fetchall()

    updated = 0
    for row in rows:
        try:
            raw_dict = json.loads(row['raw_json'])
            details = (raw_dict.get('details') or '').strip()
            if details:
                cursor.execute("UPDATE xsoar_tickets SET details = ? WHERE id = ?", (details, row['id']))
                updated += 1
        except (ValueError, TypeError):
            continue

    cursor.execute("INSERT OR REPLACE INTO sync_metadata (key, value) VALUES ('details_backfill_v1', 'done')")
    logger.info(f"Details backfill complete: {updated}/{len(rows)} rows populated.")


def _shorten_category(full_cat: str) -> str:
    """Extract the short name from a security category.

    'CAT-5: Scans/Probes/Attempted Access' → 'Scans/Probes/Attempted Access'
    'Cat-7 Investigation' → 'Investigation'
    """
    if not full_cat:
        return ''
    if ':' in full_cat:
        return full_cat.split(':', 1)[1].strip()
    # Strip Cat-N / CAT-N prefix (no colon variant)
    import re
    stripped = re.sub(r'^[Cc][Aa][Tt]-?\d+\s+', '', full_cat).strip()
    return stripped or full_cat


def _normalize_category(cat_short: str) -> str:
    """Normalize category_short to a canonical form."""
    if not cat_short or not cat_short.strip():
        return 'Unknown'
    return cat_short.strip()


_REGION_MAP = {
    'global': 'Global',
    'americas': 'Americas',
    'apac': 'APAC',
    'emea': 'EMEA',
    'latam': 'LATAM',
    'asia': 'APAC',
    'not found': 'Unknown',
    'select': 'Unknown',
    'unknown': 'Unknown',
    '': 'Unknown',
}


def _normalize_region(region: str) -> str:
    """Normalize affected_region to canonical values."""
    if not region:
        return 'Unknown'
    cleaned = region.strip()
    if not cleaned:
        return 'Unknown'
    return _REGION_MAP.get(cleaned.lower(), cleaned)


_IMPACT_MAP = {
    'ignore': 'Ignore',
    'confirmed': 'Confirmed',
    'benign true positive': 'Benign True Positive',
    'true positive': 'True Positive',
    'false positive': 'False Positive',
    'malicious true positive': 'Malicious True Positive',
    'prevented': 'Prevented',
    'testing': 'Testing',
    'security testing': 'Security Testing',
    'automated': 'Automated',
    'detected': 'Detected',
    'resolved': 'Resolved',
    'significant': 'Significant',
    'qa': 'QA',
}


def _normalize_impact(impact: str) -> str:
    """Normalize impact to canonical title-case values."""
    if not impact or not impact.strip():
        return 'Unknown'
    cleaned = impact.strip()
    return _IMPACT_MAP.get(cleaned.lower(), cleaned)


def _normalize_date(raw):
    """Normalize date to ISO-like YYYY-MM-DDTHH:MM:SS string."""
    if not raw:
        return None
    from datetime import datetime as dt_cls, timezone as tz_cls
    if isinstance(raw, dt_cls):
        return raw.strftime('%Y-%m-%dT%H:%M:%S')
    if isinstance(raw, str):
        return raw[:19] if len(raw) > 19 else raw
    if isinstance(raw, (int, float)) and raw > 0:
        ts = raw / 1000 if raw > 10 ** 10 else raw
        return dt_cls.fromtimestamp(ts, tz=tz_cls.utc).strftime('%Y-%m-%dT%H:%M:%S')
    return None


def _parse_datetime(raw):
    """Parse raw date value to a datetime object."""
    if not raw:
        return None
    from datetime import datetime, timezone
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        return datetime.fromisoformat(raw.replace('Z', '+00:00'))
    if isinstance(raw, (int, float)) and raw > 0:
        ts = raw / 1000 if raw > 10 ** 10 else raw
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    return None


def upsert_ticket(conn, ticket_dict: dict):
    """INSERT OR REPLACE a ticket from a raw XSOAR incident dict."""
    custom = ticket_dict.get('CustomFields') or {}
    ticket_id = str(ticket_dict.get('id', ''))
    created = ticket_dict.get('created', '')
    closed = ticket_dict.get('closed', '')

    normalized_created = _normalize_date(created)
    if not normalized_created:
        return  # Skip tickets with no valid created date

    severity = ticket_dict.get('severity', 0)
    sev_display = SEVERITY_DISPLAY.get(severity, 'Unknown')
    sec_cat = custom.get('securitycategory', '')
    cat_short = _normalize_category(_shorten_category(sec_cat))

    # Calculate resolution time in hours
    resolution_hours = None
    if closed and created:
        try:
            dt_created = _parse_datetime(created)
            dt_closed = _parse_datetime(closed)
            if dt_created and dt_closed:
                delta = (dt_closed - dt_created).total_seconds()
                if delta > 0:
                    resolution_hours = round(delta / 3600, 2)
        except Exception:
            pass

    # Serialize raw XSOAR response for archival
    import json
    try:
        raw_json = json.dumps(ticket_dict, default=str)
    except Exception:
        raw_json = None

    conn.execute("""
        INSERT OR REPLACE INTO xsoar_tickets
        (id, name, created_date, closed_date, occurred_date, modified_date,
         severity, severity_display, security_category, category_short,
         affected_region, affected_country, status, type, owner,
         close_reason, close_notes, closing_user,
         impact, detection_source, source_brand, source_instance,
         hostname, username, email, automation_level,
         details, escalation_state, phase, open_duration, resolution_time_hours,
         raw_json)
        VALUES (?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?)
    """, (
        ticket_id,
        (ticket_dict.get('name') or '').strip(),
        normalized_created,
        _normalize_date(closed),
        _normalize_date(ticket_dict.get('occurred')),
        _normalize_date(ticket_dict.get('modified')),
        severity,
        sev_display,
        sec_cat,
        cat_short,
        _normalize_region(custom.get('affectedregion', '')),
        custom.get('affectedcountry') or 'Unknown',
        ticket_dict.get('status', 0),
        ticket_dict.get('type', ''),
        ticket_dict.get('owner', ''),
        ticket_dict.get('closeReason') or ticket_dict.get('close_reason', ''),
        ticket_dict.get('closeNotes') or ticket_dict.get('close_notes', ''),
        ticket_dict.get('closingUserId') or ticket_dict.get('closing_user_id', ''),
        _normalize_impact(custom.get('impact', '')),
        custom.get('detectionsource', ''),
        ticket_dict.get('sourceBrand') or ticket_dict.get('source_brand', ''),
        ticket_dict.get('sourceInstance') or ticket_dict.get('source_instance', ''),
        custom.get('hostname', ''),
        custom.get('username', ''),
        custom.get('email', ''),
        custom.get('automation') or custom.get('automationlevel', ''),
        (ticket_dict.get('details') or '').strip(),
        custom.get('escalationstate', ''),
        ticket_dict.get('phase', ''),
        ticket_dict.get('openDuration') or ticket_dict.get('open_duration', 0),
        resolution_hours,
        raw_json,
    ))


def get_aggregation(dimension: str, granularity: str = 'monthly',
                    start_date=None, end_date=None) -> dict:
    """Aggregate ticket counts by time period and the given dimension.

    Args:
        dimension: 'severity', 'category', 'region', 'type', or 'impact'
        granularity: 'monthly' or 'weekly'
        start_date: optional YYYY-MM-DD lower bound
        end_date: optional YYYY-MM-DD upper bound

    Returns:
        {periods: ['2023-01', ...], series: {'2023-01': [{name, count}, ...], ...}}
    """
    column_map = {
        'severity': 'severity_display',
        'category': 'category_short',
        'region': 'affected_region',
        'type': 'type',
        'impact': 'impact',
    }
    col = column_map.get(dimension, 'severity_display')

    if granularity == 'weekly':
        period_expr = "strftime('%Y-W%W', created_date)"
    else:
        period_expr = "strftime('%Y-%m', created_date)"

    date_sql, params = _date_filter_sql(start_date, end_date)

    query = f"""
        SELECT {period_expr} AS period,
               {col} AS dim_value,
               COUNT(*) AS cnt
        FROM xsoar_tickets
        WHERE created_date IS NOT NULL {date_sql}
        GROUP BY period, {col}
        ORDER BY period, cnt DESC
    """

    # Build a prefix to strip from ticket type names (e.g. "METCIRT " → "")
    type_prefix = ''
    if dimension == 'type':
        try:
            from my_config import get_config
            team = get_config().team_name
            if team:
                type_prefix = team + ' '
        except Exception:
            pass

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    periods_set = set()
    series = {}
    for row in rows:
        period = row['period']
        name = row['dim_value'] or 'Unknown'
        if type_prefix and name.startswith(type_prefix):
            name = name[len(type_prefix):]
        cnt = row['cnt']
        periods_set.add(period)
        if period not in series:
            series[period] = []
        series[period].append({'name': name, 'count': cnt})

    periods = sorted(periods_set)
    return {'periods': periods, 'series': series}


# Keep backward compat alias
def get_monthly_aggregation(dimension: str, start_date=None, end_date=None) -> dict:
    return get_aggregation(dimension, 'monthly', start_date, end_date)


def get_timeline_data(granularity: str = 'monthly',
                      start_date=None, end_date=None) -> dict:
    """Return all 5 dimensions in one call."""
    return {
        'severity': get_aggregation('severity', granularity, start_date, end_date),
        'category': get_aggregation('category', granularity, start_date, end_date),
        'region': get_aggregation('region', granularity, start_date, end_date),
        'type': get_aggregation('type', granularity, start_date, end_date),
        'impact': get_aggregation('impact', granularity, start_date, end_date),
    }


def has_data() -> bool:
    if not DB_PATH.exists():
        return False
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM xsoar_tickets").fetchone()
            return row[0] > 0
    except Exception:
        return False


def get_ticket_count() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM xsoar_tickets").fetchone()[0]


def get_date_range() -> dict:
    with get_connection() as conn:
        row = conn.execute("""
            SELECT MIN(created_date) AS earliest, MAX(created_date) AS latest
            FROM xsoar_tickets
        """).fetchone()
        return {'earliest': row['earliest'], 'latest': row['latest']}


def get_sync_metadata(key: str):
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT value FROM sync_metadata WHERE key = ?", (key,)).fetchone()
            return row['value'] if row else None
    except Exception:
        return None


def set_sync_metadata(key: str, value: str):
    with get_connection() as conn:
        conn.execute("INSERT OR REPLACE INTO sync_metadata (key, value) VALUES (?, ?)", (key, value))


def update_user_notes(conn, ticket_id: str, notes_text: str):
    """Update the user_notes column for a single ticket."""
    conn.execute(
        "UPDATE xsoar_tickets SET user_notes = ? WHERE id = ?",
        (notes_text, ticket_id),
    )


def _date_filter_sql(start_date, end_date):
    """Build date filter SQL fragments and params."""
    sql = ""
    params = []
    if start_date:
        sql += " AND created_date >= ?"
        params.append(start_date)
    if end_date:
        sql += " AND created_date <= ?"
        params.append(end_date + 'T23:59:59')
    return sql, params
