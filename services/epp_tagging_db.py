"""
EPP Device Tagging Metrics Database

SQLite database for storing CrowdStrike and Tanium device tagging metrics.
Replaces Excel file storage with efficient queryable database.
"""

import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime, date
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Database location
DB_DIR = Path(__file__).parent.parent / "data" / "epp_tagging"
DB_PATH = DB_DIR / "epp_tagging_metrics.db"

# Ensure directory exists
DB_DIR.mkdir(parents=True, exist_ok=True)


def get_db_path() -> Path:
    """Return the database file path."""
    return DB_PATH


@contextmanager
def get_connection():
    """Context manager for database connections."""
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


def init_db():
    """Initialize database schema."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Tagging runs table - metadata about each automation run
        # Note: CHECK constraint updated to support Tanium Cloud and On-Prem separately
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tagging_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_date DATE NOT NULL,
                platform TEXT NOT NULL CHECK(platform IN ('CrowdStrike', 'Tanium', 'Tanium Cloud', 'Tanium On-Prem')),
                run_timestamp DATETIME,
                source_file TEXT,
                total_devices INTEGER DEFAULT 0,
                successfully_tagged INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0,
                run_by TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(run_date, platform, run_timestamp)
            )
        """)

        # Add columns to existing table if they don't exist
        cursor.execute("PRAGMA table_info(tagging_runs)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'run_by' not in columns:
            cursor.execute("ALTER TABLE tagging_runs ADD COLUMN run_by TEXT")
        if 'untagged_missing_snow_data' not in columns:
            cursor.execute("ALTER TABLE tagging_runs ADD COLUMN untagged_missing_snow_data INTEGER DEFAULT 0")
        if 'untagged_no_snow_entry' not in columns:
            cursor.execute("ALTER TABLE tagging_runs ADD COLUMN untagged_no_snow_entry INTEGER DEFAULT 0")
        if 'untagged_error' not in columns:
            cursor.execute("ALTER TABLE tagging_runs ADD COLUMN untagged_error INTEGER DEFAULT 0")

        # Tagging results table - aggregated results by country/category per run
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tagging_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                country TEXT NOT NULL,
                region TEXT,
                category TEXT,
                environment TEXT,
                ring_tag TEXT,
                total_devices INTEGER DEFAULT 0,
                successfully_tagged INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0,
                country_guessed INTEGER DEFAULT 0,
                FOREIGN KEY (run_id) REFERENCES tagging_runs(id) ON DELETE CASCADE
            )
        """)

        # Add environment column to existing table if it doesn't exist
        cursor.execute("PRAGMA table_info(tagging_results)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'environment' not in columns:
            cursor.execute("ALTER TABLE tagging_results ADD COLUMN environment TEXT")

        # Create indexes for efficient querying
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_runs_date ON tagging_runs(run_date)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_runs_platform ON tagging_runs(platform)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_country ON tagging_results(country)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_run_id ON tagging_results(run_id)
        """)

        logger.info(f"Database initialized at {DB_PATH}")


def insert_tagging_run(
    run_date: date,
    platform: str,
    run_timestamp: Optional[datetime] = None,
    source_file: Optional[str] = None,
    total_devices: int = 0,
    successfully_tagged: int = 0,
    failed: int = 0,
    run_by: Optional[str] = None,
    untagged_missing_snow_data: int = 0,
    untagged_no_snow_entry: int = 0,
    untagged_error: int = 0
) -> int:
    """
    Insert a new tagging run record.

    Args:
        run_date: Date of the tagging run
        platform: 'CrowdStrike' or 'Tanium'
        run_timestamp: Optional timestamp of the run
        source_file: Filename of the result Excel file
        total_devices: Total number of devices processed
        successfully_tagged: Number successfully tagged
        failed: Number that failed
        run_by: Who initiated the run (user name or 'scheduled job')
        untagged_missing_snow_data: Hosts untagged due to missing Snow data
        untagged_no_snow_entry: Hosts untagged because not found in Snow
        untagged_error: Hosts untagged due to API errors

    Returns:
        The ID of the inserted run.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tagging_runs
            (run_date, platform, run_timestamp, source_file, total_devices, successfully_tagged, failed, run_by,
             untagged_missing_snow_data, untagged_no_snow_entry, untagged_error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_date, platform, run_timestamp, source_file, total_devices, successfully_tagged, failed, run_by,
              untagged_missing_snow_data, untagged_no_snow_entry, untagged_error))
        return cursor.lastrowid


def insert_tagging_result(
    run_id: int,
    country: str,
    region: Optional[str] = None,
    category: Optional[str] = None,
    environment: Optional[str] = None,
    ring_tag: Optional[str] = None,
    total_devices: int = 0,
    successfully_tagged: int = 0,
    failed: int = 0,
    country_guessed: int = 0
):
    """Insert a tagging result record for a specific run."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tagging_results
            (run_id, country, region, category, environment, ring_tag, total_devices, successfully_tagged, failed, country_guessed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, country, region, category, environment, ring_tag, total_devices, successfully_tagged, failed, country_guessed))


def bulk_insert_results(run_id: int, results: list[dict]):
    """
    Bulk insert tagging results for a run.

    Args:
        run_id: The run ID to associate results with.
        results: List of dicts with keys: country, region, category, environment, ring_tag,
                 total_devices, successfully_tagged, failed, country_guessed
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO tagging_results
            (run_id, country, region, category, environment, ring_tag, total_devices, successfully_tagged, failed, country_guessed)
            VALUES (:run_id, :country, :region, :category, :environment, :ring_tag, :total_devices, :successfully_tagged, :failed, :country_guessed)
        """, [{**r, 'run_id': run_id, 'environment': r.get('environment')} for r in results])


def get_summary_stats() -> dict:
    """Get overall summary statistics."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Total counts
        cursor.execute("""
            SELECT
                COUNT(DISTINCT id) as total_runs,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as total_tagged,
                MIN(run_date) as earliest_date,
                MAX(run_date) as latest_date
            FROM tagging_runs
        """)
        row = cursor.fetchone()

        # By platform
        cursor.execute("""
            SELECT
                platform,
                COUNT(*) as runs,
                SUM(total_devices) as devices,
                SUM(successfully_tagged) as tagged
            FROM tagging_runs
            GROUP BY platform
        """)
        by_platform = {r['platform']: dict(r) for r in cursor.fetchall()}

        return {
            'total_runs': row['total_runs'] or 0,
            'total_devices': row['total_devices'] or 0,
            'total_tagged': row['total_tagged'] or 0,
            'earliest_date': row['earliest_date'],
            'latest_date': row['latest_date'],
            'by_platform': by_platform
        }


def get_monthly_stats() -> list[dict]:
    """Get monthly aggregated statistics."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                strftime('%Y-%m', run_date) as month,
                platform,
                COUNT(*) as runs,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as successfully_tagged
            FROM tagging_runs
            GROUP BY month, platform
            ORDER BY month
        """)
        return [dict(r) for r in cursor.fetchall()]


def get_country_stats() -> list[dict]:
    """Get statistics by country."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                country,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as successfully_tagged,
                SUM(country_guessed) as country_guessed
            FROM tagging_results
            GROUP BY country
            ORDER BY successfully_tagged DESC
        """)
        return [dict(r) for r in cursor.fetchall()]


def get_daily_stats(start_date: Optional[date] = None, end_date: Optional[date] = None) -> list[dict]:
    """Get daily statistics, optionally filtered by date range."""
    with get_connection() as conn:
        cursor = conn.cursor()

        query = """
            SELECT
                run_date,
                platform,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as successfully_tagged
            FROM tagging_runs
            WHERE 1=1
        """
        params = []

        if start_date:
            query += " AND run_date >= ?"
            params.append(start_date)
        if end_date:
            query += " AND run_date <= ?"
            params.append(end_date)

        query += " GROUP BY run_date, platform ORDER BY run_date"

        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]


def get_region_stats() -> list[dict]:
    """Get statistics by region."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                region,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as successfully_tagged
            FROM tagging_results
            WHERE region IS NOT NULL AND region != ''
            GROUP BY region
            ORDER BY successfully_tagged DESC
        """)
        return [dict(r) for r in cursor.fetchall()]


def get_category_stats() -> list[dict]:
    """Get statistics by device category (Workstation, Server, etc.)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                category,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as successfully_tagged
            FROM tagging_results
            WHERE category IS NOT NULL AND category != ''
            GROUP BY category
            ORDER BY successfully_tagged DESC
        """)
        return [dict(r) for r in cursor.fetchall()]


def get_ring_tag_stats() -> list[dict]:
    """Get statistics by ring tag."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                ring_tag,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as successfully_tagged
            FROM tagging_results
            WHERE ring_tag IS NOT NULL AND ring_tag != ''
            GROUP BY ring_tag
            ORDER BY successfully_tagged DESC
        """)
        return [dict(r) for r in cursor.fetchall()]


def get_recent_runs(limit: int = 20) -> list[dict]:
    """Get recent tagging runs with run_by information."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                id,
                run_date,
                platform,
                run_timestamp,
                source_file,
                total_devices,
                successfully_tagged,
                failed,
                run_by,
                created_at
            FROM tagging_runs
            ORDER BY run_date DESC, run_timestamp DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cursor.fetchall()]


def update_run_by_for_historical_data():
    """
    Update run_by field for historical data.
    - Runs from last 7 days: 'scheduled job'
    - Older runs: 'Ashok'
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        from datetime import date, timedelta

        week_ago = date.today() - timedelta(days=7)

        # Update runs from last week to 'scheduled job'
        cursor.execute("""
            UPDATE tagging_runs
            SET run_by = 'scheduled job'
            WHERE run_by IS NULL AND run_date >= ?
        """, (week_ago,))
        recent_updated = cursor.rowcount

        # Update older runs to 'Ashok'
        cursor.execute("""
            UPDATE tagging_runs
            SET run_by = 'Ashok'
            WHERE run_by IS NULL AND run_date < ?
        """, (week_ago,))
        older_updated = cursor.rowcount

        logger.info(f"Updated run_by: {recent_updated} recent runs to 'scheduled job', {older_updated} older runs to 'Ashok'")
        return {'recent_updated': recent_updated, 'older_updated': older_updated}


def get_environment_stats() -> list[dict]:
    """Get statistics grouped by environment."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                environment,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as successfully_tagged,
                SUM(failed) as failed
            FROM tagging_results
            WHERE environment IS NOT NULL AND environment != ''
            GROUP BY environment
            ORDER BY successfully_tagged DESC
        """)
        return [dict(r) for r in cursor.fetchall()]


def get_untagged_breakdown(start_date: Optional[date] = None, end_date: Optional[date] = None) -> list[dict]:
    """Get untagged hosts breakdown by reason for each run."""
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT
                run_date,
                platform,
                untagged_missing_snow_data,
                untagged_no_snow_entry,
                untagged_error
            FROM tagging_runs
            WHERE (untagged_missing_snow_data > 0 OR untagged_no_snow_entry > 0 OR untagged_error > 0)
        """
        params = []
        if start_date:
            query += " AND run_date >= ?"
            params.append(start_date)
        if end_date:
            query += " AND run_date <= ?"
            params.append(end_date)
        query += " ORDER BY run_date"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]


def get_all_metrics_for_dashboard() -> dict:
    """
    Get all metrics needed for the dashboard in a single call.
    Optimized for dashboard rendering.
    """
    return {
        'summary': get_summary_stats(),
        'monthly': get_monthly_stats(),
        'by_country': get_country_stats(),
        'by_region': get_region_stats(),
        'by_category': get_category_stats(),
        'by_environment': get_environment_stats(),
        'by_ring_tag': get_ring_tag_stats(),
        'daily': get_daily_stats(),
        'recent_runs': get_recent_runs(limit=10),
        'untagged_breakdown': get_untagged_breakdown()
    }


def run_exists(run_date: date, platform: str, run_timestamp: Optional[datetime] = None) -> bool:
    """Check if a run already exists in the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if run_timestamp:
            cursor.execute("""
                SELECT 1 FROM tagging_runs
                WHERE run_date = ? AND platform = ? AND run_timestamp = ?
            """, (run_date, platform, run_timestamp))
        else:
            cursor.execute("""
                SELECT 1 FROM tagging_runs
                WHERE run_date = ? AND platform = ?
            """, (run_date, platform))
        return cursor.fetchone() is not None


def get_filter_options() -> dict:
    """Get all available filter options for the dashboard."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Platforms
        cursor.execute('SELECT DISTINCT platform FROM tagging_runs ORDER BY platform')
        platforms = [r[0] for r in cursor.fetchall()]

        # Run by (who initiated)
        cursor.execute('SELECT DISTINCT run_by FROM tagging_runs WHERE run_by IS NOT NULL ORDER BY run_by')
        run_by = [r[0] for r in cursor.fetchall()]

        # Regions
        cursor.execute('''
            SELECT DISTINCT region FROM tagging_results
            WHERE region IS NOT NULL AND region != ''
            ORDER BY region
        ''')
        regions = [r[0] for r in cursor.fetchall()]

        # Countries
        cursor.execute('''
            SELECT DISTINCT country FROM tagging_results
            WHERE country IS NOT NULL AND country != ''
            ORDER BY country
        ''')
        countries = [r[0] for r in cursor.fetchall()]

        # Categories
        cursor.execute('''
            SELECT DISTINCT category FROM tagging_results
            WHERE category IS NOT NULL AND category != ''
            ORDER BY category
        ''')
        categories = [r[0] for r in cursor.fetchall()]

        # Environments
        cursor.execute('''
            SELECT DISTINCT environment FROM tagging_results
            WHERE environment IS NOT NULL AND environment != ''
            ORDER BY environment
        ''')
        environments = [r[0] for r in cursor.fetchall()]

        # Ring tags (extract unique ring numbers)
        rings = ['Ring1', 'Ring2', 'Ring3', 'Ring4']

        # Date range
        cursor.execute('SELECT MIN(run_date), MAX(run_date) FROM tagging_runs')
        row = cursor.fetchone()
        date_range = {'min': row[0], 'max': row[1]}

        return {
            'platforms': platforms,
            'run_by': run_by,
            'regions': regions,
            'countries': countries,
            'categories': categories,
            'environments': environments,
            'rings': rings,
            'date_range': date_range
        }


def get_filtered_metrics(
    platforms: list[str] = None,
    run_by: list[str] = None,
    start_date: date = None,
    end_date: date = None,
    regions: list[str] = None,
    countries: list[str] = None,
    categories: list[str] = None,
    rings: list[str] = None
) -> dict:
    """
    Get metrics filtered by the provided parameters.
    All filters are optional - if not provided, no filtering is applied for that dimension.
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Build run IDs filter based on tagging_runs filters
        run_conditions = []
        run_params = []

        if platforms:
            placeholders = ','.join('?' * len(platforms))
            run_conditions.append(f'platform IN ({placeholders})')
            run_params.extend(platforms)

        if run_by:
            placeholders = ','.join('?' * len(run_by))
            run_conditions.append(f'run_by IN ({placeholders})')
            run_params.extend(run_by)

        if start_date:
            run_conditions.append('run_date >= ?')
            run_params.append(start_date)

        if end_date:
            run_conditions.append('run_date <= ?')
            run_params.append(end_date)

        run_where = ' AND '.join(run_conditions) if run_conditions else '1=1'

        # Get filtered run IDs
        cursor.execute(f'''
            SELECT id, run_date, platform, total_devices, successfully_tagged, failed, run_by, run_timestamp
            FROM tagging_runs WHERE {run_where}
        ''', run_params)
        runs = cursor.fetchall()
        run_ids = [r['id'] for r in runs]

        if not run_ids:
            return _empty_metrics()

        # Build results filter
        result_conditions = [f"run_id IN ({','.join('?' * len(run_ids))})"]
        result_params = list(run_ids)

        if regions:
            placeholders = ','.join('?' * len(regions))
            result_conditions.append(f'region IN ({placeholders})')
            result_params.extend(regions)

        if countries:
            placeholders = ','.join('?' * len(countries))
            result_conditions.append(f'country IN ({placeholders})')
            result_params.extend(countries)

        if categories:
            placeholders = ','.join('?' * len(categories))
            result_conditions.append(f'category IN ({placeholders})')
            result_params.extend(categories)

        if rings:
            ring_conditions = []
            for ring in rings:
                ring_conditions.append('ring_tag LIKE ?')
                result_params.append(f'%{ring}%')
            result_conditions.append(f"({' OR '.join(ring_conditions)})")

        result_where = ' AND '.join(result_conditions)

        # Get summary stats
        cursor.execute(f'''
            SELECT
                COUNT(DISTINCT run_id) as total_runs,
                SUM(total_devices) as total_devices,
                SUM(successfully_tagged) as total_tagged,
                SUM(failed) as total_failed
            FROM tagging_results
            WHERE {result_where}
        ''', result_params)
        summary_row = cursor.fetchone()

        # Get by platform
        by_platform = {}
        for platform in (platforms or ['CrowdStrike', 'Tanium']):
            platform_run_ids = [r['id'] for r in runs if r['platform'] == platform]
            if platform_run_ids:
                platform_params = list(platform_run_ids) + result_params[len(run_ids):]
                platform_where = result_where.replace(
                    f"run_id IN ({','.join('?' * len(run_ids))})",
                    f"run_id IN ({','.join('?' * len(platform_run_ids))})"
                )
                cursor.execute(f'''
                    SELECT SUM(total_devices) as devices, SUM(successfully_tagged) as tagged
                    FROM tagging_results WHERE {platform_where}
                ''', platform_params)
                row = cursor.fetchone()
                by_platform[platform] = {
                    'devices': row['devices'] or 0,
                    'tagged': row['tagged'] or 0,
                    'runs': len(platform_run_ids)
                }

        # Get by country
        cursor.execute(f'''
            SELECT country, SUM(total_devices) as total_devices,
                   SUM(successfully_tagged) as successfully_tagged,
                   SUM(country_guessed) as country_guessed
            FROM tagging_results
            WHERE {result_where}
            GROUP BY country
            ORDER BY successfully_tagged DESC
        ''', result_params)
        by_country = [dict(r) for r in cursor.fetchall()]

        # Get by region
        cursor.execute(f'''
            SELECT region, SUM(total_devices) as total_devices,
                   SUM(successfully_tagged) as successfully_tagged
            FROM tagging_results
            WHERE {result_where} AND region IS NOT NULL AND region != ''
            GROUP BY region
            ORDER BY successfully_tagged DESC
        ''', result_params)
        by_region = [dict(r) for r in cursor.fetchall()]

        # Get by category
        cursor.execute(f'''
            SELECT category, SUM(total_devices) as total_devices,
                   SUM(successfully_tagged) as successfully_tagged
            FROM tagging_results
            WHERE {result_where} AND category IS NOT NULL AND category != ''
            GROUP BY category
            ORDER BY successfully_tagged DESC
        ''', result_params)
        by_category = [dict(r) for r in cursor.fetchall()]

        # Get by ring tag
        cursor.execute(f'''
            SELECT ring_tag, SUM(total_devices) as total_devices,
                   SUM(successfully_tagged) as successfully_tagged
            FROM tagging_results
            WHERE {result_where} AND ring_tag IS NOT NULL AND ring_tag != ''
            GROUP BY ring_tag
            ORDER BY successfully_tagged DESC
        ''', result_params)
        by_ring_tag = [dict(r) for r in cursor.fetchall()]

        # Get monthly stats
        monthly = []
        for r in runs:
            month = r['run_date'][:7] if r['run_date'] else None
            if month:
                monthly.append({
                    'month': month,
                    'platform': r['platform'],
                    'successfully_tagged': r['successfully_tagged'] or 0
                })

        # Aggregate monthly
        monthly_agg = {}
        for m in monthly:
            key = (m['month'], m['platform'])
            if key not in monthly_agg:
                monthly_agg[key] = {'month': m['month'], 'platform': m['platform'], 'successfully_tagged': 0, 'runs': 0}
            monthly_agg[key]['successfully_tagged'] += m['successfully_tagged']
            monthly_agg[key]['runs'] += 1
        monthly = sorted(monthly_agg.values(), key=lambda x: x['month'])

        # Get daily stats
        daily = []
        for r in runs:
            daily.append({
                'run_date': r['run_date'],
                'platform': r['platform'],
                'total_devices': r['total_devices'] or 0,
                'successfully_tagged': r['successfully_tagged'] or 0
            })

        # Get recent runs
        recent_runs = sorted(
            [dict(r) for r in runs],
            key=lambda x: (x['run_date'], x['run_timestamp'] or ''),
            reverse=True
        )[:10]

        # Calculate date range from filtered data
        dates = [r['run_date'] for r in runs if r['run_date']]
        earliest = min(dates) if dates else None
        latest = max(dates) if dates else None

        # Get untagged breakdown filtered by same run-level criteria
        cursor.execute(f'''
            SELECT run_date, platform, untagged_missing_snow_data, untagged_no_snow_entry, untagged_error
            FROM tagging_runs
            WHERE {run_where} AND untagged_missing_snow_data IS NOT NULL
            ORDER BY run_date
        ''', run_params)
        untagged_breakdown = [dict(r) for r in cursor.fetchall()]

        return {
            'summary': {
                'total_runs': summary_row['total_runs'] or 0,
                'total_devices': summary_row['total_devices'] or 0,
                'total_tagged': summary_row['total_tagged'] or 0,
                'earliest_date': earliest,
                'latest_date': latest,
                'by_platform': by_platform
            },
            'monthly': monthly,
            'by_country': by_country,
            'by_region': by_region,
            'by_category': by_category,
            'by_ring_tag': by_ring_tag,
            'daily': daily,
            'recent_runs': recent_runs,
            'untagged_breakdown': untagged_breakdown
        }


def _empty_metrics() -> dict:
    """Return empty metrics structure when no data matches filters."""
    return {
        'summary': {
            'total_runs': 0,
            'total_devices': 0,
            'total_tagged': 0,
            'earliest_date': None,
            'latest_date': None,
            'by_platform': {}
        },
        'monthly': [],
        'by_country': [],
        'by_region': [],
        'by_category': [],
        'by_ring_tag': [],
        'daily': [],
        'recent_runs': [],
        'untagged_breakdown': []
    }


# Initialize database on module import
init_db()
