"""
Threat Intel Dashboard Database

SQLite database for storing entity-extracted insights from tippers.
Provides persistent, incremental storage with fast SQL aggregation
queries for the threat intel dashboard.
"""

import logging
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# Database location
DB_DIR = Path(__file__).parent.parent / "data" / "threat_intel"
DB_PATH = DB_DIR / "threat_intel_dashboard.db"

# Ensure directory exists
DB_DIR.mkdir(parents=True, exist_ok=True)

# Priority and action constants
PRIORITY_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Info']
ACTION_TYPES = ['Detection Opportunity', 'Hunt Opportunity', 'None Required']

PRIORITY_COLORS = {
    'Critical': '#dc2626',
    'High': '#ea580c',
    'Medium': '#eab308',
    'Low': '#2563eb',
    'Info': '#9ca3af',
}

ACTION_COLORS = {
    'Detection Opportunity': '#0284c7',
    'Hunt Opportunity': '#059669',
    'None Required': '#4b5563',
}

# Benign domains to exclude from dashboard IOC aggregation.
# The entity extractor intentionally keeps these (for VT enrichment in the analyzer),
# but they're noise for the dashboard's "top IOCs" insights since tippers mention
# victim/target organizations and security vendors as context, not as threat IOCs.
def _get_company_domains() -> set:
    """Build company domain set from config (COMPANY_DOMAINS env var)."""
    try:
        from my_config import get_config
        cfg = get_config()
        if cfg.company_domains:
            return {d.strip().lower() for d in cfg.company_domains.split(',') if d.strip()}
        if cfg.my_web_domain:
            return {cfg.my_web_domain.lower()}
    except Exception:
        pass
    return set()


BENIGN_DOMAINS = _get_company_domains() | {
    # Microsoft ecosystem
    'microsoft.com', 'windows.com', 'office.com', 'live.com', 'outlook.com',
    'azure.com', 'azureedge.net', 'msn.com', 'bing.com', 'sharepoint.com',
    'microsoftonline.com', 'windows.net', 'office365.com', 'onmicrosoft.com',
    'visualstudio.com', 'aka.ms', 'skype.com', 'linkedin.com',
    # Google ecosystem
    'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com',
    'android.com', 'chromium.org', 'gmail.com', 'googlesyndication.com',
    # Apple
    'apple.com', 'icloud.com',
    # Amazon / AWS
    'amazon.com', 'amazonaws.com', 'aws.amazon.com', 'cloudfront.net',
    # Security vendors & threat intel sources
    'virustotal.com', 'recordedfuture.com', 'crowdstrike.com',
    'paloaltonetworks.com', 'trendmicro.com', 'mandiant.com',
    'fireeye.com', 'symantec.com', 'mcafee.com', 'kaspersky.com',
    'fortinet.com', 'sentinelone.com', 'elastic.co', 'splunk.com',
    'checkpoint.com', 'sophos.com', 'rapid7.com', 'qualys.com',
    'tenable.com', 'proxy.com', 'proofpoint.com', 'mimecast.com',
    'secureworks.com', 'volexity.com', 'unit42.paloaltonetworks.com',
    'blog.talosintelligence.com', 'talosintelligence.com',
    'threatpost.com', 'bleepingcomputer.com', 'thehackernews.com',
    'darkreading.com', 'securityweek.com', 'krebsonsecurity.com',
    'infosecurity-magazine.com', 'therecord.media', 'arstechnica.com',
    'cybersecuritynews.com', 'securityaffairs.com', 'tria.ge',
    'bazaar.abuse.ch', 'urlhaus.abuse.ch', 'abuse.ch',
    'any.run', 'hybrid-analysis.com', 'joe.security',
    'shodan.io', 'censys.io', 'greynoise.io',
    # Security research / analysis platforms
    'ahnlab.com', 'huntress.com', 'welivesecurity.com', 'securelist.com',
    'trellix.com', 'nextron-systems.com', 'malpedia.caad.fkie.fraunhofer.de',
    'fsisac.com', 'intezer.com', 'deepinstinct.com', 'cybereason.com',
    'group-ib.com', 'malwarebytes.com', 'bitdefender.com', 'eset.com',
    'avast.com', 'avg.com', 'nortonlifelock.com', 'mcafee.com',
    # CDNs and infrastructure
    'cloudflare.com', 'akamai.com', 'fastly.com', 'incapsula.com',
    # Social media / comms
    'twitter.com', 'x.com', 'facebook.com', 'telegram.org', 't.me',
    'reddit.com', 'discord.com', 'slack.com',
    # Developer platforms (already in entity_extractor, but repeated for clarity)
    'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
    'stackoverflow.com', 'npmjs.org', 'pypi.org',
    # Government / CERT
    'cisa.gov', 'nist.gov', 'us-cert.gov', 'mitre.org', 'nvd.nist.gov',
    'cert.org', 'ic3.gov', 'fbi.gov',
    # Security research / analysis (additional)
    'eclecticiq.com', 'sekoia.io', 'acronis.com', 'cloudsek.com',
    'cyfirma.com', 'varonis.com', 'securonix.com', 'jamf.com',
    'thedfirreport.com', 'reliaquest.com', 'arcticwolf.com',
    'hackread.com', 'redcanary.com', 'cyble.com', 'withsecure.com',
    'infoblox.com', 'horizon3.ai', 'hunt.io',
    # File sharing / developer tools
    'dropbox.com', 'mega.nz', 'socket.dev', 'jsdelivr.net',
    # Government CERTs
    'cert.gov.ua', 'jpcert.or.jp',
    # Development frameworks
    'asp.net',
    # Common benign TLD patterns
    'wikipedia.org', 'wikimedia.org', 'archive.org',
    'medium.com', 'isc.sans.edu', 'booking.com',
    # Email providers
    'yahoo.com', 'hotmail.com', 'protonmail.com', 'proton.me', 'zoho.com',
}

def _is_benign_domain(domain: str) -> bool:
    """Check if a domain or any of its parent domains is in the benign set.

    Handles subdomains: www.bleepingcomputer.com matches bleepingcomputer.com,
    falcon.us-2.crowdstrike.com matches crowdstrike.com.
    """
    d = domain.lower()
    if d in BENIGN_DOMAINS:
        return True
    # Walk up parent domains
    parts = d.split('.')
    for i in range(1, len(parts) - 1):
        parent = '.'.join(parts[i:])
        if parent in BENIGN_DOMAINS:
            return True
    return False


def _url_domain(url: str) -> str:
    """Extract domain from a URL string."""
    try:
        d = url.split('://', 1)[-1].split('/')[0].split(':')[0].lower()
        return d
    except Exception:
        return ''


def get_db_path() -> Path:
    """Return the database file path."""
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
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tippers (
                azdo_id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                tags TEXT DEFAULT '',
                priority TEXT DEFAULT 'Info',
                action TEXT DEFAULT 'None Required',
                state TEXT DEFAULT '',
                created_date DATETIME,
                created_week TEXT,
                processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tipper_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipper_id INTEGER NOT NULL REFERENCES tippers(azdo_id),
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tipper_threat_actors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipper_id INTEGER NOT NULL REFERENCES tippers(azdo_id),
                actor_name TEXT NOT NULL,
                region TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tipper_mitre_techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipper_id INTEGER NOT NULL REFERENCES tippers(azdo_id),
                technique_id TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tipper_malware (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipper_id INTEGER NOT NULL REFERENCES tippers(azdo_id),
                family_name TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc_enrichment (
                ioc_value TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                vt_malicious INTEGER,
                vt_total INTEGER,
                vt_verdict TEXT,
                rf_risk_score INTEGER,
                rf_risk_level TEXT,
                enriched_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attackiq_assessments (
                tipper_id INTEGER PRIMARY KEY REFERENCES tippers(azdo_id),
                assessment_id TEXT NOT NULL,
                assessment_url TEXT,
                test_id TEXT,
                scenarios_matched INTEGER DEFAULT 0,
                status TEXT DEFAULT 'created',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_checked_at DATETIME
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attackiq_status ON attackiq_assessments(status)")

        # Per-result BAS outcomes polled from AttackIQ. One row per scenario
        # result. prevention_outcome = was the action blocked; detection_outcome
        # = did our SIEM/EDR alert on it ("Detected"/"Not Detected") — the latter
        # is what powers the "did our detection actually fire?" matrix overlay.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attackiq_scenario_results (
                result_id TEXT PRIMARY KEY,
                project_id TEXT,
                project_name TEXT,
                scenario_id TEXT,
                scenario_name TEXT,
                asset_hostname TEXT,
                prevention_outcome TEXT,
                detection_outcome TEXT,
                outcome_name TEXT,
                tested_at TEXT,
                polled_at TEXT DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_aiq_res_scenario ON attackiq_scenario_results(scenario_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_aiq_res_tested ON attackiq_scenario_results(tested_at)")

        # Reverse index: which AttackIQ scenario UUIDs exercise a MITRE technique.
        # Built from the tag-list endpoint (scenario detail GET is 403), refreshed
        # periodically. Used to attribute a result's scenario back to a technique.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attackiq_technique_scenarios (
                technique_id TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                refreshed_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (technique_id, scenario_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_aiq_ts_scenario ON attackiq_technique_scenarios(scenario_id)")

        # Resolution-attempt ledger for the reverse index. attackiq_technique_scenarios
        # only stores rows for techniques that map to >=1 scenario, so a no-coverage
        # technique would otherwise be re-resolved against the (3s rate-limited) API
        # every night forever. Record every attempt here — including empty ones — so
        # the nightly index job can skip anything resolved recently and stay inside
        # its time budget (556 techniques * ~6s would blow a 30-min window).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attackiq_technique_attempts (
                technique_id TEXT PRIMARY KEY,
                attempted_at TEXT DEFAULT (datetime('now')),
                scenario_count INTEGER DEFAULT 0
            )
        """)
        # One-time backfill: techniques that already have fresh mappings in the
        # reverse index don't need re-resolving, so seed their attempt timestamps
        # from refreshed_at. Idempotent (INSERT OR IGNORE), so it only ever fills
        # the ledger's initial gap, not subsequent runs.
        cursor.execute("""
            INSERT OR IGNORE INTO attackiq_technique_attempts (technique_id, attempted_at, scenario_count)
            SELECT technique_id, MAX(refreshed_at), COUNT(*)
            FROM attackiq_technique_scenarios
            GROUP BY technique_id
        """)

        # Migration: add procedure_text column if missing
        cursor.execute("PRAGMA table_info(tipper_mitre_techniques)")
        columns = {r['name'] for r in cursor.fetchall()}
        if 'procedure_text' not in columns:
            cursor.execute("ALTER TABLE tipper_mitre_techniques ADD COLUMN procedure_text TEXT DEFAULT ''")

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tippers_created_week ON tippers(created_week)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tippers_priority ON tippers(priority)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tippers_action ON tippers(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON tipper_iocs(ioc_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON tipper_iocs(ioc_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_actors_name ON tipper_threat_actors(actor_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_actors_region ON tipper_threat_actors(region)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mitre_technique ON tipper_mitre_techniques(technique_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_malware_family ON tipper_malware(family_name)")

        # Approved security testing TTPs (red team submissions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS approved_testing_ttps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL,
                submitter TEXT,
                description TEXT,
                expiry_date TEXT,
                submitted_at TEXT DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_approved_ttps_technique ON approved_testing_ttps(technique_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_approved_ttps_submitted ON approved_testing_ttps(submitted_at)")

        # ATLAS (AI threat) detections — HiddenLayer integration
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS atlas_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_id TEXT UNIQUE,
                source TEXT NOT NULL DEFAULT 'hiddenlayer',
                model_name TEXT,
                detection_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                detected_at DATETIME,
                ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                raw_json TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS atlas_detection_techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER NOT NULL REFERENCES atlas_detections(id),
                technique_id TEXT NOT NULL
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_atlas_det_external ON atlas_detections(external_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_atlas_det_detected ON atlas_detections(detected_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_atlas_det_source ON atlas_detections(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_atlas_tech_technique ON atlas_detection_techniques(technique_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_atlas_tech_detection ON atlas_detection_techniques(detection_id)")

        logger.info(f"Threat intel database initialized at {DB_PATH}")


def get_existing_tipper_ids() -> set:
    """Get set of all azdo_ids already in the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT azdo_id FROM tippers")
        return {row[0] for row in cursor.fetchall()}


def get_existing_tipper_titles() -> set:
    """Get set of all titles already in the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT title FROM tippers")
        return {row[0] for row in cursor.fetchall()}


def insert_tipper(conn, azdo_id, title, tags, priority, action, state, created_date, created_week):
    """Insert a tipper row. Uses INSERT OR IGNORE to skip duplicates."""
    conn.execute("""
        INSERT OR IGNORE INTO tippers
        (azdo_id, title, tags, priority, action, state, created_date, created_week)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (azdo_id, title, tags, priority, action, state, created_date, created_week))


def insert_tipper_entities(conn, tipper_id, entities, procedures=None):
    """Insert extracted entities into child tables for a tipper."""
    # IOCs - IPs
    for ip in entities.ips:
        conn.execute(
            "INSERT INTO tipper_iocs (tipper_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
            (tipper_id, 'IP', ip)
        )

    # IOCs - Domains (skip benign)
    for domain in entities.domains:
        if _is_benign_domain(domain):
            continue
        conn.execute(
            "INSERT INTO tipper_iocs (tipper_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
            (tipper_id, 'Domain', domain)
        )

    # IOCs - URLs (skip if domain is benign)
    for url in entities.urls:
        if _is_benign_domain(_url_domain(url)):
            continue
        conn.execute(
            "INSERT INTO tipper_iocs (tipper_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
            (tipper_id, 'URL', url)
        )

    # IOCs - Hashes
    for hash_type in ['md5', 'sha1', 'sha256']:
        for h in entities.hashes.get(hash_type, []):
            conn.execute(
                "INSERT INTO tipper_iocs (tipper_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                (tipper_id, 'Hash', h)
            )

    # IOCs - CVEs
    for cve in entities.cves:
        conn.execute(
            "INSERT INTO tipper_iocs (tipper_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
            (tipper_id, 'CVE', cve)
        )

    # Threat actors (filter out MITRE tactic IDs like TA0001 which the extractor
    # misidentifies as threat actors due to the TA\d+ pattern)
    import re as _re
    for actor_info in entities.threat_actors_enriched:
        name = actor_info.common_name or actor_info.name
        if _re.match(r'^TA\d{4}$', name):
            continue
        conn.execute(
            "INSERT INTO tipper_threat_actors (tipper_id, actor_name, region) VALUES (?, ?, ?)",
            (tipper_id, name, actor_info.region or None)
        )

    # MITRE techniques
    procs = procedures or {}
    for technique in entities.mitre_techniques:
        procedure = procs.get(technique, '')
        conn.execute(
            "INSERT INTO tipper_mitre_techniques (tipper_id, technique_id, procedure_text) VALUES (?, ?, ?)",
            (tipper_id, technique, procedure)
        )

    # Malware families
    for family in entities.malware_families:
        conn.execute(
            "INSERT INTO tipper_malware (tipper_id, family_name) VALUES (?, ?)",
            (tipper_id, family)
        )


def upsert_attackiq_assessment(tipper_id: int, assessment_id: str,
                               assessment_url: str = '', test_id: str = '',
                               scenarios_matched: int = 0, status: str = 'created'):
    """Insert or update an AttackIQ assessment record for a tipper."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO attackiq_assessments
                (tipper_id, assessment_id, assessment_url, test_id, scenarios_matched, status)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tipper_id) DO UPDATE SET
                assessment_id = excluded.assessment_id,
                assessment_url = excluded.assessment_url,
                test_id = excluded.test_id,
                scenarios_matched = excluded.scenarios_matched,
                status = excluded.status,
                last_checked_at = CURRENT_TIMESTAMP
        """, (tipper_id, assessment_id, assessment_url, test_id, scenarios_matched, status))


def get_attackiq_assessment(tipper_id: int) -> dict | None:
    """Get the AttackIQ assessment record for a tipper, or None."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attackiq_assessments WHERE tipper_id = ?", (tipper_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_attackiq_assessments_by_status(status: str) -> list:
    """Get all AttackIQ assessment records with a given status."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attackiq_assessments WHERE status = ?", (status,))
        return [dict(r) for r in cursor.fetchall()]


# --- AttackIQ BAS validation (results overlay) ---------------------------

def upsert_technique_scenarios(technique_id: str, scenario_ids: list):
    """Replace the cached scenario list for one technique (reverse index)."""
    with get_connection() as conn:
        conn.execute("DELETE FROM attackiq_technique_scenarios WHERE technique_id = ?", (technique_id,))
        conn.executemany(
            "INSERT OR IGNORE INTO attackiq_technique_scenarios (technique_id, scenario_id) VALUES (?, ?)",
            [(technique_id, sid) for sid in scenario_ids],
        )


def record_technique_attempt(technique_id: str, scenario_count: int):
    """Stamp a resolution attempt for one technique (even a zero-scenario one)."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO attackiq_technique_attempts (technique_id, attempted_at, scenario_count)
               VALUES (?, datetime('now'), ?)
               ON CONFLICT(technique_id) DO UPDATE SET
                   attempted_at = datetime('now'),
                   scenario_count = excluded.scenario_count""",
            (technique_id, scenario_count),
        )


def get_recently_attempted_techniques(max_age_days: int) -> set:
    """Return technique IDs resolved against AttackIQ within max_age_days."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT technique_id FROM attackiq_technique_attempts "
            "WHERE attempted_at >= datetime('now', ?)",
            (f'-{int(max_age_days)} days',),
        )
        return {r['technique_id'] for r in cursor.fetchall()}


def get_technique_validation_status() -> dict:
    """Roll up polled BAS results into a per-technique validation verdict.

    Joins scenario results to the technique->scenario reverse index. For each
    technique we report:
        status: 'detected' (≥1 result our SIEM/EDR alerted on),
                'gap'      (scenarios ran but NOTHING detected — covered on
                            paper, silent in practice),
                'untested' (no results) — techniques with no row are untested.
        detected/total/prevented counts + last_tested timestamp.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        # Only CONCLUSIVE detection outcomes count toward the verdict.
        # 'Errored'/'Not Configured'/'Canceled' mean the sim didn't validly
        # exercise the control, so they don't make a technique a false "gap".
        cursor.execute("""
            SELECT ts.technique_id AS technique_id,
                   SUM(CASE WHEN r.detection_outcome IN ('Detected','Not Detected') THEN 1 ELSE 0 END) AS conclusive,
                   SUM(CASE WHEN r.detection_outcome = 'Detected' THEN 1 ELSE 0 END) AS detected,
                   SUM(CASE WHEN r.prevention_outcome = 'Prevented' THEN 1 ELSE 0 END) AS prevented,
                   MAX(CASE WHEN r.detection_outcome IN ('Detected','Not Detected') THEN r.tested_at END) AS last_tested
            FROM attackiq_technique_scenarios ts
            JOIN attackiq_scenario_results r ON r.scenario_id = ts.scenario_id
            GROUP BY ts.technique_id
        """)
        out = {}
        for row in cursor.fetchall():
            conclusive = row['conclusive'] or 0
            if conclusive == 0:
                continue  # only inconclusive runs → leave untested
            detected = row['detected'] or 0
            out[row['technique_id']] = {
                'status': 'detected' if detected > 0 else 'gap',
                'detected': detected,
                'prevented': row['prevented'] or 0,
                'total': conclusive,
                'last_tested': row['last_tested'],
            }
        return out


def refresh_technique_scenario_index(max_techniques: int = None,
                                     max_age_days: int = 14,
                                     per_run_limit: int = 250) -> dict:
    """Rebuild the technique->scenario reverse index for techniques that
    actually appear on the matrix (present in tipper_mitre_techniques).

    Incremental: AttackIQ's technique->scenario library is near-static, but the
    matrix now carries 556 distinct techniques and the client sleeps 3s/request
    (~6s/technique with the sub-technique parent fallback) — re-resolving all of
    them from scratch is ~55 min and blows the scheduler's 30-min budget every
    night. So each run skips techniques resolved within max_age_days and caps
    itself at per_run_limit; a cold start drains over a few nights, then steady
    state is just the handful of newly-seen techniques. Pass max_techniques to
    force an explicit (still skip-filtered) slice.

    Rate-limited, so this is a scheduler job, not a request-path call.
    Returns {techniques, scenarios, skipped, remaining}.
    """
    from services.attackiq import AttackIQClient
    aq = AttackIQClient()
    if not aq.is_configured():
        return {'error': 'AttackIQ not configured'}

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT technique_id FROM tipper_mitre_techniques")
        all_techniques = [r['technique_id'] for r in cursor.fetchall()]

    recent = get_recently_attempted_techniques(max_age_days)
    stale = [t for t in all_techniques if t not in recent]
    skipped = len(all_techniques) - len(stale)

    cap = max_techniques if max_techniques else per_run_limit
    techniques = stale[:cap]
    remaining = len(stale) - len(techniques)

    if not techniques:
        logger.info(f"AttackIQ technique index: nothing stale "
                    f"({skipped} fresh within {max_age_days}d, {len(all_techniques)} total)")
        return {'techniques': 0, 'scenarios': 0, 'skipped': skipped, 'remaining': 0}

    mapped = aq.get_scenario_uuids_for_techniques(techniques)
    total_scenarios = 0
    for tech_id, scenario_ids in mapped.items():
        upsert_technique_scenarios(tech_id, scenario_ids)
        record_technique_attempt(tech_id, len(scenario_ids))
        total_scenarios += len(scenario_ids)

    logger.info(f"AttackIQ technique index: resolved {len(techniques)} techniques, "
                f"{total_scenarios} scenario links ({skipped} skipped as fresh, "
                f"{remaining} stale remaining for next run)")
    return {'techniques': len(techniques), 'scenarios': total_scenarios,
            'skipped': skipped, 'remaining': remaining}


def refresh_attackiq_results(max_pages: int = 20) -> dict:
    """Poll recent AttackIQ results and upsert per-scenario detection outcomes.

    Read-only against the tenant. Backfills from existing run history too, so
    the overlay shows real data without anything new being fired. Returns
    {polled} count.
    """
    from services.attackiq import AttackIQClient
    aq = AttackIQClient()
    if not aq.is_configured():
        return {'error': 'AttackIQ not configured'}

    results = aq.list_recent_results(max_pages=max_pages)
    polled = 0
    with get_connection() as conn:
        for r in results:
            scenario = r.get('scenario') or {}
            scenario_id = scenario.get('id') if isinstance(scenario, dict) else scenario
            result_id = r.get('result_id') or r.get('id')
            if not result_id or not scenario_id:
                continue
            conn.execute("""
                INSERT INTO attackiq_scenario_results
                    (result_id, project_id, project_name, scenario_id, scenario_name,
                     asset_hostname, prevention_outcome, detection_outcome, outcome_name,
                     tested_at, polled_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(result_id) DO UPDATE SET
                    prevention_outcome = excluded.prevention_outcome,
                    detection_outcome = excluded.detection_outcome,
                    outcome_name = excluded.outcome_name,
                    tested_at = excluded.tested_at,
                    polled_at = datetime('now')
            """, (
                result_id, r.get('project_id'), r.get('project_name'),
                scenario_id, r.get('scenario_name') or (scenario.get('name') if isinstance(scenario, dict) else None),
                r.get('asset_hostname'), r.get('outcome_description'), r.get('detection_outcome'),
                r.get('outcome_name'), r.get('modified') or r.get('completed'),
            ))
            polled += 1

    logger.info(f"AttackIQ results poll: {polled} results upserted")
    return {'polled': polled}


def auto_fire_pending_assessments(max_scenarios: int = 25) -> dict:
    """Fire newly-built tipper assessments at the small test group, throttled
    to a per-night SCENARIO budget — the auto-execution half of the
    tipper -> BAS -> dashboard loop.

    `sync_tippers` auto-BUILDS an assessment per new tipper (status='created')
    but does not run it. This pass picks those up oldest-first and fires each
    one WHOLE (run_all = all its matched scenarios) at the configured test
    asset group, stopping once the night's cumulative scenario count would
    exceed `max_scenarios`. Anything left stays 'created' and drains on a later
    night — so a tipper spike can never fire a huge batch in one window.

    Safety: the firing primitive (`fire_built_assessment`) re-verifies the
    bound target is the small 1..MAX curated test group before every trigger,
    so blast radius is bounded by construction. The actor hosts are on the
    SOC-approved testing list, so runs raise no SOC tickets. Idempotent: a
    fired assessment is marked 'fired' and never re-run here.

    Returns {fired, scenarios, skipped, remaining, [error]}.
    """
    from services.attackiq import AttackIQClient
    aq = AttackIQClient()
    if not aq.is_configured():
        return {'error': 'AttackIQ not configured', 'fired': 0, 'scenarios': 0}

    asset_group_id = getattr(aq.config, 'attackiq_test_asset_group_id', None)
    if not asset_group_id:
        logger.info("AttackIQ auto-fire skipped: no ATTACKIQ_TEST_ASSET_GROUP_ID configured")
        return {'error': 'no test asset group configured', 'fired': 0, 'scenarios': 0}

    # Verify the target is the small curated test group ONCE up front — if it's
    # missing or unexpectedly large, fire nothing this run.
    asset_count, group_err = aq._verify_test_group_size(asset_group_id)
    if group_err:
        logger.warning(f"AttackIQ auto-fire refused: {group_err}")
        return {'error': group_err, 'fired': 0, 'scenarios': 0}

    pending = get_attackiq_assessments_by_status('created')
    # Oldest tippers first so the backlog drains in arrival order.
    pending.sort(key=lambda a: (a.get('created_at') or '', a.get('tipper_id') or 0))

    fired = 0
    scenarios = 0
    skipped = 0
    for a in pending:
        matched = a.get('scenarios_matched') or 0
        if matched <= 0:
            # Nothing to fire; mark so it's not reconsidered every night.
            upsert_attackiq_assessment(
                tipper_id=a['tipper_id'], assessment_id=a['assessment_id'],
                assessment_url=a.get('assessment_url', ''), test_id=a.get('test_id', ''),
                scenarios_matched=matched, status='empty')
            skipped += 1
            continue
        # Stop before exceeding the budget — but always fire at least one so a
        # single large assessment can't permanently stall the queue.
        if scenarios > 0 and scenarios + matched > max_scenarios:
            break

        result = aq.fire_built_assessment(a['assessment_id'], asset_group_id)
        if result.get('error'):
            logger.warning(f"AttackIQ auto-fire failed for tipper {a['tipper_id']}: {result['error']}")
            skipped += 1
            continue

        upsert_attackiq_assessment(
            tipper_id=a['tipper_id'], assessment_id=a['assessment_id'],
            assessment_url=a.get('assessment_url', ''), test_id=a.get('test_id', ''),
            scenarios_matched=matched, status='fired')
        fired += 1
        scenarios += matched
        if scenarios >= max_scenarios:
            break

    remaining = max(0, len(pending) - fired - skipped)
    logger.info(
        f"AttackIQ auto-fire: fired {fired} assessment(s) / {scenarios} scenario(s) "
        f"at {asset_count}-host test group (cap {max_scenarios}); "
        f"{remaining} still pending, {skipped} skipped")
    return {'fired': fired, 'scenarios': scenarios, 'skipped': skipped, 'remaining': remaining}


def sync_tippers(days_back=365) -> dict:
    """
    Sync tippers from AZDO into the database.

    Fetches tippers, diffs against existing IDs, extracts entities for new
    tippers only, and inserts into DB.

    Returns dict with new_count and total_count.
    """
    from data.data_maps import azdo_area_paths
    import services.azdo as azdo
    from src.utils.entity_extractor import extract_entities, extract_mitre_procedures

    area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')
    query = f"""
        SELECT [System.Id], [System.Title], [System.Description],
               [System.CreatedDate], [System.Tags], [System.State],
               [Microsoft.VSTS.Common.ClosedDate]
        FROM WorkItems
        WHERE [System.AreaPath] UNDER '{area_path}'
          AND [System.CreatedDate] >= @Today-{days_back}
        ORDER BY [System.CreatedDate] DESC
    """

    logger.info(f"Syncing threat intel dashboard (days_back={days_back})...")
    tippers = azdo.fetch_work_items(query)

    if not tippers:
        logger.warning("No tippers found in AZDO")
        return {'new_count': 0, 'total_count': 0}

    existing_ids = get_existing_tipper_ids()
    existing_titles = get_existing_tipper_titles()
    new_tippers = []
    for t in tippers:
        if t.get('id') in existing_ids:
            continue
        title = t.get('fields', {}).get('System.Title', '')
        if title and title in existing_titles:
            logger.info(f"Skipping tipper #{t.get('id')} — title already in DB: {title[:60]}")
            continue
        new_tippers.append(t)

    # Deduplicate within the batch by title — keep only the highest ID (newest)
    seen_titles = set()
    unique_tippers = []
    for t in sorted(new_tippers, key=lambda t: int(t.get('id', 0)), reverse=True):
        title = t.get('fields', {}).get('System.Title', '')
        if title and title in seen_titles:
            logger.info(f"Skipping duplicate tipper #{t.get('id')} (same title in batch, keeping higher ID)")
            continue
        if title:
            seen_titles.add(title)
        unique_tippers.append(t)
    new_tippers = unique_tippers

    logger.info(f"Found {len(tippers)} tippers, {len(new_tippers)} are new")

    if not new_tippers:
        update_sync_metadata('last_sync_at', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
        return {'new_count': 0, 'total_count': len(existing_ids)}

    with get_connection() as conn:
        for i, tipper in enumerate(new_tippers):
            if (i + 1) % 50 == 0:
                logger.info(f"Processing tipper {i + 1}/{len(new_tippers)}...")

            fields = tipper.get('fields', {})
            azdo_id = tipper.get('id')
            title = fields.get('System.Title', '')
            description = fields.get('System.Description', '')
            tags = fields.get('System.Tags', '') or ''
            state = fields.get('System.State', '')
            created_date_str = fields.get('System.CreatedDate', '')

            # Parse creation date
            created_date = None
            if created_date_str:
                try:
                    created_date = datetime.strptime(created_date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                except ValueError:
                    try:
                        created_date = datetime.strptime(created_date_str, '%Y-%m-%dT%H:%M:%SZ')
                    except ValueError:
                        pass

            # Compute week start (Monday of ISO week)
            created_week = None
            if created_date:
                week_start = created_date - timedelta(days=created_date.weekday())
                created_week = week_start.strftime('%Y-%m-%d')

            # Parse priority and action from tags
            priority = next((tag for tag in PRIORITY_LEVELS if tag in tags), 'Info')
            action = next((tag for tag in ACTION_TYPES if tag in tags), 'None Required')

            # Insert tipper row
            insert_tipper(
                conn, azdo_id, title, tags, priority, action, state,
                created_date.strftime('%Y-%m-%dT%H:%M:%SZ') if created_date else None,
                created_week,
            )

            # Strip HTML and extract entities
            text = title + ' '
            if description:
                clean_desc = re.sub(r'<[^>]+>', ' ', description)
                clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
                text += clean_desc

            try:
                entities = extract_entities(text, include_apt_database=True)
                procedures = extract_mitre_procedures(text)
                insert_tipper_entities(conn, azdo_id, entities, procedures=procedures)
            except Exception as e:
                logger.warning(f"Entity extraction failed for tipper {azdo_id}: {e}")

            # Create AttackIQ assessment if configured
            try:
                from services.attackiq import AttackIQClient
                aq = AttackIQClient()
                if aq.is_configured() and entities.mitre_techniques:
                    result = aq.create_tipper_assessment(azdo_id, title, entities.mitre_techniques)
                    if not result.get('error'):
                        upsert_attackiq_assessment(
                            tipper_id=azdo_id,
                            assessment_id=result['assessment_id'],
                            assessment_url=result.get('assessment_url', ''),
                            test_id=result.get('test_id', ''),
                            scenarios_matched=result.get('scenarios_matched', 0),
                            status='created',
                        )
            except Exception as e:
                logger.warning(f"AttackIQ assessment creation skipped for tipper {azdo_id}: {e}")

    update_sync_metadata('last_sync_at', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
    total = len(existing_ids) + len(new_tippers)
    logger.info(f"Sync complete: {len(new_tippers)} new tippers, {total} total")
    return {'new_count': len(new_tippers), 'total_count': total}


def update_sync_metadata(key, value):
    """Upsert a key/value pair into sync_metadata."""
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sync_metadata (key, value) VALUES (?, ?)",
            (key, value)
        )


def get_sync_metadata(key):
    """Get a value from sync_metadata, or None if not set."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM sync_metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None


def has_data() -> bool:
    """Check if the database has any tippers."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tippers")
        return cursor.fetchone()[0] > 0


# --- Aggregation query functions ---

def _date_filter_sql(alias, start_date, end_date):
    """Build date filter SQL fragments and params for tippers.created_date.

    Args:
        alias: table alias for the tippers table (e.g. 't' or '')
        start_date: YYYY-MM-DD string or None
        end_date: YYYY-MM-DD string or None

    Returns:
        (sql_fragment, params_list) — sql uses AND prefix so caller needs WHERE or WHERE 1=1 first.
    """
    prefix = f"{alias}." if alias else ""
    sql = ""
    params = []
    if start_date:
        sql += f" AND {prefix}created_date >= ?"
        params.append(start_date)
    if end_date:
        sql += f" AND {prefix}created_date <= ?"
        params.append(end_date + 'T23:59:59')
    return sql, params


def get_summary(start_date=None, end_date=None) -> dict:
    """Get summary statistics for the dashboard."""
    with get_connection() as conn:
        cursor = conn.cursor()

        date_sql, date_params = _date_filter_sql('', start_date, end_date)
        t_date_sql, t_date_params = _date_filter_sql('t', start_date, end_date)

        query = "SELECT COUNT(*) FROM tippers WHERE 1=1" + date_sql
        cursor.execute(query, date_params)
        total_tippers = cursor.fetchone()[0]

        query = "SELECT COUNT(DISTINCT ta.actor_name) FROM tipper_threat_actors ta JOIN tippers t ON t.azdo_id = ta.tipper_id WHERE 1=1" + t_date_sql
        cursor.execute(query, t_date_params)
        unique_actors = cursor.fetchone()[0]

        query = "SELECT COUNT(*) FROM tipper_iocs i JOIN tippers t ON t.azdo_id = i.tipper_id WHERE 1=1" + t_date_sql
        cursor.execute(query, t_date_params)
        total_iocs = cursor.fetchone()[0]

        query = "SELECT COUNT(DISTINCT tm.technique_id) FROM tipper_mitre_techniques tm JOIN tippers t ON t.azdo_id = tm.tipper_id WHERE 1=1" + t_date_sql
        cursor.execute(query, t_date_params)
        mitre_count = cursor.fetchone()[0]

        query = "SELECT MIN(created_date), MAX(created_date) FROM tippers WHERE created_date IS NOT NULL" + date_sql
        cursor.execute(query, date_params)
        row = cursor.fetchone()
        min_date = row[0][:10] if row[0] else None
        max_date = row[1][:10] if row[1] else None
        date_range = f"{min_date} to {max_date}" if min_date and max_date else "N/A"

        # Full (unfiltered) date range for the frontend date picker bounds
        cursor.execute("SELECT MIN(created_date), MAX(created_date) FROM tippers WHERE created_date IS NOT NULL")
        full_row = cursor.fetchone()
        full_min = full_row[0][:10] if full_row[0] else None
        full_max = full_row[1][:10] if full_row[1] else None

        return {
            'total_tippers': total_tippers,
            'unique_threat_actors': unique_actors,
            'total_iocs': total_iocs,
            'mitre_techniques_count': mitre_count,
            'date_range': date_range,
            'full_date_range': {'min': full_min, 'max': full_max},
        }


def get_tippers_over_time(start_date=None, end_date=None) -> dict:
    """Get weekly tipper counts stacked by priority."""
    date_sql, date_params = _date_filter_sql('', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT created_week, priority, COUNT(*) as cnt
            FROM tippers
            WHERE created_week IS NOT NULL
        """ + date_sql + """
            GROUP BY created_week, priority
            ORDER BY created_week
        """, date_params)
        rows = cursor.fetchall()

    # Build weeks list and series per priority
    weekly_data = {}
    for row in rows:
        week = row['created_week']
        priority = row['priority']
        count = row['cnt']
        if week not in weekly_data:
            weekly_data[week] = {}
        weekly_data[week][priority] = count

    sorted_weeks = sorted(weekly_data.keys())
    series = {}
    for p in PRIORITY_LEVELS:
        series[p] = [weekly_data[w].get(p, 0) for w in sorted_weeks]

    return {
        'weeks': sorted_weeks,
        'series': series,
        'colors': PRIORITY_COLORS,
    }


def get_top_threat_actors(limit=15, start_date=None, end_date=None) -> dict:
    """Get top threat actors by mention count."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ta.actor_name, COUNT(*) as cnt
            FROM tipper_threat_actors ta
            JOIN tippers t ON t.azdo_id = ta.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY ta.actor_name
            ORDER BY cnt DESC
            LIMIT ?
        """, date_params + [limit])
        rows = cursor.fetchall()

    return {
        'labels': [r['actor_name'] for r in rows],
        'values': [r['cnt'] for r in rows],
    }


def get_ioc_type_breakdown(start_date=None, end_date=None) -> dict:
    """Get IOC counts by type."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT i.ioc_type, COUNT(*) as cnt
            FROM tipper_iocs i
            JOIN tippers t ON t.azdo_id = i.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY i.ioc_type
            ORDER BY cnt DESC
        """, date_params)
        rows = cursor.fetchall()

    return {
        'labels': [r['ioc_type'] for r in rows],
        'values': [r['cnt'] for r in rows],
    }


def get_top_mitre_techniques(limit=15, start_date=None, end_date=None) -> dict:
    """Get top MITRE ATT&CK techniques by count."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT tm.technique_id, COUNT(*) as cnt
            FROM tipper_mitre_techniques tm
            JOIN tippers t ON t.azdo_id = tm.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY tm.technique_id
            ORDER BY cnt DESC
            LIMIT ?
        """, date_params + [limit])
        rows = cursor.fetchall()

    return {
        'labels': [r['technique_id'] for r in rows],
        'values': [r['cnt'] for r in rows],
    }


def get_threat_actor_regions(limit=10, start_date=None, end_date=None) -> dict:
    """Get threat actor attribution by region."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ta.region, COUNT(*) as cnt
            FROM tipper_threat_actors ta
            JOIN tippers t ON t.azdo_id = ta.tipper_id
            WHERE ta.region IS NOT NULL AND ta.region != ''
        """ + date_sql + """
            GROUP BY ta.region
            ORDER BY cnt DESC
            LIMIT ?
        """, date_params + [limit])
        rows = cursor.fetchall()

    return {
        'labels': [r['region'] for r in rows],
        'values': [r['cnt'] for r in rows],
    }


def get_priority_distribution(start_date=None, end_date=None) -> dict:
    """Get tipper count by priority level."""
    date_sql, date_params = _date_filter_sql('', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT priority, COUNT(*) as cnt
            FROM tippers
            WHERE 1=1
        """ + date_sql + """
            GROUP BY priority
            ORDER BY cnt DESC
        """, date_params)
        rows = cursor.fetchall()

    labels = [r['priority'] for r in rows]
    values = [r['cnt'] for r in rows]
    colors = {p: PRIORITY_COLORS[p] for p in labels if p in PRIORITY_COLORS}

    return {
        'labels': labels,
        'values': values,
        'colors': colors,
    }


def get_action_distribution(start_date=None, end_date=None) -> dict:
    """Get tipper count by action type."""
    date_sql, date_params = _date_filter_sql('', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT action, COUNT(*) as cnt
            FROM tippers
            WHERE 1=1
        """ + date_sql + """
            GROUP BY action
            ORDER BY cnt DESC
        """, date_params)
        rows = cursor.fetchall()

    labels = [r['action'] for r in rows]
    values = [r['cnt'] for r in rows]
    colors = {a: ACTION_COLORS[a] for a in labels if a in ACTION_COLORS}

    return {
        'labels': labels,
        'values': values,
        'colors': colors,
    }


def get_top_iocs_by_type(ioc_type, limit=20, start_date=None, end_date=None) -> list:
    """Get top IOCs of a specific type (Domain, IP, Hash) by occurrence count, with enrichment."""
    date_sql, date_params = _date_filter_sql('tp', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.ioc_value as value, t.ioc_type as type, COUNT(*) as count,
                   e.vt_verdict, e.vt_malicious, e.vt_total,
                   e.rf_risk_score, e.rf_risk_level
            FROM tipper_iocs t
            JOIN tippers tp ON tp.azdo_id = t.tipper_id
            LEFT JOIN ioc_enrichment e ON t.ioc_value = e.ioc_value
            WHERE t.ioc_type = ?
        """ + date_sql + """
            GROUP BY t.ioc_value, t.ioc_type
            ORDER BY count DESC
            LIMIT ?
        """, [ioc_type] + date_params + [limit])
        return [dict(r) for r in cursor.fetchall()]


def get_top_threat_actors_table(limit=20, start_date=None, end_date=None) -> list:
    """Get top threat actors with region for table display."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ta.actor_name as name, ta.region, COUNT(*) as count
            FROM tipper_threat_actors ta
            JOIN tippers t ON t.azdo_id = ta.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY ta.actor_name, ta.region
            ORDER BY count DESC
            LIMIT ?
        """, date_params + [limit])
        return [dict(r) for r in cursor.fetchall()]


def get_top_mitre_techniques_table(limit=20, start_date=None, end_date=None) -> list:
    """Get top MITRE ATT&CK techniques for table display."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT tm.technique_id, COUNT(*) as count
            FROM tipper_mitre_techniques tm
            JOIN tippers t ON t.azdo_id = tm.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY tm.technique_id
            ORDER BY count DESC
            LIMIT ?
        """, date_params + [limit])
        return [dict(r) for r in cursor.fetchall()]


def get_all_mitre_technique_counts(start_date=None, end_date=None) -> dict:
    """Returns {technique_id: count} for ALL techniques (no LIMIT)."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT tm.technique_id, COUNT(*) as count
            FROM tipper_mitre_techniques tm
            JOIN tippers t ON t.azdo_id = tm.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY tm.technique_id
        """, date_params)
        return {row['technique_id']: row['count'] for row in cursor.fetchall()}


def get_filtered_mitre_technique_counts(actors=None, tipper_titles=None, tipper_ids=None) -> dict:
    """Returns {technique_id: count} with optional actor/tipper filters.

    All params accept lists for multi-select (IN clause).
    Filters combine with AND across params, OR within a param.
    """
    parts = ["SELECT tmt.technique_id, COUNT(*) as count FROM tipper_mitre_techniques tmt"]
    conditions = []
    params = []

    if actors:
        parts.append("JOIN tipper_threat_actors tta ON tmt.tipper_id = tta.tipper_id")
        placeholders = ",".join("?" for _ in actors)
        conditions.append(f"tta.actor_name IN ({placeholders})")
        params.extend(actors)

    if tipper_titles:
        parts.append("JOIN tippers t ON tmt.tipper_id = t.azdo_id")
        placeholders = ",".join("?" for _ in tipper_titles)
        conditions.append(f"t.title IN ({placeholders})")
        params.extend(tipper_titles)

    if tipper_ids:
        placeholders = ",".join("?" for _ in tipper_ids)
        conditions.append(f"tmt.tipper_id IN ({placeholders})")
        params.extend(tipper_ids)

    if conditions:
        parts.append("WHERE " + " AND ".join(conditions))

    parts.append("GROUP BY tmt.technique_id")

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(" ".join(parts), params)
        return {row['technique_id']: row['count'] for row in cursor.fetchall()}


def get_technique_procedures(actors=None, tipper_titles=None, tipper_ids=None) -> dict:
    """Returns {technique_id: [procedure_text, ...]} with optional filters.

    Same filter logic as get_filtered_mitre_technique_counts.
    Only includes non-empty procedure texts.
    """
    parts = ["SELECT tmt.technique_id, tmt.procedure_text FROM tipper_mitre_techniques tmt"]
    conditions = ["tmt.procedure_text IS NOT NULL", "tmt.procedure_text != ''"]
    params = []

    if actors:
        parts.append("JOIN tipper_threat_actors tta ON tmt.tipper_id = tta.tipper_id")
        placeholders = ",".join("?" for _ in actors)
        conditions.append(f"tta.actor_name IN ({placeholders})")
        params.extend(actors)

    if tipper_titles:
        parts.append("JOIN tippers t ON tmt.tipper_id = t.azdo_id")
        placeholders = ",".join("?" for _ in tipper_titles)
        conditions.append(f"t.title IN ({placeholders})")
        params.extend(tipper_titles)

    if tipper_ids:
        placeholders = ",".join("?" for _ in tipper_ids)
        conditions.append(f"tmt.tipper_id IN ({placeholders})")
        params.extend(tipper_ids)

    parts.append("WHERE " + " AND ".join(conditions))

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(" ".join(parts), params)
        result = {}
        for row in cursor.fetchall():
            tech_id = row['technique_id']
            proc = row['procedure_text']
            result.setdefault(tech_id, []).append(proc)
        return result


##############################################################################
# ATLAS (AI threat) detection helpers
##############################################################################

def insert_atlas_detection(conn, external_id, source, model_name, detection_type,
                           severity, title, description, detected_at, technique_ids,
                           raw_json=None):
    """Insert a HiddenLayer (or other AI-sec) detection and its ATLAS techniques."""
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO atlas_detections
        (external_id, source, model_name, detection_type, severity, title,
         description, detected_at, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (external_id, source, model_name, detection_type, severity, title,
          description, detected_at, raw_json))

    if cursor.rowcount == 0:
        return  # duplicate — already ingested

    detection_id = cursor.lastrowid
    for tech_id in technique_ids:
        conn.execute(
            "INSERT INTO atlas_detection_techniques (detection_id, technique_id) VALUES (?, ?)",
            (detection_id, tech_id)
        )


def get_all_atlas_technique_counts(start_date=None, end_date=None) -> dict:
    """Returns {technique_id: count} for all ATLAS techniques."""
    sql = """
        SELECT adt.technique_id, COUNT(*) as count
        FROM atlas_detection_techniques adt
        JOIN atlas_detections ad ON ad.id = adt.detection_id
        WHERE 1=1
    """
    params = []
    if start_date:
        sql += " AND ad.detected_at >= ?"
        params.append(start_date)
    if end_date:
        sql += " AND ad.detected_at <= ?"
        params.append(end_date + 'T23:59:59')
    sql += " GROUP BY adt.technique_id"

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return {row['technique_id']: row['count'] for row in cursor.fetchall()}


def get_atlas_detection_count(start_date=None, end_date=None) -> int:
    """Return total number of ATLAS detections (for dashboard summary card)."""
    sql = "SELECT COUNT(*) as cnt FROM atlas_detections WHERE 1=1"
    params = []
    if start_date:
        sql += " AND detected_at >= ?"
        params.append(start_date)
    if end_date:
        sql += " AND detected_at <= ?"
        params.append(end_date + 'T23:59:59')
    with get_connection() as conn:
        row = conn.execute(sql, params).fetchone()
        return row['cnt'] if row else 0


def get_atlas_detections_list(limit=50, start_date=None, end_date=None) -> list:
    """Return recent ATLAS detections for table display."""
    sql = """
        SELECT ad.id, ad.external_id, ad.source, ad.model_name,
               ad.detection_type, ad.severity, ad.title, ad.detected_at,
               GROUP_CONCAT(adt.technique_id) as techniques
        FROM atlas_detections ad
        LEFT JOIN atlas_detection_techniques adt ON ad.id = adt.detection_id
        WHERE 1=1
    """
    params = []
    if start_date:
        sql += " AND ad.detected_at >= ?"
        params.append(start_date)
    if end_date:
        sql += " AND ad.detected_at <= ?"
        params.append(end_date + 'T23:59:59')
    sql += " GROUP BY ad.id ORDER BY ad.detected_at DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return [dict(r) for r in cursor.fetchall()]


def get_distinct_threat_actors() -> list:
    """Return list of all distinct threat actor names for filter dropdowns."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT actor_name FROM tipper_threat_actors ORDER BY actor_name")
        return [row['actor_name'] for row in cursor.fetchall()]


def get_distinct_tipper_titles() -> list:
    """Return list of distinct tipper titles for filter dropdowns."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT title FROM tippers ORDER BY title")
        return [row['title'] for row in cursor.fetchall()]


def get_tipper_id_title_pairs() -> list:
    """Return list of {id, title} dicts for all tippers, ordered by ID descending."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT azdo_id, title FROM tippers ORDER BY azdo_id DESC")
        return [{'id': row['azdo_id'], 'title': row['title']} for row in cursor.fetchall()]


def get_top_iocs(limit=20) -> list:
    """Get top IOCs (IPs, Domains, Hashes) by occurrence count, with enrichment data."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.ioc_value as value, t.ioc_type as type, COUNT(*) as count,
                   e.vt_verdict, e.vt_malicious, e.vt_total,
                   e.rf_risk_score, e.rf_risk_level
            FROM tipper_iocs t
            LEFT JOIN ioc_enrichment e ON t.ioc_value = e.ioc_value
            WHERE t.ioc_type IN ('IP', 'Domain', 'Hash')
            GROUP BY t.ioc_value, t.ioc_type
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cursor.fetchall()]


def get_recent_cves(limit=20, start_date=None, end_date=None) -> list:
    """Get recent CVEs with first/last seen dates."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                i.ioc_value as cve,
                COUNT(*) as count,
                MIN(t.created_date) as first_seen,
                MAX(t.created_date) as last_seen
            FROM tipper_iocs i
            JOIN tippers t ON t.azdo_id = i.tipper_id
            WHERE i.ioc_type = 'CVE'
        """ + date_sql + """
            GROUP BY i.ioc_value
            ORDER BY count DESC
            LIMIT ?
        """, date_params + [limit])
        rows = cursor.fetchall()

    return [
        {
            'cve': r['cve'],
            'count': r['count'],
            'first_seen': r['first_seen'][:10] if r['first_seen'] else '',
            'last_seen': r['last_seen'][:10] if r['last_seen'] else '',
        }
        for r in rows
    ]


def get_top_malware_families(limit=15, start_date=None, end_date=None) -> list:
    """Get top malware families by mention count."""
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT m.family_name as name, COUNT(*) as count
            FROM tipper_malware m
            JOIN tippers t ON t.azdo_id = m.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY m.family_name
            ORDER BY count DESC
            LIMIT ?
        """, date_params + [limit])
        return [dict(r) for r in cursor.fetchall()]


def insert_approved_testing_ttps(ttps_str, submitter=None, description=None, expiry_date=None):
    """Insert approved testing TTPs from a comma-separated string.

    Splits on commas, strips whitespace, uppercases, and inserts one row per technique.
    """
    if not ttps_str:
        return 0
    techniques = [t.strip().upper() for t in ttps_str.split(',') if t.strip()]
    if not techniques:
        return 0

    with get_connection() as conn:
        for tech_id in techniques:
            conn.execute("""
                INSERT INTO approved_testing_ttps (technique_id, submitter, description, expiry_date)
                VALUES (?, ?, ?, ?)
            """, (tech_id, submitter, description, expiry_date))

    logger.info(f"Inserted {len(techniques)} approved testing TTPs from {submitter}")
    return len(techniques)


def get_top_approved_testing_ttps(limit=15) -> list:
    """Get top approved testing TTPs by submission count."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT technique_id, COUNT(*) as count,
                   MAX(submitted_at) as last_tested,
                   GROUP_CONCAT(DISTINCT submitter) as submitters
            FROM approved_testing_ttps
            GROUP BY technique_id
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cursor.fetchall()]


def get_approved_testing_ttps_detail(limit=100) -> list:
    """Get recent approved testing TTP submissions with all fields."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT technique_id, submitter, description, expiry_date, submitted_at
            FROM approved_testing_ttps
            ORDER BY submitted_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cursor.fetchall()]


def get_actor_technique_map(limit_actors=8, limit_techniques_per_actor=3,
                            start_date=None, end_date=None) -> list:
    """Get top threat actors mapped to their most-used MITRE techniques.

    Returns list of {actor_name, region, techniques: [{technique_id, count}]}.
    """
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        # Get top actors by tipper mention count
        cursor.execute("""
            SELECT a.actor_name, a.region, COUNT(DISTINCT a.tipper_id) as actor_count
            FROM tipper_threat_actors a
            JOIN tippers t ON t.azdo_id = a.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY a.actor_name
            ORDER BY actor_count DESC
            LIMIT ?
        """, date_params + [limit_actors])
        actors = [dict(r) for r in cursor.fetchall()]

        # For each actor, get their top techniques
        for actor in actors:
            cursor.execute("""
                SELECT m.technique_id, COUNT(*) as count
                FROM tipper_mitre_techniques m
                JOIN tippers t ON t.azdo_id = m.tipper_id
                JOIN tipper_threat_actors a ON a.tipper_id = m.tipper_id
                WHERE a.actor_name = ?
            """ + date_sql + """
                GROUP BY m.technique_id
                ORDER BY count DESC
                LIMIT ?
            """, [actor['actor_name']] + date_params + [limit_techniques_per_actor])
            actor['techniques'] = [dict(r) for r in cursor.fetchall()]

    return actors


def get_malware_actor_map(limit_malware=10, start_date=None, end_date=None) -> list:
    """Get top malware families mapped to associated threat actors and regions.

    Returns list of {family_name, count, actors: [{actor_name, region}]}.
    """
    date_sql, date_params = _date_filter_sql('t', start_date, end_date)
    with get_connection() as conn:
        cursor = conn.cursor()
        # Get top malware families
        cursor.execute("""
            SELECT m.family_name, COUNT(*) as count
            FROM tipper_malware m
            JOIN tippers t ON t.azdo_id = m.tipper_id
            WHERE 1=1
        """ + date_sql + """
            GROUP BY m.family_name
            ORDER BY count DESC
            LIMIT ?
        """, date_params + [limit_malware])
        families = [dict(r) for r in cursor.fetchall()]

        # For each malware family, get associated actors
        for family in families:
            cursor.execute("""
                SELECT DISTINCT a.actor_name, a.region
                FROM tipper_threat_actors a
                JOIN tippers t ON t.azdo_id = a.tipper_id
                JOIN tipper_malware m ON m.tipper_id = a.tipper_id
                WHERE m.family_name = ?
            """ + date_sql + """
                ORDER BY a.actor_name
            """, [family['family_name']] + date_params)
            family['actors'] = [dict(r) for r in cursor.fetchall()]

    return families


def search_entities(tab: str, query: str, limit: int = 500) -> list:
    """Search ALL entities of a given tab type matching a query string.

    Unlike the top-N functions, this searches the full dataset (up to `limit`).
    """
    q = f'%{query}%'
    with get_connection() as conn:
        cursor = conn.cursor()

        if tab in ('domains', 'ips', 'hashes'):
            ioc_type = {'domains': 'Domain', 'ips': 'IP', 'hashes': 'Hash'}[tab]
            cursor.execute("""
                SELECT t.ioc_value as value, t.ioc_type as type, COUNT(*) as count,
                       e.vt_verdict, e.vt_malicious, e.vt_total,
                       e.rf_risk_score, e.rf_risk_level
                FROM tipper_iocs t
                LEFT JOIN ioc_enrichment e ON t.ioc_value = e.ioc_value
                WHERE t.ioc_type = ? AND t.ioc_value LIKE ?
                GROUP BY t.ioc_value, t.ioc_type
                ORDER BY count DESC
                LIMIT ?
            """, (ioc_type, q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'cves':
            cursor.execute("""
                SELECT i.ioc_value as cve, COUNT(*) as count,
                       MIN(t.created_date) as first_seen,
                       MAX(t.created_date) as last_seen
                FROM tipper_iocs i
                JOIN tippers t ON t.azdo_id = i.tipper_id
                WHERE i.ioc_type = 'CVE' AND i.ioc_value LIKE ?
                GROUP BY i.ioc_value
                ORDER BY count DESC
                LIMIT ?
            """, (q, limit))
            return [
                {
                    'cve': r['cve'], 'count': r['count'],
                    'first_seen': r['first_seen'][:10] if r['first_seen'] else '',
                    'last_seen': r['last_seen'][:10] if r['last_seen'] else '',
                }
                for r in cursor.fetchall()
            ]

        elif tab == 'malware':
            cursor.execute("""
                SELECT family_name as name, COUNT(*) as count
                FROM tipper_malware
                WHERE family_name LIKE ?
                GROUP BY family_name
                ORDER BY count DESC
                LIMIT ?
            """, (q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'actors':
            cursor.execute("""
                SELECT actor_name as name, region, COUNT(*) as count
                FROM tipper_threat_actors
                WHERE actor_name LIKE ? OR region LIKE ?
                GROUP BY actor_name, region
                ORDER BY count DESC
                LIMIT ?
            """, (q, q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'ttps':
            cursor.execute("""
                SELECT technique_id, COUNT(*) as count
                FROM tipper_mitre_techniques
                WHERE technique_id LIKE ?
                GROUP BY technique_id
                ORDER BY count DESC
                LIMIT ?
            """, (q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'redteam':
            cursor.execute("""
                SELECT technique_id, COUNT(*) as count,
                       MAX(submitted_at) as last_tested,
                       GROUP_CONCAT(DISTINCT submitter) as submitters
                FROM approved_testing_ttps
                WHERE technique_id LIKE ? OR submitter LIKE ? OR description LIKE ?
                GROUP BY technique_id
                ORDER BY count DESC
                LIMIT ?
            """, (q, q, q, limit))
            return [dict(r) for r in cursor.fetchall()]

        return []


def export_entities(tab: str, query: str = '', limit: int = 5000) -> list:
    """Export entities with AZDO work item IDs included.

    Like search_entities but adds GROUP_CONCAT(tipper_id) as azdo_ids.
    When query is empty, returns all data (up to limit).
    """
    has_filter = bool(query)
    q = f'%{query}%' if has_filter else '%'
    with get_connection() as conn:
        cursor = conn.cursor()

        if tab in ('domains', 'ips', 'hashes'):
            ioc_type = {'domains': 'Domain', 'ips': 'IP', 'hashes': 'Hash'}[tab]
            cursor.execute("""
                SELECT t.ioc_value as value, t.ioc_type as type, COUNT(*) as count,
                       GROUP_CONCAT(DISTINCT t.tipper_id) as azdo_ids,
                       e.vt_verdict, e.vt_malicious, e.vt_total,
                       e.rf_risk_score, e.rf_risk_level
                FROM tipper_iocs t
                LEFT JOIN ioc_enrichment e ON t.ioc_value = e.ioc_value
                WHERE t.ioc_type = ? AND t.ioc_value LIKE ?
                GROUP BY t.ioc_value, t.ioc_type
                ORDER BY count DESC
                LIMIT ?
            """, (ioc_type, q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'cves':
            cursor.execute("""
                SELECT i.ioc_value as cve, COUNT(*) as count,
                       GROUP_CONCAT(DISTINCT i.tipper_id) as azdo_ids,
                       MIN(t.created_date) as first_seen,
                       MAX(t.created_date) as last_seen
                FROM tipper_iocs i
                JOIN tippers t ON t.azdo_id = i.tipper_id
                WHERE i.ioc_type = 'CVE' AND i.ioc_value LIKE ?
                GROUP BY i.ioc_value
                ORDER BY count DESC
                LIMIT ?
            """, (q, limit))
            return [
                {
                    'cve': r['cve'], 'count': r['count'],
                    'azdo_ids': r['azdo_ids'] or '',
                    'first_seen': r['first_seen'][:10] if r['first_seen'] else '',
                    'last_seen': r['last_seen'][:10] if r['last_seen'] else '',
                }
                for r in cursor.fetchall()
            ]

        elif tab == 'malware':
            cursor.execute("""
                SELECT family_name as name, COUNT(*) as count,
                       GROUP_CONCAT(DISTINCT tipper_id) as azdo_ids
                FROM tipper_malware
                WHERE family_name LIKE ?
                GROUP BY family_name
                ORDER BY count DESC
                LIMIT ?
            """, (q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'actors':
            cursor.execute("""
                SELECT actor_name as name, region, COUNT(*) as count,
                       GROUP_CONCAT(DISTINCT tipper_id) as azdo_ids
                FROM tipper_threat_actors
                WHERE actor_name LIKE ? OR region LIKE ?
                GROUP BY actor_name, region
                ORDER BY count DESC
                LIMIT ?
            """, (q, q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'ttps':
            cursor.execute("""
                SELECT technique_id, COUNT(*) as count,
                       GROUP_CONCAT(DISTINCT tipper_id) as azdo_ids
                FROM tipper_mitre_techniques
                WHERE technique_id LIKE ?
                GROUP BY technique_id
                ORDER BY count DESC
                LIMIT ?
            """, (q, limit))
            return [dict(r) for r in cursor.fetchall()]

        elif tab == 'redteam':
            cursor.execute("""
                SELECT technique_id, COUNT(*) as count,
                       MAX(submitted_at) as last_tested,
                       GROUP_CONCAT(DISTINCT submitter) as submitters
                FROM approved_testing_ttps
                WHERE technique_id LIKE ? OR submitter LIKE ? OR description LIKE ?
                GROUP BY technique_id
                ORDER BY count DESC
                LIMIT ?
            """, (q, q, q, limit))
            return [dict(r) for r in cursor.fetchall()]

        return []


def get_dashboard_data(start_date=None, end_date=None) -> dict:
    """Get all aggregated data for the dashboard in a single call."""
    d = dict(start_date=start_date, end_date=end_date)
    return {
        'summary': get_summary(**d),
        'charts': {
            'tippers_over_time': get_tippers_over_time(**d),
            'top_threat_actors': get_top_threat_actors(**d),
            'ioc_type_breakdown': get_ioc_type_breakdown(**d),
            'top_mitre_techniques': get_top_mitre_techniques(**d),
            'threat_actor_regions': get_threat_actor_regions(**d),
            'priority_distribution': get_priority_distribution(**d),
            'action_distribution': get_action_distribution(**d),
        },
        'tables': {
            'top_domains': get_top_iocs_by_type('Domain', **d),
            'top_ips': get_top_iocs_by_type('IP', **d),
            'top_hashes': get_top_iocs_by_type('Hash', **d),
            'recent_cves': get_recent_cves(**d),
            'top_malware_families': get_top_malware_families(**d),
            'top_threat_actors': get_top_threat_actors_table(**d),
            'top_mitre_techniques': get_top_mitre_techniques_table(**d),
            'top_redteam_ttps': get_top_approved_testing_ttps(),
        },
    }


# --- Enrichment functions ---

def get_unenriched_iocs(limit=200, stale_days=7) -> list:
    """Get top IOCs that need enrichment (missing or stale).

    Returns IOCs ordered by occurrence count, prioritizing those without
    any enrichment data or with data older than stale_days.
    """
    cutoff = (datetime.utcnow() - timedelta(days=stale_days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.ioc_value as value, t.ioc_type as type, COUNT(*) as count
            FROM tipper_iocs t
            LEFT JOIN ioc_enrichment e ON t.ioc_value = e.ioc_value
            WHERE t.ioc_type IN ('IP', 'Domain', 'Hash')
              AND (e.ioc_value IS NULL OR e.enriched_at < ?)
            GROUP BY t.ioc_value, t.ioc_type
            ORDER BY count DESC
            LIMIT ?
        """, (cutoff, limit))
        return [dict(r) for r in cursor.fetchall()]


def upsert_enrichment(ioc_value, ioc_type, vt_malicious=None, vt_total=None,
                      vt_verdict=None, rf_risk_score=None, rf_risk_level=None):
    """Insert or update enrichment data, preserving existing partial data with COALESCE."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO ioc_enrichment (ioc_value, ioc_type, vt_malicious, vt_total,
                                        vt_verdict, rf_risk_score, rf_risk_level, enriched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(ioc_value) DO UPDATE SET
                ioc_type = excluded.ioc_type,
                vt_malicious = COALESCE(excluded.vt_malicious, ioc_enrichment.vt_malicious),
                vt_total = COALESCE(excluded.vt_total, ioc_enrichment.vt_total),
                vt_verdict = COALESCE(excluded.vt_verdict, ioc_enrichment.vt_verdict),
                rf_risk_score = COALESCE(excluded.rf_risk_score, ioc_enrichment.rf_risk_score),
                rf_risk_level = COALESCE(excluded.rf_risk_level, ioc_enrichment.rf_risk_level),
                enriched_at = CURRENT_TIMESTAMP
        """, (ioc_value, ioc_type, vt_malicious, vt_total, vt_verdict, rf_risk_score, rf_risk_level))


def cleanup_benign_iocs():
    """Delete IOC rows that match the expanded benign domain list.

    Useful after adding new domains to BENIGN_DOMAINS to clean up
    previously-inserted rows.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT ioc_value FROM tipper_iocs WHERE ioc_type = 'Domain'")
        domains = [row[0] for row in cursor.fetchall()]

        removed = 0
        for domain in domains:
            if _is_benign_domain(domain):
                cursor.execute("DELETE FROM tipper_iocs WHERE ioc_value = ?", (domain,))
                removed += cursor.rowcount

        logger.info(f"Cleaned up {removed} benign IOC rows across {len(domains)} distinct domains")
        return removed


def _map_vt_threat_level(threat_level: str) -> str:
    """Map VT get_threat_level() output to dashboard verdict labels."""
    mapping = {
        'MALWARE DETECTED': 'Malicious',
        'HIGH RISK': 'Malicious',
        'SUSPICIOUS': 'Suspicious',
        'CLEAN': 'Clean',
    }
    return mapping.get(threat_level, 'Unknown')


def enrich_top_iocs(vt_limit=50, rf_limit=200) -> dict:
    """Enrich top IOCs with VirusTotal and Recorded Future data.

    Phase 1: RF batch enrichment (fast, up to 1000 per API call)
    Phase 2: VT sequential enrichment (rate-limited, 4 req/min)

    Args:
        vt_limit: Max IOCs to enrich via VT (0 to skip VT)
        rf_limit: Max IOCs to enrich via RF (0 to skip RF)

    Returns:
        dict with rf_enriched and vt_enriched counts
    """
    import time as _time

    stats = {'rf_enriched': 0, 'vt_enriched': 0, 'errors': []}

    # Get IOCs that need enrichment
    iocs_to_enrich = get_unenriched_iocs(limit=max(vt_limit, rf_limit))
    if not iocs_to_enrich:
        logger.info("No IOCs need enrichment")
        return stats

    # Separate by type
    ips = [i for i in iocs_to_enrich if i['type'] == 'IP']
    domains = [i for i in iocs_to_enrich if i['type'] == 'Domain']
    hashes = [i for i in iocs_to_enrich if i['type'] == 'Hash']

    # --- Phase 1: Recorded Future batch enrichment ---
    if rf_limit > 0:
        try:
            from services.recorded_future import RecordedFutureClient
            rf_client = RecordedFutureClient()
            if rf_client.is_configured():
                rf_ips = [i['value'] for i in ips[:rf_limit]]
                rf_domains = [i['value'] for i in domains[:rf_limit]]
                rf_hashes = [i['value'] for i in hashes[:rf_limit]]

                if rf_ips or rf_domains or rf_hashes:
                    logger.info(f"RF enriching {len(rf_ips)} IPs, {len(rf_domains)} domains, {len(rf_hashes)} hashes")
                    response = rf_client.enrich(
                        ips=rf_ips or None,
                        domains=rf_domains or None,
                        hashes=rf_hashes or None,
                    )
                    results = rf_client.extract_enrichment_results(response)

                    for r in results:
                        value = r.get('value')
                        if not value:
                            continue
                        # Determine ioc_type from the RF entity type
                        rf_type = (r.get('type') or '').lower()
                        if rf_type in ('ipaddress', 'ip'):
                            ioc_type = 'IP'
                        elif rf_type in ('internetdomainname', 'domain'):
                            ioc_type = 'Domain'
                        elif rf_type in ('hash',):
                            ioc_type = 'Hash'
                        else:
                            ioc_type = 'Unknown'

                        upsert_enrichment(
                            ioc_value=value,
                            ioc_type=ioc_type,
                            rf_risk_score=r.get('risk_score'),
                            rf_risk_level=r.get('risk_level'),
                        )
                        stats['rf_enriched'] += 1

                    logger.info(f"RF enrichment complete: {stats['rf_enriched']} IOCs")
            else:
                logger.warning("RecordedFuture client not configured, skipping RF enrichment")
        except Exception as e:
            logger.error(f"RF enrichment failed: {e}", exc_info=True)
            stats['errors'].append(f"RF: {e}")

    # --- Phase 2: VirusTotal sequential enrichment ---
    if vt_limit > 0:
        try:
            from services.virustotal import VirusTotalClient
            vt_client = VirusTotalClient()
            if vt_client.is_configured():
                # Re-fetch unenriched to get IOCs that still need VT (RF may have partially filled)
                vt_iocs = get_unenriched_iocs(limit=vt_limit, stale_days=7)
                # Also include IOCs that have RF but no VT data
                if len(vt_iocs) < vt_limit:
                    with get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT t.ioc_value as value, t.ioc_type as type, COUNT(*) as count
                            FROM tipper_iocs t
                            LEFT JOIN ioc_enrichment e ON t.ioc_value = e.ioc_value
                            WHERE t.ioc_type IN ('IP', 'Domain', 'Hash')
                              AND e.vt_verdict IS NULL
                            GROUP BY t.ioc_value, t.ioc_type
                            ORDER BY count DESC
                            LIMIT ?
                        """, (vt_limit,))
                        vt_iocs = [dict(r) for r in cursor.fetchall()]

                vt_iocs = vt_iocs[:vt_limit]
                logger.info(f"VT enriching {len(vt_iocs)} IOCs (rate-limited at 4 req/min)")

                req_count = 0
                for ioc in vt_iocs:
                    try:
                        ioc_type = ioc['type']
                        ioc_value = ioc['value']

                        if ioc_type == 'IP':
                            result = vt_client.lookup_ip(ioc_value)
                        elif ioc_type == 'Domain':
                            result = vt_client.lookup_domain(ioc_value)
                        elif ioc_type == 'Hash':
                            result = vt_client.lookup_hash(ioc_value)
                        else:
                            continue

                        if 'error' in result:
                            logger.debug(f"VT lookup error for {ioc_value}: {result['error']}")
                            # Still mark as enriched with Unknown verdict to avoid retrying
                            upsert_enrichment(
                                ioc_value=ioc_value,
                                ioc_type=ioc_type,
                                vt_verdict='Unknown',
                                vt_malicious=0,
                                vt_total=0,
                            )
                            stats['vt_enriched'] += 1
                        else:
                            attrs = result.get('data', {}).get('attributes', {})
                            analysis_stats = attrs.get('last_analysis_stats', {})
                            malicious = analysis_stats.get('malicious', 0)
                            total = sum(analysis_stats.values()) if analysis_stats else 0
                            is_file = ioc_type == 'Hash'
                            threat_level = vt_client.get_threat_level(analysis_stats, is_file=is_file)
                            verdict = _map_vt_threat_level(threat_level)

                            upsert_enrichment(
                                ioc_value=ioc_value,
                                ioc_type=ioc_type,
                                vt_malicious=malicious,
                                vt_total=total,
                                vt_verdict=verdict,
                            )
                            stats['vt_enriched'] += 1

                        req_count += 1
                        # Rate limit: 4 requests per minute
                        if req_count % 4 == 0 and req_count < len(vt_iocs):
                            logger.debug(f"VT rate limit pause after {req_count} requests")
                            _time.sleep(60)

                    except Exception as e:
                        logger.warning(f"VT enrichment failed for {ioc['value']}: {e}")
                        stats['errors'].append(f"VT {ioc['value']}: {e}")

                logger.info(f"VT enrichment complete: {stats['vt_enriched']} IOCs")
            else:
                logger.warning("VirusTotal client not configured, skipping VT enrichment")
        except Exception as e:
            logger.error(f"VT enrichment failed: {e}", exc_info=True)
            stats['errors'].append(f"VT: {e}")

    return stats


def get_tippers_for_entity(entity_type: str, entity_value: str) -> list:
    """Get the source tippers (AZDO work items) that mention a specific entity.

    Args:
        entity_type: One of Domain, IP, Hash, CVE, Malware, Actor, TTP
        entity_value: The entity value to look up

    Returns:
        List of dicts with azdo_id, title, created_date, url
    """
    from my_config import get_config
    config = get_config()
    org = config.azdo_org or 'Company-Org'
    project = config.azdo_de_project or 'Detection-Engineering'

    # Map entity type to the appropriate child table and filter
    type_map = {
        'Domain':  ('tipper_iocs', 'ioc_type = ? AND ioc_value = ?', ['Domain', entity_value]),
        'IP':      ('tipper_iocs', 'ioc_type = ? AND ioc_value = ?', ['IP', entity_value]),
        'Hash':    ('tipper_iocs', 'ioc_type = ? AND ioc_value = ?', ['Hash', entity_value]),
        'CVE':     ('tipper_iocs', 'ioc_type = ? AND ioc_value = ?', ['CVE', entity_value]),
        'Malware': ('tipper_malware', 'family_name = ?', [entity_value]),
        'Actor':   ('tipper_threat_actors', 'actor_name = ?', [entity_value]),
        'TTP':     ('tipper_mitre_techniques', 'technique_id = ?', [entity_value]),
    }

    if entity_type not in type_map:
        return []

    table, where_clause, params = type_map[entity_type]

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT DISTINCT t.azdo_id, t.title, t.created_date
            FROM tippers t
            JOIN {table} c ON c.tipper_id = t.azdo_id
            WHERE {where_clause}
            ORDER BY t.created_date DESC
        """, params)
        rows = cursor.fetchall()

    return [
        {
            'azdo_id': r['azdo_id'],
            'title': r['title'],
            'created_date': r['created_date'][:10] if r['created_date'] else '',
            'url': f'https://dev.azure.com/{org}/{project}/_workitems/edit/{r["azdo_id"]}',
        }
        for r in rows
    ]


def backfill_procedure_text() -> dict:
    """One-time migration: re-fetch tipper descriptions from AZDO and populate procedure_text.

    For each tipper that has MITRE techniques but empty procedure_text,
    re-fetches the description, extracts procedures, and UPDATEs existing rows.

    Returns dict with updated_count and skipped_count.
    """
    from data.data_maps import azdo_area_paths
    import services.azdo as azdo
    from src.utils.entity_extractor import extract_mitre_procedures

    stats = {'updated_count': 0, 'skipped_count': 0, 'tipper_count': 0}

    # Get tipper IDs that have techniques with empty procedure_text
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT tipper_id FROM tipper_mitre_techniques
            WHERE procedure_text IS NULL OR procedure_text = ''
        """)
        tipper_ids = [row[0] for row in cursor.fetchall()]

    if not tipper_ids:
        logger.info("Backfill: no tippers need procedure text update")
        return stats

    logger.info(f"Backfill: {len(tipper_ids)} tippers need procedure text")
    stats['tipper_count'] = len(tipper_ids)

    # Fetch descriptions from AZDO in batches
    area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')
    id_list = ",".join(str(i) for i in tipper_ids)
    query = f"""
        SELECT [System.Id], [System.Title], [System.Description]
        FROM WorkItems
        WHERE [System.AreaPath] UNDER '{area_path}'
          AND [System.Id] IN ({id_list})
    """

    tippers = azdo.fetch_work_items(query)
    if not tippers:
        logger.warning("Backfill: no tippers returned from AZDO")
        return stats

    with get_connection() as conn:
        for tipper in tippers:
            azdo_id = tipper.get('id')
            fields = tipper.get('fields', {})
            title = fields.get('System.Title', '')
            description = fields.get('System.Description', '')

            text = title + ' '
            if description:
                clean_desc = re.sub(r'<[^>]+>', ' ', description)
                clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
                text += clean_desc

            procedures = extract_mitre_procedures(text)
            if not procedures:
                stats['skipped_count'] += 1
                continue

            for tech_id, proc_text in procedures.items():
                conn.execute("""
                    UPDATE tipper_mitre_techniques
                    SET procedure_text = ?
                    WHERE tipper_id = ? AND technique_id = ? AND (procedure_text IS NULL OR procedure_text = '')
                """, (proc_text, azdo_id, tech_id))
                stats['updated_count'] += conn.execute("SELECT changes()").fetchone()[0]

    logger.info(f"Backfill complete: {stats['updated_count']} rows updated, {stats['skipped_count']} tippers skipped")
    return stats


def backfill_malware_families() -> dict:
    """Re-extract malware families for tippers that have no rows in tipper_malware.

    Fetches descriptions from AZDO, runs entity extraction with the new
    MITRE-based malware matcher, and inserts any found families.

    Returns dict with processed_count, inserted_count, skipped_count.
    """
    from data.data_maps import azdo_area_paths
    import services.azdo as azdo
    from src.utils.entity_extractor import extract_malware_families

    stats = {'processed_count': 0, 'inserted_count': 0, 'skipped_count': 0}

    # Find tippers with no malware rows
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.azdo_id FROM tippers t
            LEFT JOIN tipper_malware m ON t.azdo_id = m.tipper_id
            WHERE m.id IS NULL
        """)
        tipper_ids = [row[0] for row in cursor.fetchall()]

    if not tipper_ids:
        logger.info("Backfill: all tippers already have malware data")
        return stats

    logger.info(f"Backfill: {len(tipper_ids)} tippers need malware extraction")

    # Fetch descriptions from AZDO in batches (WIQL IN clause max ~200)
    area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')
    batch_size = 200
    all_tippers = []
    for i in range(0, len(tipper_ids), batch_size):
        batch = tipper_ids[i:i + batch_size]
        id_list = ",".join(str(tid) for tid in batch)
        query = f"""
            SELECT [System.Id], [System.Title], [System.Description]
            FROM WorkItems
            WHERE [System.AreaPath] UNDER '{area_path}'
              AND [System.Id] IN ({id_list})
        """
        fetched = azdo.fetch_work_items(query)
        if fetched:
            all_tippers.extend(fetched)

    if not all_tippers:
        logger.warning("Backfill: no tippers returned from AZDO")
        return stats

    with get_connection() as conn:
        for tipper in all_tippers:
            azdo_id = tipper.get('id')
            fields = tipper.get('fields', {})
            title = fields.get('System.Title', '')
            description = fields.get('System.Description', '')

            text = title + ' '
            if description:
                clean_desc = re.sub(r'<[^>]+>', ' ', description)
                clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
                text += clean_desc

            families = extract_malware_families(text)
            stats['processed_count'] += 1

            if not families:
                stats['skipped_count'] += 1
                continue

            for family in families:
                conn.execute(
                    "INSERT INTO tipper_malware (tipper_id, family_name) VALUES (?, ?)",
                    (azdo_id, family)
                )
                stats['inserted_count'] += 1

    logger.info(
        f"Backfill complete: {stats['processed_count']} tippers processed, "
        f"{stats['inserted_count']} malware rows inserted, "
        f"{stats['skipped_count']} tippers had no malware"
    )
    return stats


# Initialize database on module import
init_db()
