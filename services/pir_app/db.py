"""
Database layer for PIR Management Platform.
Uses Python's built-in sqlite3 — no external packages required.
"""

import sqlite3
import hashlib
import secrets
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DB_PATH = os.path.join(_PROJECT_ROOT, 'data', 'transient', 'pir_management.db')

# Security configuration
PBKDF2_ITERATIONS = 100000
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
MAX_INPUT_LENGTH = 10000  # Maximum length for text inputs

# ---------------------------------------------------------------------------
# Default sources — used to seed the database on first run.
# These can be managed dynamically through the UI after initial setup.
# ---------------------------------------------------------------------------
_DEFAULT_SOURCES = [
    'RecordedFuture',
    'Intel471',
    'Dataminr',
    'FlashPoint',
    'RecordedFuture (Insikt)',
    'Dataminr (FINTEL)',
    'Intel471 (FINTEL)',
    'FlashPoint (FINTEL)',
    'CrowdStrike (CAO)',
    'FS-ISAC',
    'NCFTA',
    'CISA KEV',
    'BlueVoyant',
    'SIEM',
    'VulnDB',
    'EDR',
    'Email Gateway',
    'Firewall (PAs)',
    'Akamai',
    'Proxy',
    'Cloud Logs',
    'Endpoint Logs',
    'FS-ISAC Sharing',
    'Peer Intel / Closed Groups',
    'Vendor Briefings',
    'Law Enforcement',
    'Employee Reports',
]

# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db():
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL DEFAULT 'analyst',
                full_name     TEXT,
                created_at    TEXT    DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS requirements (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                req_id               TEXT UNIQUE NOT NULL,
                req_type             TEXT NOT NULL,
                req_text             TEXT NOT NULL,
                parent_id            TEXT,
                priority             TEXT,
                collection_frequency TEXT,
                primary_owner        TEXT,
                status               TEXT DEFAULT 'Active',
                notes                TEXT,
                updated_at           TEXT DEFAULT (datetime('now')),
                updated_by           TEXT
            );

            CREATE TABLE IF NOT EXISTS sources (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    UNIQUE NOT NULL,
                sort_order INTEGER DEFAULT 0,
                created_at TEXT    DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS source_coverage (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                req_id           TEXT NOT NULL,
                source_name      TEXT NOT NULL,
                source_category  TEXT,
                coverage_value   TEXT,
                detection_logic  TEXT,
                updated_at       TEXT DEFAULT (datetime('now')),
                UNIQUE(req_id, source_name)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                username   TEXT    NOT NULL,
                role       TEXT    NOT NULL,
                csrf_token TEXT    NOT NULL,
                expires_at TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT,
                action     TEXT,
                table_name TEXT,
                record_id  TEXT,
                old_value  TEXT,
                new_value  TEXT,
                timestamp  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT NOT NULL,
                ip_address TEXT,
                success    INTEGER NOT NULL,
                timestamp  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS account_lockouts (
                username   TEXT PRIMARY KEY,
                locked_at  TEXT NOT NULL,
                unlock_at  TEXT NOT NULL
            );
        """)

        # Migrate: add detection_logic column if it doesn't exist yet
        existing = {row[1] for row in conn.execute("PRAGMA table_info(source_coverage)").fetchall()}
        if 'detection_logic' not in existing:
            conn.execute("ALTER TABLE source_coverage ADD COLUMN detection_logic TEXT")

        # Migrate: add csrf_token column to sessions if it doesn't exist
        session_cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if 'csrf_token' not in session_cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN csrf_token TEXT")
            # Generate CSRF tokens for existing sessions
            conn.execute("UPDATE sessions SET csrf_token=? WHERE csrf_token IS NULL", (secrets.token_urlsafe(32),))

        # Migrate: update old SHA-256 passwords to PBKDF2 (admin only, on next login)
        # Add a flag column to track password format
        user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if 'password_needs_reset' not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_needs_reset INTEGER DEFAULT 0")
        if 'locked_until' not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
        if 'failed_login_count' not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN failed_login_count INTEGER DEFAULT 0")

        # Create default admin user if table is empty
        cur = conn.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                ('admin', _hash_password('admin123'), 'admin', 'Administrator')
            )
            print("[db] Default admin user created. Change the password before use.")

        # Seed default sources if table is empty
        cur = conn.execute("SELECT COUNT(*) FROM sources")
        if cur.fetchone()[0] == 0:
            for i, name in enumerate(_DEFAULT_SOURCES):
                conn.execute(
                    "INSERT INTO sources (name, sort_order) VALUES (?, ?)",
                    (name, i)
                )
            print(f"[db] Seeded {len(_DEFAULT_SOURCES)} default sources")

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with random salt."""
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    # Store salt + key together
    return salt.hex() + ':' + key.hex()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against stored hash. Supports both old SHA-256 and new PBKDF2."""
    if ':' not in password_hash:
        # Old SHA-256 format (for backward compatibility)
        old_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return secrets.compare_digest(old_hash, password_hash)
    else:
        # New PBKDF2 format
        try:
            salt_hex, key_hex = password_hash.split(':', 1)
            salt = bytes.fromhex(salt_hex)
            stored_key = bytes.fromhex(key_hex)
            new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
            return secrets.compare_digest(new_key, stored_key)
        except (ValueError, AttributeError):
            return False

def validate_input_length(text: str, field_name: str, max_length: int = MAX_INPUT_LENGTH) -> None:
    """Validate input length. Raises ValueError if too long."""
    if text and len(text) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length} characters")

# ---------------------------------------------------------------------------
# Auth / Sessions / Account Lockout
# ---------------------------------------------------------------------------

def is_account_locked(username: str) -> bool:
    """Check if account is currently locked."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT locked_until FROM users WHERE username=? AND locked_until > datetime('now')",
            (username,)
        ).fetchone()
        if row:
            return True
        # Also check account_lockouts table
        row = conn.execute(
            "SELECT unlock_at FROM account_lockouts WHERE username=? AND unlock_at > datetime('now')",
            (username,)
        ).fetchone()
        return row is not None

def record_login_attempt(username: str, ip_address: str, success: bool):
    """Record login attempt and apply lockout if needed."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
            (username, ip_address, 1 if success else 0)
        )
        if not success:
            # Count recent failed attempts (last 15 minutes)
            cutoff = (datetime.utcnow() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
            failed_count = conn.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE username=? AND success=0 AND timestamp > ?",
                (username, cutoff)
            ).fetchone()[0]
            
            if failed_count >= MAX_LOGIN_ATTEMPTS:
                # Lock the account
                unlock_at = (datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
                conn.execute(
                    "INSERT OR REPLACE INTO account_lockouts (username, locked_at, unlock_at) VALUES (?, datetime('now'), ?)",
                    (username, unlock_at)
                )
                conn.execute(
                    "UPDATE users SET locked_until=?, failed_login_count=? WHERE username=?",
                    (unlock_at, failed_count, username)
                )
                conn.execute(
                    "INSERT INTO audit_log (username, action, table_name, record_id) VALUES (?, ?, ?, ?)",
                    (username, 'ACCOUNT_LOCKED', 'users', username)
                )
        else:
            # Clear failed login count on success
            conn.execute(
                "UPDATE users SET failed_login_count=0, locked_until=NULL WHERE username=?",
                (username,)
            )
            conn.execute(
                "DELETE FROM account_lockouts WHERE username=?",
                (username,)
            )

def login(username: str, password: str, ip_address: str = None):
    """Authenticate user and return user dict if successful."""
    # Check if account is locked
    if is_account_locked(username):
        record_login_attempt(username, ip_address, False)
        return None
    
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
    
    if row and verify_password(password, row['password_hash']):
        record_login_attempt(username, ip_address, True)
        user = dict(row)
        # Check if password needs upgrade from old SHA-256 to PBKDF2
        if ':' not in row['password_hash']:
            # Rehash with new method
            new_hash = _hash_password(password)
            with get_connection() as conn:
                conn.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (new_hash, row['id'])
                )
            user['password_hash'] = new_hash
        return user
    else:
        if row:  # User exists but wrong password
            record_login_attempt(username, ip_address, False)
        return None

def create_session(user_id: int, username: str, role: str) -> tuple:
    """Create new session and return (session_id, csrf_token)."""
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, user_id, username, role, csrf_token, expires_at)
        )
    return session_id, csrf_token

def get_session(session_id: str):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id=? AND expires_at > datetime('now')",
            (session_id,)
        ).fetchone()
    return dict(row) if row else None

def delete_session(session_id: str):
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))

def regenerate_session(old_session_id: str) -> tuple:
    """Regenerate session ID after login to prevent session fixation."""
    session = get_session(old_session_id)
    if not session:
        return None, None
    
    # Create new session with same user but new IDs
    new_session_id = secrets.token_urlsafe(32)
    new_csrf_token = secrets.token_urlsafe(32)
    
    with get_connection() as conn:
        # Delete old session
        conn.execute("DELETE FROM sessions WHERE session_id=?", (old_session_id,))
        # Create new session
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
            (new_session_id, session['user_id'], session['username'], 
             session['role'], new_csrf_token, session['expires_at'])
        )
    return new_session_id, new_csrf_token

def validate_csrf_token(session_id: str, provided_token: str) -> bool:
    """Validate CSRF token for a session."""
    session = get_session(session_id)
    if not session or 'csrf_token' not in session:
        return False
    return secrets.compare_digest(session['csrf_token'], provided_token)

def cleanup_sessions():
    """Remove expired sessions and old login attempts."""
    with get_connection() as conn:
        # Remove expired sessions
        conn.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")
        # Remove old login attempts (keep only last 24 hours)
        cutoff = (datetime.utcnow() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("DELETE FROM login_attempts WHERE timestamp < ?", (cutoff,))
        # Remove expired lockouts
        conn.execute("DELETE FROM account_lockouts WHERE unlock_at <= datetime('now')")

# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------

def get_requirements(req_type=None, status=None, priority=None,
                     owner=None, search=None, parent_id=None):
    query  = "SELECT * FROM requirements WHERE 1=1"
    params = []
    if req_type:
        query += " AND req_type=?";   params.append(req_type)
    if status:
        query += " AND status=?";     params.append(status)
    if priority:
        query += " AND priority=?";   params.append(priority)
    if owner:
        query += " AND primary_owner=?"; params.append(owner)
    if parent_id:
        query += " AND parent_id=?";  params.append(parent_id)
    if search:
        query += " AND req_text LIKE ?"; params.append(f'%{search}%')
    query += " ORDER BY req_id"
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]

def get_requirement(req_id: str):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM requirements WHERE req_id=?", (req_id,)
        ).fetchone()
    return dict(row) if row else None

def update_requirement(req_id: str, data: dict, username: str):
    allowed = ['priority', 'collection_frequency', 'primary_owner',
               'status', 'notes', 'req_text']
    old = get_requirement(req_id)
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return
    with get_connection() as conn:
        for field, value in updates.items():
            conn.execute(
                f"UPDATE requirements SET {field}=?, updated_at=datetime('now'), updated_by=? WHERE req_id=?",
                (value, username, req_id)
            )
        conn.execute(
            "INSERT INTO audit_log (username, action, table_name, record_id, old_value, new_value) "
            "VALUES (?,?,?,?,?,?)",
            (username, 'UPDATE', 'requirements', req_id,
             json.dumps(old), json.dumps(updates))
        )

# ---------------------------------------------------------------------------
# Source coverage
# ---------------------------------------------------------------------------

def get_source_coverage(req_id: str):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM source_coverage WHERE req_id=? ORDER BY source_category, source_name",
            (req_id,)
        ).fetchall()
    return [dict(r) for r in rows]

def upsert_source_coverage(req_id: str, source_name: str,
                           coverage_value, username: str, source_category: str = '',
                           detection_logic: str = None):
    with get_connection() as conn:
        old = conn.execute(
            "SELECT coverage_value, detection_logic FROM source_coverage WHERE req_id=? AND source_name=?",
            (req_id, source_name)
        ).fetchone()
        conn.execute(
            """INSERT INTO source_coverage (req_id, source_name, source_category, coverage_value, detection_logic, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(req_id, source_name)
               DO UPDATE SET coverage_value=excluded.coverage_value,
                             detection_logic=excluded.detection_logic,
                             updated_at=excluded.updated_at""",
            (req_id, source_name, source_category, coverage_value or None, detection_logic or None)
        )
        conn.execute(
            "INSERT INTO audit_log (username, action, table_name, record_id, old_value, new_value) "
            "VALUES (?,?,?,?,?,?)",
            (username, 'UPDATE', 'source_coverage', f'{req_id}/{source_name}',
             old['coverage_value'] if old else None, coverage_value)
        )

def upsert_many_sources(req_id: str, coverage_map: dict, username: str):
    """coverage_map = {source_name: {coverage_value, detection_logic} or plain string}"""
    for source_name, val in coverage_map.items():
        if isinstance(val, dict):
            upsert_source_coverage(req_id, source_name,
                                   val.get('coverage_value'), username,
                                   detection_logic=val.get('detection_logic'))
        else:
            upsert_source_coverage(req_id, source_name, val, username)

# ---------------------------------------------------------------------------
# Sources management
# ---------------------------------------------------------------------------

def get_sources() -> list:
    """Return ordered list of source names."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT name FROM sources ORDER BY sort_order, id"
        ).fetchall()
    return [r['name'] for r in rows]

def add_source(name: str) -> None:
    with get_connection() as conn:
        max_order = conn.execute(
            "SELECT COALESCE(MAX(sort_order), -1) FROM sources"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO sources (name, sort_order) VALUES (?, ?)",
            (name.strip(), max_order + 1)
        )

def delete_source(name: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM sources WHERE name=?", (name,))
        conn.execute("DELETE FROM source_coverage WHERE source_name=?", (name,))

# ---------------------------------------------------------------------------
# Matrix (full data for table view)
# ---------------------------------------------------------------------------

def get_matrix_data():
    with get_connection() as conn:
        requirements = [dict(r) for r in
                        conn.execute("SELECT * FROM requirements ORDER BY req_id").fetchall()]
        coverage_rows = conn.execute("SELECT * FROM source_coverage").fetchall()

    cov_map = {}
    for row in coverage_rows:
        rid = row['req_id']
        if rid not in cov_map:
            cov_map[rid] = {}
        cov_map[rid][row['source_name']] = {
            'coverage_value': row['coverage_value'],
            'detection_logic': row['detection_logic'],
        }

    for req in requirements:
        req['coverage'] = cov_map.get(req['req_id'], {})
    return requirements

# ---------------------------------------------------------------------------
# Create / Delete requirements
# ---------------------------------------------------------------------------

def next_req_id(req_type: str, parent_id: str = None) -> str:
    """Return the next auto-generated requirement ID for the given type."""
    with get_connection() as conn:
        if req_type == 'PIR':
            rows = conn.execute(
                "SELECT req_id FROM requirements WHERE req_type='PIR'"
            ).fetchall()
            nums = [int(m.group(1)) for r in rows
                    for m in [re.match(r'^PIR-(\d+)$', r['req_id'])] if m]
            n = max(nums) + 1 if nums else 1
            return f'PIR-{n:03d}'

        elif req_type == 'EEI' and parent_id:
            pir_num = parent_id[4:]   # e.g. '001'
            rows = conn.execute(
                "SELECT req_id FROM requirements WHERE req_type='EEI' AND parent_id=?",
                (parent_id,)
            ).fetchall()
            pat = rf'^EEI-{re.escape(pir_num)}\.(\d+)$'
            nums = [int(m.group(1)) for r in rows
                    for m in [re.match(pat, r['req_id'], re.IGNORECASE)] if m]
            n = max(nums) + 1 if nums else 1
            return f'EEI-{pir_num}.{n}'

        elif req_type == 'SIR' and parent_id:
            eei_suffix = parent_id[4:]  # e.g. '001.1'
            rows = conn.execute(
                "SELECT req_id FROM requirements WHERE req_type='SIR' AND parent_id=?",
                (parent_id,)
            ).fetchall()
            pat = rf'^SIR-{re.escape(eei_suffix)}\.(\d+)$'
            nums = [int(m.group(1)) for r in rows
                    for m in [re.match(pat, r['req_id'], re.IGNORECASE)] if m]
            n = max(nums) + 1 if nums else 1
            return f'SIR-{eei_suffix}.{n}'

    return f'{req_type}-NEW'


def create_requirement(req_id: str, req_type: str, req_text: str,
                       parent_id: str, status: str, username: str) -> dict:
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO requirements
               (req_id, req_type, req_text, parent_id, status, updated_by)
               VALUES (?,?,?,?,?,?)""",
            (req_id, req_type, req_text, parent_id or None,
             status or 'Active', username)
        )
        conn.execute(
            "INSERT INTO audit_log (username, action, table_name, record_id, new_value) "
            "VALUES (?,?,?,?,?)",
            (username, 'CREATE', 'requirements', req_id,
             json.dumps({'req_type': req_type, 'req_text': req_text}))
        )
    return get_requirement(req_id)


def delete_requirement(req_id: str, username: str) -> dict:
    """Delete a requirement, cascading to all children and their coverage."""
    req = get_requirement(req_id)
    if not req:
        return {'deleted': 0, 'ids': []}

    with get_connection() as conn:
        to_delete = [req_id]

        if req['req_type'] == 'PIR':
            eeis = conn.execute(
                "SELECT req_id FROM requirements WHERE req_type='EEI' AND parent_id=?",
                (req_id,)
            ).fetchall()
            for eei in eeis:
                to_delete.append(eei['req_id'])
                sirs = conn.execute(
                    "SELECT req_id FROM requirements WHERE req_type='SIR' AND parent_id=?",
                    (eei['req_id'],)
                ).fetchall()
                to_delete.extend(r['req_id'] for r in sirs)

        elif req['req_type'] == 'EEI':
            sirs = conn.execute(
                "SELECT req_id FROM requirements WHERE req_type='SIR' AND parent_id=?",
                (req_id,)
            ).fetchall()
            to_delete.extend(r['req_id'] for r in sirs)

        ph = ','.join('?' * len(to_delete))
        conn.execute(f"DELETE FROM source_coverage WHERE req_id IN ({ph})", to_delete)
        conn.execute(f"DELETE FROM requirements WHERE req_id IN ({ph})", to_delete)
        conn.execute(
            "INSERT INTO audit_log (username, action, table_name, record_id, old_value) "
            "VALUES (?,?,?,?,?)",
            (username, 'DELETE', 'requirements', req_id,
             json.dumps({'cascade': to_delete}))
        )

    return {'deleted': len(to_delete), 'ids': to_delete}


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------

def get_coverage_gaps():
    """Return EEIs/SIRs with zero source coverage, grouped by PIR."""
    with get_connection() as conn:
        covered_ids = {r['req_id'] for r in conn.execute(
            "SELECT DISTINCT req_id FROM source_coverage "
            "WHERE coverage_value IS NOT NULL AND coverage_value != ''"
        ).fetchall()}
        reqs = [dict(r) for r in conn.execute(
            "SELECT * FROM requirements ORDER BY req_id"
        ).fetchall()]
        source_count = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]

    pir_map, eei_map, sir_map = {}, {}, {}
    for r in reqs:
        if r['req_type'] == 'PIR':
            pir_map[r['req_id']] = r
        elif r['req_type'] == 'EEI':
            eei_map.setdefault(r['parent_id'], []).append(r)
        elif r['req_type'] == 'SIR':
            sir_map.setdefault(r['parent_id'], []).append(r)

    gaps = []
    for pir_id, pir in pir_map.items():
        for eei in eei_map.get(pir_id, []):
            eei_sirs = sir_map.get(eei['req_id'], [])
            uncovered_sirs = [s for s in eei_sirs if s['req_id'] not in covered_ids]
            eei_covered = eei['req_id'] in covered_ids
            if uncovered_sirs or not eei_covered:
                gaps.append({
                    'pir_id':   pir_id,
                    'pir_text': pir['req_text'],
                    'eei_id':   eei['req_id'],
                    'eei_text': eei['req_text'],
                    'eei_covered': eei_covered,
                    'sir_total':   len(eei_sirs),
                    'sir_uncovered': len(uncovered_sirs),
                    'uncovered_sirs': [{'req_id': s['req_id'], 'req_text': s['req_text'],
                                        'priority': s['priority']} for s in uncovered_sirs],
                })
    total_sirs = sum(len(v) for v in sir_map.values())
    covered_sirs = sum(1 for r in reqs if r['req_type'] == 'SIR' and r['req_id'] in covered_ids)
    return {
        'gaps': gaps,
        'source_count': source_count,
        'total_sirs': total_sirs,
        'covered_sirs': covered_sirs,
        'uncovered_sirs': total_sirs - covered_sirs,
    }


def get_export_data():
    """Full requirements + coverage for CSV export."""
    with get_connection() as conn:
        reqs = [dict(r) for r in conn.execute(
            "SELECT * FROM requirements ORDER BY req_id"
        ).fetchall()]
        sources = [r['name'] for r in conn.execute(
            "SELECT name FROM sources ORDER BY sort_order"
        ).fetchall()]
        cov_rows = conn.execute("SELECT * FROM source_coverage").fetchall()
    cov_map = {}
    for row in cov_rows:
        cov_map.setdefault(row['req_id'], {})[row['source_name']] = {
            'coverage_value':  row['coverage_value'],
            'detection_logic': row['detection_logic'],
        }
    return {'requirements': reqs, 'sources': sources, 'coverage': cov_map}


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def get_stats():
    with get_connection() as conn:
        stats = {}
        for rt in ['PIR', 'EEI', 'SIR']:
            stats[rt.lower() + '_count'] = conn.execute(
                "SELECT COUNT(*) FROM requirements WHERE req_type=?", (rt,)
            ).fetchone()[0]
        stats['active_count'] = conn.execute(
            "SELECT COUNT(*) FROM requirements WHERE status='Active'"
        ).fetchone()[0]
        stats['inactive_count'] = conn.execute(
            "SELECT COUNT(*) FROM requirements WHERE status='Inactive'"
        ).fetchone()[0]
        for pri in ['Critical', 'High', 'Medium', 'Low']:
            stats['priority_' + pri.lower()] = conn.execute(
                "SELECT COUNT(*) FROM requirements WHERE priority=?", (pri,)
            ).fetchone()[0]
        stats['covered_count'] = conn.execute(
            "SELECT COUNT(DISTINCT req_id) FROM source_coverage "
            "WHERE coverage_value IS NOT NULL AND coverage_value != ''"
        ).fetchone()[0]
        stats['total_requirements'] = (
            stats['pir_count'] + stats['eei_count'] + stats['sir_count']
        )
        # Distinct owners
        rows = conn.execute(
            "SELECT DISTINCT primary_owner FROM requirements "
            "WHERE primary_owner IS NOT NULL ORDER BY primary_owner"
        ).fetchall()
        stats['owners'] = [r[0] for r in rows]
    return stats

# ---------------------------------------------------------------------------
# Users (admin only)
# ---------------------------------------------------------------------------

def get_users():
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, username, role, full_name, created_at FROM users ORDER BY username"
        ).fetchall()]

def create_user(username: str, password: str, role: str, full_name: str):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, full_name) VALUES (?,?,?,?)",
            (username, _hash_password(password), role, full_name)
        )

def update_user(user_id: int, data: dict):
    with get_connection() as conn:
        if 'password' in data and data['password']:
            conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                         (_hash_password(data['password']), user_id))
        if 'role' in data:
            conn.execute("UPDATE users SET role=? WHERE id=?",
                         (data['role'], user_id))
        if 'full_name' in data:
            conn.execute("UPDATE users SET full_name=? WHERE id=?",
                         (data['full_name'], user_id))

def delete_user(user_id: int):
    with get_connection() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))

def change_password(username: str, old_password: str, new_password: str) -> bool:
    """Change user password. Returns True if successful."""
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username=?",
            (username,)
        ).fetchone()
        
        if not row:
            return False
        
        # Verify old password
        if not verify_password(old_password, row['password_hash']):
            return False
        
        # Update to new password
        new_hash = _hash_password(new_password)
        conn.execute(
            "UPDATE users SET password_hash=?, password_needs_reset=0 WHERE id=?",
            (new_hash, row['id'])
        )
        conn.execute(
            "INSERT INTO audit_log (username, action, table_name, record_id) VALUES (?, ?, ?, ?)",
            (username, 'PASSWORD_CHANGE', 'users', username)
        )
        return True

# ---------------------------------------------------------------------------
# Background cleanup task
# ---------------------------------------------------------------------------

_cleanup_thread = None
_cleanup_stop = False

def start_cleanup_thread():
    """Start background thread to periodically clean up expired sessions."""
    global _cleanup_thread, _cleanup_stop
    if _cleanup_thread and _cleanup_thread.is_alive():
        return  # Already running
    
    _cleanup_stop = False
    def cleanup_loop():
        while not _cleanup_stop:
            try:
                cleanup_sessions()
            except Exception as e:
                print(f"[db] Cleanup error: {e}")
            # Sleep for 15 minutes
            for _ in range(900):  # 15 minutes in seconds
                if _cleanup_stop:
                    break
                time.sleep(1)
    
    _cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    _cleanup_thread.start()
    print("[db] Background cleanup thread started")

def stop_cleanup_thread():
    """Stop the background cleanup thread."""
    global _cleanup_stop
    _cleanup_stop = True

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def get_audit_log(limit: int = 200):
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()]


if __name__ == '__main__':
    init_db()
    print(f"[db] Database initialised at: {DB_PATH}")
