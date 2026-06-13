"""SQLite-backed user store for the IR web app.

Schema is created on first connect. WAL mode is enabled so the Flask app
and the ccr shim (which runs in a separate process) can both read/write
the database safely.
"""
from __future__ import annotations

import ipaddress
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator, Optional

_DEFAULT_PATH = '/home/vinay/security-ops-platform/data/auth/auth.db'


def _path() -> str:
    return os.environ.get('AUTH_DB_PATH', _DEFAULT_PATH)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    email_verified_at INTEGER,
    role TEXT,
    access_reason TEXT,
    exclude_from_traffic_log INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS email_verify_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pats_user ON pats(user_id);
CREATE INDEX IF NOT EXISTS idx_evt_user ON email_verify_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_prt_user ON password_reset_tokens(user_id);
CREATE TABLE IF NOT EXISTS pat_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pat_id INTEGER NOT NULL REFERENCES pats(id),
    client_ip TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(pat_id, client_ip)
);
CREATE INDEX IF NOT EXISTS idx_pat_usage_pat ON pat_usage(pat_id);
"""


def _connect() -> sqlite3.Connection:
    path = _path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=5000')
    return conn


_initialized = False


def _migrate(conn: sqlite3.Connection) -> None:
    """Idempotent column-add migrations for pre-existing DBs.

    Pre-existing rows are left with NULL role on purpose — the admin is
    asked to assign roles to legacy users manually; we don't silently
    backfill a default that might misrepresent them.
    """
    user_cols = {r['name'] for r in conn.execute('PRAGMA table_info(users)').fetchall()}
    if 'role' not in user_cols:
        conn.execute('ALTER TABLE users ADD COLUMN role TEXT')

    # Free-text "why do you need this access?" captured at signup. Old rows
    # pre-date the field and stay NULL — the admin reads it as a blank cell.
    if 'access_reason' not in user_cols:
        conn.execute('ALTER TABLE users ADD COLUMN access_reason TEXT')

    # The role a user *requested* at signup (or via /account). Non-binding —
    # the effective `role` (which drives capabilities) is admin-assigned.
    # Old rows pre-date the split; their self-selected value lives in `role`
    # and is mirrored here so the admin can see what they originally asked
    # for. See web/auth/rbac.py.
    if 'requested_role' not in user_cols:
        conn.execute('ALTER TABLE users ADD COLUMN requested_role TEXT')
        conn.execute(
            'UPDATE users SET requested_role = role '
            'WHERE requested_role IS NULL AND role IS NOT NULL'
        )

    # Per-user capability grants ON TOP of what the role confers, as a
    # comma-separated token list (e.g. "data.destructive"). Lets an admin
    # grant a single person a sensitive capability on request without
    # changing their role or promoting them to admin. See web/auth/rbac.py.
    if 'extra_capabilities' not in user_cols:
        conn.execute('ALTER TABLE users ADD COLUMN extra_capabilities TEXT')

    # Per-user opt-out from web traffic logging, keyed on auth identity rather
    # than IP (replaces the old SCANNER_IPS self-exclusion). Old rows default
    # to 0 = logged.
    if 'exclude_from_traffic_log' not in user_cols:
        conn.execute(
            'ALTER TABLE users ADD COLUMN exclude_from_traffic_log INTEGER NOT NULL DEFAULT 0'
        )

    # Persist the plaintext PAT so users can come back to /account and copy
    # it later — by design this trades the "shown once" security property
    # for ergonomics on this internal tool. Old rows stay NULL (we never
    # had the plaintext for them).
    pat_cols = {r['name'] for r in conn.execute('PRAGMA table_info(pats)').fetchall()}
    if 'token_plaintext' not in pat_cols:
        conn.execute('ALTER TABLE pats ADD COLUMN token_plaintext TEXT')


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    global _initialized
    conn = _connect()
    try:
        if not _initialized:
            conn.executescript(_SCHEMA)
            _migrate(conn)
            _initialized = True
        yield conn
    finally:
        conn.close()


def now() -> int:
    return int(time.time())


# --- users -----------------------------------------------------------------

def create_user(email: str, password_hash: str, role: str,
                access_reason: Optional[str] = None,
                requested_role: Optional[str] = None) -> int:
    with connect() as c:
        cur = c.execute(
            'INSERT INTO users(email, password_hash, role, access_reason, requested_role, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (email.strip().lower(), password_hash, role, access_reason, requested_role, now()),
        )
        return cur.lastrowid


def set_user_role(user_id: int, role: str) -> None:
    """Set a user's *effective* (capability-bearing) role. Admin action."""
    with connect() as c:
        c.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))


def set_user_requested_role(user_id: int, role: str) -> None:
    """Set a user's *requested* role hint. Self-service; non-binding."""
    with connect() as c:
        c.execute('UPDATE users SET requested_role = ? WHERE id = ?', (role, user_id))


def set_user_extra_capabilities(user_id: int, caps_csv: str) -> None:
    """Set a user's per-user capability grants (comma-separated tokens, or ''
    to clear). Admin action; capabilities granted on top of the role."""
    with connect() as c:
        c.execute('UPDATE users SET extra_capabilities = ? WHERE id = ?',
                  (caps_csv or None, user_id))


def set_user_traffic_log_exclude(user_id: int, exclude: bool) -> None:
    with connect() as c:
        c.execute(
            'UPDATE users SET exclude_from_traffic_log = ? WHERE id = ?',
            (1 if exclude else 0, user_id),
        )


def distinct_assigned_roles() -> list[str]:
    """Distinct, non-empty role values held by verified accounts, sorted.

    Used to surface roles a previous registrant entered via the "Other"
    box on the signup dropdown, so the next person can pick one instead
    of re-typing it. Verified-only so an unconfirmed drive-by signup
    can't pollute the list; preset/admin filtering happens in helpers.
    """
    with connect() as c:
        rows = c.execute(
            "SELECT DISTINCT role FROM users "
            "WHERE role IS NOT NULL AND TRIM(role) != '' "
            "AND email_verified_at IS NOT NULL "
            "ORDER BY role COLLATE NOCASE"
        ).fetchall()
        return [r['role'] for r in rows]


def list_users_without_role() -> list[sqlite3.Row]:
    with connect() as c:
        return list(c.execute(
            'SELECT id, email FROM users WHERE role IS NULL ORDER BY id'
        ).fetchall())


def list_users_with_pat_summary() -> list[dict]:
    """For the admin page: every registered user joined with a summary of
    their PAT activity. `active_pats` = unrevoked, unexpired tokens.
    `total_pats` includes revoked/expired ones — so an admin can tell at
    a glance "user signed up but never minted a token" vs "user minted
    one and revoked it" vs "user has a live token in use."
    """
    now_ts = now()
    with connect() as c:
        rows = c.execute(
            'SELECT u.id, u.email, u.role, u.requested_role, u.extra_capabilities, u.access_reason, u.exclude_from_traffic_log, '
            '       u.email_verified_at, u.created_at, '
            '       COUNT(p.id) AS total_pats, '
            '       SUM(CASE WHEN p.revoked_at IS NULL AND p.expires_at >= ? THEN 1 ELSE 0 END) AS active_pats, '
            '       MAX(p.last_used_at) AS last_pat_used_at, '
            '       MAX(p.created_at) AS last_pat_created_at '
            'FROM users u LEFT JOIN pats p ON p.user_id = u.id '
            'GROUP BY u.id '
            'ORDER BY u.created_at DESC',
            (now_ts,),
        ).fetchall()
        return [
            {
                'id': r['id'],
                'email': r['email'],
                'role': r['role'],
                'requested_role': r['requested_role'],
                'extra_capabilities': r['extra_capabilities'],
                'access_reason': r['access_reason'],
                'exclude_from_traffic_log': bool(r['exclude_from_traffic_log']),
                'email_verified': r['email_verified_at'] is not None,
                'created_at': r['created_at'],
                'total_pats': r['total_pats'] or 0,
                'active_pats': r['active_pats'] or 0,
                'last_pat_used_at': r['last_pat_used_at'],
                'last_pat_created_at': r['last_pat_created_at'],
            }
            for r in rows
        ]


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with connect() as c:
        return c.execute(
            'SELECT * FROM users WHERE email = ? COLLATE NOCASE',
            (email.strip().lower(),),
        ).fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with connect() as c:
        return c.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def mark_email_verified(user_id: int) -> None:
    with connect() as c:
        c.execute(
            'UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL',
            (now(), user_id),
        )


def update_password_hash(user_id: int, password_hash: str) -> None:
    with connect() as c:
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))


# --- one-time tokens -------------------------------------------------------

def insert_email_verify_token(user_id: int, token_hash: str, expires_at: int) -> None:
    with connect() as c:
        c.execute(
            'INSERT INTO email_verify_tokens(user_id, token_hash, expires_at, created_at) '
            'VALUES (?, ?, ?, ?)',
            (user_id, token_hash, expires_at, now()),
        )


def consume_email_verify_token(token_hash: str) -> Optional[int]:
    with connect() as c:
        row = c.execute(
            'SELECT id, user_id, expires_at, used_at FROM email_verify_tokens WHERE token_hash = ?',
            (token_hash,),
        ).fetchone()
        if not row or row['used_at'] is not None or row['expires_at'] < now():
            return None
        c.execute('UPDATE email_verify_tokens SET used_at = ? WHERE id = ?', (now(), row['id']))
        return row['user_id']


def insert_password_reset_token(user_id: int, token_hash: str, expires_at: int) -> None:
    with connect() as c:
        c.execute(
            'INSERT INTO password_reset_tokens(user_id, token_hash, expires_at, created_at) '
            'VALUES (?, ?, ?, ?)',
            (user_id, token_hash, expires_at, now()),
        )


def consume_password_reset_token(token_hash: str) -> Optional[int]:
    with connect() as c:
        row = c.execute(
            'SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ?',
            (token_hash,),
        ).fetchone()
        if not row or row['used_at'] is not None or row['expires_at'] < now():
            return None
        c.execute('UPDATE password_reset_tokens SET used_at = ? WHERE id = ?', (now(), row['id']))
        return row['user_id']


# --- pats ------------------------------------------------------------------

def insert_pat(user_id: int, name: str, token_hash: str, token_plaintext: str, expires_at: int) -> int:
    with connect() as c:
        cur = c.execute(
            'INSERT INTO pats(user_id, name, token_hash, token_plaintext, expires_at, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (user_id, name, token_hash, token_plaintext, expires_at, now()),
        )
        return cur.lastrowid


def list_pats(user_id: int) -> list[sqlite3.Row]:
    with connect() as c:
        return list(c.execute(
            'SELECT id, name, token_plaintext, expires_at, last_used_at, revoked_at, created_at '
            'FROM pats WHERE user_id = ? ORDER BY created_at DESC',
            (user_id,),
        ).fetchall())


def revoke_pat(user_id: int, pat_id: int) -> bool:
    with connect() as c:
        cur = c.execute(
            'UPDATE pats SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL',
            (now(), pat_id, user_id),
        )
        return cur.rowcount > 0


# Corp-side IP ranges where NAT/proxy egress rotates within a pool. An IP
# inside one of these ranges is collapsed to its /24 for the "is this a
# new client?" check, so the same user bouncing between adjacent NAT
# exits (e.g. <internal-host> → 134 → 135) does not look like 3 separate
# clients. Public IPs are NOT bucketed — that's where genuine PAT sharing
# (a token leaked to someone outside corp) would show up.
_CORP_BUCKET_NETS = tuple(
    ipaddress.ip_network(n) for n in (
        '10.0.0.0/8',       # RFC1918 private range
        '172.16.0.0/12',    # RFC1918 private range
        '192.168.0.0/16',   # RFC1918 private range
        '127.0.0.0/8',      # loopback
    )
)


def _bucket_ip(ip: str) -> str:
    """Return a stable bucket key for sharing-detection purposes.

    Corp/private ranges → /24 of the address (so a NAT pool counts once).
    Public IPs → unchanged (1:1 — that's where real sharing surfaces).
    Unparseable input → returned as-is.
    """
    s = (ip or '').strip()
    if not s or s == 'unknown':
        return s or 'unknown'
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return s
    for net in _CORP_BUCKET_NETS:
        if addr in net:
            return str(ipaddress.ip_network(f'{s}/24', strict=False))
    return s


def record_pat_usage(pat_id: int, client_ip: str) -> None:
    """Stamp this (pat_id, client_ip) pair for the admin audit view.

    The raw IP is stored 1:1 in `pat_usage` (UNIQUE(pat_id, client_ip)).
    The admin Traffic Logs page uses `_bucket_ip` at read time to collapse
    corp NAT exits when surfacing the SHARED signal — see
    `list_pat_usage_admin`.
    """
    ts = now()
    ip = (client_ip or '').strip() or 'unknown'
    with connect() as c:
        cur = c.execute(
            'INSERT OR IGNORE INTO pat_usage(pat_id, client_ip, first_seen_at, last_seen_at, request_count) '
            'VALUES (?, ?, ?, ?, 1)',
            (pat_id, ip, ts, ts),
        )
        if cur.rowcount == 0:
            c.execute(
                'UPDATE pat_usage SET last_seen_at = ?, request_count = request_count + 1 '
                'WHERE pat_id = ? AND client_ip = ?',
                (ts, pat_id, ip),
            )


def list_pat_usage_admin() -> list[dict]:
    """Return one row per PAT joined with its IP fingerprint summary.
    Used by the Traffic Logs admin tab.

    `ips` is a JSON-serializable list of {ip, bucket, first_seen_at,
    last_seen_at, request_count} sorted by last_seen desc.

    Sharing signal:
      `distinct_ip_count`     — raw row count (forensic — counts NAT exits)
      `distinct_bucket_count` — buckets the IPs fall into (corp NATs
                                collapsed to /24, public IPs 1:1). This is
                                what the UI should highlight; >1 means the
                                token has been seen from genuinely
                                different clients.
    """
    with connect() as c:
        rows = c.execute(
            'SELECT p.id AS pat_id, p.name, p.created_at, p.expires_at, '
            '       p.last_used_at, p.revoked_at, u.email '
            'FROM pats p JOIN users u ON u.id = p.user_id '
            'ORDER BY p.created_at DESC'
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            ip_rows = c.execute(
                'SELECT client_ip, first_seen_at, last_seen_at, request_count '
                'FROM pat_usage WHERE pat_id = ? '
                'ORDER BY last_seen_at DESC',
                (r['pat_id'],),
            ).fetchall()
            ips = []
            buckets: set[str] = set()
            for ipr in ip_rows:
                bucket = _bucket_ip(ipr['client_ip'])
                buckets.add(bucket)
                ips.append({
                    'ip': ipr['client_ip'],
                    'bucket': bucket,
                    'first_seen_at': ipr['first_seen_at'],
                    'last_seen_at': ipr['last_seen_at'],
                    'request_count': ipr['request_count'],
                })
            out.append({
                'pat_id': r['pat_id'],
                'email': r['email'],
                'name': r['name'],
                'created_at': r['created_at'],
                'expires_at': r['expires_at'],
                'last_used_at': r['last_used_at'],
                'revoked': r['revoked_at'] is not None,
                'distinct_ip_count': len(ips),
                'distinct_bucket_count': len(buckets),
                'ips': ips,
            })
        return out


def lookup_pat(token_hash: str) -> Optional[sqlite3.Row]:
    """Return the active PAT row (with joined user email) or None."""
    with connect() as c:
        row = c.execute(
            'SELECT p.id, p.user_id, p.name, p.expires_at, p.revoked_at, '
            '       u.email, u.email_verified_at '
            'FROM pats p JOIN users u ON u.id = p.user_id '
            'WHERE p.token_hash = ?',
            (token_hash,),
        ).fetchone()
        if not row or row['revoked_at'] is not None or row['expires_at'] < now():
            return None
        c.execute('UPDATE pats SET last_used_at = ? WHERE id = ?', (now(), row['id']))
        return row
