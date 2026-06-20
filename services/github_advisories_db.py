"""SQLite store for the security-advisory triage workflow.

Originally GitHub-only (hence the module/route name), this is now a
**multi-source** store: the hourly poller pulls from several advisory feeds
(GitHub reviewed-critical, GitHub malware, OSV malicious packages, CISA KEV)
and each advisory becomes one row here. The row IS the dedup key, the
notification record, and the triage record (status / notes / who-reviewed /
who-reported), so there is a single source of truth that the poller, the email
link, and the web page all read and write.

Identity & dedup
----------------
Each row has a synthetic ``uid = "{source}:{source_id}"`` primary key. Because
the same vulnerability shows up in several feeds (e.g. a GitHub malware GHSA is
re-published by OSV; a CVE appears in both NVD-derived feeds and CISA KEV),
every known identifier for a row (its native id, CVE, GHSA, MAL-id, …) is
recorded in the ``advisory_aliases`` table pointing back at the owning uid. On
insert we first check whether ANY of a candidate's aliases is already known —
if so it's a cross-source duplicate and is skipped (the first feed to report it
owns it). This keeps the queue free of the same finding reported three times.

Lifecycle of ``status``:
    seeded               -> pre-existing the first time a source is polled;
                            never notified and HIDDEN from the web queue
                            entirely, so onboarding a new feed doesn't dump its
                            historical backlog on the reviewer. Internal
                            baseline only — not a user-facing state.
    new                  -> freshly published after a source's baseline; notified.
    under_review         -> a reviewer opened it / saved notes.
    closed_not_reported  -> reviewed, judged not worth escalating.
    reported             -> escalated to the Package Compromise Assessment Teams
                            channel (terminal; ``reported_at`` set, idempotent).

Adding a source: see ``services.github_advisories`` — a source only has to
produce *normalized records* (see ``upsert_advisory`` for the shape). Nothing
here is GitHub-specific, so a future free-text / LLM-extracted source (a blog
or RSS post with no CVE/CVSS, packages pulled by a model) is just another
``source`` value with ``cve_id``/``ecosystem`` left null.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).resolve().parent.parent / "data" / "transient" / "github_advisories"
DB_PATH = DB_DIR / "advisories.db"

# Statuses that count as an open item in the reviewer's active queue.
ACTIVE_STATUSES = ("new", "under_review")
ALL_STATUSES = ("seeded", "new", "under_review", "closed_not_reported", "reported")


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


# ---------------------------------------------------------------------------
# Schema + migration
# ---------------------------------------------------------------------------
_ADVISORIES_SCHEMA = """
    CREATE TABLE IF NOT EXISTS advisories (
        uid           TEXT PRIMARY KEY,
        source        TEXT NOT NULL,
        source_id     TEXT NOT NULL,
        cve_id        TEXT,
        aliases       TEXT,
        summary       TEXT,
        description   TEXT,
        severity      TEXT,
        ecosystem     TEXT,
        packages      TEXT,
        published_at  TEXT,
        html_url      TEXT,
        raw_json      TEXT,
        status        TEXT NOT NULL DEFAULT 'new',
        notes         TEXT,
        reviewed_by   TEXT,
        reviewed_at   TEXT,
        reported_by   TEXT,
        reported_at   TEXT,
        first_seen_at TEXT NOT NULL,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        ai_assessment TEXT,
        veracode_enrichment TEXT
    )
"""


def init_db() -> None:
    with get_connection() as conn:
        # Migrate the legacy GHSA-keyed table FIRST, before any index touches the
        # new columns — otherwise CREATE INDEX on a column the old table lacks
        # blows up.
        _migrate_legacy_ghsa_schema(conn)
        conn.execute(_ADVISORIES_SCHEMA)
        # Add columns introduced after the table already existed.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(advisories)").fetchall()}
        if "ai_assessment" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN ai_assessment TEXT")
        if "veracode_enrichment" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN veracode_enrichment TEXT")
        if "archived_at" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN archived_at TEXT")
        if "archived_by" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN archived_by TEXT")
        if "owner" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN owner TEXT")
        if "owned_at" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN owned_at TEXT")
        if "xsoar_ticket_id" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN xsoar_ticket_id TEXT")
        if "xsoar_ticket_url" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN xsoar_ticket_url TEXT")
        if "xsoar_ticket_at" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN xsoar_ticket_at TEXT")
        if "xsoar_ticket_by" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN xsoar_ticket_by TEXT")
        # Assessment-team back-channel: their work status, distinct from the SOC's
        # triage `status`. Lets the Package Compromise Assessment team flag where
        # they are (assessing / no exposure / remediating / closed).
        if "assessment_status" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN assessment_status TEXT")
        if "assessment_note" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN assessment_note TEXT")
        if "assessment_by" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN assessment_by TEXT")
        if "assessment_at" not in cols:
            conn.execute("ALTER TABLE advisories ADD COLUMN assessment_at TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_status ON advisories(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_archived ON advisories(archived_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_source ON advisories(source)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_published ON advisories(published_at)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS advisory_aliases (alias TEXT PRIMARY KEY, uid TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS poll_state (source TEXT PRIMARY KEY, last_at TEXT, cursor TEXT)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS source_config (source TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS custom_sources (
                key        TEXT PRIMARY KEY,
                type       TEXT NOT NULL,
                label      TEXT NOT NULL,
                config     TEXT,
                created_by TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Self-service email-digest subscribers. The email key is stored
        # lowercased so membership checks are case-insensitive.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS advisory_subscribers (
                email      TEXT PRIMARY KEY,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Per-advisory discussion thread. uid → the advisory's internal uid.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS advisory_comments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                uid        TEXT NOT NULL,
                author     TEXT,
                body       TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_comments_uid ON advisory_comments(uid)")
        # Persisted results of owner-run capability checks (e.g. JFrog Xray), one
        # row per (advisory, capability) so the latest run shows on reload.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS advisory_capability_results (
                uid         TEXT NOT NULL,
                capability  TEXT NOT NULL,
                result_json TEXT,
                run_by      TEXT,
                run_at      TEXT,
                PRIMARY KEY (uid, capability)
            )
            """
        )
        # Multi-team validation sign-off: each validating team independently marks
        # whether it has cleared this advisory, with its own note (editable by any
        # verified user). Supersedes the single-owner model for "who has checked".
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS advisory_team_signoff (
                uid        TEXT NOT NULL,
                team       TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'pending',
                note       TEXT,
                updated_by TEXT,
                updated_at TEXT,
                PRIMARY KEY (uid, team)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_signoff_uid ON advisory_team_signoff(uid)")
        # The configurable roster of validating teams (admin-editable). Seeded once
        # with the teams that triage package advisories today.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signoff_teams (
                team       TEXT PRIMARY KEY,
                label      TEXT NOT NULL,
                emoji      TEXT,
                sort_order INTEGER NOT NULL DEFAULT 0,
                enabled    INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        if not conn.execute("SELECT 1 FROM signoff_teams LIMIT 1").fetchone():
            conn.executemany(
                "INSERT INTO signoff_teams (team, label, emoji, sort_order) VALUES (?, ?, ?, ?)",
                [
                    ("oss_governance", "OSS Governance", "🏛️", 1),
                    ("detection_engineering", "Detection Engineering", "🛠️", 2),
                    ("package_compromise_assessment", "Package Compromise Assessment", "🧪", 3),
                    ("soc_threat_intel", "SOC / Threat Intel", "🛡️", 4),
                ],
            )


def _migrate_legacy_ghsa_schema(conn) -> None:
    """Migrate the original GHSA-keyed table (ghsa_id PRIMARY KEY, no ``source``
    column) into the multi-source schema. One-time, idempotent, in-connection.
    No-op for a fresh DB (no table yet) or an already-migrated one."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(advisories)").fetchall()}
    if not cols or "uid" in cols:  # fresh DB, or already on the new schema
        return
    logger.info("[Advisories DB] Migrating legacy GHSA-keyed schema to multi-source")
    conn.execute("ALTER TABLE advisories RENAME TO advisories_legacy")
    conn.execute(_ADVISORIES_SCHEMA)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_status ON advisories(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_source ON advisories(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_published ON advisories(published_at)")
    conn.execute("CREATE TABLE IF NOT EXISTS advisory_aliases (alias TEXT PRIMARY KEY, uid TEXT NOT NULL)")
    for row in conn.execute("SELECT * FROM advisories_legacy").fetchall():
        r = dict(row)
        ghsa = r.get("ghsa_id")
        if not ghsa:
            continue
        uid = make_uid("github", ghsa)
        try:
            raw = json.loads(r.get("raw_json") or "{}")
        except (json.JSONDecodeError, TypeError):
            raw = {}
        packages = _packages_from_github_raw(raw)
        ecosystem = packages[0].split(" (")[-1].rstrip(")") if packages and "(" in packages[0] else None
        aliases = _dedup_aliases([ghsa, r.get("cve_id")])
        conn.execute(
            """
            INSERT INTO advisories
                (uid, source, source_id, cve_id, aliases, summary, description,
                 severity, ecosystem, packages, published_at, html_url, raw_json,
                 status, notes, reviewed_by, reviewed_at, reported_by, reported_at,
                 first_seen_at, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                uid, "github", ghsa, r.get("cve_id"), json.dumps(aliases),
                r.get("summary"), r.get("description"), r.get("severity"),
                ecosystem, json.dumps(packages), r.get("published_at"),
                r.get("html_url"), r.get("raw_json"), r.get("status") or "new",
                r.get("notes"), r.get("reviewed_by"), r.get("reviewed_at"),
                r.get("reported_by"), r.get("reported_at"),
                r.get("first_seen_at") or _now_iso(), r.get("created_at"),
            ),
        )
        for a in aliases:
            conn.execute(
                "INSERT OR IGNORE INTO advisory_aliases (alias, uid) VALUES (?, ?)", (a, uid)
            )
    conn.execute("DROP TABLE advisories_legacy")
    logger.info("[Advisories DB] Legacy migration complete")


def _packages_from_github_raw(raw: dict) -> list[str]:
    out = []
    for v in (raw or {}).get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        name = pkg.get("name")
        eco = pkg.get("ecosystem")
        if name:
            out.append(f"{name} ({eco})" if eco else name)
    return out


def _dedup_aliases(values: Iterable[Optional[str]]) -> list[str]:
    seen, out = set(), []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# Source bookkeeping
# ---------------------------------------------------------------------------
def list_custom_sources() -> list[dict[str, Any]]:
    """User-added sources (RSS feeds, extra OSV ecosystems). Built-ins are
    code-defined and not stored here."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT key, type, label, config, created_by FROM custom_sources ORDER BY created_at"
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["config"] = json.loads(d.get("config") or "{}")
        except (json.JSONDecodeError, TypeError):
            d["config"] = {}
        out.append(d)
    return out


def add_custom_source(key: str, type_: str, label: str, config: dict, created_by: str = "") -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO custom_sources (key, type, label, config, created_by) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET type=excluded.type, label=excluded.label, config=excluded.config",
            (key, type_, label, json.dumps(config or {}), created_by),
        )


# ---------------------------------------------------------------------------
# Email-digest subscribers (self-service from the /cs-advisories page)
# ---------------------------------------------------------------------------
def add_subscriber(email: str) -> bool:
    """Add an email to the advisory digest. Returns True if newly added,
    False if it was already subscribed. Email is stored lowercased."""
    email = (email or "").strip().lower()
    if not email:
        return False
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO advisory_subscribers (email) VALUES (?)", (email,)
        )
        return cur.rowcount > 0


def remove_subscriber(email: str) -> bool:
    """Remove an email from the digest. Returns True if a row was removed."""
    email = (email or "").strip().lower()
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM advisory_subscribers WHERE email = ?", (email,))
        return cur.rowcount > 0


def is_subscribed(email: str) -> bool:
    email = (email or "").strip().lower()
    if not email:
        return False
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM advisory_subscribers WHERE email = ?", (email,)
        ).fetchone()
    return row is not None


def list_subscribers() -> list[str]:
    """All subscriber emails, oldest first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT email FROM advisory_subscribers ORDER BY created_at"
        ).fetchall()
    return [r["email"] for r in rows]


# ---------------------------------------------------------------------------
# Discussion thread (per advisory)
# ---------------------------------------------------------------------------
def add_comment(key: str, author: str, body: str) -> Optional[dict[str, Any]]:
    """Append a comment to an advisory's discussion thread. Returns the stored
    comment dict, or None if the advisory doesn't exist / the body is empty."""
    body = (body or "").strip()
    if not body:
        return None
    adv = get_advisory(key)
    if not adv:
        return None
    ts = _now_iso()
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO advisory_comments (uid, author, body, created_at) VALUES (?, ?, ?, ?)",
            (adv["uid"], author, body, ts),
        )
        return {"id": cur.lastrowid, "uid": adv["uid"], "author": author,
                "body": body, "created_at": ts}


def list_comments(key: str) -> list[dict[str, Any]]:
    """All comments for an advisory, oldest first."""
    adv = get_advisory(key)
    if not adv:
        return []
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, uid, author, body, created_at FROM advisory_comments "
            "WHERE uid = ? ORDER BY created_at, id",
            (adv["uid"],),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Capability run results (owner-run checks like JFrog Xray)
# ---------------------------------------------------------------------------
def save_capability_result(key: str, capability: str, result: Any, run_by: str = "") -> bool:
    """Persist the result of an owner-run capability check. Returns False if the
    advisory doesn't exist."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO advisory_capability_results (uid, capability, result_json, run_by, run_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(uid, capability) DO UPDATE SET "
            "result_json=excluded.result_json, run_by=excluded.run_by, run_at=excluded.run_at",
            (adv["uid"], capability, json.dumps(result), run_by, _now_iso()),
        )
    return True


def get_capability_results(key: str) -> dict[str, dict[str, Any]]:
    """All persisted capability results for an advisory, keyed by capability."""
    adv = get_advisory(key)
    if not adv:
        return {}
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT capability, result_json, run_by, run_at FROM advisory_capability_results WHERE uid = ?",
            (adv["uid"],),
        ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        try:
            result = json.loads(r["result_json"] or "null")
        except (json.JSONDecodeError, TypeError):
            result = None
        out[r["capability"]] = {"result": result, "run_by": r["run_by"], "run_at": r["run_at"]}
    return out


def remove_custom_source(key: str) -> bool:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM custom_sources WHERE key = ?", (key,))
        conn.execute("DELETE FROM source_config WHERE source = ?", (key,))
        conn.execute("DELETE FROM poll_state WHERE source = ?", (key,))
        return cur.rowcount > 0


def is_baselined(source: str) -> bool:
    """Whether a source has completed its first (silent) poll. Tracked via a
    poll_state row so it works both for sources that seed their backlog as hidden
    rows (GitHub, CISA KEV) and for OSV, which baselines only a timestamp."""
    return bool(get_poll_state(source))


def mark_baselined(source: str) -> None:
    set_poll_state(source)


def is_source_enabled(source: str) -> bool:
    """Whether a source is active in the poller. Defaults to True for any source
    not explicitly turned off, so a newly-added feed is on until disabled."""
    with get_connection() as conn:
        row = conn.execute("SELECT enabled FROM source_config WHERE source = ?", (source,)).fetchone()
        return True if row is None else bool(row["enabled"])


def get_sources_enabled(sources: Iterable[str]) -> dict[str, bool]:
    with get_connection() as conn:
        rows = {r["source"]: bool(r["enabled"]) for r in conn.execute("SELECT source, enabled FROM source_config").fetchall()}
    return {s: rows.get(s, True) for s in sources}


def set_source_enabled(source: str, enabled: bool) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO source_config (source, enabled) VALUES (?, ?) "
            "ON CONFLICT(source) DO UPDATE SET enabled = excluded.enabled",
            (source, 1 if enabled else 0),
        )


def get_poll_state(source: str) -> dict[str, Any]:
    with get_connection() as conn:
        row = conn.execute("SELECT last_at, cursor FROM poll_state WHERE source = ?", (source,)).fetchone()
        if not row:
            return {}
        cursor = {}
        try:
            cursor = json.loads(row["cursor"] or "{}")
        except (json.JSONDecodeError, TypeError):
            cursor = {}
        return {"last_at": row["last_at"], "cursor": cursor}


def set_poll_state(source: str, *, cursor: Optional[dict] = None) -> None:
    with get_connection() as conn:
        existing = conn.execute("SELECT cursor FROM poll_state WHERE source = ?", (source,)).fetchone()
        merged = {}
        if existing and existing["cursor"]:
            try:
                merged = json.loads(existing["cursor"])
            except (json.JSONDecodeError, TypeError):
                merged = {}
        if cursor:
            merged.update(cursor)
        conn.execute(
            "INSERT INTO poll_state (source, last_at, cursor) VALUES (?, ?, ?) "
            "ON CONFLICT(source) DO UPDATE SET last_at = excluded.last_at, cursor = excluded.cursor",
            (source, _now_iso(), json.dumps(merged)),
        )


# ---------------------------------------------------------------------------
# Advisory CRUD
# ---------------------------------------------------------------------------
def _find_uid_by_alias(conn, aliases: Iterable[str]) -> Optional[str]:
    aliases = [a for a in aliases if a]
    if not aliases:
        return None
    placeholders = ",".join("?" * len(aliases))
    row = conn.execute(
        f"SELECT uid FROM advisory_aliases WHERE alias IN ({placeholders}) LIMIT 1", aliases
    ).fetchone()
    return row["uid"] if row else None


def upsert_advisory(rec: dict[str, Any], *, initial_status: str = "new") -> bool:
    """Insert a normalized advisory record if it's genuinely new.

    A normalized record has: ``source``, ``source_id`` (required), and any of
    ``cve_id``, ``aliases`` (list), ``summary``, ``description``, ``severity``,
    ``ecosystem``, ``packages`` (list), ``published_at``, ``html_url``, ``raw``.

    Returns True iff a new row was inserted — the caller treats that as "worth
    notifying on". Returns False if the uid already exists OR if any of the
    record's aliases already belongs to another row (cross-source duplicate); in
    the duplicate case the new aliases are still registered against the existing
    row so future feeds resolve to it. Existing triage state is never touched.
    """
    source = rec.get("source")
    source_id = rec.get("source_id")
    if not source or not source_id:
        return False
    uid = make_uid(source, source_id)
    aliases = _dedup_aliases([source_id, rec.get("cve_id"), *(rec.get("aliases") or [])])

    with get_connection() as conn:
        if conn.execute("SELECT 1 FROM advisories WHERE uid = ?", (uid,)).fetchone():
            return False
        existing_uid = _find_uid_by_alias(conn, aliases)
        if existing_uid:
            # Cross-source duplicate — point any newly-learned aliases at the
            # row that already owns this finding, but don't create a new card.
            for a in aliases:
                conn.execute(
                    "INSERT OR IGNORE INTO advisory_aliases (alias, uid) VALUES (?, ?)", (a, existing_uid)
                )
            return False

        packages = rec.get("packages") or []
        conn.execute(
            """
            INSERT INTO advisories
                (uid, source, source_id, cve_id, aliases, summary, description,
                 severity, ecosystem, packages, published_at, html_url, raw_json,
                 status, first_seen_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                uid, source, source_id, rec.get("cve_id"), json.dumps(aliases),
                (rec.get("summary") or "").strip(), (rec.get("description") or "").strip(),
                rec.get("severity"), rec.get("ecosystem"), json.dumps(packages),
                rec.get("published_at"), rec.get("html_url"),
                json.dumps(rec.get("raw") or {}), initial_status, _now_iso(),
            ),
        )
        for a in aliases:
            conn.execute("INSERT OR IGNORE INTO advisory_aliases (alias, uid) VALUES (?, ?)", (a, uid))
        return True


def bulk_seed(records: list[dict[str, Any]]) -> int:
    """Insert many records as the hidden ``seeded`` baseline in one transaction.

    Used on a source's first poll, where potentially thousands of pre-existing
    advisories are recorded silently. Skips the cross-source alias dedup (these
    rows are hidden, so an occasional duplicate baseline row is harmless) and
    avoids the per-row connection overhead of ``upsert_advisory``. Returns the
    number of rows actually inserted."""
    inserted = 0
    with get_connection() as conn:
        for rec in records:
            source = rec.get("source")
            source_id = rec.get("source_id")
            if not source or not source_id:
                continue
            uid = make_uid(source, source_id)
            if conn.execute("SELECT 1 FROM advisories WHERE uid = ?", (uid,)).fetchone():
                continue
            aliases = _dedup_aliases([source_id, rec.get("cve_id"), *(rec.get("aliases") or [])])
            conn.execute(
                """
                INSERT INTO advisories
                    (uid, source, source_id, cve_id, aliases, summary, description,
                     severity, ecosystem, packages, published_at, html_url, raw_json,
                     status, first_seen_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'seeded',?)
                """,
                (
                    uid, source, source_id, rec.get("cve_id"), json.dumps(aliases),
                    (rec.get("summary") or "").strip(), (rec.get("description") or "").strip(),
                    rec.get("severity"), rec.get("ecosystem"), json.dumps(rec.get("packages") or []),
                    rec.get("published_at"), rec.get("html_url"),
                    json.dumps(rec.get("raw") or {}), _now_iso(),
                ),
            )
            for a in aliases:
                conn.execute("INSERT OR IGNORE INTO advisory_aliases (alias, uid) VALUES (?, ?)", (a, uid))
            inserted += 1
    return inserted


def get_advisory(key: str) -> Optional[dict[str, Any]]:
    """Fetch by uid, or by any known alias (native id / CVE / GHSA / MAL-id).

    The alias fallback keeps old ``/cs-advisories/GHSA-xxxx`` links working and
    lets notifications link by the human-friendly native id rather than the uid."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM advisories WHERE uid = ?", (key,)).fetchone()
        if not row:
            resolved = _find_uid_by_alias(conn, [key])
            if resolved:
                row = conn.execute("SELECT * FROM advisories WHERE uid = ?", (resolved,)).fetchone()
        return _row_to_dict(row) if row else None


def list_advisories(status: Optional[str] = None, limit: int = 500,
                    only_archived: bool = False) -> list[dict[str, Any]]:
    """List advisories, newest published first.

    ``status`` semantics:
        None     -> the visible triage queue: everything EXCEPT the hidden
                    ``seeded`` baseline (new / under_review / reported / closed).
        "active" -> just the open work (new + under_review).
        "all"    -> everything, including the seeded baseline.
        other    -> that single status.

    Archived rows (``archived_at`` set) are excluded from every view EXCEPT when
    ``only_archived`` is True, which returns just the archive (and ignores the
    ``status`` arg). "all" still shows everything including archived, for debug.
    """
    with get_connection() as conn:
        if only_archived:
            rows = conn.execute(
                "SELECT * FROM advisories WHERE archived_at IS NOT NULL AND status != 'seeded' "
                "ORDER BY archived_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        elif status == "active":
            rows = conn.execute(
                f"SELECT * FROM advisories WHERE status IN ({','.join('?' * len(ACTIVE_STATUSES))}) "
                "AND archived_at IS NULL ORDER BY published_at DESC LIMIT ?",
                (*ACTIVE_STATUSES, limit),
            ).fetchall()
        elif status == "all":
            rows = conn.execute(
                "SELECT * FROM advisories ORDER BY published_at DESC LIMIT ?", (limit,)
            ).fetchall()
        elif status:
            rows = conn.execute(
                "SELECT * FROM advisories WHERE status = ? AND archived_at IS NULL "
                "ORDER BY published_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            # Default = the visible queue. The seeded cold-start baseline is
            # plumbing (so onboarding a feed doesn't dump its historical backlog
            # as fresh work); it must never surface on the page. Archived rows
            # are hidden here too — they live behind the Archived view.
            rows = conn.execute(
                "SELECT * FROM advisories WHERE status != 'seeded' AND archived_at IS NULL "
                "ORDER BY published_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


def status_counts() -> dict[str, int]:
    """Per-status counts for the queue chips — archived rows excluded."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) c FROM advisories WHERE archived_at IS NULL GROUP BY status"
        ).fetchall()
        return {r["status"]: r["c"] for r in rows}


def risk_kpis(aging_days: int = 3) -> dict[str, int]:
    """Risk-focused headline counts for the KPI stat-card strip — all over the
    live (non-seeded, non-archived) queue:

      total      — everything in the live queue
      kev        — known-exploited (CISA KEV source or known_exploited severity)
      critical   — critical / malicious / known-exploited severity
      aging      — unowned, past the auto-archive cutoff (about to be archived)
      escalated  — already reported to the wider team
    """
    base = "FROM advisories WHERE archived_at IS NULL AND status != 'seeded'"
    cutoff = (datetime.now(timezone.utc) - timedelta(days=aging_days)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    with get_connection() as conn:
        def _n(sql: str, *args) -> int:
            row = conn.execute(sql, args).fetchone()
            return row["c"] if row else 0

        return {
            "total": _n(f"SELECT COUNT(*) c {base}"),
            "kev": _n(f"SELECT COUNT(*) c {base} AND (source = 'cisa_kev' OR severity = 'known_exploited')"),
            "critical": _n(f"SELECT COUNT(*) c {base} AND severity IN ('critical', 'malicious', 'known_exploited')"),
            "aging": _n(f"SELECT COUNT(*) c {base} AND (owner IS NULL OR owner = '') "
                        f"AND status != 'reported' AND first_seen_at < ?", cutoff),
            "escalated": _n(f"SELECT COUNT(*) c {base} AND status = 'reported'"),
        }


def posture_kpis(trend_days: int = 14) -> dict[str, Any]:
    """Leadership operating-tempo metrics over the live queue:

      mtt_triage_h   — median hours first_seen -> owner assigned (how fast we pick up)
      mtt_notify_h   — median hours first_seen -> escalated to the assessment team
      notified_rate  — % of the queue escalated
      exposure_confirmed_pct — of advisories with a Veracode SCA result, % that
                       actually carry an affected component (real exposure rate)
      intake_trend   — [{date, count}] new advisories per day for the last N days
    """
    from statistics import median

    def _parse(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            return None

    def _hours(a, b):
        da, db_ = _parse(a), _parse(b)
        if not da or not db_:
            return None
        h = (db_ - da).total_seconds() / 3600.0
        return h if h >= 0 else None

    with get_connection() as conn:
        rows = conn.execute(
            "SELECT first_seen_at, owned_at, reported_at, status, veracode_enrichment "
            "FROM advisories WHERE archived_at IS NULL AND status != 'seeded'"
        ).fetchall()

    triage, notify = [], []
    vc_total = vc_exposed = 0
    total = len(rows)
    reported = 0
    for r in rows:
        if r["status"] == "reported":
            reported += 1
        t = _hours(r["first_seen_at"], r["owned_at"])
        if t is not None:
            triage.append(t)
        n = _hours(r["first_seen_at"], r["reported_at"])
        if n is not None:
            notify.append(n)
        vc = r["veracode_enrichment"]
        if vc:
            try:
                d = json.loads(vc)
                vc_total += 1
                if (d or {}).get("affected_app_count"):
                    vc_exposed += 1
            except (ValueError, TypeError):
                pass

    # intake trend by day (first_seen_at) for the last N days, oldest -> newest
    today = datetime.now(timezone.utc).date()
    counts = {}
    for r in rows:
        d = _parse(r["first_seen_at"])
        if d:
            counts[d.date()] = counts.get(d.date(), 0) + 1
    trend = []
    for i in range(trend_days - 1, -1, -1):
        day = today - timedelta(days=i)
        trend.append({"date": day.strftime("%m/%d"), "count": counts.get(day, 0)})

    return {
        "mtt_triage_h": round(median(triage), 1) if triage else None,
        "mtt_notify_h": round(median(notify), 1) if notify else None,
        "notified_rate": int(round(reported / total * 100)) if total else 0,
        "exposure_confirmed_pct": int(round(vc_exposed / vc_total * 100)) if vc_total else None,
        "exposure_checked": vc_total,
        "intake_trend": trend,
    }


def metrics_summary(trend_days: int = 30, ecosystem_top: int = 12) -> dict[str, Any]:
    """Aggregate analytics for the /cs-advisories/metrics dashboard and JSON feed.

    Everything is computed over the live queue (archived + seeded rows excluded),
    except ``archived`` which is the archived count. Returns plain dicts/lists so
    the same payload can render the dashboard or be served as a BI feed.

      headline      — total / open / escalated / archived / kev / critical
      by_severity   — {severity: count}
      by_source     — {source_key: count}   (route maps keys -> friendly labels)
      by_status     — {status: count}
      by_ecosystem  — [{ecosystem, count}]  top N, descending
      assessment    — {assessment_status: count}  (assessment-team back-channel)
      signoff       — per-team clear/not_clear/pending coverage + fully-cleared count
      exposure      — Veracode SCA: checked / exposed / clear
      throughput    — [{date, new, reported}] for the last N days, oldest -> newest
    """
    def _parse(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            return None

    base = "FROM advisories WHERE archived_at IS NULL AND status != 'seeded'"
    with get_connection() as conn:
        def _grp(col: str) -> dict[str, int]:
            rows = conn.execute(
                f"SELECT {col} k, COUNT(*) c {base} GROUP BY {col} ORDER BY c DESC"
            ).fetchall()
            return {(r["k"] or "—"): r["c"] for r in rows}

        by_severity = _grp("severity")
        by_source = _grp("source")
        by_status = _grp("status")

        total = sum(by_status.values())
        kev = conn.execute(
            f"SELECT COUNT(*) c {base} AND (source = 'cisa_kev' OR severity = 'known_exploited')"
        ).fetchone()["c"]
        critical = conn.execute(
            f"SELECT COUNT(*) c {base} AND severity IN ('critical','malicious','known_exploited')"
        ).fetchone()["c"]
        escalated = by_status.get("reported", 0)
        open_n = total - escalated - by_status.get("closed_not_reported", 0) - by_status.get("closed", 0)

        # Ecosystem — packages are stored as "name (ecosystem)" JSON; tally the
        # advisory's own ecosystem column when set, else parse the package tails.
        eco_counts: dict[str, int] = {}
        prows = conn.execute(f"SELECT ecosystem, packages {base}").fetchall()
        for r in prows:
            ecos = set()
            if r["ecosystem"]:
                ecos.add(str(r["ecosystem"]).strip().lower())
            else:
                try:
                    for entry in (json.loads(r["packages"]) if r["packages"] else []):
                        if "(" in entry and entry.rstrip().endswith(")"):
                            ecos.add(entry[entry.rfind("(") + 1:-1].strip().lower())
                except (ValueError, TypeError):
                    pass
            for e in (ecos or {"—"}):
                eco_counts[e] = eco_counts.get(e, 0) + 1
        by_ecosystem = [{"ecosystem": k, "count": v} for k, v in
                        sorted(eco_counts.items(), key=lambda kv: kv[1], reverse=True)[:ecosystem_top]]

        assessment = {}
        for r in conn.execute(
            f"SELECT assessment_status k, COUNT(*) c {base} "
            f"AND assessment_status IS NOT NULL AND assessment_status != '' GROUP BY k"
        ).fetchall():
            assessment[r["k"]] = r["c"]

        # Veracode exposure rate over advisories that actually have a result.
        vc_checked = vc_exposed = 0
        for r in conn.execute(f"SELECT veracode_enrichment {base} AND veracode_enrichment IS NOT NULL").fetchall():
            try:
                d = json.loads(r["veracode_enrichment"]) or {}
            except (ValueError, TypeError):
                continue
            vc_checked += 1
            if d.get("affected_app_count"):
                vc_exposed += 1

        # Team sign-off coverage. Per team: how many advisories each status; plus
        # how many advisories every enabled team has cleared.
        teams = conn.execute(
            "SELECT team, label, emoji, sort_order FROM signoff_teams WHERE enabled = 1 "
            "ORDER BY sort_order, label"
        ).fetchall()
        team_meta = [{"team": t["team"], "label": t["label"], "emoji": t["emoji"] or ""} for t in teams]
        enabled_keys = [t["team"] for t in teams]
        per_team = {t: {"clear": 0, "not_clear": 0, "pending": 0} for t in enabled_keys}
        cleared_by_adv: dict[str, set] = {}
        for r in conn.execute(
            "SELECT uid, team, status FROM advisory_team_signoff WHERE team IN ({})".format(
                ",".join("?" * len(enabled_keys)) or "''"), enabled_keys).fetchall() if enabled_keys else []:
            st = r["status"] or "pending"
            if st in per_team.get(r["team"], {}):
                per_team[r["team"]][st] += 1
            if st == "clear":
                cleared_by_adv.setdefault(r["uid"], set()).add(r["team"])
        fully_cleared = sum(1 for s in cleared_by_adv.values() if enabled_keys and set(enabled_keys) <= s)
        signoff = {
            "teams": [{**m, **per_team.get(m["team"], {})} for m in team_meta],
            "fully_cleared": fully_cleared,
            "total": total,
        }

        # Throughput trend: new (first_seen_at) vs escalated (reported_at) per day.
        new_by_day: dict = {}
        rep_by_day: dict = {}
        for r in conn.execute(f"SELECT first_seen_at, reported_at, status {base}").fetchall():
            d = _parse(r["first_seen_at"])
            if d:
                new_by_day[d.date()] = new_by_day.get(d.date(), 0) + 1
            if r["status"] == "reported":
                rd = _parse(r["reported_at"])
                if rd:
                    rep_by_day[rd.date()] = rep_by_day.get(rd.date(), 0) + 1

    today = datetime.now(timezone.utc).date()
    throughput = []
    for i in range(trend_days - 1, -1, -1):
        day = today - timedelta(days=i)
        throughput.append({
            "date": day.strftime("%m/%d"),
            "new": new_by_day.get(day, 0),
            "reported": rep_by_day.get(day, 0),
        })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "headline": {
            "total": total, "open": max(open_n, 0), "escalated": escalated,
            "archived": archived_count(), "kev": kev, "critical": critical,
        },
        "by_severity": by_severity,
        "by_source": by_source,
        "by_status": by_status,
        "by_ecosystem": by_ecosystem,
        "assessment": assessment,
        "signoff": signoff,
        "exposure": {"checked": vc_checked, "exposed": vc_exposed, "clear": vc_checked - vc_exposed},
        "throughput": throughput,
    }


def archived_count() -> int:
    """How many advisories are archived (for the Archived view chip)."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) c FROM advisories WHERE archived_at IS NOT NULL AND status != 'seeded'"
        ).fetchone()
    return row["c"] if row else 0


def source_counts() -> dict[str, int]:
    """Visible (non-seeded, non-archived) row count per source — for the source filter chips."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT source, COUNT(*) c FROM advisories "
            "WHERE status != 'seeded' AND archived_at IS NULL GROUP BY source"
        ).fetchall()
        return {r["source"]: r["c"] for r in rows}


# ---------------------------------------------------------------------------
# Archiving (lifecycle — orthogonal to triage status)
# ---------------------------------------------------------------------------
def archive_advisory(key: str, by: str = "") -> bool:
    """Archive one advisory (hides it from the queue; reversible). Returns False
    if the advisory doesn't exist."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET archived_at = ?, archived_by = ? WHERE uid = ?",
            (_now_iso(), by, adv["uid"]),
        )
    return True


def unarchive_advisory(key: str, by: str = "") -> bool:
    """Restore one advisory from the archive back to the live queue."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET archived_at = NULL, archived_by = NULL WHERE uid = ?",
            (adv["uid"],),
        )
    return True


def assign_owner(key: str, email: str) -> bool:
    """Set the owner of an advisory (and stamp owned_at). Returns False if the
    advisory doesn't exist."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET owner = ?, owned_at = ? WHERE uid = ?",
            (email, _now_iso(), adv["uid"]),
        )
    return True


def release_owner(key: str) -> bool:
    """Clear the owner of an advisory."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET owner = NULL, owned_at = NULL WHERE uid = ?",
            (adv["uid"],),
        )
    return True


def archive_stale_unowned(days: int = 3, by: str = "auto-archive") -> int:
    """Archive advisories that are unowned AND older than ``days`` (measured from
    first_seen_at). Owned and reported advisories are exempt. Returns the count
    archived. Drives the daily auto-archive housekeeping job."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE advisories SET archived_at = ?, archived_by = ? "
            "WHERE archived_at IS NULL "
            "AND (owner IS NULL OR owner = '') "
            "AND status NOT IN ('seeded', 'reported') "
            "AND first_seen_at < ?",
            (_now_iso(), by, cutoff),
        )
        return cur.rowcount


def archive_backlog(exclude_statuses: Iterable[str] = ("reported",), by: str = "system") -> int:
    """Bulk-archive every live (non-seeded, not-already-archived) advisory whose
    status is not in ``exclude_statuses``. Returns the number archived. Used for
    the one-time backlog clear and reusable for housekeeping."""
    excl = tuple(exclude_statuses) + ("seeded",)
    placeholders = ",".join("?" * len(excl))
    with get_connection() as conn:
        cur = conn.execute(
            f"UPDATE advisories SET archived_at = ?, archived_by = ? "
            f"WHERE archived_at IS NULL AND status NOT IN ({placeholders})",
            (_now_iso(), by, *excl),
        )
        return cur.rowcount


def save_notes(key: str, notes: str, user: str) -> bool:
    """Persist reviewer notes. A still-new advisory moves to under_review; an
    already-closed/reported one keeps its status. Returns False if not found."""
    adv = get_advisory(key)
    if not adv:
        return False
    uid = adv["uid"]
    new_status = "under_review" if adv["status"] in ("seeded", "new") else adv["status"]
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET notes = ?, status = ?, reviewed_by = ?, reviewed_at = ? WHERE uid = ?",
            (notes, new_status, user, _now_iso(), uid),
        )
    return True


def set_status(key: str, status: str, user: str) -> bool:
    """Move an advisory to ``status`` (e.g. closed_not_reported, under_review).
    Does not touch the reported_* fields — use ``mark_reported`` for that."""
    if status not in ALL_STATUSES:
        raise ValueError(f"invalid status {status!r}")
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE uid = ?",
            (status, user, _now_iso(), adv["uid"]),
        )
    return True


def mark_reported(key: str, user: str) -> bool:
    """Mark an advisory escalated to the Teams channel. Idempotent: returns
    False if it was already reported (so the caller skips the Teams send)."""
    adv = get_advisory(key)
    if not adv:
        return False
    if adv.get("reported_at"):
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET status = 'reported', reported_by = ?, reported_at = ? WHERE uid = ?",
            (user, _now_iso(), adv["uid"]),
        )
    return True


def set_assessment_status(key: str, status: str, note: str, user: str) -> bool:
    """Record the assessment team's work status on this advisory. ``status=''``
    clears it. Returns False if the advisory doesn't exist."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET assessment_status = ?, assessment_note = ?, "
            "assessment_by = ?, assessment_at = ? WHERE uid = ?",
            (status or None, (note or "").strip()[:1000] or None,
             user, _now_iso() if status else None, adv["uid"]),
        )
    return True


_SIGNOFF_STATUSES = ("pending", "clear", "not_clear")


def list_signoff_teams(include_disabled: bool = False) -> list[dict[str, Any]]:
    """The configured roster of validating teams, in display order."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT team, label, emoji, sort_order, enabled FROM signoff_teams "
            + ("" if include_disabled else "WHERE enabled = 1 ")
            + "ORDER BY sort_order, label"
        ).fetchall()
    return [dict(r) for r in rows]


def add_signoff_team(team: str, label: str, emoji: str = "") -> bool:
    """Add (or re-enable) a validating team. ``team`` is the stable key."""
    team = (team or "").strip()
    label = (label or "").strip()
    if not team or not label:
        return False
    with get_connection() as conn:
        nxt = conn.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM signoff_teams").fetchone()[0]
        conn.execute(
            "INSERT INTO signoff_teams (team, label, emoji, sort_order, enabled) VALUES (?, ?, ?, ?, 1) "
            "ON CONFLICT(team) DO UPDATE SET label=excluded.label, emoji=excluded.emoji, enabled=1",
            (team, label, emoji or "", nxt),
        )
    return True


def set_signoff_team_enabled(team: str, enabled: bool) -> bool:
    """Enable/disable a team without dropping its historical sign-offs."""
    with get_connection() as conn:
        cur = conn.execute("UPDATE signoff_teams SET enabled = ? WHERE team = ?",
                           (1 if enabled else 0, team))
    return cur.rowcount > 0


def get_team_signoffs(key: str) -> dict[str, dict[str, Any]]:
    """Per-team sign-off state for an advisory, keyed by team."""
    adv = get_advisory(key)
    if not adv:
        return {}
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT team, status, note, updated_by, updated_at FROM advisory_team_signoff WHERE uid = ?",
            (adv["uid"],),
        ).fetchall()
    return {r["team"]: dict(r) for r in rows}


def set_team_signoff(key: str, team: str, status: str, note: str, user: str) -> bool:
    """Upsert one team's sign-off (status + note). ``status`` ∈ pending/clear/
    not_clear. Returns False if the advisory doesn't exist or status is invalid."""
    if status not in _SIGNOFF_STATUSES:
        return False
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO advisory_team_signoff (uid, team, status, note, updated_by, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(uid, team) DO UPDATE SET "
            "status=excluded.status, note=excluded.note, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            (adv["uid"], team, status, (note or "").strip()[:1000] or None, user, _now_iso()),
        )
    return True


def bulk_set_team_signoff(keys: list[str], team: str, status: str, note: str, user: str) -> int:
    """Apply one team's sign-off to many advisories at once (campaign bulk-clear).
    Returns the number actually updated (advisories that resolve + valid status)."""
    if status not in _SIGNOFF_STATUSES:
        return 0
    count = 0
    for key in keys:
        if set_team_signoff(key, team, status, note, user):
            count += 1
    return count


def set_xsoar_ticket(key: str, ticket_id: str, ticket_url: str, user: str) -> bool:
    """Record the XSOAR incident created for this advisory (idempotency anchor:
    the route refuses to create a second ticket once this is set)."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute(
            "UPDATE advisories SET xsoar_ticket_id = ?, xsoar_ticket_url = ?, "
            "xsoar_ticket_at = ?, xsoar_ticket_by = ? WHERE uid = ?",
            (str(ticket_id), ticket_url or "", _now_iso(), user, adv["uid"]),
        )
    return True


def save_ai_assessment(key: str, assessment: dict) -> bool:
    """Persist the LLM-generated triage assessment on the advisory row."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute("UPDATE advisories SET ai_assessment = ? WHERE uid = ?",
                     (json.dumps(assessment), adv["uid"]))
    return True


def save_veracode_enrichment(key: str, enrichment: dict) -> bool:
    """Persist Veracode SCA exposure (which apps carry the vulnerable component)."""
    adv = get_advisory(key)
    if not adv:
        return False
    with get_connection() as conn:
        conn.execute("UPDATE advisories SET veracode_enrichment = ? WHERE uid = ?",
                     (json.dumps(enrichment), adv["uid"]))
    return True


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for field, default in (("raw_json", "{}"), ("aliases", "[]"), ("packages", "[]"),
                           ("ai_assessment", "null"), ("veracode_enrichment", "null")):
        try:
            parsed = json.loads(d.get(field) or default)
        except (json.JSONDecodeError, TypeError):
            parsed = json.loads(default)
        key = "raw" if field == "raw_json" else field
        d[key] = parsed
    return d


# Initialize on import (matches the pattern used by the other *_db.py modules).
init_db()
