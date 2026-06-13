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
from datetime import datetime, timezone
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_adv_status ON advisories(status)")
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


def list_advisories(status: Optional[str] = None, limit: int = 500) -> list[dict[str, Any]]:
    """List advisories, newest published first.

    ``status`` semantics:
        None     -> the visible triage queue: everything EXCEPT the hidden
                    ``seeded`` baseline (new / under_review / reported / closed).
        "active" -> just the open work (new + under_review).
        "all"    -> everything, including the seeded baseline.
        other    -> that single status.
    """
    with get_connection() as conn:
        if status == "active":
            rows = conn.execute(
                f"SELECT * FROM advisories WHERE status IN ({','.join('?' * len(ACTIVE_STATUSES))}) "
                "ORDER BY published_at DESC LIMIT ?",
                (*ACTIVE_STATUSES, limit),
            ).fetchall()
        elif status == "all":
            rows = conn.execute(
                "SELECT * FROM advisories ORDER BY published_at DESC LIMIT ?", (limit,)
            ).fetchall()
        elif status:
            rows = conn.execute(
                "SELECT * FROM advisories WHERE status = ? ORDER BY published_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            # Default = the visible queue. The seeded cold-start baseline is
            # plumbing (so onboarding a feed doesn't dump its historical backlog
            # as fresh work); it must never surface on the page.
            rows = conn.execute(
                "SELECT * FROM advisories WHERE status != 'seeded' "
                "ORDER BY published_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


def status_counts() -> dict[str, int]:
    with get_connection() as conn:
        rows = conn.execute("SELECT status, COUNT(*) c FROM advisories GROUP BY status").fetchall()
        return {r["status"]: r["c"] for r in rows}


def source_counts() -> dict[str, int]:
    """Visible (non-seeded) row count per source — for the source filter chips."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT source, COUNT(*) c FROM advisories WHERE status != 'seeded' GROUP BY source"
        ).fetchall()
        return {r["source"]: r["c"] for r in rows}


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
