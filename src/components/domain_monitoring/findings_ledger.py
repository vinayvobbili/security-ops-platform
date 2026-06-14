"""Domain-monitoring findings ledger.

The daily scans discover domains; analysts then triage them (relevant vs
irrelevant, which brand, who owns it, was a takedown raised). That triage state
— not the raw discovery — is what the monthly Domain Monitoring & Brand
Protection report is built from, so it needs a durable home.

This module is that home: a small SQLite ledger that the scans UPSERT into and
the dashboard / reports page curate. One row per domain; ``monthly_rollup``
slices it into the sheets the monthly report needs.
"""

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).parent.parent.parent.parent / "data" / "domain_monitoring"
DB_PATH = DB_DIR / "findings.db"

# Triage dispositions. ``new`` until an analyst classifies it.
STATUSES = ("new", "monitoring", "takedown", "irrelevant", "bau_owned")

# Discovery sources, mapped from the scan sections.
SOURCES = ("lookalike", "rf_watchlist", "brand_ct", "manual")


# Columns added after the initial schema shipped — migrated in via ALTER TABLE
# so existing prod ledgers pick them up without a rebuild. (col_name, sql_type).
_MIGRATION_COLUMNS = (
    # Weaponization triage (LLM verdict + hard signals).
    ("weaponization_tier",      "TEXT"),     # P1 | P2 | P3 | P4
    ("weaponization_active",    "INTEGER"),  # 1 if is_active_phishing
    ("weaponization_json",      "TEXT"),     # full {signals, verdict} blob
    ("weaponization_scored_at", "TEXT"),
    # "Were we touched?" exposure hunt across DNS/proxy/EDR.
    ("exposure_status",         "TEXT"),     # running | done | error (NULL = never run)
    ("exposure_touched",        "INTEGER"),  # 1 if any internal host/user hit the domain
    ("exposure_hosts",          "INTEGER"),  # count of unique internal hosts
    ("exposure_json",           "TEXT"),     # full hunt result blob
    ("exposure_checked_at",     "TEXT"),
    ("exposure_progress",       "TEXT"),     # per-tool incremental status {tools:{qradar:{...}}}
    # Archive attribution — who hid the row ('system' for the auto 7-day job,
    # else the analyst's name/email) and when.
    ("archived_by",             "TEXT"),
    ("archived_at",             "TEXT"),
    # SLA / response lifecycle timestamps — power the turnaround metrics.
    ("blocked_at",              "TEXT"),     # first XSOAR block recorded for this domain
    ("takedown_at",             "TEXT"),     # takedown submitted to PhishFort
    ("takedown_status",         "TEXT"),     # latest PhishFort incident status (synced)
    ("takedown_completed_at",   "TEXT"),     # when PhishFort reported it resolved / down
    # Infrastructure pivots — shared across a finding's discovery enrichment.
    # Persisted so campaign clustering can group domains that share an actor's
    # hosting/registration footprint. Lists are stored as JSON arrays.
    ("registrar",               "TEXT"),     # registrar name (often a bulk registrar)
    ("registrant_org",          "TEXT"),     # WHOIS registrant org (strong pivot when not privacy-proxied)
    ("ip_addresses",            "TEXT"),     # JSON list of resolved A records
    ("nameservers",             "TEXT"),     # JSON list of authoritative NS
    ("cert_issuer",             "TEXT"),     # TLS cert issuer (weak alone; mostly Let's Encrypt)
)


@contextmanager
def get_connection():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL lets the scheduled scan write while the dashboard reads without
    # "database is locked" — this ledger is touched by both.
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create the ledger schema if absent, then apply additive migrations."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_findings (
                domain                TEXT PRIMARY KEY,
                first_seen            TEXT NOT NULL,
                last_seen             TEXT NOT NULL,
                source                TEXT,
                brand                 TEXT,
                status                TEXT NOT NULL DEFAULT 'new',
                assignee              TEXT,
                phishfort_incident_id TEXT,
                xsoar_id              TEXT,
                risk_score            INTEGER,
                notes                 TEXT,
                updated_at            TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON domain_findings(first_seen)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON domain_findings(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_brand ON domain_findings(brand)")
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(domain_findings)")}
        for col, col_type in _MIGRATION_COLUMNS:
            if col not in existing:
                conn.execute(f"ALTER TABLE domain_findings ADD COLUMN {col} {col_type}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_weap_tier ON domain_findings(weaponization_tier)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_finding(
    domain: str,
    source: Optional[str] = None,
    brand: Optional[str] = None,
    risk_score: Optional[int] = None,
) -> bool:
    """Record a discovered domain, or refresh ``last_seen`` if already known.

    Never overwrites analyst-set triage fields (status/assignee/brand once set)
    — only fills brand/risk when they were empty and always bumps ``last_seen``.
    Returns True if this was a brand-new finding.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return False
    now = _now()
    with get_connection() as conn:
        row = conn.execute("SELECT domain, brand FROM domain_findings WHERE domain = ?", (domain,)).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO domain_findings
                   (domain, first_seen, last_seen, source, brand, status, risk_score, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'new', ?, ?)""",
                (domain, now, now, source, brand, risk_score, now),
            )
            return True
        # Existing: bump last_seen; backfill brand/risk only if empty.
        conn.execute(
            """UPDATE domain_findings
               SET last_seen = ?,
                   brand = COALESCE(brand, ?),
                   risk_score = COALESCE(?, risk_score),
                   updated_at = ?
               WHERE domain = ?""",
            (now, brand, risk_score, now, domain),
        )
        return False


def set_triage(
    domain: str,
    status: Optional[str] = None,
    brand: Optional[str] = None,
    assignee: Optional[str] = None,
    notes: Optional[str] = None,
    xsoar_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply analyst triage to a finding. Only provided fields are changed."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"ok": False, "error": "domain required"}
    if status is not None and status not in STATUSES:
        return {"ok": False, "error": f"invalid status '{status}'"}

    sets, params = [], []
    for col, val in (("status", status), ("brand", brand), ("assignee", assignee),
                     ("notes", notes), ("xsoar_id", xsoar_id)):
        if val is not None:
            sets.append(f"{col} = ?")
            params.append(val)
    if not sets:
        return {"ok": False, "error": "no fields to update"}
    sets.append("updated_at = ?")
    params.append(_now())
    params.append(domain)

    with get_connection() as conn:
        cur = conn.execute(
            f"UPDATE domain_findings SET {', '.join(sets)} WHERE domain = ?", params
        )
        if cur.rowcount == 0:
            return {"ok": False, "error": f"finding not found: {domain}"}
    logger.info(f"Triage updated for {domain}: {', '.join(s.split(' =')[0] for s in sets[:-1])}")
    return {"ok": True, "domain": domain}


def record_takedown(domain: str, incident_id: Optional[str], assignee: Optional[str] = None) -> None:
    """Record a takedown against a finding (status + PhishFort incident id).

    Upserts first so a takedown on a domain that wasn't in a scan still lands.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return
    upsert_finding(domain, source="manual")
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """UPDATE domain_findings
               SET status = 'takedown',
                   phishfort_incident_id = COALESCE(?, phishfort_incident_id),
                   assignee = COALESCE(assignee, ?),
                   takedown_at = COALESCE(takedown_at, ?),
                   updated_at = ?
               WHERE domain = ?""",
            (incident_id, assignee, now, now, domain),
        )
    logger.info(f"Recorded takedown for {domain} (incident={incident_id})")


def record_block(domain: str, xsoar_ticket_id: Optional[str], assignee: Optional[str] = None) -> None:
    """Record a proactive XSOAR URL block against a finding.

    A block is a containment action that runs *before* takedown (protect users
    while the takedown is brokered), so it stamps the XSOAR ticket id + assignee
    without overriding an existing takedown/triage status. Upserts first so a
    block on a domain that wasn't in a scan still lands.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return
    upsert_finding(domain, source="manual")
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """UPDATE domain_findings
               SET xsoar_id = COALESCE(?, xsoar_id),
                   assignee = COALESCE(assignee, ?),
                   blocked_at = COALESCE(blocked_at, ?),
                   updated_at = ?
               WHERE domain = ?""",
            (xsoar_ticket_id, assignee, now, now, domain),
        )
    logger.info(f"Recorded XSOAR block for {domain} (ticket={xsoar_ticket_id})")


def _merge_json_list(existing: Optional[str], new_vals: Optional[List[str]]) -> Optional[str]:
    """Union an incoming list of values with whatever JSON list is already
    stored, normalised + de-duped, preserving order. Returns JSON or None."""
    have: List[str] = []
    if existing:
        try:
            have = [str(v).strip().lower() for v in (json.loads(existing) or []) if str(v).strip()]
        except (ValueError, TypeError):
            have = []
    for v in (new_vals or []):
        s = str(v).strip().lower()
        if s and s not in have:
            have.append(s)
    return json.dumps(have) if have else None


def set_infrastructure(
    domain: str,
    registrar: Optional[str] = None,
    registrant_org: Optional[str] = None,
    ips: Optional[List[str]] = None,
    nameservers: Optional[List[str]] = None,
    cert_issuer: Optional[str] = None,
) -> None:
    """Record the infrastructure pivots collected for a domain during scan
    enrichment. Scalars fill only when empty (COALESCE); list fields (IPs,
    nameservers) accumulate the union across scans, since a domain can rotate
    hosting over time and every observed value is a clustering signal.

    Best-effort: never let an enrichment hiccup fail a scan.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return
    registrar = (registrar or "").strip() or None
    registrant_org = (registrant_org or "").strip() or None
    cert_issuer = (cert_issuer or "").strip() or None
    if not any((registrar, registrant_org, cert_issuer, ips, nameservers)):
        return
    upsert_finding(domain, source="manual")
    with get_connection() as conn:
        row = conn.execute(
            "SELECT ip_addresses, nameservers FROM domain_findings WHERE domain = ?", (domain,)
        ).fetchone()
        ip_json = _merge_json_list(row["ip_addresses"] if row else None, ips)
        ns_json = _merge_json_list(row["nameservers"] if row else None, nameservers)
        conn.execute(
            """UPDATE domain_findings
               SET registrar = COALESCE(registrar, ?),
                   registrant_org = COALESCE(registrant_org, ?),
                   cert_issuer = COALESCE(cert_issuer, ?),
                   ip_addresses = ?,
                   nameservers = ?,
                   updated_at = ?
               WHERE domain = ?""",
            (registrar, registrant_org, cert_issuer, ip_json, ns_json, _now(), domain),
        )


# PhishFort statuses that mean the takedown is done — used to stamp
# takedown_completed_at. Kept generous (the live CAPI vocabulary isn't fully
# documented here); the status-sync logs any unrecognised status it sees so
# this set can be tuned to reality.
TAKEDOWN_DONE_STATUSES = {
    "resolved", "takedown_successful", "taken_down", "takedown_complete",
    "takedown_completed", "closed", "down", "completed",
}


def set_takedown_status(domain: str, status: Optional[str]) -> None:
    """Update the synced PhishFort status for a domain, stamping
    takedown_completed_at the first time it reaches a 'done' status.

    Best-effort: a status hiccup must never break the sync loop.
    """
    domain = (domain or "").strip().lower()
    status = (status or "").strip()
    if not domain or not status:
        return
    now = _now()
    done = status.lower() in TAKEDOWN_DONE_STATUSES
    with get_connection() as conn:
        conn.execute(
            """UPDATE domain_findings
               SET takedown_status = ?,
                   takedown_completed_at = CASE
                       WHEN ? = 1 AND takedown_completed_at IS NULL THEN ?
                       ELSE takedown_completed_at END,
                   updated_at = ?
               WHERE domain = ?""",
            (status, 1 if done else 0, now, now, domain),
        )


def findings_with_incident() -> List[Dict[str, Any]]:
    """Findings that have a PhishFort incident id (the status-sync work set)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT domain, phishfort_incident_id, takedown_status, takedown_completed_at "
            "FROM domain_findings WHERE phishfort_incident_id IS NOT NULL AND phishfort_incident_id != ''"
        ).fetchall()
    return [dict(r) for r in rows]


def get_finding(domain: str) -> Optional[Dict[str, Any]]:
    """Return a single finding row as a dict, or None if not present."""
    domain = (domain or "").strip().lower()
    if not domain:
        return None
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM domain_findings WHERE domain = ?", (domain,)
        ).fetchone()
    return dict(row) if row else None


def set_weaponization(domain: str, tier: Optional[str], is_active: bool,
                      verdict_blob: Dict[str, Any]) -> None:
    """Store a weaponization-triage result against a finding (upserts first).

    ``tier`` is the LLM risk tier (P1-P4); ``verdict_blob`` is the full
    {signals, verdict} payload kept for the drill-down. Does not touch analyst
    triage status — weaponization is advisory.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return
    upsert_finding(domain, source="manual")
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """UPDATE domain_findings
               SET weaponization_tier = ?, weaponization_active = ?,
                   weaponization_json = ?, weaponization_scored_at = ?,
                   updated_at = ?
               WHERE domain = ?""",
            (tier, 1 if is_active else 0, json.dumps(verdict_blob), now, now, domain),
        )
    logger.info(f"Weaponization scored for {domain}: tier={tier} active={is_active}")


def set_exposure_status(domain: str, status: str) -> None:
    """Mark an exposure-hunt's lifecycle state (running | done | error)."""
    domain = (domain or "").strip().lower()
    if not domain:
        return
    upsert_finding(domain, source="manual")
    with get_connection() as conn:
        conn.execute(
            "UPDATE domain_findings SET exposure_status = ?, updated_at = ? WHERE domain = ?",
            (status, _now(), domain),
        )


def set_exposure_result(domain: str, touched: bool, hosts: int,
                        result_blob: Dict[str, Any]) -> None:
    """Store a completed 'were we touched?' hunt result against a finding."""
    domain = (domain or "").strip().lower()
    if not domain:
        return
    upsert_finding(domain, source="manual")
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """UPDATE domain_findings
               SET exposure_status = 'done', exposure_touched = ?, exposure_hosts = ?,
                   exposure_json = ?, exposure_checked_at = ?, updated_at = ?
               WHERE domain = ?""",
            (1 if touched else 0, hosts, json.dumps(result_blob), now, now, domain),
        )
    logger.info(f"Exposure hunt recorded for {domain}: touched={touched} hosts={hosts}")


# Incremental per-tool progress merges fire from parallel hunt threads; serialize
# the read-modify-write so QRadar's and CrowdStrike's callbacks don't clobber.
_progress_lock = threading.Lock()

# Human labels for the per-tool progress UI.
_TOOL_LABELS = {"qradar": "QRadar", "crowdstrike": "CrowdStrike",
                "xsiam": "XSIAM", "abnormal": "Abnormal"}


def init_exposure_progress(domain: str, tools: List[str]) -> None:
    """Seed per-tool progress (each tool 'running') so the modal can show both
    sources before either finishes."""
    domain = (domain or "").strip().lower()
    if not domain:
        return
    upsert_finding(domain, source="manual")
    blob = {
        "tools": {t: {"status": "running", "label": _TOOL_LABELS.get(t, t)}
                  for t in (tools or [])},
        "updated_at": _now(),
    }
    with get_connection() as conn:
        conn.execute(
            "UPDATE domain_findings SET exposure_progress = ?, updated_at = ? WHERE domain = ?",
            (json.dumps(blob), _now(), domain),
        )


def record_tool_progress(domain: str, tool_key: str, data: Dict[str, Any]) -> None:
    """Merge one tool's completion into the exposure progress blob (thread-safe)."""
    domain = (domain or "").strip().lower()
    tool_key = (tool_key or "").strip().lower()
    if not domain or not tool_key:
        return
    with _progress_lock, get_connection() as conn:
        row = conn.execute(
            "SELECT exposure_progress FROM domain_findings WHERE domain = ?", (domain,)
        ).fetchone()
        try:
            blob = json.loads(row["exposure_progress"]) if row and row["exposure_progress"] else {}
        except (ValueError, TypeError):
            blob = {}
        tools = blob.get("tools") or {}
        entry = tools.get(tool_key) or {}
        entry.update(data)
        entry.setdefault("label", _TOOL_LABELS.get(tool_key, tool_key))
        tools[tool_key] = entry
        blob["tools"] = tools
        blob["updated_at"] = _now()
        conn.execute(
            "UPDATE domain_findings SET exposure_progress = ?, updated_at = ? WHERE domain = ?",
            (json.dumps(blob), _now(), domain),
        )


def list_findings(
    month: Optional[str] = None,
    status: Optional[str] = None,
    brand: Optional[str] = None,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """List findings, optionally filtered by month (YYYY-MM, on first_seen),
    status and brand."""
    where, params = [], []
    if month:
        where.append("substr(first_seen, 1, 7) = ?")
        params.append(month)
    if status:
        where.append("status = ?")
        params.append(status)
    if brand:
        where.append("brand = ?")
        params.append(brand)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM domain_findings {clause} ORDER BY first_seen DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def weaponization_map() -> Dict[str, Dict[str, Any]]:
    """Map of domain -> {tier, active, first_seen, status} for every finding.

    Lets the dashboard, in one bulk load, tag rows with their stored tier (P1-P4)
    for the high-threat filter, show the 'Detected On' date (first_seen), and
    hide archived rows from the default view.
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT domain, weaponization_tier, weaponization_active, "
            "       first_seen, status, archived_by "
            "FROM domain_findings"
        ).fetchall()
    return {
        r["domain"]: {"tier": r["weaponization_tier"],
                      "active": bool(r["weaponization_active"]),
                      "first_seen": r["first_seen"],
                      "status": r["status"],
                      "archived_by": r["archived_by"]}
        for r in rows
    }


def untriaged_findings(limit: int = 2000) -> List[Dict[str, Any]]:
    """Findings that have never been weaponization-scored, highest-signal first.

    Ordered so a bounded backfill spends its LLM budget on the domains that
    actually resolve (and then by risk score) before the dormant long tail.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM domain_findings
               WHERE weaponization_scored_at IS NULL
               ORDER BY
                 CASE WHEN ip_addresses IS NOT NULL AND ip_addresses != ''
                           AND ip_addresses != '[]' THEN 0 ELSE 1 END,
                 COALESCE(risk_score, 0) DESC,
                 first_seen DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def archive_finding(domain: str, archived_by: str) -> bool:
    """Manually archive (reversibly hide) one finding, recording who did it.

    Unlike the auto job this has no quiet-time/safety guards — an analyst is
    explicitly choosing to ignore the row. ``archived_by`` is the analyst's
    name/email (the auto job stamps 'system'). Returns True if a row changed.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return False
    upsert_finding(domain, source="manual")
    now = _now()
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE domain_findings SET status = 'archived', archived_by = ?, "
            "archived_at = ?, updated_at = ? WHERE domain = ?",
            (archived_by or "analyst", now, now, domain),
        )
    logger.info(f"Finding {domain} archived by {archived_by}")
    return cur.rowcount > 0


def unarchive_finding(domain: str) -> bool:
    """Restore an archived finding to the active ('new') view, clearing the
    archive attribution. Returns True if a row changed."""
    domain = (domain or "").strip().lower()
    if not domain:
        return False
    now = _now()
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE domain_findings SET status = 'new', archived_by = NULL, "
            "archived_at = NULL, updated_at = ? WHERE domain = ? AND status = 'archived'",
            (now, domain),
        )
    logger.info(f"Finding {domain} unarchived")
    return cur.rowcount > 0


def archive_stale_findings(days: int = 7, dry_run: bool = False) -> Dict[str, Any]:
    """Archive (reversibly hide) findings that have gone quiet — no scan activity
    in ``days`` — and that no one has acted on.

    Sets ``status='archived'`` rather than deleting, so the row drops off the
    default dashboard view but stays in the ledger and monthly report and can be
    surfaced again via the 'Archived' filter. Same guards as the hard prune: an
    analyst-triaged, weaponized (active/P1/P2), exposure-touched, or in-flight
    finding is never archived. The 30-day :func:`prune_stale_findings` later
    hard-deletes anything (new or archived) that stays quiet that long.

    Returns ``{eligible, archived, cutoff, dry_run, sample}``.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    where = """
        last_seen < ?
        AND status = 'new'
        AND COALESCE(weaponization_active, 0) = 0
        AND (weaponization_tier IS NULL OR weaponization_tier NOT IN ('P1', 'P2'))
        AND COALESCE(exposure_touched, 0) = 0
        AND (phishfort_incident_id IS NULL OR phishfort_incident_id = '')
        AND (xsoar_id IS NULL OR xsoar_id = '')
        AND blocked_at IS NULL
        AND takedown_at IS NULL
    """
    now = _now()
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT domain, brand, last_seen FROM domain_findings WHERE {where} "
            f"ORDER BY last_seen LIMIT 25",
            (cutoff,),
        ).fetchall()
        eligible = conn.execute(
            f"SELECT COUNT(*) FROM domain_findings WHERE {where}", (cutoff,)
        ).fetchone()[0]
        archived = 0
        if not dry_run and eligible:
            cur = conn.execute(
                f"UPDATE domain_findings SET status = 'archived', "
                f"archived_by = 'system', archived_at = ?, updated_at = ? WHERE {where}",
                (now, now, cutoff),
            )
            archived = cur.rowcount
    logger.info(
        f"archive_stale_findings(days={days}, dry_run={dry_run}): "
        f"{eligible} eligible, {archived} archived (cutoff {cutoff[:10]})"
    )
    return {
        "eligible": eligible,
        "archived": archived,
        "cutoff": cutoff,
        "dry_run": dry_run,
        "sample": [dict(r) for r in rows],
    }


def prune_stale_findings(days: int = 30, dry_run: bool = False) -> Dict[str, Any]:
    """Delete findings that have gone quiet — not re-surfaced by a scan in
    ``days`` — and that no one has acted on.

    Aggressively guarded: only ``status='new'`` rows that are NOT weaponized
    (no active flag, not P1/P2), NOT exposure-touched, and NOT in any block or
    takedown workflow are eligible. So an analyst-triaged, confirmed, or
    in-flight finding is never pruned regardless of age. ``last_seen`` tracks
    last *activity* (new / became-active / reregistered / RF / CT), so a domain
    still on the RF watchlist or showing new behaviour keeps getting refreshed
    and won't age out.

    Returns ``{eligible, pruned, cutoff, dry_run, sample}``.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    where = """
        last_seen < ?
        AND status IN ('new', 'archived')
        AND COALESCE(weaponization_active, 0) = 0
        AND (weaponization_tier IS NULL OR weaponization_tier NOT IN ('P1', 'P2'))
        AND COALESCE(exposure_touched, 0) = 0
        AND (phishfort_incident_id IS NULL OR phishfort_incident_id = '')
        AND (xsoar_id IS NULL OR xsoar_id = '')
        AND blocked_at IS NULL
        AND takedown_at IS NULL
    """
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT domain, brand, last_seen FROM domain_findings WHERE {where} "
            f"ORDER BY last_seen LIMIT 25",
            (cutoff,),
        ).fetchall()
        eligible = conn.execute(
            f"SELECT COUNT(*) FROM domain_findings WHERE {where}", (cutoff,)
        ).fetchone()[0]
        pruned = 0
        if not dry_run and eligible:
            cur = conn.execute(
                f"DELETE FROM domain_findings WHERE {where}", (cutoff,)
            )
            pruned = cur.rowcount
    logger.info(
        f"prune_stale_findings(days={days}, dry_run={dry_run}): "
        f"{eligible} eligible, {pruned} pruned (cutoff {cutoff[:10]})"
    )
    return {
        "eligible": eligible,
        "pruned": pruned,
        "cutoff": cutoff,
        "dry_run": dry_run,
        "sample": [dict(r) for r in rows],
    }


def available_months() -> List[str]:
    """Distinct YYYY-MM buckets that have findings, newest first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT DISTINCT substr(first_seen, 1, 7) AS m FROM domain_findings ORDER BY m DESC"
        ).fetchall()
    return [r["m"] for r in rows if r["m"]]


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts) if ts else None
    except (ValueError, TypeError):
        return None


def _median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def sla_metrics(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Turnaround metrics over a set of findings: time-to-respond (detect→first
    block/takedown), time-to-takedown (submitted→resolved), % of confirmed-active
    threats contained, and open-takedown aging. All durations are best-effort and
    skip findings missing the timestamps they need.
    """
    respond_hrs: List[float] = []      # first_seen → first response action
    takedown_days: List[float] = []    # takedown submitted → resolved
    open_takedowns = 0
    oldest_open_days = 0.0
    confirmed = contained = 0
    now = datetime.now(timezone.utc)

    for f in findings:
        seen = _parse_ts(f.get("first_seen"))
        blocked = _parse_ts(f.get("blocked_at"))
        td_at = _parse_ts(f.get("takedown_at"))
        td_done = _parse_ts(f.get("takedown_completed_at"))

        # Time to respond: detection → earliest of (block, takedown).
        actions = [t for t in (blocked, td_at) if t]
        if seen and actions:
            delta_h = (min(actions) - seen).total_seconds() / 3600.0
            if delta_h >= 0:
                respond_hrs.append(delta_h)

        # Time to takedown: submitted → PhishFort-reported resolution.
        if td_at and td_done:
            delta_d = (td_done - td_at).total_seconds() / 86400.0
            if delta_d >= 0:
                takedown_days.append(delta_d)

        # Open takedown aging.
        if td_at and not td_done:
            open_takedowns += 1
            oldest_open_days = max(oldest_open_days, (now - td_at).total_seconds() / 86400.0)

        # Containment rate over confirmed-active threats.
        is_confirmed = (f.get("weaponization_active") == 1
                        or f.get("weaponization_tier") in ("P1", "P2"))
        if is_confirmed:
            confirmed += 1
            if (f.get("xsoar_id") or f.get("takedown_at") or f.get("status") == "takedown"):
                contained += 1

    return {
        "median_respond_hrs": round(_median(respond_hrs), 1) if respond_hrs else None,
        "responded_count": len(respond_hrs),
        "median_takedown_days": round(_median(takedown_days), 1) if takedown_days else None,
        "completed_takedowns": len(takedown_days),
        "open_takedowns": open_takedowns,
        "oldest_open_days": round(oldest_open_days, 1) if open_takedowns else None,
        "confirmed_active": confirmed,
        "contained": contained,
        "pct_contained": round(100.0 * contained / confirmed, 0) if confirmed else None,
    }


# --- Campaign clustering ---------------------------------------------------
#
# Goal: group findings that share an actor's footprint into "campaigns" so a
# coordinated wave of lookalikes reads as one thing (and can be taken down as a
# batch), instead of N scattered one-offs.
#
# The trap is over-clustering: phishing kits overwhelmingly reuse a handful of
# bulk registrars, Let's Encrypt, and shared CDNs — joining on those would merge
# everything into one meaningless blob. So we (1) only join on *discriminating*
# pivots, (2) drop pivot values on hard noise lists, and (3) drop any pivot value
# shared by an implausibly large share of the population (infrastructure, not a
# campaign). Registrar + generic issuer are kept as descriptive context on a
# cluster but are NOT used as join keys.

# Registrant orgs that mean "privacy-protected", i.e. no real attribution.
_PRIVACY_REGISTRANTS = (
    "redacted", "privacy", "whoisguard", "domains by proxy", "perfect privacy",
    "withheld", "data protected", "not disclosed", "private", "contact privacy",
    "identity protection", "domain protection", "gdpr", "registration private",
)
# Nameserver substrings that mark bulk/parking/CDN providers — shared by huge
# numbers of unrelated domains, so useless as a campaign join key.
_BULK_NS_SUBSTRINGS = (
    "cloudflare", "domaincontrol", "godaddy", "namecheap", "registrar-servers",
    "sedoparking", "bodis", "parkingcrew", "above.com", "dan.com", "uniregistry",
    "amazonaws", "awsdns", "azure-dns", "googledomains", "google.com", "ns.cloudns",
    "hostinger", "wixdns", "squarespace", "shopify", "fastly", "akamai",
)
# Cert issuers too generic to be a join key on their own.
_GENERIC_ISSUERS = (
    "let's encrypt", "lets encrypt", "r3", "r10", "r11", "e1", "e5", "e6",
    "google trust services", "gts", "amazon", "digicert", "sectigo", "zerossl",
    "cloudflare", "globalsign",
)
# Shared/CDN/parking IPs that connect unrelated domains — never a join key.
_NOISE_IPS = {"127.0.0.1", "0.0.0.0", "::1"}


def _is_privacy_registrant(val: str) -> bool:
    v = val.lower()
    return any(tok in v for tok in _PRIVACY_REGISTRANTS)


def _is_bulk_ns(val: str) -> bool:
    v = val.lower()
    return any(tok in v for tok in _BULK_NS_SUBSTRINGS)


def _is_generic_issuer(val: str) -> bool:
    v = val.lower()
    return any(tok in v for tok in _GENERIC_ISSUERS)


def _json_list(blob: Optional[str]) -> List[str]:
    if not blob:
        return []
    try:
        return [str(v).strip().lower() for v in (json.loads(blob) or []) if str(v).strip()]
    except (ValueError, TypeError):
        return []


class _UnionFind:
    def __init__(self):
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


# Pivot value shared by more than this fraction of the population is treated as
# infrastructure (e.g. one IP fronting every parked lookalike), not a campaign.
_MAX_PIVOT_SHARE = 0.5
_MAX_PIVOT_DOMAINS = 25  # absolute ceiling regardless of share


def cluster_campaigns(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group findings into campaigns by shared, discriminating infrastructure.

    Join keys: resolved IP, WHOIS registrant org (non-privacy), and authoritative
    nameserver (non-bulk). A campaign is a connected component of ≥2 domains. Each
    returned campaign carries the pivots that bound it, the brands/tiers involved,
    and whether anything in it is confirmed-active (so leadership can prioritise).
    """
    # Build pivot_value -> set(domains) for each discriminating pivot type.
    buckets: Dict[str, Dict[str, set]] = {"ip": {}, "registrant": {}, "nameserver": {}}
    by_domain: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        dom = (f.get("domain") or "").strip().lower()
        if not dom:
            continue
        by_domain[dom] = f
        for ip in _json_list(f.get("ip_addresses")):
            if ip not in _NOISE_IPS:
                buckets["ip"].setdefault(ip, set()).add(dom)
        org = (f.get("registrant_org") or "").strip().lower()
        if org and not _is_privacy_registrant(org):
            buckets["registrant"].setdefault(org, set()).add(dom)
        for ns in _json_list(f.get("nameservers")):
            if not _is_bulk_ns(ns):
                buckets["nameserver"].setdefault(ns, set()).add(dom)

    total = max(1, len(by_domain))
    cap = min(_MAX_PIVOT_DOMAINS, max(2, int(total * _MAX_PIVOT_SHARE)))

    uf = _UnionFind()
    for f in findings:  # seed every domain so singletons exist as their own root
        dom = (f.get("domain") or "").strip().lower()
        if dom:
            uf.find(dom)

    # Each non-noise pivot value shared by 2..cap domains is a campaign edge.
    edges: List[tuple] = []  # (ptype, value, [domains])
    for ptype, vmap in buckets.items():
        for value, doms in vmap.items():
            if 2 <= len(doms) <= cap:
                doms = sorted(doms)
                first = doms[0]
                for other in doms[1:]:
                    uf.union(first, other)
                edges.append((ptype, value, doms))

    # Collect connected components of size >= 2.
    comps: Dict[str, List[str]] = {}
    for dom in by_domain:
        comps.setdefault(uf.find(dom), []).append(dom)
    campaigns = []
    cid = 0
    for root, doms in comps.items():
        if len(doms) < 2:
            continue
        cid += 1
        domset = set(doms)
        pivots = []
        for ptype, value, edoms in edges:
            shared = sorted(domset.intersection(edoms))
            if len(shared) >= 2:
                pivots.append({"type": ptype, "value": value, "count": len(shared)})
        pivots.sort(key=lambda p: p["count"], reverse=True)

        rows = [by_domain[d] for d in doms]
        brands = sorted({(r.get("brand") or "Unattributed") for r in rows})
        tiers = sorted({r.get("weaponization_tier") for r in rows if r.get("weaponization_tier")})
        registrars = sorted({(r.get("registrar") or "").strip() for r in rows if (r.get("registrar") or "").strip()})
        any_active = any(r.get("weaponization_active") == 1 or r.get("weaponization_tier") in ("P1", "P2") for r in rows)
        contained = sum(1 for r in rows if (r.get("xsoar_id") or r.get("takedown_at") or r.get("status") == "takedown"))
        campaigns.append({
            "id": cid,
            "size": len(doms),
            "domains": sorted(doms),
            "pivots": pivots,
            "brands": brands,
            "tiers": tiers,
            "registrars": registrars,
            "any_active": any_active,
            "contained": contained,
        })

    # Biggest + active-first: the campaigns leadership should look at first.
    campaigns.sort(key=lambda c: (c["any_active"], c["size"]), reverse=True)
    for i, c in enumerate(campaigns, 1):
        c["id"] = i
    return campaigns


def monthly_rollup(month: str) -> Dict[str, Any]:
    """Aggregate a month (YYYY-MM) into the monthly-report shape.

    Returns by-brand counts, takedown-vs-monitoring split, the irrelevant list,
    a weekly trend, and the full triaged domain list — mirroring the sheets of
    the manual Domain Monitoring & Brand Protection report.
    """
    findings = list_findings(month=month, limit=100000)
    relevant = [f for f in findings if f["status"] != "irrelevant"]
    irrelevant = [f for f in findings if f["status"] == "irrelevant"]
    takedowns = [f for f in findings if f["status"] == "takedown"]
    # "Under monitoring" is the explicitly-triaged monitoring state — NOT every
    # non-irrelevant finding, which would mislabel untriaged 'new' discoveries
    # (and bau_owned) as actively monitored in a leadership-facing report.
    monitoring = [f for f in findings if f["status"] == "monitoring"]
    untriaged = [f for f in findings if f["status"] == "new"]

    by_brand: Dict[str, int] = {}
    for f in relevant:
        b = (f.get("brand") or "Unattributed")
        by_brand[b] = by_brand.get(b, 0) + 1

    # Weekly trend: count of findings whose first_seen falls in ISO week buckets.
    weekly: Dict[str, int] = {}
    for f in findings:
        try:
            d = datetime.fromisoformat(f["first_seen"])
            wk = f"{d.isocalendar().year}-W{d.isocalendar().week:02d}"
            weekly[wk] = weekly.get(wk, 0) + 1
        except (ValueError, TypeError):
            continue

    return {
        "month": month,
        "total_findings": len(findings),
        "relevant": len(relevant),
        "irrelevant": len(irrelevant),
        "takedowns": len(takedowns),
        "monitoring": len(monitoring),
        "untriaged": len(untriaged),
        "by_brand": dict(sorted(by_brand.items(), key=lambda kv: kv[1], reverse=True)),
        "weekly_trend": dict(sorted(weekly.items())),
        "sla": sla_metrics(findings),
        "campaigns": cluster_campaigns(relevant),
        "findings": findings,
        "irrelevant_findings": irrelevant,
    }


# Initialize on import so callers don't have to.
try:
    init_db()
    logger.info(f"Domain findings ledger initialized at {DB_PATH}")
except Exception as e:  # pragma: no cover
    logger.error(f"Could not initialize findings ledger: {e}")
