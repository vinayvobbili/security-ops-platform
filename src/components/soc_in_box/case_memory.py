"""Cross-incident case memory for SOC-in-a-Box.

The reactive agent chain (Tier 2 / IR Lead / Threat Intel) investigates every
ticket cold — nothing tells an agent "we saw this host / IOC / actor three weeks
ago and dispositioned it benign." This module is the durable, queryable index
that closes that gap. It sits on top of the data we already persist (the
``soc.audit`` event log + ``verdicts.sqlite``); it does NOT change agent
behavior on its own.

Lives at ``data/soc_in_box/case_memory.sqlite`` (gitignored runtime data).
Schema is created on first connection — no separate migration step.

Two tables:

- ``case_index``    — one row per ticket: terminal verdict, disposition, actor,
  a short summary, timestamps.
- ``case_entities`` — fan-out: every host / ip / domain / hash / user / actor /
  campaign / mitre / cve / rule a ticket touched. This is what cross-incident
  matching joins on.

Three public read paths, all built on the index:

- :func:`recall_similar_cases` — "how did we handle cases like this before?"
  Structured entity-overlap match, ranked by weighted overlap + recency +
  prior confidence. Powers the recall block injected into agent prompts
  (behind a flag, later slice) and campaign clustering.
- :func:`get_case_reasoning` — "why did the agent do X on ticket N?" Assembles
  the full recorded reasoning timeline (audit replay + verdict rows + HITL
  decisions) for a grounded, no-hallucination narrator.
- :func:`backfill` / :func:`index_recent` — populate / refresh the index from
  the audit stream. Indexing runs on a timer (like the other rollup agents),
  so no inline hook in the agent loop.

CLI::

    python -m src.components.soc_in_box.case_memory backfill
    python -m src.components.soc_in_box.case_memory recall --ticket 12345
    python -m src.components.soc_in_box.case_memory why --ticket 12345
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


DB_PATH = Path("data/soc_in_box/case_memory.sqlite")

# Entity types we index. Weights drive recall ranking: a shared command-and-
# control hash or actor is a far stronger signal of relatedness than a shared
# host or user (which can be coincidentally common in a busy SOC).
ENTITY_WEIGHTS: dict[str, float] = {
    "actor": 3.0,
    "hash": 3.0,
    "campaign": 3.0,
    "ip": 2.0,
    "domain": 2.0,
    "cve": 2.0,
    "mitre": 1.0,
    "host": 1.0,
    "user": 1.0,
    "rule": 0.5,
}

# Terminal events — presence of one means the ticket has been worked far enough
# to be worth indexing. (There is no explicit "case closed" event in v1.)
_TERMINAL_EVENT_TYPES = ("ir.plan", "threat_intel.report", "tier2.analysis")

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")


SCHEMA = """
CREATE TABLE IF NOT EXISTS case_index (
    ticket_id      TEXT PRIMARY KEY,
    correlation_id TEXT,
    final_verdict  TEXT,
    confidence     REAL NOT NULL DEFAULT 0.0,
    severity       TEXT,
    disposition    TEXT,
    likely_actor   TEXT,
    summary        TEXT,
    playbook_json  TEXT,
    last_event_at  TEXT,
    indexed_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_case_index_verdict ON case_index(final_verdict);
CREATE INDEX IF NOT EXISTS idx_case_index_lastev  ON case_index(last_event_at);

CREATE TABLE IF NOT EXISTS case_entities (
    ticket_id    TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    PRIMARY KEY (ticket_id, entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_case_entities_value ON case_entities(entity_value);
CREATE INDEX IF NOT EXISTS idx_case_entities_type  ON case_entities(entity_type, entity_value);

CREATE TABLE IF NOT EXISTS campaign_alerts (
    campaign_id        TEXT PRIMARY KEY,
    shared_json        TEXT,
    member_tickets_json TEXT,
    case_count         INTEGER NOT NULL DEFAULT 0,
    first_alerted_at   TEXT NOT NULL,
    last_alerted_at    TEXT NOT NULL
);
"""

# Entity types strong enough to LINK two cases into one campaign. Shared external
# infra / attribution — not noisy internal signals (host repeat is the Threat
# Hunter's job; user/mitre/rule are too generic to imply a campaign).
_STRONG_LINK_TYPES = ("actor", "campaign", "hash", "domain", "ip", "cve")

_SEVERITY_ORDER = ("SEV-1", "SEV-2", "SEV-3", "SEV-4")


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)
    # In-place migration for indexes created before playbook capture (Slice 5).
    cols = {r[1] for r in conn.execute("PRAGMA table_info(case_index)").fetchall()}
    if "playbook_json" not in cols:
        conn.execute("ALTER TABLE case_index ADD COLUMN playbook_json TEXT")
        conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


# -- entity extraction ---------------------------------------------------

def _norm(v: Any) -> str:
    return str(v or "").strip()


def _extract_iocs_from_struct(iocs: Any) -> dict[str, set[str]]:
    """Pull entities out of Threat Intel's ``iocs_examined`` (list of dicts).

    Entry shapes vary; we defensively read common key names and classify by an
    explicit ``type`` field when present, otherwise by value shape.
    """
    out: dict[str, set[str]] = defaultdict(set)
    if not isinstance(iocs, list):
        return out
    for entry in iocs:
        if not isinstance(entry, dict):
            continue
        value = ""
        for k in ("indicator", "value", "ioc", "artifact", "name"):
            if entry.get(k):
                value = _norm(entry[k])
                break
        if not value:
            continue
        kind = _norm(entry.get("type") or entry.get("kind") or entry.get("ioc_type")).lower()
        if "hash" in kind or "sha" in kind or "md5" in kind or _HASH_RE.fullmatch(value):
            out["hash"].add(value.lower())
        elif "domain" in kind or "host" in kind and "." in value:
            out["domain"].add(value.lower())
        elif "ip" in kind:
            out["ip"].add(value)
        elif "url" in kind:
            # keep the host of a URL as a domain entity
            m = re.search(r"https?://([^/:\s]+)", value, re.IGNORECASE)
            if m:
                out["domain"].add(m.group(1).lower())
        elif "cve" in kind or _CVE_RE.fullmatch(value):
            out["cve"].add(value.upper())
        else:
            # Unknown type — fall back to value-shape sniffing
            if _HASH_RE.fullmatch(value):
                out["hash"].add(value.lower())
            elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
                out["ip"].add(value)
            elif "." in value and " " not in value:
                out["domain"].add(value.lower())
    return out


def extract_entities(events: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Extract every indexable entity from one ticket's event list.

    Reuses Threat Hunter's conservative IP/domain text extraction so the two
    subsystems agree on what counts as an indicator. Structured fields
    (hostname, username, actor, campaigns, mitre, iocs_examined) are preferred;
    free-text summaries are mined as a backstop.
    """
    # Indicator extraction lives in the kernel (vendor-neutral, dependency-free)
    # so every subsystem agrees on what counts as an IP/domain.
    from aisoc.extract import extract_indicators as _extract_indicators

    ents: dict[str, set[str]] = defaultdict(set)
    text_blobs: list[str] = []

    for e in events:
        for host_key in ("hostname",):
            h = _norm(e.get(host_key))
            if h:
                ents["host"].add(h.lower())
        u = _norm(e.get("username"))
        if u:
            ents["user"].add(u.lower())

        actor = _norm(e.get("likely_actor"))
        if actor and actor.lower() not in ("", "unknown", "none", "n/a"):
            ents["actor"].add(actor)

        for camp in e.get("campaigns") or []:
            c = _norm(camp)
            if c:
                ents["campaign"].add(c)
        for tech in e.get("mitre_techniques") or []:
            t = _norm(tech)
            if t:
                ents["mitre"].add(t.upper())

        ioc_ents = _extract_iocs_from_struct(e.get("iocs_examined"))
        for k, vals in ioc_ents.items():
            ents[k] |= vals

        # rule name lives under details for triage events
        details = e.get("details") or {}
        for rk in ("rule_name", "alert_rule", "ruleName"):
            if details.get(rk):
                ents["rule"].add(_norm(details[rk]))
                break

        for tk in ("summary", "tier2_summary", "ir_summary", "intel_summary",
                   "recommended_action"):
            blob = _norm(e.get(tk))
            if blob:
                text_blobs.append(blob)

    joined = "\n".join(text_blobs)
    if joined:
        ips, domains = _extract_indicators(joined)
        ents["ip"] |= set(ips)
        ents["domain"] |= {d.lower() for d in domains}
        for cve in _CVE_RE.findall(joined):
            ents["cve"].add(cve.upper())
        for h in _HASH_RE.findall(joined):
            ents["hash"].add(h.lower())

    # Drop empties
    return {k: v for k, v in ents.items() if v}


# -- case summarization --------------------------------------------------

def _parse_ts(raw: Any) -> Optional[datetime]:
    from aisoc.extract import parse_event_ts
    return parse_event_ts(raw)


# Verdict severity order (worst first) — used to pick a ticket's terminal verdict
# when multiple roles weighed in.
_VERDICT_RANK = {
    "true_positive_malicious": 0,
    "true_positive_malicious_contained": 1,
    "true_positive_benign": 2,
    "false_positive": 3,
    "close_ticket": 4,
}


def _summarize_case(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll one ticket's events into the ``case_index`` row fields."""
    final_verdict = ""
    confidence = 0.0
    severity = ""
    disposition = ""
    likely_actor = ""
    summary = ""
    last_event_at: Optional[datetime] = None

    # Prefer the most authoritative verdict: refined (Tier 2) > triaged.
    best_rank = 99
    for e in events:
        ts = _parse_ts(e.get("timestamp"))
        if ts and (last_event_at is None or ts > last_event_at):
            last_event_at = ts

        et = e.get("event_type") or ""
        v = _norm(e.get("refined_verdict") or e.get("verdict"))
        if v and _VERDICT_RANK.get(v, 99) <= best_rank:
            best_rank = _VERDICT_RANK.get(v, 99)
            final_verdict = v
            try:
                confidence = float(e.get("confidence") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0

        if et == "ir.plan":
            severity = _norm(e.get("severity")) or severity
            disposition = "ir_plan_drafted"
            summary = _norm(e.get("ir_summary")) or summary
        elif et == "tier2.analysis":
            disposition = disposition or _norm(e.get("escalation_decision"))
            summary = summary or _norm(e.get("tier2_summary"))
        elif et == "threat_intel.report":
            likely_actor = _norm(e.get("likely_actor")) or likely_actor
            summary = summary or _norm(e.get("intel_summary"))
        elif et == "alert.triaged":
            severity = severity or _norm(e.get("severity"))
            summary = summary or _norm(e.get("summary"))

    return {
        "final_verdict": final_verdict,
        "confidence": confidence,
        "severity": severity,
        "disposition": disposition,
        "likely_actor": likely_actor,
        "summary": summary[:600],
        "last_event_at": last_event_at.isoformat() if last_event_at else None,
    }


# Playbook phases in canonical SOC response order — the sequence analysts
# actually work a case through. Used to bucket + order replicated actions.
_PLAYBOOK_PHASES = ("triage", "escalation", "containment", "eradication",
                    "recovery", "notification")


def _extract_playbook(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract the ordered ACTION sequence taken on a case — the 'playbook'.

    This is what analyst-action replication recalls: not just the verdict, but
    the concrete steps (escalate, isolate host, block domain, open bridge, …) in
    response order. Deduped, source-attributed. Pulled from the same events the
    case was worked through.
    """
    steps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(phase: str, action: Any, role: str) -> None:
        a = _norm(action)
        key = (phase, a.lower())
        if a and key not in seen:
            seen.add(key)
            steps.append({"phase": phase, "action": a, "by": role})

    ordered = sorted(events, key=lambda e: (_parse_ts(e.get("timestamp"))
                     or datetime.min.replace(tzinfo=timezone.utc)))
    for e in ordered:
        et = e.get("event_type") or ""
        role = _norm(e.get("produced_by"))
        if et == "tier2.analysis":
            dec = _norm(e.get("escalation_decision"))
            if dec:
                add("escalation", f"Tier 2: {dec}", role)
            for ns in e.get("next_steps") or []:
                add("triage", ns, role)
        elif et == "ir.plan":
            for a in e.get("containment_actions") or []:
                add("containment", a, role)
            for a in e.get("eradication_actions") or []:
                add("eradication", a, role)
            for a in e.get("recovery_actions") or []:
                add("recovery", a, role)
            for a in e.get("notifications") or []:
                add("notification", a, role)
            if e.get("bridge_required"):
                add("escalation", "Open incident bridge", role)
        elif et == "action.proposed":
            for a in e.get("actions_summary") or []:
                add("containment", a, role)
    return steps


# -- indexing ------------------------------------------------------------

def _events_by_ticket(client) -> dict[str, list[dict[str, Any]]]:
    """Replay the full audit stream, bucketed by ticket_id/correlation_id."""
    from src.components.soc_in_box.bus import STREAM_AUDIT, replay
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in replay(client, STREAM_AUDIT, start="-", end="+", count=None):
        tid = _norm(e.get("ticket_id") or e.get("correlation_id"))
        if tid:
            buckets[tid].append(e)
    return buckets


def index_case(ticket_id: str,
               events: Optional[list[dict[str, Any]]] = None,
               client=None) -> bool:
    """Index (or re-index, idempotently) one ticket.

    If ``events`` is not supplied, the audit stream is replayed and filtered to
    this ticket. Returns True if a row was written, False if the ticket has no
    terminal/working events worth indexing.
    """
    if events is None:
        from src.components.soc_in_box.bus import get_redis_client
        client = client or get_redis_client()
        events = _events_by_ticket(client).get(ticket_id, [])

    if not events:
        return False
    # Only index tickets that were actually worked (not bare alerts).
    if not any((e.get("event_type") in _TERMINAL_EVENT_TYPES) for e in events):
        return False

    row = _summarize_case(events)
    ents = extract_entities(events)
    playbook = _extract_playbook(events)
    correlation_id = _norm(events[0].get("correlation_id")) or ticket_id

    conn = _connect()
    with conn:
        conn.execute(
            """INSERT INTO case_index
                 (ticket_id, correlation_id, final_verdict, confidence, severity,
                  disposition, likely_actor, summary, playbook_json, last_event_at,
                  indexed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ticket_id) DO UPDATE SET
                  correlation_id=excluded.correlation_id,
                  final_verdict=excluded.final_verdict,
                  confidence=excluded.confidence,
                  severity=excluded.severity,
                  disposition=excluded.disposition,
                  likely_actor=excluded.likely_actor,
                  summary=excluded.summary,
                  playbook_json=excluded.playbook_json,
                  last_event_at=excluded.last_event_at,
                  indexed_at=excluded.indexed_at""",
            (ticket_id, correlation_id, row["final_verdict"], row["confidence"],
             row["severity"], row["disposition"], row["likely_actor"],
             row["summary"], json.dumps(playbook), row["last_event_at"],
             datetime.now(timezone.utc).isoformat()),
        )
        # Replace this ticket's entity rows wholesale (re-index is authoritative).
        conn.execute("DELETE FROM case_entities WHERE ticket_id = ?", (ticket_id,))
        conn.executemany(
            "INSERT OR IGNORE INTO case_entities (ticket_id, entity_type, entity_value) "
            "VALUES (?, ?, ?)",
            [(ticket_id, et, val) for et, vals in ents.items() for val in vals],
        )
    conn.close()
    logger.debug("case_memory.index_case ticket=%s verdict=%s entities=%d",
                 ticket_id, row["final_verdict"], sum(len(v) for v in ents.values()))
    return True


def backfill(client=None) -> int:
    """Index every worked ticket currently in the audit stream. Returns count."""
    from src.components.soc_in_box.bus import get_redis_client
    client = client or get_redis_client()
    buckets = _events_by_ticket(client)
    n = 0
    for tid, events in buckets.items():
        if index_case(tid, events=events):
            n += 1
    logger.info("case_memory.backfill indexed %d/%d tickets", n, len(buckets))
    return n


def index_recent(window_hours: float = 24.0, client=None) -> int:
    """Re-index tickets with audit activity in the last ``window_hours``.

    Cheap to run on a timer. Re-indexing is idempotent, so a sliding window
    that overlaps the previous run is fine.
    """
    from src.components.soc_in_box.bus import get_redis_client
    client = client or get_redis_client()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    buckets = _events_by_ticket(client)
    n = 0
    for tid, events in buckets.items():
        recent = any((ts := _parse_ts(e.get("timestamp"))) and ts >= cutoff
                     for e in events)
        if recent and index_case(tid, events=events):
            n += 1
    logger.info("case_memory.index_recent window=%sh indexed %d tickets",
                window_hours, n)
    return n


# -- recall --------------------------------------------------------------

def recall_similar_cases(entities: dict[str, set[str]] | dict[str, list[str]],
                         *,
                         exclude_ticket_id: Optional[str] = None,
                         k: int = 5,
                         min_score: float = 1.0) -> list[dict[str, Any]]:
    """Find prior cases that share entities with ``entities``.

    Structured entity-overlap match. Score = sum over shared entities of the
    entity-type weight, multiplied by a recency factor (cases older than ~180
    days are down-weighted) and nudged by the prior case's confidence. Returns
    up to ``k`` cases sorted by score desc, each with the shared entities that
    matched (so the reason is fully explainable — no black box).
    """
    # Flatten the query entities to (type, value) pairs.
    pairs: list[tuple[str, str]] = []
    for etype, vals in entities.items():
        for v in vals:
            v = _norm(v)
            if v:
                pairs.append((etype, v.lower() if etype not in ("actor", "campaign", "mitre", "cve")
                              else (v.upper() if etype in ("mitre", "cve") else v)))
    if not pairs:
        return []

    conn = _connect()
    # Match on value (a host that's also a domain string still corroborates).
    matched: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for etype, val in pairs:
        rows = conn.execute(
            "SELECT ticket_id, entity_type, entity_value FROM case_entities "
            "WHERE entity_value = ?",
            (val,),
        ).fetchall()
        for r in rows:
            if exclude_ticket_id and r["ticket_id"] == exclude_ticket_id:
                continue
            matched[r["ticket_id"]].append((r["entity_type"], r["entity_value"]))

    if not matched:
        conn.close()
        return []

    now = datetime.now(timezone.utc)
    results: list[dict[str, Any]] = []
    for tid, shared in matched.items():
        idx = conn.execute(
            "SELECT * FROM case_index WHERE ticket_id = ?", (tid,)
        ).fetchone()
        if idx is None:
            continue
        # De-dup shared entities, score by weight.
        uniq = sorted(set(shared))
        raw = sum(ENTITY_WEIGHTS.get(et, 1.0) for et, _ in uniq)

        recency = 1.0
        last = _parse_ts(idx["last_event_at"])
        if last:
            age_days = max(0.0, (now - last).total_seconds() / 86400.0)
            # Linear decay to 0.4 floor over 180 days.
            recency = max(0.4, 1.0 - (age_days / 180.0) * 0.6)
        conf_nudge = 0.85 + 0.15 * float(idx["confidence"] or 0.0)
        score = raw * recency * conf_nudge

        if score < min_score:
            continue
        results.append({
            "ticket_id": tid,
            "final_verdict": idx["final_verdict"],
            "confidence": float(idx["confidence"] or 0.0),
            "severity": idx["severity"],
            "disposition": idx["disposition"],
            "likely_actor": idx["likely_actor"],
            "summary": idx["summary"],
            "last_event_at": idx["last_event_at"],
            "shared_entities": [{"type": et, "value": val} for et, val in uniq],
            "score": round(score, 3),
        })

    conn.close()
    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:k]


def _load_ticket_entities(ticket_id: str, client=None) -> dict[str, set[str]]:
    """Entities for a ticket — from the live bus if reachable, else the index.

    A brand-new ticket's entities live on the audit stream; an already-worked
    ticket's are in ``case_entities``. Trying the bus first keeps recall current
    for in-flight tickets, while the index fallback means recall still works when
    Redis is down or the events have aged out.
    """
    try:
        from src.components.soc_in_box.bus import get_redis_client
        events = _events_by_ticket(client or get_redis_client()).get(ticket_id, [])
        if events:
            return extract_entities(events)
    except Exception as exc:
        logger.debug("case_memory: bus entity load failed for %s (%s); "
                     "falling back to index", ticket_id, exc)

    conn = _connect()
    rows = conn.execute(
        "SELECT entity_type, entity_value FROM case_entities WHERE ticket_id = ?",
        (ticket_id,),
    ).fetchall()
    conn.close()
    ents: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        ents[r["entity_type"]].add(r["entity_value"])
    return dict(ents)


def recall_for_ticket(ticket_id: str, *, k: int = 5, client=None) -> list[dict[str, Any]]:
    """Convenience: load the ticket's entities, then recall prior cases.

    Excludes the ticket itself. Returns [] if the ticket has no known entities.
    """
    ents = _load_ticket_entities(ticket_id, client=client)
    if not ents:
        return []
    return recall_similar_cases(ents, exclude_ticket_id=ticket_id, k=k)


# -- action replication (playbook recall) --------------------------------

def get_case_playbook(ticket_id: str) -> list[dict[str, Any]]:
    """The ordered action sequence recorded for one case (its own playbook)."""
    conn = _connect()
    row = conn.execute(
        "SELECT playbook_json FROM case_index WHERE ticket_id = ?", (ticket_id,)
    ).fetchone()
    conn.close()
    if not row:
        return []
    try:
        return json.loads(row["playbook_json"] or "[]")
    except (json.JSONDecodeError, TypeError):
        return []


def recommend_playbook(ticket_id: str, *, k: int = 5, client=None) -> dict[str, Any]:
    """Recommend a response playbook for ``ticket_id`` from PRECEDENT.

    Finds the most similar prior cases (shared entities) and aggregates what
    analysts actually did on them, by phase — "behavioral cloning by retrieval."
    The recommendation is the established practice, with each action carrying how
    many precedent cases used it + the ticket refs, so it's fully explainable and
    advisory (no agent action taken here).
    """
    similar = recall_for_ticket(ticket_id, k=k, client=client)
    if not similar:
        return {"found": False, "ticket_id": ticket_id, "precedents": 0,
                "phases": [], "similar": []}

    phase_actions: dict[str, Counter] = defaultdict(Counter)
    action_tickets: dict[tuple[str, str], list[str]] = defaultdict(list)
    verdicts: Counter = Counter()
    for s in similar:
        verdicts[s.get("final_verdict") or "unknown"] += 1
        for step in get_case_playbook(s["ticket_id"]):
            phase, action = step.get("phase", ""), _norm(step.get("action"))
            if not action:
                continue
            phase_actions[phase][action] += 1
            action_tickets[(phase, action)].append(s["ticket_id"])

    phases: list[dict[str, Any]] = []
    for phase in _PLAYBOOK_PHASES:
        acts = phase_actions.get(phase)
        if not acts:
            continue
        phases.append({
            "phase": phase,
            "actions": [{"action": a, "used_in": n,
                         "tickets": action_tickets[(phase, a)]}
                        for a, n in acts.most_common()],
        })

    return {
        "found": bool(phases),
        "ticket_id": ticket_id,
        "precedents": len(similar),
        "verdict_mix": dict(verdicts.most_common()),
        "phases": phases,
        "similar": similar,
    }


def render_playbook_for_chat(rec: dict[str, Any]) -> str:
    """Render :func:`recommend_playbook` output into a grounding block for a
    toolless narrator to present as a precedent-based recommendation.
    """
    tid = rec.get("ticket_id", "?")
    if not rec.get("found"):
        return (f"[SOC-IN-A-BOX PLAYBOOK — no comparable prior cases found for "
                f"ticket #{tid}, so there is no established precedent to cite. Say "
                f"so plainly; do not invent a playbook.]")

    n = rec.get("precedents", 0)
    lines = [
        f"[SOC-IN-A-BOX PLAYBOOK for ticket #{tid} — derived from {n} similar PRIOR "
        "cases (what analysts actually did). Present this as the established, "
        "precedent-based playbook. Order the phases as given. For each action note "
        "how many of the prior cases used it (that's the strength of precedent). "
        "This is ADVISORY — recommend, don't claim any action was taken. Use ONLY "
        "what's below.",
        "",
        "Precedent verdict mix: " + (", ".join(f"{k}={v}" for k, v in
                                     rec.get("verdict_mix", {}).items()) or "n/a"),
        "",
        "Recommended playbook by phase:",
    ]
    for ph in rec["phases"]:
        lines.append(f"  {ph['phase'].upper()}:")
        for a in ph["actions"]:
            refs = ", ".join("#" + t for t in a["tickets"][:6])
            lines.append(f"    - {a['action']}  "
                         f"(used in {a['used_in']}/{n} precedents: {refs})")
    lines.append("")
    lines.append("End of playbook.]")
    return "\n".join(lines)


# -- precedent injection into the agents' own prompts --------------------
# These render the SAME recall/playbook data as the chat helpers above, but as
# first-person prompt sections an agent reads while reasoning (vs. a grounding
# block for a narrator). Injection is FLAG-GATED so landing it changes no agent
# behavior until SIAB_CASE_RECALL=1 is deliberately set.

def render_recall_for_prompt(similar: list[dict[str, Any]]) -> str:
    """Prompt section listing prior similar cases + how they resolved. Empty if none."""
    if not similar:
        return ""
    lines = [
        "## Precedent — similar prior cases (from case memory)",
        "_Cases sharing strong indicators with this one, and how they resolved. "
        "Treat as PRIOR evidence: corroborate or explicitly differ — it is not "
        "ground truth for this ticket._",
    ]
    for s in similar:
        shared = ", ".join(f"{e['type']}:{e['value']}"
                            for e in s.get("shared_entities", [])[:6])
        actor = f", actor {s['likely_actor']}" if s.get("likely_actor") else ""
        lines.append(
            f"- #{s['ticket_id']}: {s.get('final_verdict') or '?'} "
            f"(conf {float(s.get('confidence') or 0):.2f}, "
            f"{s.get('disposition') or 'n/a'}{actor}) — shared {shared or 'n/a'}"
        )
        if s.get("summary"):
            lines.append(f"    {str(s['summary'])[:200]}")
    return "\n".join(lines)


def render_playbook_for_prompt(rec: dict[str, Any]) -> str:
    """Prompt section: precedent-derived playbook for an agent drafting a plan."""
    if not rec.get("found"):
        return ""
    n = rec.get("precedents", 0)
    lines = [
        f"## Precedent playbook — what we did on {n} similar prior cases",
        "_Aggregated from what analysts actually did on the most similar past "
        "cases (strength = how many precedents used each step). ADVISORY: adapt "
        "to this incident, don't copy blindly._",
    ]
    for ph in rec["phases"]:
        lines.append(f"- **{ph['phase'].upper()}**")
        for a in ph["actions"][:6]:
            lines.append(f"    - {a['action']} (used in {a['used_in']}/{n})")
    return "\n".join(lines)


def incident_precedent_block(ticket_id: str, *, include_playbook: bool = True,
                             k: int = 5, client=None) -> str:
    """Flag-gated precedent block for an agent's prompt (``SIAB_CASE_RECALL=1``).

    Returns the prior similar cases and, optionally, the precedent-derived
    playbook, so an agent can reason from what this SOC has actually seen and
    done before. Returns an empty string when the flag is off, nothing matches,
    or retrieval fails — callers append the result unconditionally.
    """
    import os
    if os.getenv("SIAB_CASE_RECALL", "") != "1":
        return ""
    try:
        if include_playbook:
            rec = recommend_playbook(ticket_id, k=k, client=client)
            blocks = [render_recall_for_prompt(rec.get("similar", [])),
                      render_playbook_for_prompt(rec)]
        else:
            blocks = [render_recall_for_prompt(
                recall_for_ticket(ticket_id, k=k, client=client))]
        return "\n\n".join(b for b in blocks if b)
    except Exception as exc:  # never let recall break the agent loop
        logger.debug("case_memory: precedent block skipped for %s (%s)",
                     ticket_id, exc)
        return ""


def entity_precedent_block(entities: dict[str, set[str]] | dict[str, list[str]],
                           *, exclude_ticket_ids: Optional[set[str]] = None,
                           k: int = 5) -> str:
    """Flag-gated recall block keyed on ENTITIES rather than a ticket id.

    For the cluster agents (Threat Hunter, Detection Engineer) whose unit of work
    is a cluster of tickets sharing an indicator, not a single case. Returns prior
    cases that share those entities — excluding the cluster's own member tickets —
    so the agent can see how the same host/pivot resolved before. Empty string
    when the flag is off, nothing matches, or retrieval fails.
    """
    import os
    if os.getenv("SIAB_CASE_RECALL", "") != "1":
        return ""
    try:
        if not entities:
            return ""
        excl = exclude_ticket_ids or set()
        # Over-fetch so post-filtering the cluster's own tickets still leaves k.
        # Lower min_score than the per-incident path: this is an explicit
        # exact-entity lookup ("did we see this host/pivot before?"), so a single
        # weak-entity (host/user) match is the signal we want, not noise.
        similar = recall_similar_cases(entities, k=k + len(excl), min_score=0.5)
        if excl:
            similar = [s for s in similar if s["ticket_id"] not in excl]
        return render_recall_for_prompt(similar[:k])
    except Exception as exc:  # never let recall break the agent loop
        logger.debug("case_memory: entity precedent block skipped (%s)", exc)
        return ""


def shift_campaign_block(window_days: float = 0.34, *, min_cases: int = 2,
                         client=None) -> str:
    """Flag-gated cross-incident signal for the SOC Manager's shift summary.

    The Manager summarizes a window, not one incident — so the useful case-memory
    addition is the forming-campaign signal: indicators/actors linking multiple
    tickets this shift (the same primitive the Campaign Detector alerts on). Empty
    string when the flag is off, nothing clusters, or retrieval fails.
    """
    import os
    if os.getenv("SIAB_CASE_RECALL", "") != "1":
        return ""
    try:
        clusters = find_campaign_clusters(
            window_days=window_days, min_cases=min_cases, client=client)
        if not clusters:
            return ""
        lines = [
            "## Cross-incident signal this shift (from case memory)",
            "_Indicators/actors linking multiple tickets in the window — possible "
            "forming campaigns. Call these out in the readout if notable._",
        ]
        for c in clusters[:5]:
            shared = ", ".join(f"{s['type']}:{s['value']}"
                               for s in c.get("shared_indicators", [])[:5])
            tix = ", ".join("#" + t for t in c.get("member_tickets", [])[:8])
            actor = f" [{c['likely_actor']}]" if c.get("likely_actor") else ""
            lines.append(f"- {c.get('case_count', 0)} tickets share {shared}{actor} — {tix}")
        return "\n".join(lines)
    except Exception as exc:  # never let recall break the summary
        logger.debug("case_memory: shift campaign block skipped (%s)", exc)
        return ""


# -- trends (leadership rollup) ------------------------------------------

def compute_trends(window_days: float = 7.0, client=None) -> dict[str, Any]:
    """Deterministic SOC-in-a-Box rollup over the last ``window_days``.

    Aggregates three durable sources — the case index (volume / verdict mix /
    severity / disposition / actors / recurring entities), ``verdicts.sqlite``
    (per-role cost, latency, confidence, accuracy-vs-ground-truth), and the HITL
    decisions (approval bottleneck). Pure arithmetic — the narrative is a
    separate LLM step (:func:`render_trends_for_chat`) so the numbers are never
    invented.

    Recurring entities (an indicator/actor touching 2+ cases in the window) are
    surfaced as the early campaign signal — the same primitive Slice 4 alerts on.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=window_days)
    since_sql = since.strftime("%Y-%m-%d %H:%M:%S")
    since_iso = since.isoformat()

    # --- worked cases from the index (filter by last_event_at) ---
    conn = _connect()
    idx_rows = conn.execute("SELECT * FROM case_index").fetchall()
    in_window = [r for r in idx_rows
                 if (ts := _parse_ts(r["last_event_at"])) and ts >= since]
    case_ids = [r["ticket_id"] for r in in_window]

    verdict_mix = Counter((r["final_verdict"] or "unknown") for r in in_window)
    severity_mix = Counter((r["severity"] or "unknown") for r in in_window)
    disposition_mix = Counter((r["disposition"] or "unknown") for r in in_window)
    actor_mix = Counter(r["likely_actor"] for r in in_window
                        if (r["likely_actor"] or "").strip())

    recurring: dict[str, list[dict[str, Any]]] = {}
    if case_ids:
        qmarks = ",".join("?" * len(case_ids))
        ent_rows = conn.execute(
            f"SELECT entity_type, entity_value, COUNT(DISTINCT ticket_id) AS c "
            f"FROM case_entities WHERE ticket_id IN ({qmarks}) "
            f"GROUP BY entity_type, entity_value HAVING c >= 2 ORDER BY c DESC",
            case_ids,
        ).fetchall()
        for er in ent_rows:
            recurring.setdefault(er["entity_type"], []).append(
                {"value": er["entity_value"], "cases": er["c"]})
    conn.close()

    # --- per-role cost / latency / confidence / accuracy ---
    from src.components.soc_in_box import verdict_store
    vrows = verdict_store.get_verdicts_since(since_sql)
    roles: dict[str, dict[str, float]] = {}
    gt_total = gt_correct = 0
    for v in vrows:
        d = roles.setdefault(v["role"], {"count": 0, "conf": 0.0, "tools": 0,
                                         "wall": 0, "in_tok": 0, "out_tok": 0,
                                         "gt_total": 0, "gt_correct": 0})
        d["count"] += 1
        d["conf"] += float(v["confidence"] or 0.0)
        d["tools"] += int(v["tool_calls_made"] or 0)
        d["wall"] += int(v["wall_time_ms"] or 0)
        d["in_tok"] += int(v["input_tokens"] or 0)
        d["out_tok"] += int(v["output_tokens"] or 0)
        gt = (v["ground_truth"] or "").strip()
        if gt:
            gt_total += 1
            gt_correct += int(gt == v["verdict"])
            d["gt_total"] += 1
            d["gt_correct"] += int(gt == v["verdict"])

    per_role = {}
    for role, d in sorted(roles.items()):
        n = d["count"] or 1
        gt_n = int(d["gt_total"])
        per_role[role] = {
            "verdicts": int(d["count"]),
            "avg_confidence": round(d["conf"] / n, 3),
            "avg_tool_calls": round(d["tools"] / n, 1),
            "avg_wall_s": round(d["wall"] / n / 1000.0, 1),
            "total_tokens": int(d["in_tok"] + d["out_tok"]),
            "gt_labeled": gt_n,
            "accuracy_pct": (round(100.0 * d["gt_correct"] / gt_n, 1) if gt_n else None),
        }

    from src.components.soc_in_box import hitl_store
    hitl_counts = hitl_store.count_decisions_since(since_iso)

    return {
        "window_days": window_days,
        "window_start": since_iso,
        "window_end": now.isoformat(),
        "worked_cases": len(in_window),
        "verdict_mix": dict(verdict_mix.most_common()),
        "severity_mix": dict(severity_mix.most_common()),
        "disposition_mix": dict(disposition_mix.most_common()),
        "top_actors": dict(actor_mix.most_common(5)),
        "recurring_entities": recurring,
        "per_role": per_role,
        "hitl_decisions": hitl_counts,
        "ground_truth_labeled": gt_total,
        "decision_accuracy_vs_truth": (round(gt_correct / gt_total, 3)
                                       if gt_total else None),
    }


def render_trends_for_chat(stats: dict[str, Any]) -> str:
    """Render :func:`compute_trends` output into a grounding block for a toolless
    narrator to turn into a SOC leadership readout — from THESE numbers only.
    """
    def _mix(d: dict[str, Any]) -> str:
        return ", ".join(f"{k}={v}" for k, v in d.items()) or "none"

    lines = [
        f"[SOC-IN-A-BOX TREND DATA — last {stats.get('window_days')} days "
        f"({stats.get('window_start')} → {stats.get('window_end')}). Write a concise "
        "SOC leadership readout from THESE NUMBERS ONLY. Lead with what matters: "
        "volume, what we're catching, where the load sits. Call out notable verdict "
        "mix, any EMERGING CAMPAIGN signal (indicators/actors recurring across "
        "multiple cases), and where human-in-the-loop approval is the bottleneck. "
        "Do NOT invent numbers not present here. Skimmable — short bold-labelled "
        "bullets, no tables.",
        "",
        f"Worked cases: {stats.get('worked_cases', 0)}",
        f"Verdict mix: {_mix(stats.get('verdict_mix', {}))}",
        f"Severity mix: {_mix(stats.get('severity_mix', {}))}",
        f"Disposition mix: {_mix(stats.get('disposition_mix', {}))}",
        f"Top actors: {_mix(stats.get('top_actors', {}))}",
    ]

    recurring = stats.get("recurring_entities") or {}
    if recurring:
        lines.append("Recurring indicators/actors (>=2 cases — CAMPAIGN signal):")
        for etype, items in recurring.items():
            shown = ", ".join(f"{i['value']} ({i['cases']} cases)" for i in items[:8])
            lines.append(f"  - {etype}: {shown}")
    else:
        lines.append("Recurring indicators/actors (campaign signal): none")

    per_role = stats.get("per_role") or {}
    if per_role:
        lines.append("Per-role (verdicts / avg confidence / avg tool calls / avg wall s / tokens):")
        for role, d in per_role.items():
            lines.append(
                f"  - {role}: {d['verdicts']} / {d['avg_confidence']} / "
                f"{d['avg_tool_calls']} / {d['avg_wall_s']}s / {d['total_tokens']} tok"
            )

    hitl = stats.get("hitl_decisions") or {}
    lines.append(
        f"HITL decisions: approved={hitl.get('approved', 0)}, rejected={hitl.get('rejected', 0)}"
    )
    acc = stats.get("decision_accuracy_vs_truth")
    if acc is None:
        lines.append("Decision accuracy vs ground truth: no ground-truth labels yet "
                     "(shadow-mode running; label outcomes to enable).")
    else:
        lines.append(f"Decision accuracy vs ground truth: {acc} "
                     f"over {stats.get('ground_truth_labeled', 0)} labeled cases")

    lines.append("")
    lines.append("End of trend data.]")
    return "\n".join(lines)


# -- campaign clustering (Slice 4) ---------------------------------------

def _worst_severity(sevs: list[str]) -> str:
    present = [s for s in sevs if s in _SEVERITY_ORDER]
    return min(present, key=_SEVERITY_ORDER.index) if present else ""


def _campaign_signature(shared: list[dict[str, Any]]) -> str:
    """Stable id for a campaign so we don't re-alert it every run.

    Anchored on the named actor / campaign if present (those persist as the
    cluster grows), else the single strongest shared indicator. New member
    tickets joining keep the same id — growth is reported as an update, not a
    brand-new campaign.
    """
    anchors = [f"{s['type']}:{s['value']}" for s in shared
               if s["type"] in ("actor", "campaign")]
    if not anchors and shared:
        top = shared[0]
        anchors = [f"{top['type']}:{top['value']}"]
    sig = "|".join(sorted(anchors))
    return hashlib.sha1(sig.encode()).hexdigest()[:12]


def find_campaign_clusters(window_days: float = 14.0,
                           min_cases: int = 3,
                           client=None) -> list[dict[str, Any]]:
    """Cluster worked cases that share strong indicators into candidate campaigns.

    Cases are linked when they share a strong entity (actor/campaign/hash/
    domain/ip/cve) that appears in 2+ cases; connected components become
    clusters. A cluster qualifies as a campaign if it has ``min_cases`` cases,
    OR it shares a named actor/campaign across 2+ cases (named attribution is a
    strong signal even at two). Each cluster carries a stable ``campaign_id``.

    Pure read over the index — no LLM, no side effects. The detector adds the
    narrative + alert dedup.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=window_days)
    conn = _connect()
    idx_rows = conn.execute("SELECT * FROM case_index").fetchall()
    in_window = {r["ticket_id"]: r for r in idx_rows
                 if (ts := _parse_ts(r["last_event_at"])) and ts >= since}
    case_ids = list(in_window)
    if len(case_ids) < 2:
        conn.close()
        return []

    qmarks = ",".join("?" * len(case_ids))
    type_marks = ",".join("?" * len(_STRONG_LINK_TYPES))
    ent_rows = conn.execute(
        f"SELECT ticket_id, entity_type, entity_value FROM case_entities "
        f"WHERE ticket_id IN ({qmarks}) AND entity_type IN ({type_marks})",
        case_ids + list(_STRONG_LINK_TYPES),
    ).fetchall()
    conn.close()

    ent_cases: dict[tuple[str, str], set[str]] = defaultdict(set)
    case_ents: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for r in ent_rows:
        key = (r["entity_type"], r["entity_value"])
        ent_cases[key].add(r["ticket_id"])
        case_ents[r["ticket_id"]].add(key)

    # Union-find: link cases sharing any strong entity seen in 2+ cases.
    parent = {c: c for c in case_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for cases in ent_cases.values():
        if len(cases) >= 2:
            cs = list(cases)
            for c in cs[1:]:
                union(cs[0], c)

    groups: dict[str, list[str]] = defaultdict(list)
    for c in case_ids:
        groups[find(c)].append(c)

    clusters: list[dict[str, Any]] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        ent_count: Counter = Counter()
        for c in members:
            for key in case_ents[c]:
                ent_count[key] += 1
        shared = [{"type": t, "value": v, "cases": n}
                  for (t, v), n in ent_count.items() if n >= 2]
        if not shared:
            continue
        named = any(s["type"] in ("actor", "campaign") for s in shared)
        if len(members) < min_cases and not named:
            continue
        shared.sort(key=lambda s: (-s["cases"], s["type"], s["value"]))
        actors = sorted({s["value"] for s in shared if s["type"] == "actor"})
        campaigns = sorted({s["value"] for s in shared if s["type"] == "campaign"})
        clusters.append({
            "campaign_id": _campaign_signature(shared),
            "member_tickets": sorted(members),
            "case_count": len(members),
            "shared_indicators": shared,
            "likely_actor": actors[0] if actors else "",
            "campaigns": campaigns,
            "severity_hint": _worst_severity([in_window[c]["severity"] for c in members]),
            "verdict_mix": dict(Counter(in_window[c]["final_verdict"] for c in members)),
        })

    clusters.sort(key=lambda c: c["case_count"], reverse=True)
    return clusters


def get_known_campaign(campaign_id: str) -> Optional[dict[str, Any]]:
    """Return the persisted alert record for ``campaign_id``, or None."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM campaign_alerts WHERE campaign_id = ?", (campaign_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    out = dict(row)
    out["member_tickets"] = json.loads(out.pop("member_tickets_json") or "[]")
    out["shared"] = json.loads(out.pop("shared_json") or "[]")
    return out


def list_campaign_alerts(limit: int = 50) -> list[dict[str, Any]]:
    """All persisted campaign alert records, most-recently-alerted first.

    The durable counterpart to the Campaign Detector's ephemeral Webex card —
    used by the web Campaign Radar to show campaign history + dedup state.
    """
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM campaign_alerts ORDER BY last_alerted_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    out: list[dict[str, Any]] = []
    for row in rows:
        rec = dict(row)
        rec["member_tickets"] = json.loads(rec.pop("member_tickets_json") or "[]")
        rec["shared"] = json.loads(rec.pop("shared_json") or "[]")
        out.append(rec)
    return out


def save_campaign_alert(campaign_id: str, shared: list[dict[str, Any]],
                        member_tickets: list[str]) -> None:
    """Upsert the alert record so a campaign isn't re-alerted unless it grows."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    with conn:
        conn.execute(
            """INSERT INTO campaign_alerts
                 (campaign_id, shared_json, member_tickets_json, case_count,
                  first_alerted_at, last_alerted_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(campaign_id) DO UPDATE SET
                  shared_json=excluded.shared_json,
                  member_tickets_json=excluded.member_tickets_json,
                  case_count=excluded.case_count,
                  last_alerted_at=excluded.last_alerted_at""",
            (campaign_id, json.dumps(shared), json.dumps(sorted(member_tickets)),
             len(member_tickets), now_iso, now_iso),
        )
    conn.close()


# -- reasoning trace (interrogation) -------------------------------------

# Per-event headline + the reasoning fields worth surfacing to a narrator.
_TRACE_FIELDS: dict[str, list[str]] = {
    "alert.triaged": ["verdict", "confidence", "priority_score", "summary",
                      "recommended_action"],
    "tier2.analysis": ["original_verdict", "refined_verdict", "confidence",
                       "escalation_decision", "tier2_summary", "next_steps"],
    "ir.plan": ["severity", "confidence", "ir_summary", "containment_actions",
                "eradication_actions", "recovery_actions", "bridge_required"],
    "threat_intel.report": ["likely_actor", "actor_confidence", "actor_evidence",
                            "campaigns", "mitre_techniques", "severity_adjustment",
                            "severity_adjustment_reason", "intel_summary"],
    "action.proposed": ["kind", "description", "actions_summary", "approver_role"],
    "action.decision": ["decision", "decided_by", "reason"],
    "case.escalated": ["from_role", "to_role", "reason"],
}


def get_case_reasoning(ticket_id: str, client=None) -> dict[str, Any]:
    """Assemble the recorded reasoning trace for one ticket.

    Combines three durable sources, all already persisted:

    - the ``soc.audit`` event timeline (what each role saw + decided, in order),
    - the ``verdicts.sqlite`` rows (per-role reason / confidence / evidence /
      tool-call count), and
    - the HITL proposals + human decisions.

    The return value is structured for a grounded narrator: it carries ONLY what
    actually happened, so a "why did the agent do X?" answer can cite the record
    instead of inventing a post-hoc rationale. Returns ``found=False`` if the
    ticket is unknown to the bus.
    """
    from src.components.soc_in_box.bus import get_redis_client
    client = client or get_redis_client()
    events = sorted(
        _events_by_ticket(client).get(ticket_id, []),
        key=lambda e: (_parse_ts(e.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)),
    )

    timeline: list[dict[str, Any]] = []
    for e in events:
        et = e.get("event_type") or ""
        fields = {f: e.get(f) for f in _TRACE_FIELDS.get(et, []) if e.get(f) not in (None, "", [], {})}
        timeline.append({
            "timestamp": e.get("timestamp"),
            "role": e.get("produced_by") or "",
            "event_type": et,
            "fields": fields,
        })

    verdicts = _verdict_rows_for_ticket(ticket_id)
    hitl = _hitl_rows_for_ticket(ticket_id)

    summary_row = _summarize_case(events) if events else {}
    return {
        "ticket_id": ticket_id,
        "found": bool(events),
        "final_verdict": summary_row.get("final_verdict", ""),
        "summary": summary_row.get("summary", ""),
        "timeline": timeline,
        "verdicts": verdicts,
        "hitl": hitl,
    }


def _short(v: Any, limit: int = 240) -> str:
    if isinstance(v, (list, tuple)):
        v = ", ".join(str(x) for x in v)
    s = str(v)
    return s if len(s) <= limit else s[:limit] + "…"


def render_reasoning_for_chat(trace: dict[str, Any]) -> str:
    """Render a :func:`get_case_reasoning` trace into a grounding block for a
    toolless narrator (the LLM).

    The block is a system instruction + the recorded facts. It tells the model
    to answer ONLY from this record and to cite the role + recorded reason — so a
    "why did the agent do X?" answer reflects what actually happened, never a
    plausible-but-invented rationale. Reused by the Webex bot today and the web
    case panel later.
    """
    tid = trace.get("ticket_id", "?")
    lines = [
        f"[SOC-IN-A-BOX CASE RECORD — ticket #{tid}. Answer the user's question "
        "USING ONLY this record. It is what the autonomous agents actually saw and "
        "decided; it is NOT a live re-investigation. If the record does not contain "
        "the answer, say so plainly and do not speculate. When you explain a "
        "decision, name the agent role that made it and quote its recorded reason.",
        "",
        f"Final verdict: {trace.get('final_verdict') or 'n/a'}",
    ]
    if trace.get("summary"):
        lines.append(f"Case summary: {trace['summary']}")

    if trace.get("timeline"):
        lines.append("")
        lines.append("Decision timeline (chronological):")
        for step in trace["timeline"]:
            role = step.get("role") or step.get("event_type") or "?"
            et = step.get("event_type") or "?"
            ts = step.get("timestamp") or "?"
            fields = step.get("fields") or {}
            field_str = "; ".join(f"{k}={_short(v)}" for k, v in fields.items())
            lines.append(f"  - [{ts}] {role} ({et}): {field_str or '(no detail)'}")

    if trace.get("verdicts"):
        lines.append("")
        lines.append("Per-role recorded verdicts (reason + evidence):")
        for v in trace["verdicts"]:
            ev = "; ".join(v.get("evidence") or []) or "—"
            lines.append(
                f"  - {v.get('role')}: {v.get('verdict')} "
                f"(confidence {v.get('confidence')}). Reason: {v.get('reason') or '—'}. "
                f"Evidence: {ev}. Tool calls: {v.get('tool_calls_made', 0)}."
            )

    if trace.get("hitl"):
        lines.append("")
        lines.append("Human-in-the-loop actions + decisions:")
        for h in trace["hitl"]:
            dec = h.get("latest_decision") or "pending"
            who = f" by {h['latest_decided_by']}" if h.get("latest_decided_by") else ""
            why = f": {h['latest_reason']}" if h.get("latest_reason") else ""
            lines.append(
                f"  - {h.get('proposed_by')} proposed '{h.get('description')}' "
                f"({h.get('kind')}) → {dec}{who}{why}"
            )

    lines.append("")
    lines.append("End of case record.]")
    return "\n".join(lines)


def _verdict_rows_for_ticket(ticket_id: str) -> list[dict[str, Any]]:
    try:
        from src.components.soc_in_box import verdict_store
        return verdict_store.get_verdicts_for_ticket(ticket_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("case_memory: verdict lookup failed for %s: %s", ticket_id, exc)
        return []


def _hitl_rows_for_ticket(ticket_id: str) -> list[dict[str, Any]]:
    try:
        from src.components.soc_in_box import hitl_store
        return hitl_store.get_actions_for_ticket(ticket_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("case_memory: hitl lookup failed for %s: %s", ticket_id, exc)
        return []


# -- CLI -----------------------------------------------------------------

def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SOC-in-a-Box case memory")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("backfill", help="index every worked ticket in the audit stream")

    pr = sub.add_parser("recall", help="show prior cases similar to a ticket")
    pr.add_argument("--ticket", required=True)
    pr.add_argument("-k", type=int, default=5)

    pw = sub.add_parser("why", help="dump the recorded reasoning trace for a ticket")
    pw.add_argument("--ticket", required=True)

    pt = sub.add_parser("trends", help="leadership rollup over a window")
    pt.add_argument("--days", type=float, default=7.0)

    pp = sub.add_parser("playbook", help="recommend a playbook from precedent")
    pp.add_argument("--ticket", required=True)
    pp.add_argument("-k", type=int, default=5)

    sub.add_parser("recent", help="re-index tickets active in the last 24h")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level="INFO", format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _build_argparser().parse_args(argv)
    if args.cmd == "backfill":
        print(json.dumps({"indexed": backfill()}, indent=2))
    elif args.cmd == "recent":
        print(json.dumps({"indexed": index_recent()}, indent=2))
    elif args.cmd == "recall":
        print(json.dumps(recall_for_ticket(args.ticket, k=args.k), indent=2, default=str))
    elif args.cmd == "why":
        print(json.dumps(get_case_reasoning(args.ticket), indent=2, default=str))
    elif args.cmd == "trends":
        print(json.dumps(compute_trends(window_days=args.days), indent=2, default=str))
    elif args.cmd == "playbook":
        print(json.dumps(recommend_playbook(args.ticket, k=args.k), indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
