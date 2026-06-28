"""Durable knowledge / tradecraft store for the AI SOC.

The third way the SOC teaches the autonomous agents from the room (alongside the
disposition corrections in ``coaching.py``): when an analyst drops a durable,
reusable security FACT or piece of tradecraft in ThreatCon chatter that isn't
tied to one ticket's disposition — "the new Citrix CVE is exploited via
session-token theft", "for beaconing to that ASN, pull the proxy logs first" —
the ambient watcher captures it here.

Unlike a ticket correction (which is a one-shot ground-truth label), a fact is
something the SOC should *recall later*: during triage the reasoning agents can
call ``recall_soc_knowledge`` to consult the room's tribal knowledge, and an
analyst can ask Sleuth "what do we know about X?". A fact can carry a TTL when
it's only true for a while (an active campaign), after which it stops surfacing.

Recall is deterministic token-overlap retrieval (not classification) over the
fact + topic + tags — the *semantic* judgement of what counts as a durable fact
happens once, in the LLM extraction pass at write time.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path("data/soc_in_box/soc_knowledge.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge_facts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fact        TEXT NOT NULL,
    topic       TEXT,                       -- short subject, for grouping/display
    tags        TEXT,                       -- space/comma-separated keywords for recall
    source      TEXT NOT NULL,              -- 'chatter' | 'coaching' | ...
    author      TEXT,
    room_id     TEXT,
    message_id  TEXT UNIQUE,                -- dedup key for chatter capture
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TEXT,                       -- NULL = never expires
    superseded  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_knowledge_created ON knowledge_facts(created_at);
CREATE INDEX IF NOT EXISTS idx_knowledge_expires ON knowledge_facts(expires_at);
"""

# Minimal stopword set so token-overlap recall keys on the meaningful words.
_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are",
    "was", "were", "be", "been", "with", "that", "this", "it", "its", "as", "at",
    "by", "from", "we", "you", "they", "do", "does", "did", "what", "which",
    "about", "any", "all", "our", "their", "have", "has", "had", "but", "not",
    "can", "will", "if", "when", "how", "why", "know",
}


def _tokens(text: str) -> set[str]:
    """Lowercase alphanumeric tokens (len >= 3), stopwords removed."""
    return {
        t for t in re.findall(r"[a-z0-9][a-z0-9._-]{2,}", (text or "").lower())
        if t not in _STOP
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.executescript(_SCHEMA)
    return conn


def record_fact(
    *,
    fact: str,
    topic: str = "",
    tags: str = "",
    source: str = "chatter",
    author: str = "",
    room_id: str = "",
    message_id: Optional[str] = None,
    ttl_days: Optional[float] = None,
) -> dict[str, Any]:
    """Persist a durable knowledge fact.

    ``message_id`` makes chatter capture idempotent (the same message can't be
    recorded twice). ``ttl_days`` sets an expiry for time-bound facts; omit it
    for evergreen knowledge. Returns a small result dict.
    """
    result: dict[str, Any] = {"recorded": False, "id": None}
    fact = (fact or "").strip()
    if not fact:
        return result
    expires_at = None
    try:
        if ttl_days and float(ttl_days) > 0:
            expires_at = (datetime.now(timezone.utc)
                          + timedelta(days=float(ttl_days))).isoformat()
    except (TypeError, ValueError):
        expires_at = None
    try:
        with _connect() as conn:
            cur = conn.execute(
                """INSERT OR IGNORE INTO knowledge_facts
                   (fact, topic, tags, source, author, room_id, message_id,
                    expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (fact[:1500], (topic or "")[:200], (tags or "")[:300], source,
                 author, room_id, message_id, expires_at),
            )
            result["recorded"] = cur.rowcount > 0
            result["id"] = cur.lastrowid if cur.rowcount > 0 else None
    except Exception as exc:
        logger.warning("knowledge: record_fact failed: %s", exc)
    if result["recorded"]:
        logger.info("knowledge: %s fact recorded topic=%r ttl_days=%s",
                    source, (topic or "")[:60], ttl_days)
    return result


def _active_rows(conn: sqlite3.Connection,
                 include_expired: bool) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    if include_expired:
        sql = ("SELECT * FROM knowledge_facts WHERE superseded = 0 "
               "ORDER BY created_at DESC")
        return conn.execute(sql).fetchall()
    now = _now_iso()
    sql = ("SELECT * FROM knowledge_facts WHERE superseded = 0 "
           "AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC")
    return conn.execute(sql, (now,)).fetchall()


def recall_facts(query: str, *, k: int = 5,
                 include_expired: bool = False) -> list[dict[str, Any]]:
    """Top-``k`` durable facts most relevant to ``query``.

    Deterministic token-overlap: a fact scores by how many of the query's
    meaningful tokens appear in its fact/topic/tags (topic and tags weighted
    higher, since they're the curated keywords). Ties break toward the most
    recent fact. Expired facts are excluded unless ``include_expired``.
    An empty/whitespace query returns the most recent facts.
    """
    try:
        with _connect() as conn:
            rows = _active_rows(conn, include_expired)
    except Exception as exc:
        logger.warning("knowledge: recall_facts failed: %s", exc)
        return []

    q = _tokens(query)
    scored: list[tuple[float, dict[str, Any]]] = []
    for r in rows:
        d = dict(r)
        if not q:  # no query → recency feed
            scored.append((0.0, d))
            continue
        fact_tok = _tokens(d.get("fact", ""))
        key_tok = _tokens(d.get("topic", "")) | _tokens(d.get("tags", ""))
        score = 2.0 * len(q & key_tok) + 1.0 * len(q & fact_tok)
        if score > 0:
            scored.append((score, d))
    # rows already come newest-first, so a stable sort by score keeps recency as
    # the tiebreak.
    scored.sort(key=lambda x: x[0], reverse=True)
    return [d for _, d in scored[: max(1, int(k))]]


def recent_facts(days: float = 30.0,
                 include_expired: bool = False) -> list[dict[str, Any]]:
    """Facts recorded in the last ``days`` (newest first)."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%d %H:%M:%S")
    try:
        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            if include_expired:
                rows = conn.execute(
                    "SELECT * FROM knowledge_facts WHERE created_at >= ? "
                    "AND superseded = 0 ORDER BY created_at DESC",
                    (since,)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM knowledge_facts WHERE created_at >= ? "
                    "AND superseded = 0 "
                    "AND (expires_at IS NULL OR expires_at > ?) "
                    "ORDER BY created_at DESC",
                    (since, _now_iso())).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("knowledge: recent_facts failed: %s", exc)
        return []


def knowledge_stats(days: float = 30.0) -> dict[str, Any]:
    """Counts for the scorecard: active facts captured in the window, by source."""
    rows = recent_facts(days)
    return {
        "total": len(rows),
        "from_chatter": sum(1 for r in rows if r.get("source") == "chatter"),
        "from_coaching": sum(1 for r in rows if r.get("source") == "coaching"),
    }


def render_facts_for_chat(rows: list[dict[str, Any]], query: str = "") -> str:
    """Render recalled facts into a grounding block for Sleuth / agents."""
    if not rows:
        scope = f" about “{query}”" if query else ""
        return (f"No durable SOC knowledge on record{scope} yet. The room hasn't "
                "captured a reusable fact matching that — answer from your own "
                "knowledge and live tools.")
    head = (f"GROUNDING — what the SOC team has on record"
            + (f" about “{query}”" if query else "") + ". Use these analyst-"
            "captured facts as tribal knowledge; cite them where they apply.")
    lines = [head, ""]
    for r in rows:
        topic = (r.get("topic") or "").strip()
        fact = (r.get("fact") or "").strip()
        author = (r.get("author") or "").split("@")[0]
        when = (r.get("created_at") or "")[:10]
        prefix = f"[{topic}] " if topic else ""
        meta = " — ".join([p for p in (author, when) if p])
        lines.append(f"- {prefix}{fact}" + (f"  ({meta})" if meta else ""))
    lines.append("")
    lines.append("End of recorded knowledge.")
    return "\n".join(lines)
