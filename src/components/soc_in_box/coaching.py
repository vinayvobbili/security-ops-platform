"""Analyst coaching / correction store for the AI SOC.

Two ways the SOC teaches the autonomous agents, both landing here:

- **Implicit (self-learning):** the ambient watcher reads ThreatCon chatter and,
  when an analyst states or corrects a ticket's disposition in passing, records
  it (source='chatter').
- **Explicit (coaching):** an analyst deliberately tells Sleuth "this is a
  false positive on #12345 because …" via the ``coach_soc_verdict`` tool
  (source='coaching').

Either way the corrected disposition becomes a ground-truth label on that
ticket's verdict rows (via ``verdict_store.set_ground_truth_for_ticket``) — so a
human correction immediately shows up in the shadow-mode scorecard, alongside
the nightly XSOAR-close reconciler. The free-text reason is kept as a durable
lesson for the audit/eval trail.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path("data/soc_in_box/coaching.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyst_corrections (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id            TEXT,
    corrected_verdict    TEXT,
    source               TEXT NOT NULL,          -- 'chatter' | 'coaching'
    note                 TEXT,
    author               TEXT,
    room_id              TEXT,
    message_id           TEXT UNIQUE,            -- dedup key for chatter capture
    applied_to_scorecard INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_corrections_ticket  ON analyst_corrections(ticket_id);
CREATE INDEX IF NOT EXISTS idx_corrections_created ON analyst_corrections(created_at);
"""

# Friendly analyst phrasing -> verdict enum. Deterministic: the analyst is
# stating the disposition outright, so there's no semantic inference to make.
_DISPOSITION_ALIASES: dict[str, str] = {
    "false positive": "false_positive",
    "false_positive": "false_positive",
    "fp": "false_positive",
    "false alarm": "false_positive",
    "not malicious": "false_positive",
    "noise": "false_positive",
    "benign": "true_positive_benign",
    "benign true positive": "true_positive_benign",
    "btp": "true_positive_benign",
    "expected": "true_positive_benign",
    "authorized": "true_positive_benign",
    "malicious": "true_positive_malicious",
    "true positive": "true_positive_malicious",
    "malicious true positive": "true_positive_malicious",
    "mtp": "true_positive_malicious",
    "compromised": "true_positive_malicious",
    "contained": "true_positive_malicious_contained",
    "prevented": "true_positive_malicious_contained",
    "blocked": "true_positive_malicious_contained",
    "quarantined": "true_positive_malicious_contained",
}

_VALID_VERDICTS = {
    "true_positive_malicious", "true_positive_malicious_contained",
    "true_positive_benign", "false_positive",
}


def normalize_disposition(text: str) -> Optional[str]:
    """Map an analyst's disposition phrasing to a verdict enum, or None."""
    t = (text or "").strip().lower()
    if not t:
        return None
    if t in _VALID_VERDICTS:
        return t
    if t in _DISPOSITION_ALIASES:
        return _DISPOSITION_ALIASES[t]
    # tolerate a longer phrase that contains a known alias (longest first so
    # "malicious true positive" wins over "malicious")
    for alias in sorted(_DISPOSITION_ALIASES, key=len, reverse=True):
        if alias in t:
            return _DISPOSITION_ALIASES[alias]
    return None


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.executescript(_SCHEMA)
    return conn


def record_correction(
    *,
    ticket_id: Optional[str],
    verdict: Optional[str],
    source: str,
    note: str = "",
    author: str = "",
    room_id: str = "",
    message_id: Optional[str] = None,
) -> dict[str, Any]:
    """Persist a correction and, when it carries a ticket + valid verdict, push
    it onto that ticket's verdict rows as ground truth.

    ``message_id`` (for chatter capture) makes the write idempotent — the same
    message can't be recorded twice. Returns a small result dict.
    """
    result: dict[str, Any] = {"recorded": False, "applied": False,
                              "rows_updated": 0, "verdict": verdict}
    try:
        with _connect() as conn:
            applied = 0
            if ticket_id and verdict in _VALID_VERDICTS:
                try:
                    from src.components.soc_in_box import verdict_store
                    applied = verdict_store.set_ground_truth_for_ticket(str(ticket_id), verdict)
                except Exception as exc:
                    logger.warning("coaching: ground-truth write failed for %s: %s",
                                   ticket_id, exc)
            cur = conn.execute(
                """INSERT OR IGNORE INTO analyst_corrections
                   (ticket_id, corrected_verdict, source, note, author, room_id,
                    message_id, applied_to_scorecard)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (str(ticket_id) if ticket_id else None, verdict, source,
                 (note or "")[:2000], author, room_id, message_id,
                 int(applied > 0)),
            )
            result["recorded"] = cur.rowcount > 0
            result["applied"] = applied > 0
            result["rows_updated"] = applied
    except Exception as exc:
        logger.warning("coaching: record_correction failed: %s", exc)
    if result["recorded"]:
        logger.info("coaching: %s correction ticket=%s verdict=%s applied=%s",
                    source, ticket_id, verdict, result["applied"])
    return result


def recent_corrections(days: float = 30.0) -> list[dict[str, Any]]:
    """Corrections recorded in the last ``days`` (newest first)."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT ticket_id, corrected_verdict, source, note, author,
                          applied_to_scorecard, created_at
                   FROM analyst_corrections WHERE created_at >= ?
                   ORDER BY created_at DESC""",
                (since,),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("coaching: recent_corrections failed: %s", exc)
        return []


def correction_stats(days: float = 30.0) -> dict[str, Any]:
    """Counts for the scorecard: total corrections, how many fed ground truth,
    split by source."""
    rows = recent_corrections(days)
    return {
        "total": len(rows),
        "applied": sum(1 for r in rows if r.get("applied_to_scorecard")),
        "from_chatter": sum(1 for r in rows if r.get("source") == "chatter"),
        "from_coaching": sum(1 for r in rows if r.get("source") == "coaching"),
    }
