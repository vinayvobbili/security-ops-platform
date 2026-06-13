"""Sidecar SQLite for SOC-in-a-Box agent verdicts.

Lives at ``data/soc_in_box/verdicts.sqlite`` (gitignored runtime data).
Schema is created on first connection — no separate migration step.

The same table holds:
- Shadow-mode verdicts produced against the live XSOAR queue
- Backtest verdicts produced against historical tickets (``ground_truth`` filled)
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


DB_PATH = Path("data/soc_in_box/verdicts.sqlite")

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id       TEXT NOT NULL,
    correlation_id  TEXT NOT NULL,
    role            TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    confidence      REAL NOT NULL,
    reason          TEXT,
    evidence_json   TEXT,
    tool_calls_made INTEGER NOT NULL DEFAULT 0,
    wall_time_ms    INTEGER NOT NULL DEFAULT 0,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    ground_truth    TEXT,
    shadow_mode     INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_verdicts_ticket  ON verdicts(ticket_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_role    ON verdicts(role);
CREATE INDEX IF NOT EXISTS idx_verdicts_created ON verdicts(created_at);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)
    return conn


def save_verdict(
    *,
    ticket_id: str,
    correlation_id: str,
    role: str,
    verdict: str,
    confidence: float,
    reason: str = "",
    evidence: list[str] | None = None,
    tool_calls_made: int = 0,
    wall_time_ms: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    ground_truth: str | None = None,
    shadow_mode: bool = True,
) -> int:
    """Insert one verdict row. Returns the new ``id``."""
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO verdicts
               (ticket_id, correlation_id, role, verdict, confidence, reason,
                evidence_json, tool_calls_made, wall_time_ms, input_tokens,
                output_tokens, ground_truth, shadow_mode)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ticket_id, correlation_id, role, verdict, confidence, reason,
             json.dumps(evidence or []), tool_calls_made, wall_time_ms,
             input_tokens, output_tokens, ground_truth, int(shadow_mode)),
        )
        logger.debug("verdict_store.save id=%s ticket=%s role=%s verdict=%s",
                     cur.lastrowid, ticket_id, role, verdict)
        return cur.lastrowid
