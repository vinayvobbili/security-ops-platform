"""Sidecar SQLite for SOC-in-a-Box HITL (Human-In-The-Loop) actions.

Lives at ``data/soc_in_box/hitl.sqlite`` (gitignored runtime data). Captures:

- ``hitl_actions``  — agent proposals (one row per ``ActionProposed`` event)
- ``hitl_decisions`` — human approve / reject decisions (one row per
  ``ActionDecision`` event)

v1 the proposing agent is IR Lead and the only action kind is
``containment_plan``. v1 decisions are **dummy** — the executor path is
stubbed; clicking Approve records the choice but does not call
CrowdStrike/Tanium/QRadar. The whole point is to demo the human-handoff
loop and the audit trail.
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


DB_PATH = Path("data/soc_in_box/hitl.sqlite")

SCHEMA = """
CREATE TABLE IF NOT EXISTS hitl_actions (
    action_id       TEXT PRIMARY KEY,
    ticket_id       TEXT NOT NULL,
    proposed_by     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    description     TEXT NOT NULL,
    actions_summary TEXT NOT NULL,
    target          TEXT NOT NULL DEFAULT '{}',
    plan_event_id   TEXT,
    proposed_at     TEXT NOT NULL,
    approver_role   TEXT NOT NULL DEFAULT '',
    approver_name   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hitl_actions_ticket ON hitl_actions(ticket_id);
CREATE INDEX IF NOT EXISTS idx_hitl_actions_proposed_at ON hitl_actions(proposed_at);

CREATE TABLE IF NOT EXISTS hitl_decisions (
    decision_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id     TEXT NOT NULL,
    ticket_id     TEXT NOT NULL,
    decision      TEXT NOT NULL,
    decided_by    TEXT NOT NULL,
    decided_at    TEXT NOT NULL,
    reason        TEXT,
    dummy         INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (action_id) REFERENCES hitl_actions(action_id)
);
CREATE INDEX IF NOT EXISTS idx_hitl_decisions_action  ON hitl_decisions(action_id);
CREATE INDEX IF NOT EXISTS idx_hitl_decisions_decided ON hitl_decisions(decided_at);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)
    # In-place migration for DBs created before approver_role/approver_name
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hitl_actions)").fetchall()}
    if "approver_role" not in cols:
        conn.execute("ALTER TABLE hitl_actions ADD COLUMN approver_role TEXT NOT NULL DEFAULT ''")
    if "approver_name" not in cols:
        conn.execute("ALTER TABLE hitl_actions ADD COLUMN approver_name TEXT NOT NULL DEFAULT ''")
    conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


def _new_action_id() -> str:
    """Short URL-safe id. 8 bytes of entropy = 11 chars base64 — enough for
    demo and short enough to fit comfortably in a Webex card button URL.
    """
    return secrets.token_urlsafe(8)


def propose_action(*,
                   ticket_id: str,
                   proposed_by: str,
                   kind: str,
                   description: str,
                   actions_summary: list[str],
                   target: Optional[dict[str, Any]] = None,
                   plan_event_id: str = "",
                   approver_role: str = "",
                   approver_name: str = "") -> str:
    """Insert a pending action proposal. Returns the new ``action_id``."""
    action_id = _new_action_id()
    conn = _connect()
    with conn:
        conn.execute(
            """INSERT INTO hitl_actions
               (action_id, ticket_id, proposed_by, kind, description,
                actions_summary, target, plan_event_id, proposed_at,
                approver_role, approver_name)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (action_id, ticket_id, proposed_by, kind, description,
             json.dumps(actions_summary), json.dumps(target or {}),
             plan_event_id, datetime.now(timezone.utc).isoformat(),
             approver_role, approver_name),
        )
    conn.close()
    logger.info("hitl: proposed action_id=%s ticket=%s kind=%s approver=%s",
                action_id, ticket_id, kind, (approver_name or approver_role or "—"))
    return action_id


def get_action(action_id: str) -> Optional[dict[str, Any]]:
    """Look up an action by id. Returns ``None`` if not found.

    Joins the latest decision (if any) so the caller can detect duplicate-click
    scenarios in one query.
    """
    conn = _connect()
    row = conn.execute(
        """SELECT a.*,
                  d.decision     AS latest_decision,
                  d.decided_by   AS latest_decided_by,
                  d.decided_at   AS latest_decided_at,
                  d.reason       AS latest_reason,
                  d.dummy        AS latest_dummy
           FROM hitl_actions a
           LEFT JOIN (
               SELECT * FROM hitl_decisions
               WHERE action_id = ?
               ORDER BY decided_at DESC LIMIT 1
           ) d ON d.action_id = a.action_id
           WHERE a.action_id = ?""",
        (action_id, action_id),
    ).fetchone()
    conn.close()
    if not row:
        return None
    out = dict(row)
    out["actions_summary"] = json.loads(out.get("actions_summary") or "[]")
    out["target"] = json.loads(out.get("target") or "{}")
    return out


def record_decision(*,
                    action_id: str,
                    ticket_id: str,
                    decision: str,
                    decided_by: str,
                    reason: str = "",
                    dummy: bool = True) -> dict[str, Any]:
    """Insert a new decision row. Caller is responsible for any idempotency
    check (this function always inserts — duplicate clicks become duplicate
    rows so the audit shows the full history).
    """
    if decision not in ("approved", "rejected"):
        raise ValueError(f"invalid decision: {decision!r}")
    decided_at = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    with conn:
        conn.execute(
            """INSERT INTO hitl_decisions
               (action_id, ticket_id, decision, decided_by, decided_at, reason, dummy)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (action_id, ticket_id, decision, decided_by, decided_at,
             reason, 1 if dummy else 0),
        )
    conn.close()
    logger.info("hitl: recorded decision action_id=%s decision=%s by=%s dummy=%s",
                action_id, decision, decided_by, dummy)
    return {
        "action_id": action_id, "ticket_id": ticket_id,
        "decision": decision, "decided_by": decided_by,
        "decided_at": decided_at, "reason": reason, "dummy": dummy,
    }


def list_recent(limit: int = 50) -> list[dict[str, Any]]:
    """Recent actions + their latest decision. Newest first.

    Used by the audit page so leadership can see the full demo flow at a glance.
    """
    conn = _connect()
    rows = conn.execute(
        """SELECT a.action_id, a.ticket_id, a.proposed_by, a.kind, a.description,
                  a.actions_summary, a.proposed_at, a.approver_role, a.approver_name,
                  d.decision     AS latest_decision,
                  d.decided_by   AS latest_decided_by,
                  d.decided_at   AS latest_decided_at,
                  d.dummy        AS latest_dummy
           FROM hitl_actions a
           LEFT JOIN (
               SELECT * FROM hitl_decisions WHERE decision_id IN (
                   SELECT MAX(decision_id) FROM hitl_decisions GROUP BY action_id
               )
           ) d ON d.action_id = a.action_id
           ORDER BY a.proposed_at DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    out = []
    for row in rows:
        item = dict(row)
        item["actions_summary"] = json.loads(item.get("actions_summary") or "[]")
        out.append(item)
    return out
