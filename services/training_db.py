"""Training progress storage for /lessons and /admin-lessons.

SQLite-backed log of quiz attempts. One row per attempt; aggregates (best score,
pass status, seen question IDs) are derived on read.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

PASS_THRESHOLD = 0.60        # 60%+ = pass
DISTINCTION_THRESHOLD = 0.80  # 80%+ = distinction (extra celebration; not persisted)

DB_DIR = Path(__file__).parent.parent / "data" / "transient" / "training"
DB_PATH = DB_DIR / "training_progress.db"
DB_DIR.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                topic TEXT NOT NULL,
                ts TEXT NOT NULL,
                sampled_q_ids TEXT NOT NULL,
                score INTEGER NOT NULL,
                max_score INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                elapsed_seconds INTEGER NOT NULL DEFAULT 0,
                paste_chars INTEGER NOT NULL DEFAULT 0,
                paste_count INTEGER NOT NULL DEFAULT 0,
                answer_chars INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attempts_user_topic ON attempts(user_email, topic)"
        )
        # Migrate older DBs created before each anti-cheat column existed.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(attempts)").fetchall()}
        if "elapsed_seconds" not in cols:
            conn.execute("ALTER TABLE attempts ADD COLUMN elapsed_seconds INTEGER NOT NULL DEFAULT 0")
        # paste_chars/paste_count = how much typed-answer text arrived by paste;
        # answer_chars = total chars in the open-answer boxes (the denominator).
        if "paste_chars" not in cols:
            conn.execute("ALTER TABLE attempts ADD COLUMN paste_chars INTEGER NOT NULL DEFAULT 0")
        if "paste_count" not in cols:
            conn.execute("ALTER TABLE attempts ADD COLUMN paste_count INTEGER NOT NULL DEFAULT 0")
        if "answer_chars" not in cols:
            conn.execute("ALTER TABLE attempts ADD COLUMN answer_chars INTEGER NOT NULL DEFAULT 0")


def record_attempt(
    user_email: str,
    topic: str,
    sampled_q_ids: Iterable[str],
    score: float,
    max_score: float,
    elapsed_seconds: int = 0,
    paste_chars: int = 0,
    paste_count: int = 0,
    answer_chars: int = 0,
) -> bool:
    """Insert an attempt; return whether it passed.

    We persist the attempt's score as a 0-100 percentage (score / max_score,
    rounded) in the `score` column with `max_score` fixed at 100, plus the
    derived pass/fail flag. Storing the percentage — rather than the raw
    "X of 20 questions" — keeps the column integer-typed and timeline-stable
    even when the per-attempt question count or partial-credit weighting
    changes, and it's the unit the admin dashboard reports in. `best_ratio`
    (MAX(score/max_score)) therefore reads back as the analyst's best
    percentage straight from SQL with no migration. Legacy rows written before
    this change stored a normalized 1/0 and read back as 100% / 0%.
    """
    ratio = (score / max_score) if max_score > 0 else 0.0
    passed = max_score > 0 and ratio >= PASS_THRESHOLD
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO attempts (user_email, topic, ts, sampled_q_ids, score, max_score, passed, "
            "elapsed_seconds, paste_chars, paste_count, answer_chars) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_email.lower(),
                topic,
                datetime.utcnow().isoformat(timespec="seconds") + "Z",
                json.dumps(list(sampled_q_ids)),
                round(ratio * 100),   # 0-100 percentage
                100,
                1 if passed else 0,
                max(0, int(elapsed_seconds or 0)),  # for the anti-cheat timing signal
                max(0, int(paste_chars or 0)),      # chars that arrived by paste
                max(0, int(paste_count or 0)),      # number of paste events
                max(0, int(answer_chars or 0)),     # total open-answer chars (denominator)
            ),
        )
    return passed


def get_seen_question_ids(user_email: str, topic: str) -> set[str]:
    """Union of question IDs the user has been shown across all attempts."""
    seen: set[str] = set()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT sampled_q_ids FROM attempts WHERE user_email = ? AND topic = ?",
            (user_email.lower(), topic),
        ).fetchall()
    for row in rows:
        try:
            seen.update(json.loads(row["sampled_q_ids"]))
        except (json.JSONDecodeError, TypeError):
            continue
    return seen


def get_user_progress(user_email: str) -> dict[str, dict]:
    """Per-topic summary for a single user."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT topic,
                   COUNT(*) AS attempts,
                   MAX(CAST(score AS REAL) / max_score) AS best_ratio,
                   MAX(passed) AS ever_passed,
                   MAX(ts) AS last_ts
            FROM attempts
            WHERE user_email = ?
            GROUP BY topic
            """,
            (user_email.lower(),),
        ).fetchall()
    return {
        row["topic"]: {
            "attempts": row["attempts"],
            "best_ratio": row["best_ratio"] or 0.0,
            "passed": bool(row["ever_passed"]),
            "last_ts": row["last_ts"],
        }
        for row in rows
    }


def get_all_progress() -> list[dict]:
    """Cross-user summary (one row per user × topic)."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT user_email,
                   topic,
                   COUNT(*) AS attempts,
                   MAX(CAST(score AS REAL) / max_score) AS best_ratio,
                   MAX(passed) AS ever_passed,
                   MAX(ts) AS last_ts
            FROM attempts
            GROUP BY user_email, topic
            ORDER BY user_email, topic
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_all_attempts() -> list[dict]:
    """Every attempt for cross-lesson trend + integrity analytics.

    Includes ``elapsed_seconds`` and ``sampled_q_ids`` so the admin view can run
    the anti-cheat timing check (reconstructing per-attempt question formats).
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT user_email, topic, ts, score, max_score, passed, "
            "elapsed_seconds, paste_chars, paste_count, answer_chars, sampled_q_ids "
            "FROM attempts ORDER BY ts"
        ).fetchall()
    return [dict(row) for row in rows]


def get_user_attempts(user_email: str) -> list[dict]:
    """Full attempt history for one user (admin drill-down)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT topic, ts, score, max_score, passed, elapsed_seconds, "
            "paste_chars, paste_count, answer_chars, sampled_q_ids "
            "FROM attempts WHERE user_email = ? ORDER BY ts DESC",
            (user_email.lower(),),
        ).fetchall()
    return [dict(row) for row in rows]


def get_first_pass_ts(user_email: str, topic: str) -> str | None:
    """UTC ISO timestamp of the analyst's earliest passing attempt on a topic.

    Used as the certificate's stable 'awarded on' date — anchoring to the first
    pass (not 'today') keeps the derived verification code constant across views.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT MIN(ts) AS first_pass FROM attempts "
            "WHERE user_email = ? AND topic = ? AND passed = 1",
            (user_email.lower(), topic),
        ).fetchone()
    return row["first_pass"] if row else None


def has_passed(user_email: str, topic: str) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM attempts WHERE user_email = ? AND topic = ? AND passed = 1 LIMIT 1",
            (user_email.lower(), topic),
        ).fetchone()
    return row is not None
