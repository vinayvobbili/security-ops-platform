"""
Central SQLite logger for all bot activity and conversation logs.

Database: data/transient/logs/bot_logs.db
Replaces per-bot CSV files with a single queryable SQLite database
visible in the Datasette browser at http://localhost:8201/.

Tables:
  conversations    — LLM bot Q&A exchanges (the security assistant bot, the Windows triage agent)
  bot_activity     — Command/action logs (the alert triage service, Oracle, the notification service)
  tool_calls       — LLM tool invocations with timing and output
  web_activity     — Web server request log
  log_viewer_audit — Audit trail for the log viewer / git-pull API
"""

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent.parent.parent / "data" / "transient" / "logs" / "bot_logs.db"
_lock = threading.Lock()

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS conversations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bot             TEXT    NOT NULL,
    person          TEXT,
    user_prompt     TEXT,
    bot_response    TEXT,
    response_length INTEGER,
    response_time_s REAL,
    room_name       TEXT,
    message_time    TEXT
);

CREATE TABLE IF NOT EXISTS bot_activity (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    bot               TEXT NOT NULL,
    actor             TEXT,
    command_keyword   TEXT,
    room_name         TEXT,
    timestamp_eastern TEXT
);

CREATE TABLE IF NOT EXISTS llm_usage (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    bot               TEXT NOT NULL,
    actor             TEXT,
    prompt_preview    TEXT,
    model             TEXT,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER,
    cached_tokens     INTEGER,
    total_tokens      INTEGER,
    cost              REAL,
    elapsed_s         REAL,
    room_name         TEXT,
    timestamp_eastern TEXT
);

CREATE TABLE IF NOT EXISTS tool_calls (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          TEXT,
    tool_name          TEXT,
    input_args         TEXT,
    output_preview     TEXT,
    execution_time_sec REAL,
    success            INTEGER,
    error_message      TEXT,
    user_id            TEXT,
    room_id            TEXT
);

CREATE TABLE IF NOT EXISTS web_activity (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    remote_addr       TEXT,
    method            TEXT,
    path              TEXT,
    timestamp_eastern TEXT
);

CREATE TABLE IF NOT EXISTS log_viewer_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT,
    ip_address TEXT,
    action     TEXT,
    bot_name   TEXT,
    success    INTEGER,
    message    TEXT
);

CREATE TABLE IF NOT EXISTS sleuth_reasoning (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    bot          TEXT,
    person       TEXT,
    user_id      TEXT,
    room_id      TEXT,
    room_name    TEXT,
    message_id   TEXT,
    question     TEXT,
    answer       TEXT,
    route        TEXT,
    iterations   INTEGER,
    synth_used   INTEGER,
    trace_json   TEXT,
    message_time TEXT
);
CREATE INDEX IF NOT EXISTS idx_sleuth_reasoning_room ON sleuth_reasoning(room_id);
CREATE INDEX IF NOT EXISTS idx_sleuth_reasoning_user ON sleuth_reasoning(user_id);
"""


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(str(_DB_PATH), timeout=10, check_same_thread=False)


def _init():
    try:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            conn = _connect()
            conn.executescript(_DDL)
            conn.close()
    except Exception as e:
        logger.error(f"bot_logs_db init failed: {e}")


_init()


def _insert(sql: str, params: tuple):
    try:
        with _lock:
            conn = _connect()
            conn.execute(sql, params)
            conn.commit()
            conn.close()
    except Exception as e:
        logger.warning(f"bot_logs_db write failed: {e}")


def log_conversation(bot: str, person: str, user_prompt: str, bot_response: str,
                     response_length: int, response_time_s: float,
                     room_name: str, message_time: str):
    _insert(
        """INSERT INTO conversations
           (bot, person, user_prompt, bot_response, response_length,
            response_time_s, room_name, message_time)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (bot,
         person,
         (user_prompt or "")[:2000],
         (bot_response or "")[:4000],
         response_length,
         response_time_s,
         room_name,
         message_time)
    )


def log_reasoning(bot: str, person: str, user_id: str, room_id: str,
                  room_name: str, message_id: str, question: str, answer: str,
                  route: str, iterations: int, synth_used: bool,
                  trace_json: str, message_time: str):
    """Persist one Sleuth turn's own reasoning trace.

    This is the live-assistant counterpart to the autonomous SOC's case_memory:
    it records the tools Sleuth called, what they returned, and how the answer
    was composed, so a later "why did you say that?" can cite the actual record
    instead of triggering a fresh re-investigation. Keyed by room_id + user_id
    (the same context the thread-local logging key carries) so the retrieval
    tool can find the asker's most recent turn.
    """
    _insert(
        """INSERT INTO sleuth_reasoning
           (bot, person, user_id, room_id, room_name, message_id, question,
            answer, route, iterations, synth_used, trace_json, message_time)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (bot, person, user_id, room_id, room_name, message_id,
         (question or "")[:2000],
         (answer or "")[:4000],
         route,
         iterations,
         int(bool(synth_used)),
         (trace_json or "")[:12000],
         message_time)
    )


def get_recent_reasoning(room_id: Optional[str] = None,
                         user_id: Optional[str] = None,
                         exclude_message_id: Optional[str] = None,
                         limit: int = 1) -> list:
    """Fetch the most recent Sleuth reasoning rows for a room / user.

    Prefers the most recent turn matching both room_id and user_id (the asker's
    own last answer); callers can relax to room-only by omitting user_id. The
    in-flight 'why?' turn hasn't been logged yet at retrieval time, but
    exclude_message_id guards against echo if it ever has been.
    """
    try:
        with _lock:
            conn = _connect()
            where, params = ["bot = 'sleuth'"], []
            if room_id:
                where.append("room_id = ?")
                params.append(room_id)
            if user_id:
                where.append("user_id = ?")
                params.append(user_id)
            if exclude_message_id:
                where.append("COALESCE(message_id, '') != ?")
                params.append(exclude_message_id)
            sql = ("""SELECT id, bot, person, user_id, room_id, room_name,
                             message_id, question, answer, route, iterations,
                             synth_used, trace_json, message_time
                      FROM sleuth_reasoning WHERE """ + " AND ".join(where) +
                   " ORDER BY id DESC LIMIT ?")
            params.append(limit)
            rows = conn.execute(sql, tuple(params)).fetchall()
            conn.close()
        cols = ["id", "bot", "person", "user_id", "room_id", "room_name",
                "message_id", "question", "answer", "route", "iterations",
                "synth_used", "trace_json", "message_time"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        logger.error(f"get_recent_reasoning failed: {e}")
        return []


def log_activity(bot: str, actor: str, command_keyword: Optional[str],
                 room_name: str, timestamp_eastern: str):
    _insert(
        """INSERT INTO bot_activity (bot, actor, command_keyword, room_name, timestamp_eastern)
           VALUES (?, ?, ?, ?, ?)""",
        (bot, actor, command_keyword, room_name, timestamp_eastern)
    )


def log_llm_usage(bot: str, actor: str, prompt_preview: str, model: str,
                  prompt_tokens: int, completion_tokens: int, cached_tokens: int,
                  total_tokens: int, cost: float, elapsed_s: float,
                  room_name: str, timestamp_eastern: str):
    _insert(
        """INSERT INTO llm_usage
           (bot, actor, prompt_preview, model, prompt_tokens, completion_tokens,
            cached_tokens, total_tokens, cost, elapsed_s, room_name, timestamp_eastern)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (bot, actor, (prompt_preview or "")[:500], model, prompt_tokens,
         completion_tokens, cached_tokens, total_tokens, cost, elapsed_s,
         room_name, timestamp_eastern)
    )


def log_tool_call(timestamp: str, tool_name: str, input_args: str,
                  output_preview: str, execution_time_sec: float,
                  success: bool, error_message: str,
                  user_id: str, room_id: str):
    _insert(
        """INSERT INTO tool_calls
           (timestamp, tool_name, input_args, output_preview, execution_time_sec,
            success, error_message, user_id, room_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, tool_name, input_args, output_preview, execution_time_sec,
         int(success), error_message, user_id, room_id)
    )


def log_web_activity(remote_addr: str, method: str, path: str, timestamp_eastern: str):
    _insert(
        """INSERT INTO web_activity (remote_addr, method, path, timestamp_eastern)
           VALUES (?, ?, ?, ?)""",
        (remote_addr, method, path, timestamp_eastern)
    )


def log_viewer_audit(timestamp: str, ip_address: str, action: str,
                     bot_name: str, success: bool, message: str):
    _insert(
        """INSERT INTO log_viewer_audit (timestamp, ip_address, action, bot_name, success, message)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (timestamp, ip_address, action, bot_name, int(success), message)
    )


def get_web_activity(limit: int = 200, offset: int = 0, path_filter: str = "") -> list:
    """Read web activity logs for the traffic logs page."""
    try:
        with _lock:
            conn = _connect()
            if path_filter:
                rows = conn.execute(
                    """SELECT id, remote_addr, method, path, timestamp_eastern
                       FROM web_activity WHERE path LIKE ?
                       ORDER BY id DESC LIMIT ? OFFSET ?""",
                    (f"%{path_filter}%", limit, offset)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, remote_addr, method, path, timestamp_eastern
                       FROM web_activity ORDER BY id DESC LIMIT ? OFFSET ?""",
                    (limit, offset)
                ).fetchall()
            conn.close()
        cols = ["id", "remote_addr", "method", "path", "timestamp_eastern"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        logger.error(f"get_web_activity failed: {e}")
        return []


def get_web_activity_stats() -> dict:
    """Return summary stats for the traffic logs page."""
    try:
        with _lock:
            conn = _connect()
            total = conn.execute("SELECT COUNT(*) FROM web_activity").fetchone()[0]
            today_count = conn.execute(
                "SELECT COUNT(*) FROM web_activity WHERE timestamp_eastern LIKE ?",
                (f"%{__import__('datetime').date.today().strftime('%Y-%m-%d')}%",)
            ).fetchone()[0]
            top_pages = conn.execute(
                """SELECT path, COUNT(*) as cnt FROM web_activity
                   WHERE path NOT LIKE '/api/%'
                   GROUP BY path ORDER BY cnt DESC LIMIT 10"""
            ).fetchall()
            top_ips = conn.execute(
                """SELECT remote_addr, COUNT(*) as cnt FROM web_activity
                   WHERE remote_addr NOT IN ('127.0.0.1', '::1')
                   GROUP BY remote_addr ORDER BY cnt DESC LIMIT 10"""
            ).fetchall()
            conn.close()
        return {
            "total": total,
            "today": today_count,
            "top_pages": [{"path": r[0], "count": r[1]} for r in top_pages],
            "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
        }
    except Exception as e:
        logger.error(f"get_web_activity_stats failed: {e}")
        return {"total": 0, "today": 0, "top_pages": [], "top_ips": []}


def get_bot_activity(limit: int = 200, offset: int = 0) -> list:
    """Read bot activity logs."""
    try:
        with _lock:
            conn = _connect()
            rows = conn.execute(
                """SELECT id, bot, actor, command_keyword, room_name, timestamp_eastern
                   FROM bot_activity ORDER BY id DESC LIMIT ? OFFSET ?""",
                (limit, offset)
            ).fetchall()
            conn.close()
        cols = ["id", "bot", "actor", "command_keyword", "room_name", "timestamp_eastern"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        logger.error(f"get_bot_activity failed: {e}")
        return []


def get_conversations(limit: int = 200, offset: int = 0) -> list:
    """Read conversation logs."""
    try:
        with _lock:
            conn = _connect()
            rows = conn.execute(
                """SELECT id, bot, person, user_prompt, bot_response,
                          response_length, response_time_s, room_name, message_time
                   FROM conversations ORDER BY id DESC LIMIT ? OFFSET ?""",
                (limit, offset)
            ).fetchall()
            conn.close()
        cols = ["id", "bot", "person", "user_prompt", "bot_response",
                "response_length", "response_time_s", "room_name", "message_time"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        logger.error(f"get_conversations failed: {e}")
        return []


def get_recent_tool_calls(limit: int = 50) -> list:
    """Read recent tool calls — used by the web API."""
    try:
        with _lock:
            conn = _connect()
            rows = conn.execute(
                """SELECT timestamp, tool_name, input_args, output_preview,
                          execution_time_sec, success, error_message, user_id, room_id
                   FROM tool_calls ORDER BY id DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            conn.close()
        cols = ["timestamp", "tool_name", "input_args", "output_preview",
                "execution_time_sec", "success", "error_message", "user_id", "room_id"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        logger.error(f"get_recent_tool_calls failed: {e}")
        return []


def get_llm_usage(limit: int = 200, offset: int = 0, bot_filter: str = "") -> list:
    """Read LLM usage logs."""
    try:
        with _lock:
            conn = _connect()
            if bot_filter:
                rows = conn.execute(
                    """SELECT id, bot, actor, prompt_preview, model,
                              prompt_tokens, completion_tokens, cached_tokens,
                              total_tokens, cost, elapsed_s, room_name, timestamp_eastern
                       FROM llm_usage WHERE bot = ?
                       ORDER BY id DESC LIMIT ? OFFSET ?""",
                    (bot_filter, limit, offset)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, bot, actor, prompt_preview, model,
                              prompt_tokens, completion_tokens, cached_tokens,
                              total_tokens, cost, elapsed_s, room_name, timestamp_eastern
                       FROM llm_usage ORDER BY id DESC LIMIT ? OFFSET ?""",
                    (limit, offset)
                ).fetchall()
            conn.close()
        cols = ["id", "bot", "actor", "prompt_preview", "model",
                "prompt_tokens", "completion_tokens", "cached_tokens",
                "total_tokens", "cost", "elapsed_s", "room_name", "timestamp_eastern"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        logger.error(f"get_llm_usage failed: {e}")
        return []


def get_llm_usage_stats(bot_filter: str = "") -> dict:
    """Return summary stats for LLM usage dashboard."""
    try:
        with _lock:
            conn = _connect()
            where = "WHERE bot = ?" if bot_filter else ""
            params = (bot_filter,) if bot_filter else ()

            # Overall totals
            row = conn.execute(
                f"""SELECT COUNT(*), COALESCE(SUM(total_tokens), 0),
                           COALESCE(SUM(cost), 0), COALESCE(AVG(elapsed_s), 0)
                    FROM llm_usage {where}""", params
            ).fetchone()
            total_prompts, total_tokens, total_cost, avg_elapsed = row

            # Current month totals
            month_prefix = __import__('datetime').date.today().strftime('%Y-%m')
            month_where = f"WHERE timestamp_eastern LIKE ?"
            month_params: tuple = (f"{month_prefix}%",)
            if bot_filter:
                month_where += " AND bot = ?"
                month_params += (bot_filter,)
            month_row = conn.execute(
                f"""SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(cost), 0)
                    FROM llm_usage {month_where}""", month_params
            ).fetchone()
            month_prompts, month_tokens, month_cost = month_row

            # Today totals
            today_str = __import__('datetime').date.today().strftime('%Y-%m-%d')
            today_where = f"WHERE timestamp_eastern LIKE ?"
            today_params: tuple = (f"{today_str}%",)
            if bot_filter:
                today_where += " AND bot = ?"
                today_params += (bot_filter,)
            today_row = conn.execute(
                f"""SELECT COUNT(*), COALESCE(SUM(cost), 0)
                    FROM llm_usage {today_where}""", today_params
            ).fetchone()
            today_prompts, today_cost = today_row

            # Top users
            top_users = conn.execute(
                f"""SELECT actor, COUNT(*) as cnt, SUM(cost) as total_cost
                    FROM llm_usage {where}
                    GROUP BY actor ORDER BY cnt DESC LIMIT 10""", params
            ).fetchall()

            # By bot breakdown
            by_bot = conn.execute(
                """SELECT bot, COUNT(*) as cnt, SUM(total_tokens) as tokens, SUM(cost) as cost
                   FROM llm_usage GROUP BY bot ORDER BY cost DESC"""
            ).fetchall()

            # By model breakdown
            by_model = conn.execute(
                f"""SELECT model, COUNT(*) as cnt, SUM(cost) as cost
                    FROM llm_usage {where}
                    GROUP BY model ORDER BY cost DESC""", params
            ).fetchall()

            conn.close()
        return {
            "total_prompts": total_prompts,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "avg_elapsed": avg_elapsed,
            "month_prompts": month_prompts,
            "month_tokens": month_tokens,
            "month_cost": month_cost,
            "today_prompts": today_prompts,
            "today_cost": today_cost,
            "top_users": [{"actor": r[0], "count": r[1], "cost": r[2]} for r in top_users],
            "by_bot": [{"bot": r[0], "count": r[1], "tokens": r[2], "cost": r[3]} for r in by_bot],
            "by_model": [{"model": r[0], "count": r[1], "cost": r[2]} for r in by_model],
        }
    except Exception as e:
        logger.error(f"get_llm_usage_stats failed: {e}")
        return {"total_prompts": 0, "total_tokens": 0, "total_cost": 0, "avg_elapsed": 0,
                "month_prompts": 0, "month_tokens": 0, "month_cost": 0,
                "today_prompts": 0, "today_cost": 0,
                "top_users": [], "by_bot": [], "by_model": []}
