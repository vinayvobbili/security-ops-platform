#!/usr/bin/env python3
"""
One-time migration: import all existing CSV log files into bot_logs.db.

Run from the project root:
    python misc_scripts/migrate_csv_to_sqlite.py
"""

import csv
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

LOGS_DIR = PROJECT_ROOT / "data" / "transient" / "logs"
DB_PATH = LOGS_DIR / "bot_logs.db"


def connect():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _read_csv(path: Path) -> list[dict]:
    """Read a CSV file, returning rows as dicts. Skips bad rows silently."""
    rows = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            raw = list(reader)
        if not raw:
            return []

        # Detect whether first row is a header
        first = raw[0]
        header_keywords = {"person", "actor", "timestamp", "remote_addr", "user_name", "user_message"}
        if any(col.lower().strip() in header_keywords for col in first):
            headers = [h.lower().strip() for h in first]
            data_rows = raw[1:]
        else:
            # toodles has no header — infer from known schema
            headers = ["actor", "command_keyword", "room_name", "timestamp_eastern"]
            data_rows = raw

        for row in data_rows:
            if len(row) < len(headers):
                row += [""] * (len(headers) - len(row))
            rows.append(dict(zip(headers, row[:len(headers)])))
    except Exception as e:
        print(f"  WARNING: could not read {path.name}: {e}")
    return rows


def migrate_conversations(conn: sqlite3.Connection):
    """Migrate pokedex, win_ai conversation CSVs."""
    mapping = {
        "pokedex_conversations.csv": "pokedex",
        "win_ai_conversations.csv": "win_ai",
    }
    total = 0
    for filename, bot in mapping.items():
        path = LOGS_DIR / filename
        if not path.exists():
            print(f"  SKIP {filename} (not found)")
            continue
        rows = _read_csv(path)
        inserted = 0
        for r in rows:
            # Normalise column names across the two CSV formats
            person = r.get("person") or r.get("user_name") or ""
            prompt = r.get("user prompt") or r.get("user_message") or ""
            response = r.get("bot response") or r.get("bot_response") or ""
            length_raw = r.get("response length") or r.get("response_length") or ""
            time_raw = r.get("response time (s)") or r.get("response_time_seconds") or "0"
            room = r.get("webex room") or r.get("room_name") or ""
            msg_time = r.get("message time") or r.get("timestamp") or ""

            try:
                length = int(length_raw) if length_raw else len(response)
                resp_time = float(time_raw) if time_raw else 0.0
            except ValueError:
                length = len(response)
                resp_time = 0.0

            conn.execute(
                """INSERT INTO conversations
                   (bot, person, user_prompt, bot_response, response_length,
                    response_time_s, room_name, message_time)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (bot, person, prompt[:2000], response[:4000], length, resp_time, room, msg_time)
            )
            inserted += 1
        conn.commit()
        print(f"  {filename}: {inserted} rows → conversations")
        total += inserted
    return total


def migrate_activity(conn: sqlite3.Connection):
    """Migrate decorator-based activity log CSVs."""
    files = [
        ("barnacles_activity_log.csv", "barnacles"),
        ("moneyball_activity_log.csv", "moneyball"),
        ("toodles_activity_log.csv", "toodles"),
    ]
    total = 0
    for filename, bot in files:
        path = LOGS_DIR / filename
        if not path.exists():
            print(f"  SKIP {filename} (not found)")
            continue
        rows = _read_csv(path)
        inserted = 0
        for r in rows:
            actor = r.get("actor") or ""
            keyword = r.get("command_keyword") or ""
            room = r.get("room_name") or ""
            ts = r.get("timestamp_eastern") or ""
            # Skip bot self-pings
            if actor.lower() in ("ping bot", ""):
                continue
            conn.execute(
                """INSERT INTO bot_activity (bot, actor, command_keyword, room_name, timestamp_eastern)
                   VALUES (?, ?, ?, ?, ?)""",
                (bot, actor, keyword, room, ts)
            )
            inserted += 1
        conn.commit()
        print(f"  {filename}: {inserted} rows → bot_activity")
        total += inserted
    return total


def migrate_tool_calls(conn: sqlite3.Connection):
    path = LOGS_DIR / "tool_calls_log.csv"
    if not path.exists():
        print("  SKIP tool_calls_log.csv (not found)")
        return 0
    rows = _read_csv(path)
    inserted = 0
    for r in rows:
        ts = r.get("timestamp") or ""
        tool = r.get("tool_name") or ""
        inp = r.get("input_args") or ""
        out = r.get("output_preview") or ""
        exec_time_raw = r.get("execution_time_sec") or r.get("execution_time_ms") or "0"
        success_raw = r.get("success", "true")
        err = r.get("error_message") or ""
        user_id = r.get("user_id") or ""
        room_id = r.get("room_id") or ""
        try:
            exec_time = float(exec_time_raw)
        except ValueError:
            exec_time = 0.0
        success = str(success_raw).lower() not in ("false", "0", "")
        conn.execute(
            """INSERT INTO tool_calls
               (timestamp, tool_name, input_args, output_preview, execution_time_sec,
                success, error_message, user_id, room_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts, tool, inp, out, exec_time, int(success), err, user_id, room_id)
        )
        inserted += 1
    conn.commit()
    print(f"  tool_calls_log.csv: {inserted} rows → tool_calls")
    return inserted


def migrate_web_activity(conn: sqlite3.Connection):
    path = LOGS_DIR / "web_server_activity_log.csv"
    if not path.exists():
        print("  SKIP web_server_activity_log.csv (not found)")
        return 0
    rows = _read_csv(path)
    inserted = 0
    for r in rows:
        conn.execute(
            """INSERT INTO web_activity (remote_addr, method, path, timestamp_eastern)
               VALUES (?, ?, ?, ?)""",
            (r.get("remote_addr") or "", r.get("method") or "",
             r.get("path") or "", r.get("timestamp_eastern") or "")
        )
        inserted += 1
    conn.commit()
    print(f"  web_server_activity_log.csv: {inserted} rows → web_activity")
    return inserted


def migrate_audit_log(conn: sqlite3.Connection):
    path = LOGS_DIR / "log_viewer_audit_log.csv"
    if not path.exists():
        print("  SKIP log_viewer_audit_log.csv (not found)")
        return 0
    rows = _read_csv(path)
    inserted = 0
    for r in rows:
        success_raw = r.get("success", "true")
        success = str(success_raw).lower() not in ("false", "0", "")
        conn.execute(
            """INSERT INTO log_viewer_audit (timestamp, ip_address, action, bot_name, success, message)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (r.get("timestamp") or "", r.get("ip_address") or "",
             r.get("action") or "", r.get("bot_name") or "",
             int(success), r.get("message") or "")
        )
        inserted += 1
    conn.commit()
    print(f"  log_viewer_audit_log.csv: {inserted} rows → log_viewer_audit")
    return inserted


def main():
    # Ensure DB is initialised (creates tables)
    from src.utils.bot_logs_db import _init
    _init()

    print(f"Migrating CSVs → {DB_PATH}\n")
    conn = connect()

    grand_total = 0
    grand_total += migrate_conversations(conn)
    grand_total += migrate_activity(conn)
    grand_total += migrate_tool_calls(conn)
    grand_total += migrate_web_activity(conn)
    grand_total += migrate_audit_log(conn)

    conn.close()

    # Print table counts
    conn2 = connect()
    print("\nRow counts after migration:")
    for table in ["conversations", "bot_activity", "tool_calls", "web_activity", "log_viewer_audit"]:
        count = conn2.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  {table}: {count}")
    conn2.close()

    print(f"\nDone. {grand_total} rows migrated.")


if __name__ == "__main__":
    main()
