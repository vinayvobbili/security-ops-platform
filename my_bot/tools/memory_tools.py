# /my_bot/tools/memory_tools.py
"""
Team Memory Tools

Persistent key-value memory for the SOC bot. Analysts can teach the bot facts
("remember the helpdesk number is 1-800-XXXX") and recall them later.

Storage: SQLite with FTS5 for fuzzy full-text search.
Access control: restricted to allowed Webex rooms via thread-local context.
"""

import logging
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from langchain_core.tools import tool
from src.utils.tool_decorator import log_tool_call

# When a tool returns this prefix, the agentic loop short-circuits and returns
# the content directly to the user — no extra LLM iteration needed.
_FINAL = "[FINAL_RESPONSE]"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
_DB_DIR = Path(__file__).parent.parent.parent / "data" / "transient" / "memory"
_DB_PATH = str(_DB_DIR / "team_memory.db")


@contextmanager
def _get_db():
    _DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_db():
    """Create tables + FTS5 virtual table if they don't exist."""
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic TEXT NOT NULL,
                content TEXT NOT NULL,
                saved_by TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # FTS5 virtual table for full-text search over topic + content
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts
            USING fts5(topic, content, content=memories, content_rowid=id)
        """)
        # Triggers to keep FTS index in sync with the main table
        conn.executescript("""
            CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, topic, content)
                VALUES (new.id, new.topic, new.content);
            END;
            CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, topic, content)
                VALUES ('delete', old.id, old.topic, old.content);
            END;
            CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, topic, content)
                VALUES ('delete', old.id, old.topic, old.content);
                INSERT INTO memories_fts(rowid, topic, content)
                VALUES (new.id, new.topic, new.content);
            END;
        """)
        conn.commit()


# Run on import so the table exists before any tool call
_init_db()

# ---------------------------------------------------------------------------
# Room restriction
# ---------------------------------------------------------------------------

def _get_allowed_rooms() -> list:
    """Return the list of room IDs where memory tools are permitted."""
    allowed = []
    tc = os.environ.get("WEBEX_ROOM_ID_THREATCON_COLLAB")
    dev = os.environ.get("WEBEX_ROOM_ID_DEV_TEST_SPACE")
    if tc:
        allowed.append(tc)
    if dev:
        allowed.append(dev)
    return allowed


def _get_current_room_id() -> str | None:
    """Extract room_id from the thread-local logging context.

    The session_key is set as "{user_id}_{room_id}" before tool execution
    in my_model.ask() via set_logging_context().
    """
    from src.utils.tool_logging import get_logging_context
    session_id = get_logging_context()
    if session_id and "_" in session_id:
        # user_id may contain underscores (emails), room_id is the last segment
        # Actually, split on first "_" — user_id is email, room_id is the rest
        # But session_key = f"{user_id}_{room_id}" where user_id is email
        # and room_id is a base64 Webex room ID (contains no underscore typically)
        # Safest: rsplit on last underscore? No — room IDs are long base64.
        # The pattern is email_Y2lzY29... so split(_, 1) gives [email, room_id].
        # But emails have no underscore in the local part typically.
        # Let's just use the same logic as tool_logging.py: split(_, 1)
        parts = session_id.split("_", 1)
        return parts[1] if len(parts) > 1 else None
    return None


def _is_room_allowed() -> bool:
    """Return True if the current room is allowed to use memory tools."""
    allowed = _get_allowed_rooms()
    if not allowed:
        # No restriction configured (e.g. local dev) — allow all
        return True
    room_id = _get_current_room_id()
    if room_id and room_id in allowed:
        return True
    logger.warning(f"Memory tool blocked — room {room_id!r} not in allowed list")
    return False


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
@log_tool_call
def save_memory(topic: str, content: str) -> str:
    """Save a fact or piece of information for the team to recall later.
    Call this when the user says 'remember ...', 'save ...', 'note that ...', or teaches you a fact.

    Args:
        topic: Short label/category for the memory (e.g. 'helpdesk contact', 'VPN gateway IP').
        content: The actual information to remember.
    """
    if not _is_room_allowed():
        return f"{_FINAL}Memory tools are not available in this room. Please use an approved room."

    try:
        # Check if a memory with a similar topic already exists (exact match)
        with _get_db() as conn:
            existing = conn.execute(
                "SELECT id, content FROM memories WHERE LOWER(topic) = LOWER(?)",
                (topic,)
            ).fetchone()

            if existing:
                # Update existing memory
                conn.execute(
                    "UPDATE memories SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (content, existing["id"])
                )
                conn.commit()
                return f"{_FINAL}✅ Updated memory for **{topic}**: {content}"
            else:
                # Get saved_by from logging context
                from src.utils.tool_logging import get_logging_context
                session_id = get_logging_context()
                saved_by = session_id.split("_", 1)[0] if session_id and "_" in session_id else None

                conn.execute(
                    "INSERT INTO memories (topic, content, saved_by) VALUES (?, ?, ?)",
                    (topic, content, saved_by)
                )
                conn.commit()
                return f"{_FINAL}✅ Remembered **{topic}**: {content}"

    except Exception as e:
        logger.error(f"Failed to save memory: {e}", exc_info=True)
        return f"❌ Failed to save memory: {e}"


@tool
@log_tool_call
def update_memory(query: str, new_content: str) -> str:
    """Update an existing saved memory with new content.
    Call this when the user says 'update ...', 'change ... to ...', 'correct the ...'.
    Uses fuzzy search to find the memory, so the user doesn't need to repeat the exact topic.

    Args:
        query: Search terms to find the memory to update (topic or keywords).
        new_content: The new content to replace the old value with.
    """
    if not _is_room_allowed():
        return f"{_FINAL}Memory tools are not available in this room. Please use an approved room."

    try:
        with _get_db() as conn:
            # Try exact topic match first
            row = conn.execute(
                "SELECT id, topic, content FROM memories WHERE LOWER(topic) = LOWER(?)",
                (query,)
            ).fetchone()

            if not row:
                # FTS search for closest match
                fts_query = " OR ".join(f'"{word}"*' for word in query.split() if word.strip())
                row = conn.execute("""
                    SELECT m.id, m.topic, m.content
                    FROM memories_fts fts
                    JOIN memories m ON m.id = fts.rowid
                    WHERE memories_fts MATCH ?
                    ORDER BY rank
                    LIMIT 1
                """, (fts_query,)).fetchone()

            if not row:
                return f"No existing memory found matching '{query}'. Use save_memory to create a new one."

            old_content = row["content"]
            conn.execute(
                "UPDATE memories SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (new_content, row["id"])
            )
            conn.commit()
            return f"{_FINAL}✏️ Updated **{row['topic']}**: ~~{old_content}~~ → {new_content}"

    except Exception as e:
        logger.error(f"Failed to update memory: {e}", exc_info=True)
        return f"❌ Failed to update memory: {e}"


@tool
@log_tool_call
def recall_memory(query: str) -> str:
    """Search the team's saved memories/knowledge base.
    Call this when the user asks about previously saved information,
    e.g. 'what's the helpdesk number?', 'do you remember ...?', 'what did we save about ...?'.

    Args:
        query: Search terms to find relevant memories.
    """
    try:
        with _get_db() as conn:
            # FTS5 search — add * for prefix matching (e.g. "help" matches "helpdesk")
            fts_query = " OR ".join(f'"{word}"*' for word in query.split() if word.strip())
            rows = conn.execute("""
                SELECT m.id, m.topic, m.content, m.saved_by, m.updated_at,
                       rank
                FROM memories_fts fts
                JOIN memories m ON m.id = fts.rowid
                WHERE memories_fts MATCH ?
                ORDER BY rank
                LIMIT 10
            """, (fts_query,)).fetchall()

            if not rows:
                # Fallback: simple LIKE search in case FTS tokenization missed it
                like_pattern = f"%{query}%"
                rows = conn.execute("""
                    SELECT id, topic, content, saved_by, updated_at
                    FROM memories
                    WHERE topic LIKE ? OR content LIKE ?
                    ORDER BY updated_at DESC
                    LIMIT 10
                """, (like_pattern, like_pattern)).fetchall()

            if not rows:
                return (f"No memories found matching '{query}'. Nothing has been saved about this topic yet. "
                        "Do NOT call recall_memory again. Try other available tools to answer the question, "
                        "or tell the user no saved information exists and suggest they save it.")

            results = []
            for row in rows:
                entry = f"• **{row['topic']}**: {row['content']}"
                if row["saved_by"]:
                    entry += f" _(saved by {row['saved_by']})_"
                results.append(entry)

            return f"{_FINAL}Found {len(rows)} memory/memories:\n" + "\n".join(results)

    except Exception as e:
        logger.error(f"Failed to recall memory: {e}", exc_info=True)
        return f"❌ Failed to search memories: {e}"


@tool
@log_tool_call
def forget_memory(query: str) -> str:
    """Delete a saved memory by topic or search terms.
    Call this when the user says 'forget ...', 'delete memory ...', 'remove ...'.

    Args:
        query: The topic or search terms identifying the memory to delete.
    """
    if not _is_room_allowed():
        return f"{_FINAL}Memory tools are not available in this room. Please use an approved room."

    try:
        with _get_db() as conn:
            # First try exact topic match
            row = conn.execute(
                "SELECT id, topic, content FROM memories WHERE LOWER(topic) = LOWER(?)",
                (query,)
            ).fetchone()

            if not row:
                # FTS search for closest match
                fts_query = " OR ".join(f'"{word}"*' for word in query.split() if word.strip())
                row = conn.execute("""
                    SELECT m.id, m.topic, m.content
                    FROM memories_fts fts
                    JOIN memories m ON m.id = fts.rowid
                    WHERE memories_fts MATCH ?
                    ORDER BY rank
                    LIMIT 1
                """, (fts_query,)).fetchone()

            if not row:
                return f"No memory found matching '{query}'. Nothing to forget."

            conn.execute("DELETE FROM memories WHERE id = ?", (row["id"],))
            conn.commit()
            return f"{_FINAL}🗑️ Forgot **{row['topic']}**: {row['content']}"

    except Exception as e:
        logger.error(f"Failed to forget memory: {e}", exc_info=True)
        return f"❌ Failed to delete memory: {e}"
