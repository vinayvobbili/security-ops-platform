"""Team memory tools — persistent key-value store backed by SQLite with FTS5."""

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

# Same DB location as my_bot/tools/memory_tools.py so both platforms share state
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
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts
            USING fts5(topic, content, content=memories, content_rowid=id)
        """)
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


_init_db()


@mcp.tool(tags={"mutating"})
def memory_save(topic: str, content: str) -> str:
    """Save a fact or piece of information to the team's shared memory.

    Creates or updates the memory for the given topic. Both platforms
    (Sleuth and Relay) share the same memory store.

    Args:
        topic: Short label for the memory (e.g. 'VPN gateway IP', 'helpdesk number')
        content: The information to remember
    """
    try:
        with _get_db() as conn:
            existing = conn.execute(
                "SELECT id, content FROM memories WHERE LOWER(topic) = LOWER(?)",
                (topic,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE memories SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (content, existing["id"])
                )
                conn.commit()
                return f"Updated memory for '{topic}': {content}"
            else:
                conn.execute(
                    "INSERT INTO memories (topic, content) VALUES (?, ?)",
                    (topic, content)
                )
                conn.commit()
                return f"Saved memory for '{topic}': {content}"

    except Exception as e:
        logger.error(f"Failed to save memory: {e}", exc_info=True)
        return f"Error saving memory: {e}"


@mcp.tool(tags={"readonly"})
def memory_recall(query: str) -> str:
    """Search the team's saved memories for information matching the query.

    Uses full-text search to find relevant memories. Both platforms
    (Sleuth and Relay) share the same memory store.

    Args:
        query: Search terms to find relevant memories
    """
    try:
        with _get_db() as conn:
            fts_query = " OR ".join(f'"{w}"*' for w in query.split() if w.strip())
            rows = conn.execute("""
                SELECT m.id, m.topic, m.content, m.saved_by, m.updated_at
                FROM memories_fts fts
                JOIN memories m ON m.id = fts.rowid
                WHERE memories_fts MATCH ?
                ORDER BY rank
                LIMIT 10
            """, (fts_query,)).fetchall()

            if not rows:
                like = f"%{query}%"
                rows = conn.execute("""
                    SELECT id, topic, content, saved_by, updated_at
                    FROM memories
                    WHERE topic LIKE ? OR content LIKE ?
                    ORDER BY updated_at DESC
                    LIMIT 10
                """, (like, like)).fetchall()

            if not rows:
                return f"No memories found matching '{query}'."

            parts = []
            for row in rows:
                entry = f"• {row['topic']}: {row['content']}"
                if row["saved_by"]:
                    entry += f" (saved by {row['saved_by']})"
                parts.append(entry)

            return f"Found {len(rows)} memory/memories:\n" + "\n".join(parts)

    except Exception as e:
        logger.error(f"Failed to recall memory: {e}", exc_info=True)
        return f"Error searching memories: {e}"


@mcp.tool(tags={"mutating"})
def memory_forget(query: str) -> str:
    """Delete a saved memory by topic or search terms.

    Args:
        query: Topic or search terms identifying the memory to delete
    """
    try:
        with _get_db() as conn:
            row = conn.execute(
                "SELECT id, topic, content FROM memories WHERE LOWER(topic) = LOWER(?)",
                (query,)
            ).fetchone()

            if not row:
                fts_query = " OR ".join(f'"{w}"*' for w in query.split() if w.strip())
                row = conn.execute("""
                    SELECT m.id, m.topic, m.content
                    FROM memories_fts fts
                    JOIN memories m ON m.id = fts.rowid
                    WHERE memories_fts MATCH ?
                    ORDER BY rank
                    LIMIT 1
                """, (fts_query,)).fetchone()

            if not row:
                return f"No memory found matching '{query}'."

            conn.execute("DELETE FROM memories WHERE id = ?", (row["id"],))
            conn.commit()
            return f"Deleted memory '{row['topic']}': {row['content']}"

    except Exception as e:
        logger.error(f"Failed to forget memory: {e}", exc_info=True)
        return f"Error deleting memory: {e}"
