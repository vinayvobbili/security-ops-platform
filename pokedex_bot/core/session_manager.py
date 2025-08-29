# /pokedex_bot/core/session_manager.py
"""
Persistent Session Manager

Provides persistent conversation storage using SQLite database.
Maintains conversation context across bot restarts and provides
efficient session management with automatic cleanup.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)


class PersistentSessionManager:
    """Manages persistent conversation sessions using SQLite"""
    
    def __init__(self, db_path: str = None):
        # Default to data/transient directory for database
        if db_path is None:
            project_root = Path(__file__).parent.parent.parent
            db_dir = project_root / "data" / "transient" / "sessions"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "conversations.db")
        
        self.db_path = db_path
        self.max_messages_per_session = 30
        self.session_timeout_hours = 24
        self.max_context_chars = 4000
        self.max_context_messages = 20
        
        self._init_database()
        logger.info(f"Persistent session manager initialized with database: {db_path}")
    
    def _init_database(self):
        """Initialize the SQLite database with required tables"""
        with self._get_db_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_key TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_key 
                ON conversations(session_key)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON conversations(session_key, timestamp DESC)
            """)
            
            conn.commit()
    
    @contextmanager
    def _get_db_connection(self):
        """Get database connection with proper error handling"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def add_message(self, session_key: str, role: str, content: str) -> bool:
        """Add a message to the conversation session"""
        try:
            timestamp = datetime.now().isoformat()
            
            with self._get_db_connection() as conn:
                # Insert new message
                conn.execute("""
                    INSERT INTO conversations (session_key, role, content, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (session_key, role, content, timestamp))
                
                # Clean up old messages for this session (keep only last N)
                conn.execute("""
                    DELETE FROM conversations 
                    WHERE session_key = ? 
                    AND id NOT IN (
                        SELECT id FROM conversations 
                        WHERE session_key = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    )
                """, (session_key, session_key, self.max_messages_per_session))
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to add message to session {session_key}: {e}")
            return False
    
    def get_conversation_context(self, session_key: str) -> str:
        """Get recent conversation history for context"""
        try:
            with self._get_db_connection() as conn:
                # Get recent messages for this session
                cursor = conn.execute("""
                    SELECT role, content, timestamp 
                    FROM conversations 
                    WHERE session_key = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (session_key, self.max_context_messages))
                
                messages = cursor.fetchall()
                
                if not messages:
                    return ""
                
                # Build context working backwards, respecting character limits
                context_parts = []
                total_chars = 0
                
                for msg in messages:  # Already ordered DESC, so newest first
                    role_display = "User" if msg['role'] == "user" else "Assistant"
                    msg_text = f"{role_display}: {msg['content']}"
                    
                    # Check if adding this message would exceed character limit
                    if total_chars + len(msg_text) + 100 > self.max_context_chars:
                        break
                    
                    context_parts.append(msg_text)
                    total_chars += len(msg_text) + 1
                
                if context_parts:
                    # Reverse to get chronological order (oldest first)
                    context_parts.reverse()
                    context = "\n\nPrevious conversation:\n" + "\n".join(context_parts) + "\n\nCurrent question:"
                    logger.debug(f"Context for {session_key}: {len(context_parts)} messages, {len(context)} chars")
                    return context
                
                return ""
                
        except Exception as e:
            logger.error(f"Failed to get context for session {session_key}: {e}")
            return ""
    
    def cleanup_old_sessions(self) -> int:
        """Remove messages from sessions older than timeout period"""
        try:
            cutoff_time = (datetime.now() - timedelta(hours=self.session_timeout_hours)).isoformat()
            
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    DELETE FROM conversations 
                    WHERE timestamp < ?
                """, (cutoff_time,))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old conversation messages")
                
                return deleted_count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old sessions: {e}")
            return 0
    
    def get_session_info(self, session_key: str = None) -> Dict:
        """Get session information for debugging"""
        try:
            with self._get_db_connection() as conn:
                if session_key:
                    # Get specific session info
                    cursor = conn.execute("""
                        SELECT COUNT(*) as message_count,
                               MIN(timestamp) as first_message,
                               MAX(timestamp) as last_message
                        FROM conversations 
                        WHERE session_key = ?
                    """, (session_key,))
                    
                    row = cursor.fetchone()
                    
                    if row and row['message_count'] > 0:
                        # Get recent messages for detail
                        cursor = conn.execute("""
                            SELECT role, content, timestamp 
                            FROM conversations 
                            WHERE session_key = ? 
                            ORDER BY timestamp DESC 
                            LIMIT 5
                        """, (session_key,))
                        
                        recent_messages = [dict(msg) for msg in cursor.fetchall()]
                        
                        return {
                            "session_key": session_key,
                            "message_count": row['message_count'],
                            "first_message": row['first_message'],
                            "last_message": row['last_message'],
                            "recent_messages": recent_messages
                        }
                    else:
                        return {"session_key": session_key, "message_count": 0}
                        
                else:
                    # Get overall statistics
                    cursor = conn.execute("""
                        SELECT COUNT(DISTINCT session_key) as total_sessions,
                               COUNT(*) as total_messages,
                               MIN(timestamp) as oldest_message,
                               MAX(timestamp) as newest_message
                        FROM conversations
                    """)
                    
                    row = cursor.fetchone()
                    
                    # Get active sessions (with messages in last 24 hours)
                    cutoff_time = (datetime.now() - timedelta(hours=24)).isoformat()
                    cursor = conn.execute("""
                        SELECT COUNT(DISTINCT session_key) as active_sessions
                        FROM conversations 
                        WHERE timestamp > ?
                    """, (cutoff_time,))
                    
                    active_row = cursor.fetchone()
                    
                    return {
                        "total_sessions": row['total_sessions'],
                        "total_messages": row['total_messages'],
                        "active_sessions": active_row['active_sessions'],
                        "oldest_message": row['oldest_message'],
                        "newest_message": row['newest_message'],
                        "database_path": self.db_path
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get session info: {e}")
            return {"error": str(e)}
    
    def export_session(self, session_key: str) -> Optional[List[Dict]]:
        """Export a session's conversation history"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    SELECT role, content, timestamp 
                    FROM conversations 
                    WHERE session_key = ? 
                    ORDER BY timestamp ASC
                """, (session_key,))
                
                messages = [dict(msg) for msg in cursor.fetchall()]
                return messages if messages else None
                
        except Exception as e:
            logger.error(f"Failed to export session {session_key}: {e}")
            return None
    
    def delete_session(self, session_key: str) -> bool:
        """Delete all messages for a specific session"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    DELETE FROM conversations 
                    WHERE session_key = ?
                """, (session_key,))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                logger.info(f"Deleted session {session_key}: {deleted_count} messages")
                return deleted_count > 0
                
        except Exception as e:
            logger.error(f"Failed to delete session {session_key}: {e}")
            return False


# Global session manager instance
_session_manager = None


def get_session_manager() -> PersistentSessionManager:
    """Get global session manager instance (singleton)"""
    global _session_manager
    if _session_manager is None:
        _session_manager = PersistentSessionManager()
    return _session_manager