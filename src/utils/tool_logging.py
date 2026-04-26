"""
Tool Call Logging Utility

Logs all tool invocations by the LLM to help with debugging and monitoring.
Writes to bot_logs.db (SQLite) via bot_logs_db.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
import threading

# Thread-local storage for context information
_context = threading.local()


def set_logging_context(session_id: str):
    """Set the logging context for the current thread"""
    _context.session_id = session_id


def get_logging_context():
    """Get the current logging context"""
    return getattr(_context, 'session_id', 'unknown')


def log_tool_call(
    tool_name: str,
    input_args: Dict[str, Any],
    output: Any,
    execution_time_ms: float,
    success: bool = True,
    error_message: Optional[str] = None,
    session_id: Optional[str] = None
):
    """Log a tool call to SQLite."""
    try:
        from src.utils.bot_logs_db import log_tool_call as _db_log

        if session_id is None:
            session_id = get_logging_context()

        if session_id and '_' in session_id:
            parts = session_id.split('_', 1)
            user_id = parts[0]
            room_id = parts[1] if len(parts) > 1 else 'unknown'
        else:
            user_id = session_id or 'unknown'
            room_id = 'unknown'

        input_str = str(input_args)[:500] if input_args else ""
        if isinstance(output, str):
            output_preview = output[:200] + "..." if len(output) > 200 else output
        else:
            output_preview = str(output)[:200] + "..." if len(str(output)) > 200 else str(output)

        _db_log(
            timestamp=datetime.now().isoformat(),
            tool_name=tool_name,
            input_args=input_str,
            output_preview=output_preview,
            execution_time_sec=round(execution_time_ms / 1000.0, 3),
            success=success,
            error_message=error_message or "",
            user_id=user_id,
            room_id=room_id,
        )

    except Exception as e:
        logging.error(f"Failed to log tool call for {tool_name}: {e}")


def get_recent_tool_calls(limit: int = 50) -> list:
    """Get recent tool calls from SQLite."""
    try:
        from src.utils.bot_logs_db import get_recent_tool_calls as _db_get
        return _db_get(limit)
    except Exception as e:
        logging.error(f"Failed to read tool calls: {e}")
        return []
