"""
Tool Call Logging Utility

Logs all tool invocations by the LLM to help with debugging and monitoring.
"""

import csv
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import threading

# Thread-safe file writing
_log_lock = threading.Lock()

# Thread-local storage for context information
_context = threading.local()

# Get project root and set log file path
PROJECT_ROOT = Path(__file__).parent.parent.parent
LOG_FILE_PATH = PROJECT_ROOT / "data" / "transient" / "logs" / "tool_calls_log.csv"

def ensure_log_file_exists():
    """Ensure the log file exists with proper headers"""
    if not LOG_FILE_PATH.exists():
        # Create directory if it doesn't exist
        LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

        # Create CSV with headers
        with open(LOG_FILE_PATH, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp',
                'tool_name',
                'input_args',
                'output_preview',
                'execution_time_ms',
                'success',
                'error_message',
                'session_id'
            ])

def set_logging_context(session_id: str):
    """Set the logging context for the current thread"""
    _context.session_id = session_id

def get_logging_context():
    """Get the current logging context"""
    session_id = getattr(_context, 'session_id', 'unknown')
    return session_id

def log_tool_call(
    tool_name: str,
    input_args: Dict[str, Any],
    output: Any,
    execution_time_ms: float,
    success: bool = True,
    error_message: Optional[str] = None,
    session_id: Optional[str] = None
):
    """
    Log a tool call to the CSV file

    Args:
        tool_name: Name of the tool that was called
        input_args: Input arguments passed to the tool
        output: Output returned by the tool
        execution_time_ms: Execution time in milliseconds
        success: Whether the tool call was successful
        error_message: Error message if the call failed
        session_id: Session ID (format: user_id_room_id)
    """
    try:
        with _log_lock:
            ensure_log_file_exists()

            # Prepare data
            timestamp = datetime.now().isoformat()

            # Get context if not provided
            if session_id is None:
                session_id = get_logging_context()

            # Sanitize input args for CSV (convert to string, limit length)
            input_str = str(input_args)[:500] if input_args else ""

            # Sanitize output for CSV (convert to string, limit length)
            if isinstance(output, str):
                output_preview = output[:200] + "..." if len(output) > 200 else output
            else:
                output_preview = str(output)[:200] + "..." if len(str(output)) > 200 else str(output)

            # Clean up strings for CSV (remove newlines, quotes)
            input_str = input_str.replace('\n', ' ').replace('\r', ' ').replace('"', "'")
            output_preview = output_preview.replace('\n', ' ').replace('\r', ' ').replace('"', "'")
            error_message = (error_message or "").replace('\n', ' ').replace('\r', ' ').replace('"', "'")

            # Write to CSV
            with open(LOG_FILE_PATH, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    tool_name,
                    input_str,
                    output_preview,
                    round(execution_time_ms, 2),
                    success,
                    error_message,
                    session_id
                ])

    except Exception as e:
        # Don't let logging errors break the tool execution
        logging.error(f"Failed to log tool call for {tool_name}: {e}")

def get_recent_tool_calls(limit: int = 50) -> list:
    """Get recent tool calls from the log file"""
    try:
        if not LOG_FILE_PATH.exists():
            return []

        with open(LOG_FILE_PATH, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            return rows[-limit:] if rows else []

    except Exception as e:
        logging.error(f"Failed to read tool calls log: {e}")
        return []