import csv
import logging
import os
import re
import tempfile
import time
from datetime import datetime
from functools import wraps, lru_cache
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import request
from pytz import timezone

from my_config import get_config
from services.webex import get_room_name

eastern = timezone('US/Eastern')
config = get_config()

# Setup logger for this module
logger = logging.getLogger(__name__)


class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to console output"""

    def format(self, record):
        # Get the original formatted message without colors first
        log_message = super().format(record)

        # Only colorize WARNING and ERROR levels, leave INFO as default
        if record.levelname == 'WARNING':
            return f"\033[33m{log_message}\033[0m"  # Yellow
        elif record.levelname == 'ERROR':
            return f"\033[31m{log_message}\033[0m"  # Red
        elif record.levelname == 'CRITICAL':
            return f"\033[35m{log_message}\033[0m"  # Magenta
        else:
            # INFO, DEBUG and others - no color (default terminal color)
            return log_message


def setup_logging(
        bot_name: str,
        log_level=logging.INFO,
        log_dir: str = 'logs',
        info_modules: list[str] = None
):
    """
    Configure standardized logging for bots with rotation.

    Sets up both file and console handlers with:
    - Rotating file handler (10MB max per file, 5 backups)
    - Console handler with colored output (by default)
    - Local timezone formatting
    - Consistent format across all bots

    Args:
        bot_name: Name of the bot (e.g., 'msoar', 'hal9000')
        log_level: Logging level for root logger (default: logging.INFO)
        log_dir: Directory for log files (default: 'logs')
        info_modules: List of module names to set to INFO level (useful when root is WARNING)

    Returns:
        logging.Logger: Root logger instance (configured)
    """
    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f'{bot_name}.log')

    # Create rotating file handler (10MB max, 5 backups = ~50MB total)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level if log_level != logging.WARNING else logging.INFO)
    file_formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s')
    file_formatter.converter = time.localtime  # Use local timezone instead of UTC
    file_handler.setFormatter(file_formatter)

    # Configure root logger - only use file handler to avoid duplicates
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear any existing handlers (force=True equivalent)
    root_logger.handlers.clear()

    # Add file handler only (console output via tail -f is cleaner)
    root_logger.addHandler(file_handler)

    # Set specific modules to INFO level if provided
    if info_modules:
        for module_name in info_modules:
            logging.getLogger(module_name).setLevel(logging.INFO)

    return logging.getLogger()


# Room name cache to avoid repeated API calls
# Cache up to 100 room names with TTL (no expiry, rooms rarely change names)
@lru_cache(maxsize=100)
def get_room_name_cached(room_id: str, bot_access_token: str) -> str:
    """
    Cached wrapper for get_room_name to avoid repeated API calls.

    Room names rarely change, so we cache them indefinitely (until bot restart).
    This eliminates the 500-800ms API latency on every command execution.

    Args:
        room_id: Webex room ID
        bot_access_token: Bot access token

    Returns:
        Room name or 'Unknown' on error
    """
    try:
        room_name = get_room_name(room_id, bot_access_token)
        return room_name if room_name else 'Unknown'
    except Exception as e:
        logger.warning(f"Failed to fetch room name for {room_id}: {e}")
        return 'Unknown'


# Directory for logs (should be set by the main app)
LOG_FILE_DIR = Path(__file__).parent.parent.parent / 'data' / 'transient' / 'logs'

# Fallback directory if primary fails (user's temp directory)
FALLBACK_LOG_DIR = Path(tempfile.gettempdir()) / 'ir_bot_logs'


# Ensure log directory exists (lazy creation helper)
def _ensure_log_dir(log_dir: Path = LOG_FILE_DIR) -> tuple[Path, bool]:
    """
    Ensure log directory exists and is writable.

    Returns:
        tuple[Path, bool]: (directory_path, is_writable)
    """
    try:
        log_dir.mkdir(parents=True, exist_ok=True)

        # Test if we can write to the directory
        test_file = log_dir / '.write_test'
        try:
            test_file.touch()
            test_file.unlink()
            return log_dir, True
        except PermissionError:
            logger.warning(f"⚠️ No write permission for log directory {log_dir}")
            return log_dir, False

    except PermissionError as e:
        logger.warning(f"⚠️ Permission denied creating log directory {log_dir}: {e}")
        return log_dir, False
    except Exception as e:
        logger.warning(f"⚠️ Could not create log directory {log_dir}: {e}")
        return log_dir, False


def _append_csv_with_header(file_path: Path, headers: list[str], row: list[str], retry_with_fallback: bool = True):
    """
    Append a row to a CSV file, writing headers first if the file is new/empty.

    Args:
        file_path: Path to the CSV file
        headers: List of header column names
        row: List of values to append
        retry_with_fallback: If True, will retry with fallback directory on permission errors

    Returns:
        bool: True if write succeeded, False otherwise
    """
    try:
        # Ensure parent directory exists and is writable
        parent_dir, is_writable = _ensure_log_dir(file_path.parent)

        if not is_writable and retry_with_fallback:
            # Try fallback directory
            fallback_path = FALLBACK_LOG_DIR / file_path.name
            logger.warning(f"⚠️ Retrying log write to fallback location: {fallback_path}")
            return _append_csv_with_header(fallback_path, headers, row, retry_with_fallback=False)

        # Check if file exists and get its size
        is_new = not file_path.exists() or file_path.stat().st_size == 0

        # Attempt to write
        with open(file_path, 'a', newline='') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            if is_new:
                writer.writerow(headers)
            writer.writerow(row)

        return True

    except PermissionError as e:
        logger.error(f"❌ Permission denied writing to {file_path}: {e}")
        logger.error(f"💡 Fix with: sudo chown -R $USER:$USER {file_path.parent}")

        # Try fallback if not already tried
        if retry_with_fallback:
            fallback_path = FALLBACK_LOG_DIR / file_path.name
            logger.warning(f"⚠️ Retrying log write to fallback location: {fallback_path}")
            return _append_csv_with_header(fallback_path, headers, row, retry_with_fallback=False)

        return False

    except OSError as e:
        logger.error(f"❌ OS error writing CSV log {file_path.name}: {e}")
        return False

    except Exception as e:
        logger.error(f"❌ Unexpected error writing CSV log {file_path.name}: {e}", exc_info=True)
        return False


# Define patterns for known security scanners to filter from logs
SCANNER_PATTERNS = [
    # Qualys scanner patterns
    r'/administrator/components/com_.*\.xml',
    r'/wp-content/plugins/.*/timthumb\.php',
    r'QUALYS_URL',
    # Add more scanner patterns as needed
    r'/.git/',
    r'/admin/',
    r'/wp-login',
    r'/wp-admin',
    r'\.php$'
]

# Compile regex patterns for efficiency
COMPILED_SCANNER_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SCANNER_PATTERNS]

# List of known scanner IP addresses to filter
SCANNER_IPS = [
    '10.49.70.89',
    # Add more known scanner IPs as needed
]


def log_activity(bot_access_token, log_file_name):
    """
    Decorator for logging bot activity to a CSV file.

    Includes robust error handling:
    - Catches permission errors and logs helpful fix suggestions
    - Falls back to temp directory if primary location fails
    - Never crashes the bot due to logging failures
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attachment_actions = args[2]
            activity = args[3]
            now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
            try:
                actor = activity["actor"]["displayName"]
                if actor != config.my_name:
                    success = _append_csv_with_header(
                        LOG_FILE_DIR / log_file_name,
                        headers=["actor", "command_keyword", "room_name", "timestamp_eastern"],
                        row=[
                            actor,
                            attachment_actions.json_data.get('inputs', {}).get('command_keyword'),
                            get_room_name_cached(attachment_actions.json_data['roomId'], bot_access_token),
                            now_eastern
                        ]
                    )
                    if not success:
                        logger.warning(f"⚠️ Failed to log activity for {log_file_name}, but continuing...")

            except KeyError as e:
                logger.warning(f"⚠️ Missing expected data in activity log: {e}")
            except Exception as e:
                logger.error(f"❌ Unexpected error logging activity for {log_file_name}: {e}", exc_info=True)

            # Always execute the wrapped function, even if logging fails
            return func(*args, **kwargs)

        return wrapper

    return decorator


def is_scanner_request():
    """
    Determine if a request is from a known scanner based on path or IP address.
    Returns True if it matches scanner patterns, False otherwise.
    """
    # Check if the IP is a known scanner
    if request.remote_addr in SCANNER_IPS:
        return True

    # Check if the request path matches known scanner patterns
    for pattern in COMPILED_SCANNER_PATTERNS:
        if pattern.search(request.path):
            return True

    return False


def log_web_activity(func):
    """
    Decorator for logging web activity to a CSV file.
    Simplified version that doesn't require bot access token.
    Now filters out known scanner requests to prevent log pollution.

    Includes robust error handling:
    - Catches permission errors and logs helpful fix suggestions
    - Falls back to temp directory if primary location fails
    - Never crashes the web server due to logging failures
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Skip logging if this is a scanner request
        if is_scanner_request():
            return func(*args, **kwargs)

        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
        log_file_name = "web_server_activity_log.csv"
        try:
            success = _append_csv_with_header(
                LOG_FILE_DIR / log_file_name,
                headers=["remote_addr", "method", "path", "timestamp_eastern"],
                row=[
                    request.remote_addr,
                    request.method,
                    request.path,
                    now_eastern
                ]
            )
            if not success:
                logger.warning(f"⚠️ Failed to log web activity for {log_file_name}, but continuing...")

        except Exception as e:
            logger.error(f"❌ Unexpected error logging web activity: {e}", exc_info=True)

        # Always execute the wrapped function, even if logging fails
        return func(*args, **kwargs)

    return wrapper
