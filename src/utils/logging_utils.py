import csv
import re
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import request
from pytz import timezone

from my_config import get_config
from services.webex import get_room_name

eastern = timezone('US/Eastern')
config = get_config()

# Directory for logs (should be set by the main app)
LOG_FILE_DIR = Path(__file__).parent.parent.parent / 'data' / 'transient' / 'logs'


# Ensure log directory exists (lazy creation helper)
def _ensure_log_dir():
    try:
        LOG_FILE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        # Last resort: print but don't break core functionality
        print(f"Warning: could not create log directory {LOG_FILE_DIR}: {e}")


def _append_csv_with_header(file_path: Path, headers: list[str], row: list[str]):
    """Append a row to a CSV file, writing headers first if the file is new/empty."""
    try:
        # Open in append+read mode so we can detect emptiness portably
        file_path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not file_path.exists() or file_path.stat().st_size == 0
        with open(file_path, 'a', newline='') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            if is_new:
                writer.writerow(headers)
            writer.writerow(row)
    except Exception as e:
        print(f"Error writing CSV log {file_path.name}: {e}")


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
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attachment_actions = args[2]
            activity = args[3]
            now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
            try:
                _ensure_log_dir()
                actor = activity["actor"]["displayName"]
                if actor != config.my_name:
                    _append_csv_with_header(
                        LOG_FILE_DIR / log_file_name,
                        headers=["actor", "command_keyword", "room_name", "timestamp_eastern"],
                        row=[
                            actor,
                            attachment_actions.json_data.get('inputs', {}).get('command_keyword'),
                            get_room_name(attachment_actions.json_data['roomId'], bot_access_token),
                            now_eastern
                        ]
                    )
            except Exception as e:
                print(f"Error logging activity for {log_file_name}: {e}")
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
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Skip logging if this is a scanner request
        if is_scanner_request():
            return func(*args, **kwargs)

        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
        log_file_name = "web_server_activity_log.csv"
        try:
            _ensure_log_dir()
            _append_csv_with_header(
                LOG_FILE_DIR / log_file_name,
                headers=["remote_addr", "method", "path", "timestamp_eastern"],
                row=[
                    request.remote_addr,
                    request.method,
                    request.path,
                    now_eastern
                ]
            )
        except Exception as e:
            print(f"Error logging web activity: {e}")
        return func(*args, **kwargs)

    return wrapper
