import logging
from datetime import datetime
from typing import Dict, Optional

import pandas as pd
import requests
from requests.exceptions import RequestException, HTTPError
from tabulate import tabulate
from webexpythonsdk import WebexAPI

from my_config import get_config

# Configure logging with more details
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration once
CONFIG = get_config()

# Initialize Webex API client
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)

# Constants
PHISHFORT_API_URL = "https://capi.phishfort.com/v1/incidents"
PHISHFORT_API_KEY = CONFIG.phish_fort_api_key

# Debug logging for API key
if PHISHFORT_API_KEY:
    logger.debug(f"PhishFort API key loaded: length={len(PHISHFORT_API_KEY)}, "
                 f"first_4_chars='{PHISHFORT_API_KEY[:4]}...', "
                 f"last_4_chars='...{PHISHFORT_API_KEY[-4:]}'")
else:
    logger.warning("PhishFort API key is empty or None!")
WEBEX_MESSAGE_BATCH_SIZE = 7000

# List of incident statuses to fetch
INCIDENT_STATUSES = [
    "Case Building",
    "Pending Review",
    "Takedown Failed",
    "Takedown Pending",
]

# Define column order for the final display
COLUMN_ORDER = [
    "ID",
    "Type",
    "Class",
    "Status",
    "Subject",
    "Submitted On",
    "Reporter",
]

# DataFrame columns to display in the report (expanded based on sample data)
DISPLAY_COLUMNS = [
    "id",
    "domain",
    "url",
    "subject",
    "incidentType",
    "timestamp",
    "statusVerbose",
    "incidentClass",
    "reportedBy"
]

# Column name mappings for better readability
COLUMN_MAPPINGS = {
    "id": "ID",
    "domain": "Domain",
    "url": "URL",
    "subject": "Subject",
    "incidentType": "Type",
    "timestamp": "Submitted On",
    "statusVerbose": "Status",
    "incidentClass": "Class",
    "reportedBy": "Reporter",
}

# Status display with visual indicators
STATUS_ICONS = {
    "Takedown Failed": "🔴",
    "Takedown Pending": "🟡",
    "Pending Review": "🟢",
    "Case Building": "🔵",
}

# Priority order for statuses (most urgent first)
STATUS_PRIORITY = ["Takedown Failed", "Takedown Pending", "Pending Review", "Case Building"]


def contact_phishfort_api(status: str) -> Optional[Dict]:
    """
    Contact PhishFort API to retrieve incidents for a specific status.

    Args:
        status: The incident status to query

    Returns:
        API response as dictionary or None if request failed
    """
    try:
        payload = {'statusVerbose': status}
        headers = {
            'accept': 'application/json',
            'x-api-key': PHISHFORT_API_KEY
        }

        logger.info(f"Fetching incidents with status '{status}'")
        # Debug: Log API key info (without exposing full key)
        if PHISHFORT_API_KEY:
            logger.info(f"API key present: length={len(PHISHFORT_API_KEY)}, "
                        f"starts_with='{PHISHFORT_API_KEY[:4]}...', "
                        f"ends_with='...{PHISHFORT_API_KEY[-4:]}'")
        else:
            logger.error("API key is None or empty!")
        response = requests.get(
            PHISHFORT_API_URL,
            params=payload,
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        logger.error(f"HTTP error contacting PhishFort API: {e}")
        logger.error(f"Response status code: {e.response.status_code}")
        logger.error(f"Response content: {e.response.text}")
        return None
    except RequestException as e:
        logger.error(f"Error contacting PhishFort API for status '{status}': {e}")
        return None
    except ValueError as e:
        logger.error(f"Invalid JSON response from PhishFort API: {e}")
        return None


def send_webex_notification_in_batches(message: str, batch_size: int = WEBEX_MESSAGE_BATCH_SIZE, room_id=CONFIG.webex_room_id_vinay_test_space) -> None:
    """
    Send a large Webex message in batches if it exceeds the size limit.
    Splits on-line boundaries and preserves table headers in continuations.

    Args:
        message: The message to send
        batch_size: Maximum size of each message batch
    """
    if not message:
        logger.warning("Attempted to send empty message to Webex")
        return

    # If message fits in one batch, send it directly
    if len(message) <= batch_size:
        payload = {'roomId': room_id, 'markdown': message}
        for attempt in range(3):
            try:
                webex_api.messages.create(**payload)
                logger.info("Webex notification sent successfully")
                return
            except Exception as e:
                logger.error(f"Error sending Webex notification (attempt {attempt + 1}/3): {e}")
                if attempt == 2:
                    logger.error("Failed to send message after 3 attempts")
        return

    # Split message into lines for smarter batching
    lines = message.split('\n')

    # Extract table header if present (header row + separator row after ```)
    table_header_lines: list[str] = []
    in_code_block = False
    for i, line in enumerate(lines):
        if line.strip().startswith('```'):
            in_code_block = not in_code_block
            if in_code_block and i + 2 < len(lines):
                # Capture the header row and separator row
                table_header_lines = [line, lines[i + 1], lines[i + 2]]
            break

    batches: list[str] = []
    current_batch_lines: list[str] = []
    current_size = 0

    for line in lines:
        line_size = len(line) + 1  # +1 for newline
        if current_size + line_size > batch_size and current_batch_lines:
            # Close current batch
            batches.append('\n'.join(current_batch_lines))
            current_batch_lines = []
            current_size = 0
        current_batch_lines.append(line)
        current_size += line_size

    # Add remaining lines as final batch
    if current_batch_lines:
        batches.append('\n'.join(current_batch_lines))

    # Send each batch with proper headers
    for i, batch_message in enumerate(batches):
        if i > 0:
            # Add continuation header and repeat table header if applicable
            if table_header_lines:
                batch_message = (
                    "**CONTINUED FROM PREVIOUS MESSAGE**\n\n"
                    f"{table_header_lines[0]}\n{table_header_lines[1]}\n{table_header_lines[2]}\n"
                    f"{batch_message}"
                )
            else:
                batch_message = "**CONTINUED FROM PREVIOUS MESSAGE**\n\n" + batch_message

        if i < len(batches) - 1:
            batch_message += "\n\n**(Continued in next message)**"
            # Close the code block if we're in one
            if table_header_lines and '```' not in batch_message.split('\n')[-1]:
                batch_message += "\n```"

        payload = {'roomId': room_id, 'markdown': batch_message}

        for attempt in range(3):
            try:
                webex_api.messages.create(**payload)
                logger.info(f"Webex notification part {i + 1}/{len(batches)} sent successfully")
                break
            except Exception as e:
                logger.error(f"Error sending Webex notification batch (attempt {attempt + 1}/3): {e}")
                if attempt == 2:
                    logger.error("Failed to send message after 3 attempts")


def generate_incident_statistics(df: pd.DataFrame, raw_df: pd.DataFrame = None) -> str:
    """
    Generate statistics about the incidents with visual indicators and insights.

    Args:
        df: DataFrame containing incident data (with renamed columns)
        raw_df: Original DataFrame with raw timestamp for age calculations

    Returns:
        Markdown formatted string with statistics
    """
    stats = []
    total = len(df)

    # Quick summary line
    failed_count = len(df[df['Status'] == 'Takedown Failed']) if 'Status' in df.columns else 0
    pending_count = len(df[df['Status'] == 'Takedown Pending']) if 'Status' in df.columns else 0

    if failed_count > 0:
        stats.append(f"📊 **{total} active incidents** — {failed_count} failed takedowns need attention")
    elif pending_count > 0:
        stats.append(f"📊 **{total} active incidents** — {pending_count} takedowns in progress")
    else:
        stats.append(f"📊 **{total} active incidents** being tracked")

    # Aging alerts if we have timestamp data
    if raw_df is not None and 'timestamp' in raw_df.columns:
        try:
            timestamps = pd.to_datetime(raw_df['timestamp'], errors='coerce', utc=True)
            now = pd.Timestamp.now(tz='UTC')
            ages = (now - timestamps).dt.days  # type: ignore[union-attr]
            old_incidents = int((ages > 90).sum())  # type: ignore[call-overload]
            very_old = int((ages > 180).sum())  # type: ignore[call-overload]
            oldest_days = ages.max()  # type: ignore[union-attr]

            if very_old > 0 and pd.notna(oldest_days):
                stats.append(f"⚠️ **{very_old} incidents older than 180 days** — oldest is {int(oldest_days)} days")
            elif old_incidents > 0:
                stats.append(f"⏰ **{old_incidents} incidents older than 90 days** — consider escalation")
        except (ValueError, TypeError):
            pass  # Skip aging alerts if timestamp parsing fails

    # Status breakdown with icons (in priority order)
    if 'Status' in df.columns:
        stats.append("\n**By Status:**")
        status_counts = df['Status'].value_counts()
        for status in STATUS_PRIORITY:
            if status in status_counts.index:
                count = status_counts[status]
                icon = STATUS_ICONS.get(status, "")
                stats.append(f"  {icon} {status}: {count} ({round(count / total * 100, 1)}%)")

    # Classification breakdown (compact)
    if 'Class' in df.columns:
        class_counts = df['Class'].value_counts()
        class_summary = " · ".join([f"{idx}: {count}" for idx, count in class_counts.head(4).items()])
        stats.append(f"\n**By Classification:** {class_summary}")

    # Type breakdown (compact)
    if 'Type' in df.columns:
        type_counts = df['Type'].value_counts()
        type_summary = " · ".join([f"{idx}: {count}" for idx, count in type_counts.head(4).items()])
        stats.append(f"**By Type:** {type_summary}")

    return "\n".join(stats)


def format_phishfort_data(status: str) -> Optional[pd.DataFrame]:
    """
    Format the PhishFort API response data into a Pandas DataFrame.

    Args:
        status: The incident status to format data for

    Returns:
        Formatted DataFrame or None if no data
    """
    api_result = contact_phishfort_api(status)

    if not api_result or 'data' not in api_result:
        logger.info(f"No data received for status: {status}")
        return None

    data = api_result.get('data', [])

    if not data:
        logger.info(f"Empty data list for status: {status}")
        return None

    try:
        df = pd.DataFrame(data)

        if df.empty:
            logger.info(f"No incidents found for status: {status}")
            return None

        # Create a consolidated subject column that prioritizes subject, domain, and URL
        if not {'subject', 'domain', 'url'}.isdisjoint(df.columns):
            # Fill NaN values to empty strings for consolidation
            for col in ['subject', 'domain', 'url']:
                if col in df.columns:
                    df[col] = df[col].fillna('')
                else:
                    df[col] = ''

            # Create the consolidated column without redundant type prefixes
            df['consolidatedSubject'] = df.apply(
                lambda row: row['subject'] if row['subject']
                else row['domain'] if row['domain']
                else row['url'] if row['url']
                else 'N/A',
                axis=1
            )

            # Remove the original columns and replace with the consolidated one
            columns_to_display = list(DISPLAY_COLUMNS)
            if 'subject' in columns_to_display:
                columns_to_display.remove('subject')
            if 'domain' in columns_to_display:
                columns_to_display.remove('domain')
            if 'url' in columns_to_display:
                columns_to_display.remove('url')
            columns_to_display.append('consolidatedSubject')
        else:
            columns_to_display = list(DISPLAY_COLUMNS)

        # Select only the necessary columns, handle missing columns gracefully
        available_columns = [col for col in columns_to_display if col in df.columns]
        if not available_columns:
            logger.warning(f"None of the expected columns found in data for status: {status}")
            return None

        formatted_df = df[available_columns].copy()

        # Convert timestamp to readable date format
        if 'timestamp' in formatted_df.columns:
            timestamps = pd.to_datetime(formatted_df['timestamp'], errors='coerce', utc=True)
            formatted_df['timestamp'] = timestamps.dt.strftime('%m/%d/%Y')  # type: ignore[union-attr]

        # Clean up reporter names - show just the username part
        if 'reportedBy' in formatted_df.columns:
            formatted_df['reportedBy'] = (
                formatted_df['reportedBy']
                .fillna('')
                .str.replace(r'@.*$', '', regex=True)  # Remove email domain
            )

        # Update column mappings with the consolidated subject
        column_mappings_updated = COLUMN_MAPPINGS.copy()
        column_mappings_updated['consolidatedSubject'] = 'Subject'

        # Rename columns for better readability
        formatted_df.rename(
            columns={k: v for k, v in column_mappings_updated.items() if k in formatted_df.columns},
            inplace=True
        )

        # Add status as a column if not present to help with filtering later
        if 'Status' not in formatted_df.columns and status:
            formatted_df['Status'] = status

        return formatted_df

    except Exception as e:
        logger.error(f"Error formatting data for status '{status}': {e}")
        return None


def fetch_and_report_incidents(room_id: str = None) -> None:
    """
    Fetch incidents from PhishFort and send a Webex notification with the report.

    Args:
        room_id: Webex room ID to send the report to. Defaults to test space if not provided.
    """
    if room_id is None:
        room_id = CONFIG.webex_room_id_vinay_test_space

    try:
        all_frames = []

        # Fetch and process incidents for each status in priority order
        for status in STATUS_PRIORITY:
            if status in INCIDENT_STATUSES:
                df = format_phishfort_data(status)
                if df is not None and not df.empty:
                    all_frames.append(df)

        # Handle the case where no incidents are found
        if not all_frames:
            logger.info("No incidents found to report")
            send_webex_notification_in_batches("🛡️ **PhishFort Incident Report**\n\n✅ No active incidents to report.", room_id=room_id)
            return

        # Combine all dataframes
        result: pd.DataFrame = pd.concat(all_frames, ignore_index=True)

        # Sort by status priority, then by date (oldest first within each status)
        if 'Status' in result.columns:
            result['_status_priority'] = result['Status'].map(
                {s: i for i, s in enumerate(STATUS_PRIORITY)}
            ).fillna(999)

        submission_col = COLUMN_MAPPINGS.get("timestamp")  # "Submitted On"
        if submission_col and submission_col in result.columns:
            # Convert to datetime for sorting, then sort by priority + date
            result['_sort_date'] = pd.to_datetime(result[submission_col], format='%m/%d/%Y', errors='coerce')
            result.sort_values(by=['_status_priority', '_sort_date'], ascending=[True, True], inplace=True)
            result.drop(columns=['_status_priority', '_sort_date'], inplace=True, errors='ignore')
        elif '_status_priority' in result.columns:
            result.sort_values(by='_status_priority', inplace=True)
            result.drop(columns=['_status_priority'], inplace=True, errors='ignore')

        # Generate statistics
        stats_text = generate_incident_statistics(result)

        # Rearrange columns in the specified order
        available_columns = [col for col in COLUMN_ORDER if col in result.columns]
        if available_columns:
            result = result[available_columns]

        # Add status icons to the Status column for visual clarity
        if 'Status' in result.columns:
            result['Status'] = result['Status'].apply(
                lambda s: f"{STATUS_ICONS.get(s, '')} {s}" if s in STATUS_ICONS else s
            )

        # Convert dataframe to a Markdown table for Webex
        table = tabulate(result, headers="keys", tablefmt="github", showindex=False)

        # Format the current time for the report
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Build the full report message
        report_message = (
            f"🛡️ **PhishFort Incident Report**\n"
            f"_{current_time}_\n\n"
            f"{stats_text}\n\n"
            f"---\n\n"
            f"**Detailed Incident List:**\n\n"
            f"```\n{table}\n```"
        )

        # Send the report
        logger.info(f"Sending report with {len(result)} incidents")
        send_webex_notification_in_batches(report_message, room_id=room_id)

    except Exception as e:
        logger.error(f"Unexpected error in fetch_and_report_incidents: {e}", exc_info=True)
        try:
            # Attempt to notify about the error
            send_webex_notification_in_batches(
                f"**ERROR: PhishFort Incident Report Failed**\n\n"
                f"The automated report encountered an error: {str(e)}",
                room_id=room_id
            )
        except Exception as e_notify:
            logger.critical(f"Error during error notification: {e_notify}", exc_info=True)


def main():
    """Main entry point for the script."""
    logger.info("Starting PhishFort incident report process")
    fetch_and_report_incidents()
    logger.info("PhishFort incident report process completed")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
