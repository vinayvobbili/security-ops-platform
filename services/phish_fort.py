import logging
from typing import Dict, Optional

import pandas as pd
import requests
from requests.exceptions import RequestException, HTTPError
from tabulate import tabulate
from webexpythonsdk import WebexAPI

from config import get_config

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
WEBEX_ROOM_ID = CONFIG.webex_room_id_vinay_test_space  # CONFIG.phish_fort_room_id
WEBEX_MESSAGE_BATCH_SIZE = 7000

# List of incident statuses to fetch
INCIDENT_STATUSES = [
    "Case Building",
    "Pending Review",
    "Takedown Failed",
    "Takedown Pending",
    "Blocklisted",
    "Action Required"
]

# DataFrame columns to display in the report
DISPLAY_COLUMNS = [
    "statusVerbose",
    "id",
    "domain",
    "timestamp",
    "reportedBy"
]

# Column name mappings for better readability
COLUMN_MAPPINGS = {
    "statusVerbose": "Status",
    "id": "PF Incident No.",
    "domain": "Subject",
    "timestamp": "Submitted on",
    "reportedBy": "Submitted by"
}


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
        response = requests.get(
            PHISHFORT_API_URL,
            params=payload,
            headers=headers,
            timeout=30,
            verify=True
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

        # Select only the necessary columns, handle missing columns gracefully
        available_columns = [col for col in DISPLAY_COLUMNS if col in df.columns]
        if not available_columns:
            logger.warning(f"None of the expected columns found in data for status: {status}")
            return None

        formatted_df = df[available_columns].copy()

        # Convert timestamp to datetime if it exists
        if 'timestamp' in formatted_df.columns:
            formatted_df['timestamp'] = pd.to_datetime(
                formatted_df['timestamp'],
                errors='coerce'
            ).dt.strftime('%m/%d/%Y')

        # Remove email domain from reporter names if column exists
        if 'reportedBy' in formatted_df.columns:
            formatted_df['reportedBy'] = formatted_df['reportedBy'].fillna('').str.replace('@company.com', '')

        # Rename columns for better readability
        formatted_df.rename(
            columns={k: v for k, v in COLUMN_MAPPINGS.items() if k in formatted_df.columns},
            inplace=True
        )

        return formatted_df

    except Exception as e:
        logger.error(f"Error formatting data for status '{status}': {e}")
        return None


def send_webex_notification_in_batches(message: str, batch_size: int = WEBEX_MESSAGE_BATCH_SIZE) -> None:
    """
    Send a large Webex message in batches if it exceeds the size limit.

    Args:
        message: The message to send
        batch_size: Maximum size of each message batch
    """
    if not message:
        logger.warning("Attempted to send empty message to Webex")
        return

    # Split the message into smaller chunks
    for i in range(0, len(message), batch_size):
        batch_message = message[i:i + batch_size]

        # Add continuation notice if the message is split
        if i + batch_size < len(message):
            batch_message += "\n\n**(Continued in next message)**"

        payload = {
            'roomId': WEBEX_ROOM_ID,
            'markdown': batch_message
        }

        for attempt in range(3):  # Retry up to 3 times
            try:
                response = webex_api.messages.create(**payload)
                logger.info(f"Webex notification part {i // batch_size + 1} sent successfully")
                break  # Exit retry loop on success
            except Exception as e:
                logger.error(f"Error sending Webex notification batch (attempt {attempt + 1}/3): {e}")
                if attempt == 2:  # The Last attempt failed
                    logger.error("Failed to send message after 3 attempts")


def fetch_and_report_incidents() -> None:
    """
    Fetch incidents from PhishFort and send a Webex notification with the report.
    """
    try:
        all_frames = []

        # Fetch and process incidents for each status in the list
        for status in INCIDENT_STATUSES:
            df = format_phishfort_data(status)
            if df is not None and not df.empty:
                all_frames.append(df)

        # Handle the case where no incidents are found
        if not all_frames:
            logger.info("No incidents found to report")
            send_webex_notification_in_batches("**PhishFort Incident Report**\n\nNo incidents found to report.")
            return

        # Combine all dataframes
        result = pd.concat(all_frames, ignore_index=True)

        # Sort by submission date if possible
        submission_col = COLUMN_MAPPINGS["timestamp"]
        if submission_col in result.columns:
            result[submission_col] = pd.to_datetime(result[submission_col], errors='coerce')
            result.sort_values(by=submission_col, ascending=True, inplace=True)
            result[submission_col] = result[submission_col].dt.strftime('%m/%d/%Y')

        # Convert dataframe to a markdown-like string format for Webex
        table = tabulate(result, headers="keys", tablefmt="pipe", showindex=False)

        # Send the report
        logger.info(f"Sending report with {len(result)} incidents")
        send_webex_notification_in_batches(f"**PhishFort Incident Report**\n\n```\n{table}\n```")

    except Exception as e:
        logger.error(f"Unexpected error in fetch_and_report_incidents: {e}", exc_info=True)
        try:
            # Attempt to notify about the error
            send_webex_notification_in_batches(
                f"**ERROR: PhishFort Incident Report Failed**\n\n"
                f"The automated report encountered an error: {str(e)}"
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
