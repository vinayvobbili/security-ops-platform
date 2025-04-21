import logging
from pathlib import Path
from typing import List, Dict, Any

import pandas as pd
from tqdm import tqdm
from webexteamssdk import WebexTeamsAPI

from config import get_config
from services.service_now import ServiceNowClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATA_DIR = ROOT_DIRECTORY / "data/transient/epp_device_tagging"
INPUT_FILE = DATA_DIR / "all_cs_hosts.xlsx"
HOSTS_WITHOUT_TAG_FILE = DATA_DIR / "cs_hosts_without_ring_tag.xlsx"
UNIQUE_HOSTS_FILE = DATA_DIR / "unique_hosts_without_ring_tag.xlsx"
ENRICHED_HOSTS_FILE = DATA_DIR / "enriched_unique_hosts_without_ring_tag.xlsx"

# Configuration
CONFIG = get_config()
webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


def read_excel_file(file_path: Path) -> pd.DataFrame:
    """Read data from an Excel file.

    Args:
        file_path: Path to the Excel file

    Returns:
        DataFrame containing the Excel data

    Raises:
        FileNotFoundError: If the file doesn't exist
    """
    try:
        return pd.read_excel(file_path, engine="openpyxl")
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise


def write_excel_file(df: pd.DataFrame, file_path: Path) -> None:
    """Write DataFrame to an Excel file.

    Args:
        df: DataFrame to write
        file_path: Path where the file will be saved
    """
    try:
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_excel(file_path, index=False, engine="openpyxl")
        logger.info(f"Successfully wrote {len(df)} records to {file_path}")
    except Exception as e:
        logger.error(f"Error writing to {file_path}: {e}")
        raise


def send_report():
    """Sends the enriched hosts report to a Webex room.
    """
    try:
        host_count = len(read_excel_file(ENRICHED_HOSTS_FILE))
        webex_api.messages.create(
            roomId=CONFIG.webex_room_id_epp_tagging,
            text=f"UNIQUE CS hosts without a Ring tag, enriched with SNOW details. Count={host_count}!",
            files=[str(ENRICHED_HOSTS_FILE)]
        )
    except Exception as e:
        logger.error(f"Failed to send report: {e}")


def get_unique_hosts_without_ring_tag() -> None:
    """Group hosts by hostname and get the record with the latest last_seen for each."""
    try:
        # Read the input file
        df = read_excel_file(HOSTS_WITHOUT_TAG_FILE)

        # Convert last_seen to datetime for proper sorting
        df["last_seen"] = pd.to_datetime(df["last_seen"]).dt.tz_localize(None)

        # Group by hostname and get the record with the latest last_seen
        unique_hosts = df.loc[df.groupby("hostname")["last_seen"].idxmax()]

        # Write the results to a new file
        write_excel_file(unique_hosts, UNIQUE_HOSTS_FILE)
    except Exception as e:
        logger.error(f"Error processing unique hosts: {e}")


def list_cs_hosts_without_ring_tag() -> None:
    """List CrowdStrike hosts that don't have a FalconGroupingTags/*Ring* tag."""
    hosts_without_ring_tag: List[Dict[str, Any]] = []

    try:
        df = read_excel_file(INPUT_FILE)
        for _, row in df.iterrows():
            current_tags = row["current_tags"]
            if isinstance(current_tags, str):
                tags = current_tags.split(", ")
            else:
                tags = []

            has_ring_tag = any(tag.startswith("FalconGroupingTags/") and "Ring" in tag
                               for tag in tags)

            if not has_ring_tag:
                hosts_without_ring_tag.append(row.to_dict())

        output_df = pd.DataFrame(hosts_without_ring_tag)
        write_excel_file(output_df, HOSTS_WITHOUT_TAG_FILE)
        logger.info(f"Found {len(hosts_without_ring_tag)} hosts without a Ring tag.")

    except Exception as e:
        logger.error(f"Error listing hosts without ring tag: {e}")


def enrich_host_report() -> None:
    """Enrich host data with ServiceNow details."""
    try:
        # Get hosts from unique_hosts file
        unique_hosts_df = read_excel_file(UNIQUE_HOSTS_FILE)

        # Initialize ServiceNow client
        service_now = ServiceNowClient(
            CONFIG.snow_base_url,
            CONFIG.snow_functional_account_id,
            CONFIG.snow_functional_account_password,
            CONFIG.snow_client_key
        )

        # Get device details from SNOW
        hostnames = unique_hosts_df['hostname'].tolist()
        device_details = []

        for hostname in tqdm(hostnames, desc="Enriching hosts..."):
            device_details.append(service_now.get_host_details(hostname))

        # Create a new df with device details
        device_details_df = pd.json_normalize(device_details)

        # Merge the two dataframes
        merged_df = pd.merge(unique_hosts_df, device_details_df,
                             left_on='hostname', right_on='name', how='left')

        # Save the merged df
        write_excel_file(merged_df, ENRICHED_HOSTS_FILE)
    except Exception as e:
        logger.error(f"Error enriching host report: {e}")


def main() -> None:
    """Main function to run the complete workflow."""
    try:
        logger.info("Starting CrowdStrike host ring tag analysis")
        list_cs_hosts_without_ring_tag()
        get_unique_hosts_without_ring_tag()
        enrich_host_report()
        send_report()

        logger.info("Completed CrowdStrike host ring tag analysis")
    except Exception as e:
        logger.error(f"Error in main workflow: {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
