import argparse
import concurrent.futures
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Callable, TypeVar, Optional

import pandas as pd
from tqdm import tqdm
from webexteamssdk import WebexTeamsAPI

from config import get_config
from services.crowdstrike import CrowdStrikeClient
from services.service_now import ServiceNowClient
from src.epp.epp_device_tagging import ReportHandler

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Type variable for decorator
F = TypeVar('F', bound=Callable[..., Any])

# Constants - consolidated
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

# Default configuration values
DEFAULT_CHUNK_SIZE = 500
DEFAULT_MAX_WORKERS = 10

# Configuration
CONFIG = get_config()
webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


def get_dated_path(base_dir: Path, filename: str) -> Path:
    """
    Create a path with today's date directory.

    Args:
        base_dir: Base directory path
        filename: Name of the file

    Returns:
        Path with date directory
    """
    today_date = datetime.now().strftime('%m-%d-%Y')
    return base_dir / today_date / filename


def read_excel_file(file_path: Path) -> pd.DataFrame:
    """Read data from an Excel file."""
    try:
        return pd.read_excel(file_path, engine="openpyxl")
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except PermissionError:
        logger.error(f"Permission denied for file: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise


def write_excel_file(df: pd.DataFrame, file_path: Path) -> None:
    """Write DataFrame to an Excel file."""
    try:
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_excel(file_path, index=False, engine="openpyxl")
        logger.info(f"Successfully wrote {len(df)} records to {file_path}")
    except PermissionError:
        logger.error(f"Permission denied when writing to {file_path}")
        raise
    except OSError as e:
        logger.error(f"OS error when writing to {file_path}: {e}")
        raise
    except Exception as e:
        logger.error(f"Error writing to {file_path}: {e}")
        raise


def send_report(step_times: Dict[str, float]) -> None:
    """Sends the enriched hosts report to a Webex room, including step run times."""
    enriched_hosts_file = get_dated_path(DATA_DIR, "cs_hosts_last_seen_without_ring_tag.xlsx")
    hosts_count = len(pd.read_excel(enriched_hosts_file))

    try:

        report_text = (
                f"UNIQUE CS hosts without a Ring tag. Count={hosts_count}!\n\n"
                "Step execution times:\n" +
                "\n".join([f"{step}: {ReportHandler.format_duration(time)}" for step, time in step_times.items()])
        )
        webex_api.messages.create(
            roomId=CONFIG.webex_room_id_epp_tagging,
            text=report_text,
            files=[str(enriched_hosts_file)]
        )
    except FileNotFoundError:
        logger.error(f"Report file not found at {enriched_hosts_file}")
    except Exception as e:
        logger.error(f"Failed to send report: {e}")


def process_unique_hosts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Process dataframe to get unique hosts with latest last_seen.

    Args:
        df: DataFrame with host data

    Returns:
        DataFrame with unique hosts (latest entry per hostname)
    """
    # Convert last_seen to datetime for proper sorting - only once
    df["last_seen"] = pd.to_datetime(df["last_seen"], errors='coerce').dt.tz_localize(None)

    # Group by hostname and get the record with the latest last_seen
    return df.loc[df.groupby("hostname")["last_seen"].idxmax()]


def get_unique_hosts() -> None:
    """Group hosts by hostname and get the record with the latest last_seen for each."""
    try:
        # Read the input file
        hosts_without_tag_file = get_dated_path(DATA_DIR, "all_cs_hosts.xlsx")
        df = read_excel_file(hosts_without_tag_file)

        # Process the data to get unique hosts
        unique_hosts = process_unique_hosts(df)

        # Write the results to a new file
        unique_hosts_file = get_dated_path(DATA_DIR, "unique_cs_hosts.xlsx")
        write_excel_file(unique_hosts, unique_hosts_file)
        logger.info(f"Found {len(unique_hosts)} unique hosts.")
    except FileNotFoundError as e:
        logger.error(f"Input file not found: {e}")
        raise
    except Exception as e:
        logger.error(f"Error processing unique hosts: {e}")
        raise


def filter_hosts_without_ring_tag(df: pd.DataFrame) -> pd.DataFrame:
    """
    Filter hosts that don't have a Ring tag.

    Args:
        df: DataFrame with host data including tags

    Returns:
        DataFrame with filtered hosts
    """
    # Convert tags to strings and handle NaN values
    df["current_tags"] = df["current_tags"].astype(str).replace('nan', '')

    # Vectorized filtering for hosts without ring tags
    has_ring_tag = df["current_tags"].str.contains("FalconGroupingTags/.*Ring", regex=True, case=False, na=False)
    return df[~has_ring_tag]


def list_cs_hosts_without_ring_tag() -> None:
    """List CrowdStrike hosts that don't have a FalconGroupingTags/*Ring* tag."""
    input_file = get_dated_path(DATA_DIR, "unique_cs_hosts.xlsx")
    try:
        df = read_excel_file(input_file)

        # Filter hosts without ring tags
        output_df = filter_hosts_without_ring_tag(df)

        hosts_without_tag_file = get_dated_path(DATA_DIR, "cs_hosts_last_seen_without_ring_tag.xlsx")
        write_excel_file(output_df, hosts_without_tag_file)
        logger.info(f"Found {len(output_df)} hosts without a Ring tag.")
    except FileNotFoundError:
        logger.error(f"Input file not found at {input_file}")
        raise
    except Exception as e:
        logger.error(f"Error listing hosts without ring tag: {e}")
        raise


def fetch_host_details(hostname: str, service_now_client: ServiceNowClient) -> Dict[str, Any]:
    """
    Fetch host details from ServiceNow.

    Args:
        hostname: The hostname to look up
        service_now_client: Initialized ServiceNowClient

    Returns:
        Dictionary with host details
    """
    try:
        return service_now_client.get_host_details(hostname)
    except ConnectionError as e:
        logger.error(f"Connection error for {hostname}: {e}")
        return {"name": hostname, "error": "Connection error", "error_details": str(e)}
    except TimeoutError as e:
        logger.error(f"Timeout error for {hostname}: {e}")
        return {"name": hostname, "error": "Timeout error", "error_details": str(e)}
    except Exception as e:
        logger.error(f"Error fetching details for {hostname}: {e}")
        return {"name": hostname, "error": str(e)}


def enrich_host_report(chunk_size: int = DEFAULT_CHUNK_SIZE,
                       service_now_client: Optional[ServiceNowClient] = None):
    """
    Enrich host data with ServiceNow details using multithreading.

    Args:
        chunk_size: Size of batches for processing
        service_now_client: Optional pre-initialized ServiceNowClient (for testing)
    """
    try:
        # Get hosts from unique_hosts file
        unique_hosts_file = get_dated_path(DATA_DIR, "cs_hosts_last_seen_without_ring_tag.xlsx")
        unique_hosts_df = read_excel_file(unique_hosts_file)

        # Initialize ServiceNow client if not provided
        snow_client = service_now_client or ServiceNowClient(
            CONFIG.snow_base_url,
            CONFIG.snow_functional_account_id,
            CONFIG.snow_functional_account_password,
            CONFIG.snow_client_key
        )

        # Get device details from SNOW
        hostnames = unique_hosts_df['hostname'].tolist()
        all_device_details = []

        # Process in chunks
        for i in range(0, len(hostnames), chunk_size):
            chunk_hostnames = hostnames[i:i + chunk_size]
            chunk_details = []

            # Adjust number of workers based on dataset size
            # More workers for larger datasets, fewer for smaller ones
            max_workers = min(20, max(5, len(chunk_hostnames) // 100))

            # Use ThreadPoolExecutor for this chunk
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_hostname = {
                    executor.submit(fetch_host_details, hostname, snow_client): hostname
                    for hostname in chunk_hostnames
                }

                for future in tqdm(concurrent.futures.as_completed(future_to_hostname),
                                   total=len(chunk_hostnames),
                                   desc=f"Enriching hosts {i + 1}-{min(i + chunk_size, len(hostnames))}..."):
                    hostname = future_to_hostname[future]
                    try:
                        result = future.result()
                        chunk_details.append(result)
                    except Exception as e:
                        logger.error(f"Task failed for {hostname}: {e}")
                        chunk_details.append({"name": hostname, "error": str(e)})

            all_device_details.extend(chunk_details)

        # Create dataframe and merge
        device_details_df = pd.json_normalize(all_device_details)
        merged_df = pd.merge(unique_hosts_df, device_details_df,
                             left_on='hostname', right_on='name', how='left')

        enriched_hosts_file = get_dated_path(DATA_DIR, "enriched_unique_hosts_without_ring_tag.xlsx")
        write_excel_file(merged_df, enriched_hosts_file)
        logger.info(f"Successfully enriched {len(all_device_details)} host records")

        return len(all_device_details)
    except FileNotFoundError as e:
        logger.error(f"Required file not found: {e}")
        raise
    except Exception as e:
        logger.error(f"Error enriching host report: {e}")
        raise


def parse_args():
    """Parse command-line arguments for profiling options."""
    parser = argparse.ArgumentParser(description="CrowdStrike host ring tag analysis")
    parser.add_argument("--profile", action="store_true", help="Enable profiling")
    parser.add_argument("--profile-function", type=str, choices=[
        "list_cs_hosts_without_ring_tag",
        "get_unique_hosts_without_ring_tag",
        "enrich_host_report",
        "all"
    ], default="all", help="Function to profile")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                        help="Chunk size for batch processing")
    return parser.parse_args()


def main() -> None:
    """Main function to run the complete workflow."""
    try:
        logger.info("Starting CrowdStrike host ring tag analysis")
        run_workflow()
        logger.info("Completed CrowdStrike host ring tag analysis")
    except Exception as e:
        logger.error(f"Error in main workflow: {e}")


def run_workflow(chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
    """
    Run the complete workflow without profiling.

    Args:
        chunk_size: Size of batches for processing
    """
    step_times = {}
    client = CrowdStrikeClient()

    steps = [
        ('Fetch all hosts from CS', client.fetch_all_hosts_and_write_to_xlsx),
        ("Get Unique Hosts Without Ring Tag", get_unique_hosts),
        ("List CS Hosts Without Ring Tag", list_cs_hosts_without_ring_tag),
    ]

    # Run standard steps
    for step_name, step_func in steps:
        start_time = time.time()
        step_func()
        step_times[step_name] = time.time() - start_time

    '''
    # Run enrichment step
    start_time = time.time()
    enrich_host_report()
    step_times["Enrich Host Report with SNOW details"] = time.time() - start_time
    '''

    send_report(step_times)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
