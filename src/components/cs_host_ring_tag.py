import argparse
import cProfile
import concurrent.futures
import functools
import io
import logging
import pstats
import time
from pathlib import Path
from typing import Dict, Any, Callable, TypeVar, cast

import pandas as pd
from tqdm import tqdm
from webexteamssdk import WebexTeamsAPI

from config import get_config
from services.service_now import ServiceNowClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Type variable for decorator
F = TypeVar('F', bound=Callable[..., Any])

# Constants
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATA_DIR = ROOT_DIRECTORY / "data/transient/epp_device_tagging"
INPUT_FILE = DATA_DIR / "all_cs_hosts.xlsx"
HOSTS_WITHOUT_TAG_FILE = DATA_DIR / "cs_hosts_without_ring_tag.xlsx"
UNIQUE_HOSTS_FILE = DATA_DIR / "unique_hosts_without_ring_tag.xlsx"
ENRICHED_HOSTS_FILE = DATA_DIR / "enriched_unique_hosts_without_ring_tag.xlsx"
PROFILE_OUTPUT_DIR = ROOT_DIRECTORY / "profiles"

# Configuration
CONFIG = get_config()
webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


def benchmark(func: F) -> F:
    """Decorator to measure function execution time."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"BENCHMARK: {func.__name__} executed in {elapsed_time:.4f} seconds")
        return result

    return cast(F, wrapper)


def run_profiler(func: Callable, *args, **kwargs) -> None:
    """Run the cProfile profiler on a function and save results."""
    PROFILE_OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
    profile_path = PROFILE_OUTPUT_DIR / f"{func.__name__}_{int(time.time())}.prof"

    # Run the profiler
    profiler = cProfile.Profile()
    profiler.enable()
    result = func(*args, **kwargs)
    profiler.disable()

    # Save full profile to file
    profiler.dump_stats(str(profile_path))
    logger.info(f"Saved profile to {profile_path}")

    # Print summary to console
    s = io.StringIO()
    ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
    ps.print_stats(20)  # Print top 20 time-consuming functions
    logger.info(f"Profile summary for {func.__name__}:\n{s.getvalue()}")

    return result


@benchmark
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


@benchmark
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


@benchmark
def send_report(step_times: Dict[str, float]) -> None:
    """Sends the enriched hosts report to a Webex room, including step run times."""
    try:
        host_count = len(read_excel_file(ENRICHED_HOSTS_FILE))
        report_text = (
                f"UNIQUE CS hosts without a Ring tag, enriched with SNOW details. Count={host_count}!\n\n"
                "Step execution times:\n" +
                "\n".join([f"{step}: {time:.4f} seconds" for step, time in step_times.items()])
        )
        webex_api.messages.create(
            roomId=CONFIG.webex_room_id_epp_tagging,
            text=report_text,
            files=[str(ENRICHED_HOSTS_FILE)]
        )
    except Exception as e:
        logger.error(f"Failed to send report: {e}")


@benchmark
def get_unique_hosts_without_ring_tag() -> None:
    """Group hosts by hostname and get the record with the latest last_seen for each."""
    try:
        # Read the input file
        df = read_excel_file(HOSTS_WITHOUT_TAG_FILE)

        # Convert last_seen to datetime for proper sorting - only once
        df["last_seen"] = pd.to_datetime(df["last_seen"], errors='coerce').dt.tz_localize(None)

        # Group by hostname and get the record with the latest last_seen
        unique_hosts = df.loc[df.groupby("hostname")["last_seen"].idxmax()]

        # Write the results to a new file
        write_excel_file(unique_hosts, UNIQUE_HOSTS_FILE)
    except Exception as e:
        logger.error(f"Error processing unique hosts: {e}")


@benchmark
def list_cs_hosts_without_ring_tag() -> None:
    """List CrowdStrike hosts that don't have a FalconGroupingTags/*Ring* tag."""
    try:
        df = read_excel_file(INPUT_FILE)

        # Convert tags to strings and handle NaN values
        df["current_tags"] = df["current_tags"].astype(str).replace('nan', '')

        # Vectorized filtering for hosts without ring tags
        has_ring_tag = df["current_tags"].str.contains("FalconGroupingTags/.*Ring",
                                                       regex=True, case=False, na=False)
        output_df = df[~has_ring_tag]

        write_excel_file(output_df, HOSTS_WITHOUT_TAG_FILE)
        logger.info(f"Found {len(output_df)} hosts without a Ring tag.")
    except Exception as e:
        logger.error(f"Error listing hosts without ring tag: {e}")


@benchmark
def enrich_host_report() -> None:
    """Enrich host data with ServiceNow details using multithreading."""
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
        all_device_details = []

        # Process in chunks of 500 hosts at a time
        chunk_size = 500
        for i in range(0, len(hostnames), chunk_size):
            chunk_hostnames = hostnames[i:i + chunk_size]
            chunk_details = []

            def fetch_host_details(hostname: str) -> Dict[str, Any]:
                try:
                    return service_now.get_host_details(hostname)
                except Exception as e:
                    logger.error(f"Error fetching details for {hostname}: {e}")
                    return {"name": hostname, "error": str(e)}

            # Adjust number of workers based on dataset size
            # More workers for larger datasets, fewer for smaller ones
            max_workers = min(20, max(5, len(hostnames) // 100))

            # Use ThreadPoolExecutor for this chunk
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_hostname = {executor.submit(fetch_host_details, hostname): hostname
                                      for hostname in chunk_hostnames}

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

        write_excel_file(merged_df, ENRICHED_HOSTS_FILE)
        logger.info(f"Successfully enriched {len(all_device_details)} host records")
    except Exception as e:
        logger.error(f"Error enriching host report: {e}")


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
    return parser.parse_args()


def main() -> None:
    """Main function to run the complete workflow."""
    try:
        logger.info("Starting CrowdStrike host ring tag analysis")
        args = parse_args()

        # Map functions to their names for easier profiling
        function_map = {
            "list_cs_hosts_without_ring_tag": list_cs_hosts_without_ring_tag,
            "get_unique_hosts_without_ring_tag": get_unique_hosts_without_ring_tag,
            "enrich_host_report": enrich_host_report
        }

        if args.profile:
            logger.info("Running with profiling enabled")
            if args.profile_function == "all":
                # Profile the entire workflow
                run_profiler(lambda: run_workflow())
            else:
                # Profile specific function
                func = function_map.get(args.profile_function)
                if func:
                    run_profiler(func)
                else:
                    logger.error(f"Unknown function: {args.profile_function}")
        else:
            # Run normally without profiling
            run_workflow()

        logger.info("Completed CrowdStrike host ring tag analysis")
    except Exception as e:
        logger.error(f"Error in main workflow: {e}")


def run_workflow():
    """Run the complete workflow without profiling."""
    step_times = {}

    for step_name, step_func in [
        ("List CS Hosts Without Ring Tag", list_cs_hosts_without_ring_tag),
        ("Get Unique Hosts Without Ring Tag", get_unique_hosts_without_ring_tag),
        ("Enrich Host Report", enrich_host_report),
    ]:
        start_time = time.time()
        step_func()
        step_times[step_name] = time.time() - start_time

    send_report(step_times)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
