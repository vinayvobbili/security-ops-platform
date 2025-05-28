import logging
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

from services import service_now, crowdstrike
from src.epp.cs_hosts_without_ring_tag import get_dated_path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

# Server environment mappings
RING_1_ENVS = {"dev", "poc", "lab", "integration", "development"}  # All values must be in lower case
RING_2_ENVS = {"qa", "test"}
RING_3_ENVS = {"dr"}


# Ring 4 is for production or unknown environments


def generate_report():
    today_date = datetime.now().strftime('%m-%d-%Y')
    input_file_path = get_dated_path(DATA_DIR, "unique_cs_hosts.xlsx")
    if not input_file_path.exists():
        logger.info("Unique hosts file not found. Generating it now...")
        crowdstrike.update_unique_hosts_from_cs()

    try:
        # Read input file
        df = pd.read_excel(input_file_path, engine="openpyxl")
        logger.info(f"Read {len(df)} records from {input_file_path}")

        # Filter servers
        servers = df[df['cs_host_category'].str.lower().isin(['server', 'domain controller'])]
        logger.info(f"Found {len(servers)} servers")

        # Filter servers with ring tags
        servers_with_ring_tags = servers[servers["current_tags"].str.contains("FalconGroupingTags/.*SrvRing", regex=True, case=False, na=False)]
        logger.info(f"Found {len(servers_with_ring_tags)} servers with ring tags")

        # Save servers with ring tags
        servers_with_ring_tags_file_path = DATA_DIR / today_date / "cs_servers_with_ring_tags.xlsx"
        servers_with_ring_tags_file_path.parent.mkdir(parents=True, exist_ok=True)
        servers_with_ring_tags.to_excel(servers_with_ring_tags_file_path, index=False, engine="openpyxl")

        # Enrich host report with ServiceNow data
        service_now.enrich_host_report(servers_with_ring_tags_file_path)

        # Initialize columns for marking invalid tags and comments
        df['has_invalid_ring_tag'] = False
        df['comment'] = ''

        # Process servers with ring tags to check for invalid tags
        for index, server in servers_with_ring_tags.iterrows():
            env = server.get('env', '').lower() if server.get('env') else ''  # Convert to lowercase and handle None
            current_tags = server.get('current_tags', '')

            # Extract ring numbers using regex
            try:
                ring_tags = re.findall(r'FalconGroupingTags/SrvRing(\d+)', current_tags)
                ring_numbers = [int(tag) for tag in ring_tags if tag.isdigit()]

                # Skip if no ring numbers found
                if not ring_numbers:
                    logger.warning(f"No valid ring numbers found in tags for host {server.get('cs_hostname', 'Unknown')}")
                    continue

                # Check for invalid ring tags based on environment
                invalid_tag = False
                comment = ''

                if env in RING_1_ENVS:
                    if any(number != 1 for number in ring_numbers):
                        invalid_tag = True
                        comment = f'{env} is NOT a Ring 1 environment'
                elif env in RING_2_ENVS:
                    if any(number != 2 for number in ring_numbers):
                        invalid_tag = True
                        comment = f'{env} is NOT a Ring 2 environment'
                elif env in RING_3_ENVS:
                    if any(number != 3 for number in ring_numbers):
                        invalid_tag = True
                        comment = f'{env} is NOT a Ring 3 environment'
                else:  # Default to Ring 4 for production or unknown environments
                    if any(number != 4 for number in ring_numbers):
                        invalid_tag = True
                        comment = f'{env} is NOT a Ring 4 environment'

                # Update the DataFrame with the results
                df.loc[index, 'has_invalid_ring_tag'] = invalid_tag
                if invalid_tag:
                    df.loc[index, 'comment'] = comment
                    logger.info(f"Invalid ring tag found for host {server.get('cs_hostname', 'Unknown')}: {comment}")

            except Exception as e:
                logger.error(f"Error processing tags for host {server.get('cs_hostname', 'Unknown')}: {e}")
                continue

        # Save the final output
        hosts_with_invalid_ring_tags_file_path = DATA_DIR / today_date / "cs_hosts_last_seen_with_invalid_ring_tags.xlsx"
        hosts_with_invalid_ring_tags_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Create a filtered version for easier review
        hosts_with_invalid_ring_tags = df[df['has_invalid_ring_tag']].copy()

        # Save both the complete dataset and the filtered version
        df.to_excel(hosts_with_invalid_ring_tags_file_path, index=False, engine="openpyxl")

        # Save filtered version if there are any invalid tags
        if not hosts_with_invalid_ring_tags.empty:
            filtered_file_path = DATA_DIR / today_date / "cs_hosts_with_invalid_ring_tags_only.xlsx"
            hosts_with_invalid_ring_tags.to_excel(filtered_file_path, index=False, engine="openpyxl")
            logger.info(f"Found {len(hosts_with_invalid_ring_tags)} hosts with invalid ring tags")

        logger.info(f"Successfully wrote {len(df)} records to {hosts_with_invalid_ring_tags_file_path}")

    except FileNotFoundError:
        logger.error(f"Input file not found at {input_file_path}")
        raise
    except Exception as e:
        logger.error(f"Error listing hosts with invalid ring tags: {e}")
        raise


def main() -> None:
    """Main function to run the complete workflow."""
    try:
        logger.info("Starting CrowdStrike host invalid ring tag analysis")
        generate_report()
        logger.info("Completed CrowdStrike host invalid ring tag analysis")
    except Exception as e:
        logger.error(f"Error in main workflow: {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
