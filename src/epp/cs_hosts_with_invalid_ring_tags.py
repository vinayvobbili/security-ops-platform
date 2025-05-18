import logging
from datetime import datetime
from pathlib import Path

import pandas as pd

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
    try:
        df = pd.read_excel(input_file_path, engine="openpyxl")
        # if 'Category' is server, it's a server
        servers = df[df['product_type_desc'].str.lower() == 'server']
        # Filter servers with ring tags
        servers_with_ring_tags = servers[servers["current_tags"].str.contains("FalconGroupingTags/.*WksRing", regex=True, case=False, na=False)]
        for server in servers_with_ring_tags:
            env = server.get('env')
            current_tags = server.get('current_tags')
            ring_numbers = []
            for tag in current_tags:
                if 'FalconGroupingTags/WksRing' in tag:
                    ring_numbers.append(tag.split('FalconGroupingTags/WksRing')[1])

            if env in RING_1_ENVS:
                for number in ring_numbers:
                    if number is not 1:
                        server['has_invalid_ring_tag'] = True
                        break
            elif env in RING_2_ENVS:
                for number in ring_numbers:
                    if number is not 2:
                        server['has_invalid_ring_tag'] = True
            elif env in RING_3_ENVS:
                for number in ring_numbers:
                    if number is not 3:
                        server['has_invalid_ring_tag'] = True
            else:
                for number in ring_numbers:
                    if number is not 4:
                        server['has_invalid_ring_tag'] = True

        hosts_with_invalid_ring_tags_file_path = DATA_DIR / today_date / "cs_hosts_last_seen_with_invalid_ring_tags.xlsx"
        hosts_with_invalid_ring_tags_file_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_excel(hosts_with_invalid_ring_tags_file_path, index=False, engine="openpyxl")
        logger.info(f"Successfully wrote {len(df)} records to {hosts_with_invalid_ring_tags_file_path}")

    except FileNotFoundError:
        logger.error(f"Input file not found at {input_file_path}")
        raise
    except Exception as e:
        logger.error(f"Error listing hosts without ring tag: {e}")
        raise


def main() -> None:
    """Main function to run the complete workflow."""
    try:
        logger.info("Starting CrowdStrike host ring tag analysis")
        generate_report()
        logger.info("Completed CrowdStrike host ring tag analysis")
    except Exception as e:
        logger.error(f"Error in main workflow: {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
