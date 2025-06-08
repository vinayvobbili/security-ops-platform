"""
CS Host Invalid Ring Tag Analyzer

Identifies CrowdStrike servers that have incorrect ring tags based on their environment:
- Ring 1: dev, poc, lab, integration, development environments
- Ring 2: qa, test environments
- Ring 3: dr (disaster recovery) environments
- Ring 4: production or unknown environments

Creates two reports:
- Complete dataset of all servers with ring tags
- Filtered report showing only servers with invalid ring tags
"""

import logging
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

from services import crowdstrike, service_now
from src.epp.cs_hosts_without_ring_tag import get_dated_path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

# Environment to ring mappings (all values must be lowercase)
RING_1_ENVS = {"dev", "poc", "lab", "integration", "development"}
RING_2_ENVS = {"qa", "test"}
RING_3_ENVS = {"dr"}


# Ring 4 is for production or unknown environments


def get_expected_ring(env):
    """Return expected ring number based on environment."""
    if env in RING_1_ENVS:
        return 1
    if env in RING_2_ENVS:
        return 2
    if env in RING_3_ENVS:
        return 3
    return 4


def analyze_ring_tags(servers_df):
    """Analyze servers and mark those with invalid ring tags, completely ignoring Citrix rings."""
    servers_df['has_invalid_ring_tag'] = False
    servers_df['comment'] = ''

    for index, server in servers_df.iterrows():
        env = str(server.get('environment', '')).lower()
        current_tags = server.get('current_tags', '')

        # Extract all ring tags first
        all_ring_tags = re.findall(r'FalconGroupingTags/[^,]*?SRVRing(\d+)', current_tags, re.IGNORECASE)

        # Find complete ring tag strings to check for Citrix
        complete_ring_tag_matches = re.findall(r'(FalconGroupingTags/[^,]*?SRVRing\d+)', current_tags, re.IGNORECASE)

        # Filter to only non-Citrix rings by checking the complete tag
        non_citrix_rings = []
        for i, ring_num in enumerate(all_ring_tags):
            if 'citrix' not in complete_ring_tag_matches[i].lower():
                non_citrix_rings.append(int(ring_num))

        if not non_citrix_rings:
            continue

        if len(non_citrix_rings) > 1:
            servers_df.loc[index, 'has_invalid_ring_tag'] = True
            servers_df.loc[index, 'comment'] = 'multiple ring tags found'
            logger.info(f"Multiple non-Citrix ring tags found for host {server.get('hostname', 'Unknown')}: {non_citrix_rings}")
            continue

        expected_ring = get_expected_ring(env)
        if any(num != expected_ring for num in non_citrix_rings):
            servers_df.loc[index, 'has_invalid_ring_tag'] = True
            servers_df.loc[index, 'comment'] = f'{env} server should not be in Ring {non_citrix_rings}, expected Ring {expected_ring}'
            logger.info(f"Invalid ring tag found for host {server.get('hostname', 'Unknown')}: Ring {non_citrix_rings}, expected Ring {expected_ring}")


def generate_report():
    """Generate the complete invalid ring tag analysis report."""
    today_date = datetime.now().strftime('%m-%d-%Y')
    output_dir = DATA_DIR / today_date
    output_dir.mkdir(parents=True, exist_ok=True)

    # Get input file
    input_file_path = get_dated_path(DATA_DIR, "unique_cs_hosts.xlsx")
    if not input_file_path.exists():
        logger.info("Unique hosts file not found. Generating it now...")
        crowdstrike.update_unique_hosts_from_cs()

    # Read and filter data
    unique_cs_hosts_df = pd.read_excel(input_file_path, engine="openpyxl")
    logger.info(f"Read {len(unique_cs_hosts_df)} records from {input_file_path}")

    # Filter for servers only
    servers = unique_cs_hosts_df[
        unique_cs_hosts_df['cs_host_category'].str.lower().isin(['server', 'domain controller'])
    ]
    logger.info(f"Found {len(servers)} servers")

    # Filter servers with ring tags
    servers_with_ring_tags = servers[
        servers["current_tags"].str.contains("FalconGroupingTags/.*SrvRing", regex=True, case=False, na=False)
    ]
    logger.info(f"Found {len(servers_with_ring_tags)} servers with ring tags")

    # Save servers with ring tags
    servers_with_ring_tags_file_path = output_dir / "cs_servers_with_ring_tags.xlsx"
    servers_with_ring_tags.to_excel(servers_with_ring_tags_file_path, index=False, engine="openpyxl")

    # Enrich with ServiceNow data
    enriched_file_path = service_now.enrich_host_report(servers_with_ring_tags_file_path)
    enriched_servers = pd.read_excel(enriched_file_path, engine="openpyxl")

    # Analyze ring tags
    analyze_ring_tags(enriched_servers)

    # Save complete report
    complete_report_path = output_dir / "cs_servers_last_seen_with_invalid_ring_tags.xlsx"
    enriched_servers.to_excel(complete_report_path, index=False, engine="openpyxl")

    # Save filtered report (invalid tags only)
    invalid_servers = enriched_servers[enriched_servers['has_invalid_ring_tag']].copy()
    if not invalid_servers.empty:
        # Add invalid_tags column
        def extract_invalid_tags(row):
            current_tags = row.get('current_tags', '')
            # Extract all non-Citrix ring tags
            all_ring_tags = re.findall(r'FalconGroupingTags/[^,]*?SRVRing(\d+)', current_tags, re.IGNORECASE)
            complete_ring_tag_matches = re.findall(r'(FalconGroupingTags/[^,]*?SRVRing\d+)', current_tags, re.IGNORECASE)
            invalid = []
            for i, ring_num in enumerate(all_ring_tags):
                if 'citrix' not in complete_ring_tag_matches[i].lower():
                    invalid.append(complete_ring_tag_matches[i])
            return ', '.join(invalid) if invalid else ''
        invalid_servers['invalid_tags'] = invalid_servers.apply(extract_invalid_tags, axis=1)

        # Only keep the requested columns
        columns_to_keep = [
            'hostname',
            'host_id',
            'current_tags',
            'invalid_tags',
            'last_seen',
            'status',
            'cs_host_category',
            'environment',
            'lifecycleStatus',
            'comment',
        ]
        filtered_report_path = output_dir / "cs_servers_with_invalid_ring_tags_only.xlsx"
        invalid_servers[columns_to_keep].to_excel(filtered_report_path, index=False, engine="openpyxl")
        logger.info(f"Found {len(invalid_servers)} hosts with invalid ring tags")
    else:
        logger.info("No hosts with invalid ring tags found")

    logger.info(f"Successfully wrote {len(enriched_servers)} records to {complete_report_path}")


def main():
    """Main function to run the complete workflow."""
    try:
        logger.info("Starting CrowdStrike host invalid ring tag analysis")
        generate_report()
        logger.info("Completed CrowdStrike host invalid ring tag analysis")
    except FileNotFoundError as e:
        logger.error(f"Input file not found: {e}")
        raise
    except Exception as e:
        logger.error(f"Error in main workflow: {e}")
        raise


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
