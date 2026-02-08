from datetime import datetime
from pathlib import Path
import sys

import pandas as pd
import logging
from rich.progress import track

from services.crowdstrike import CrowdStrikeClient

logging.basicConfig(level=logging.DEBUG)


def get_cs_hosts_with_japan_ring_tag():
    """
    Fetch all Tanium hosts with a tag starting with 'FalconGroupingTags/JapanWksRing'.
    Returns a list of host objects (dicts).
    """
    today = datetime.now().strftime('%m-%d-%Y')
    # Use project root for all paths
    project_root = Path(__file__).resolve().parents[2]
    cached_path = project_root / 'data/transient/epp_device_tagging' / today / 'all_cs_hosts.xlsx'
    output_path = project_root / 'data/transient/epp_device_tagging' / today / "CS Hosts with FalconGroupingTags_JapanWksRing*.xlsx"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logging.debug(f"Checking if cached file exists: {cached_path}")
    logging.debug(f"Current working directory: {Path.cwd()}")
    if not cached_path.exists():
        logging.debug("Cached file does NOT exist. Entering fetch block.")
        client = CrowdStrikeClient()
        client.fetch_all_hosts_and_write_to_xlsx()
    else:
        logging.debug("Cached file exists. Skipping fetch.")

    logging.debug(f"Reading Excel file: {cached_path}")
    df = pd.read_excel(cached_path)
    filtered_hosts = []
    for _, row in track(df.iterrows(), total=len(df), description="Filtering hosts", disable=not sys.stdout.isatty()):
        tags = str(row.get('Current Tags', ''))
        if any(tag.startswith('FalconGroupingTags/JapanWksRing') for tag in tags.split(', ')):
            filtered_hosts.append(row.to_dict())
    logging.debug(f"Filtered hosts count: {len(filtered_hosts)}")
    # Save filtered hosts to spreadsheet with formatting
    if filtered_hosts:
        out_df = pd.DataFrame(filtered_hosts)
    else:
        # If no results, use the columns from the original DataFrame if available
        if 'df' in locals() and hasattr(df, 'columns'):
            out_df = pd.DataFrame(columns=df.columns)
        else:
            out_df = pd.DataFrame()
    # Write Excel file
    out_df.to_excel(output_path, index=False, engine='openpyxl')
    
    # Apply professional formatting
    if out_df.shape[1] > 0:  # Only format if there's data
        from src.utils.excel_formatting import apply_professional_formatting
        apply_professional_formatting(output_path)
    return output_path


if __name__ == "__main__":
    output_path = get_cs_hosts_with_japan_ring_tag()
    print(output_path)
