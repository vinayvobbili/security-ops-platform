import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Union

import openpyxl
import pandas as pd

from config import get_config
from services.service_now import enrich_host_report
from services.tanium import Computer, TaniumClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
CONFIG = get_config()

# Constants for ring distribution
RING_1_PERCENT = 0.10  # 10% of workstations in Ring 1
RING_2_PERCENT = 0.20  # 20% of workstations in Ring 2
RING_3_PERCENT = 0.30  # 30% of workstations in Ring 3
# Remaining 40% in Ring 4

# Environment-based ring assignment for servers
RING_1_ENVS = {'dev', 'development', 'sandbox', 'lab', 'poc', 'integration', 'int'}
RING_2_ENVS = {'test', 'testing', 'qa'}
RING_3_ENVS = {'stage', 'staging', 'uat', 'pre-prod', 'preprod', 'dr', 'qa/dr'}
# All other environments (including production) go to Ring 4

# Data directories and files
DATA_DIR = Path(__file__).parent.parent.parent / "data"
COUNTRIES_FILE = DATA_DIR / "countries_by_code.json"

# Load country data
try:
    with open(COUNTRIES_FILE, 'r') as f:
        COUNTRY_NAMES_BY_ABBREVIATION = json.load(f)
    logger.info(f"Loaded {len(COUNTRY_NAMES_BY_ABBREVIATION)} country codes from {COUNTRIES_FILE}")
except Exception as e:
    logger.error(f"Error loading country data: {e}")
    COUNTRY_NAMES_BY_ABBREVIATION = {}


def get_tanium_hosts_without_ring_tag(filename) -> str:
    """Get computers without ECM tag from all instances and export to Excel"""
    today = datetime.now().strftime('%m-%d-%Y')
    output_dir = Path(__file__).parent.parent.parent / "data" / "transient" / "epp_device_tagging" / today
    output_dir.mkdir(parents=True, exist_ok=True)
    all_hosts_file = output_dir / "All Tanium Hosts.xlsx"

    client = TaniumClient()

    if all_hosts_file.exists():
        all_hosts_filename = str(all_hosts_file)
    else:
        all_hosts_filename = client.get_and_export_all_computers()
    if not filename:
        logger.warning("No computers retrieved from any instance!")
        return 'No computers retrieved from any instance!'

    all_computers = []
    wb = openpyxl.load_workbook(all_hosts_filename)
    ws = wb.active
    for row in ws.iter_rows(min_row=2, values_only=True):
        # Add safety checks to handle missing or invalid row data
        if not row or len(row) < 6:  # We need at least 6 elements
            logger.warning(f"Skipping row with insufficient data: {row}")
            continue

        try:
            all_computers.append(
                Computer(
                    name=str(row[0]) if row[0] is not None else "",
                    id=str(row[1]) if row[1] is not None else "",
                    ip=str(row[2]) if row[2] is not None else "",
                    eidLastSeen=row[3],
                    source=str(row[4]) if row[4] is not None else "",
                    custom_tags=[tag.strip() for tag in str(row[5]).split(',')] if row[5] else []
                )
            )
        except (IndexError, TypeError, ValueError) as e:
            logger.warning(f"Error processing row {row}: {e}")
            continue

    if not all_computers:
        logger.warning("No computers retrieved from any instance!")
        return 'No computers retrieved from any instance!'
    computers_without_ring_tag = [c for c in all_computers if not c.has_epp_ring_tag()]
    computers_without_ring_tag_filename = client.export_to_excel(computers_without_ring_tag, filename)
    print(f'Found {len(computers_without_ring_tag)} Tanium hosts without ring tag')
    print('Starting enrichment of these hosts with ServiceNow data')
    enriched_report = enrich_host_report(computers_without_ring_tag_filename)

    # add a column to the enriched_report 'region'. Use the country column to derive it from regions_by_country.json
    regions_by_country_path = DATA_DIR / "regions_by_country.json"

    with open(regions_by_country_path, 'r') as f:
        regions_by_country = json.load(f)

    df_enriched = pd.read_excel(enriched_report)
    # Use consistent column name 'Region' (capital R)
    df_enriched['Region'] = None
    df_enriched['Was Country Guessed'] = False

    for index, row in df_enriched.iterrows():
        country_from_snow = row.get('SNOW_country')
        hostname = row.get('Computer Name')

        country_to_use = None
        was_country_guessed = False

        if pd.notna(country_from_snow) and country_from_snow:
            country_to_use = country_from_snow
        elif pd.notna(hostname) and hostname:
            # Create a dummy Computer object for _guess_country_from_hostname
            dummy_computer = Computer(name=hostname, id="", ip="", eidLastSeen="", source="")
            guessed_country, _ = _guess_country_from_hostname(dummy_computer)
            if guessed_country:
                country_to_use = guessed_country
                was_country_guessed = True

        if country_to_use:
            region = regions_by_country.get(country_to_use, 'Unknown Region')
            df_enriched.at[index, 'Region'] = region
            df_enriched.at[index, 'Was Country Guessed'] = was_country_guessed
        else:
            df_enriched.at[index, 'Region'] = 'Unknown Region'
            df_enriched.at[index, 'Was Country Guessed'] = False

    # Save the DataFrame with the new 'Region' column
    enriched_report_with_region = Path(enriched_report).parent / "Tanium hosts without ring tag - enriched with SNOW data.xlsx"
    df_enriched.to_excel(enriched_report_with_region, index=False)

    # Generate Ring tags
    tagged_report = generate_ring_tags(str(enriched_report_with_region))

    print(f'Completed enrichment and tag generation. The full report can be found at {tagged_report}')
    return tagged_report


def generate_ring_tags(filename: str) -> str:
    """
    Generate ring tags for a list of computers and export to Excel.

    This function assumes all enrichment (region, country, environment, category, etc.)
    has already been performed. It only generates ring tags and logs based on the given data.
    """
    # Load the enriched data from the file to get additional attributes like region, country, and environment
    enriched_data = {}
    try:
        wb = openpyxl.load_workbook(filename)
        ws = wb.active

        # Determine header indices - improved to handle case insensitivity
        headers = [str(cell.value).lower() if cell.value else "" for cell in ws[1]]

        # More robust header detection with various possible names
        name_idx = next((i for i, h in enumerate(headers) if "computer name" in h or "name" == h or "hostname" in h), 0)
        region_idx = next((i for i, h in enumerate(headers) if "region" in h), None)
        country_idx = next((i for i, h in enumerate(headers) if "country" in h), None)
        environment_idx = next((i for i, h in enumerate(headers) if "environment" in h or "env" == h), None)
        category_idx = next((i for i, h in enumerate(headers) if "category" in h), None)

        logger.info(f"Reading enrichment data from {filename}")
        logger.info(f"Headers found: {[cell.value for cell in ws[1]]}")
        logger.info(f"Column indices - Name: {name_idx}, Region: {region_idx}, Country: {country_idx}, Environment: {environment_idx}, Category: {category_idx}")

        row_count = 0
        for row in ws.iter_rows(min_row=2, values_only=True):
            if not row or len(row) <= name_idx or not row[name_idx]:
                continue
            computer_name = row[name_idx]
            category_value = row[category_idx] if category_idx is not None and len(row) > category_idx else None
            region_value = row[region_idx] if region_idx is not None and len(row) > region_idx else None
            country_value = row[country_idx] if country_idx is not None and len(row) > country_idx else None
            environment_value = row[environment_idx] if environment_idx is not None and len(row) > environment_idx else None
            enriched_data[computer_name] = {
                "region": region_value if region_value else "Unknown Region",
                "country": country_value if country_value else "",
                "environment": environment_value if environment_value else "Production",
                "category": category_value
            }
            row_count += 1
        logger.info(f"Processed {row_count} rows from enrichment data")
    except Exception as e:
        logger.error(f"Error loading enriched data: {e}")

    workstations = []
    servers = []
    # Read the Excel file into a DataFrame
    df = pd.read_excel(filename)

    # Convert DataFrame rows to Computer objects
    computers = []
    for index, row in df.iterrows():
        # Extract data, handling potential missing values or types
        name = str(row.get('Hostname', ''))
        computer_id = str(row.get('ID', ''))
        ip = str(row.get('IP Address', ''))
        eid_last_seen = row.get('Last Seen')
        source = str(row.get('Source', ''))
        current_tags_str = str(row.get('Current Tags', ''))
        custom_tags = [tag.strip() for tag in current_tags_str.split(',') if tag.strip()]

        # Create Computer object
        computer = Computer(
            name=name,
            id=computer_id,
            ip=ip,
            eidLastSeen=eid_last_seen,
            source=source,
            custom_tags=custom_tags
        )
        computers.append(computer)

    for computer in computers:
        enrichment = enriched_data.get(computer.name)
        if not enrichment:
            setattr(computer, "status", "No enrichment data found - skipping")
            continue
        setattr(computer, "region", enrichment["region"])
        setattr(computer, "country", enrichment["country"])
        setattr(computer, "environment", enrichment["environment"])
        setattr(computer, "type", enrichment["category"] if enrichment["category"] else "")
        setattr(computer, "category", enrichment["category"] if enrichment["category"] else "")
        setattr(computer, "was_country_guessed", False)
        setattr(computer, "new_tag", None)
        # Use ServiceNow-enriched category only
        category = enrichment["category"] if enrichment["category"] else ""
        if category and category.lower() in ("server", "srv"):
            servers.append(computer)
        elif category and category.lower() == "workstation":
            workstations.append(computer)
        else:
            # If category is missing or unknown, skip
            setattr(computer, "status", "Category missing or unknown - skipping")

    logger.info(f"Classified {len(servers)} servers and {len(workstations)} workstations")
    _process_workstations(workstations)
    _process_servers(servers)

    output_wb = openpyxl.Workbook()
    output_ws = output_wb.active
    output_ws.title = "Ring Assignments"
    headers = [
        "Computer Name", "Tanium ID", "Category", "Environment",
        "Country", "Region", "Was Country Guessed", "Current Tags", "Generated Tag", "Comments"
    ]
    output_ws.append(headers)
    from openpyxl.styles import Font
    for cell in output_ws[1]:
        cell.font = Font(bold=True, size=14)
    for row in output_ws.iter_rows(min_row=2, max_row=output_ws.max_row):
        for cell in row:
            cell.font = Font(size=14)
    output_ws.auto_filter.ref = f"A1:J{len(workstations) + len(servers) + 1}"
    output_ws.freeze_panes = "A2"
    for computer in workstations + servers:
        current_tags = ""
        if hasattr(computer, "custom_tags") and computer.custom_tags:
            # Filter out nan or empty tags
            filtered_tags = [tag for tag in computer.custom_tags if tag and str(tag).lower() != "nan"]
            if filtered_tags:
                current_tags = ", ".join(filtered_tags)
        if not getattr(computer, "status", ""):
            _append_status(computer, "Successfully processed")
        computer_category = getattr(computer, "category", "")
        if computer_category and computer_category.lower() == "workstation":
            computer_category = "Workstation"
        elif computer_category and computer_category.lower() in ("server", "srv"):
            computer_category = "Server"
        region = getattr(computer, "region", None)
        new_tag = getattr(computer, "new_tag", None)
        if region == "Unknown Region":
            new_tag = None
            _append_status(computer, "Skipping tag generation due to unknown region")
        output_ws.append([
            computer.name,
            computer.id,
            computer_category,
            getattr(computer, "environment"),
            getattr(computer, "country"),
            region,
            "Yes" if getattr(computer, "was_country_guessed", False) else "No",
            current_tags,
            new_tag,
            getattr(computer, "status")
        ])
    column_widths = {
        'A': 40,
        'B': 25,
        'C': 18,
        'D': 22,
        'E': 22,
        'F': 18,
        'G': 14,
        'H': 50,
        'I': 28,
        'J': 80
    }
    for col, width in column_widths.items():
        output_ws.column_dimensions[col].width = width
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_path = Path(filename).parent / f"Tanium hosts without ring tag - enriched with SNOW data and with tags generated - {timestamp}.xlsx"
    output_wb.save(output_path)
    logger.info(f"Generated ring tags for {len(computers)} computers: "
                f"{len(workstations)} workstations and {len(servers)} servers")
    logger.info(f"Processed {len(computers)} computers: {len(workstations)} workstations and {len(servers)} servers (including those skipped or with unknown region)")
    # Count computers with generated tags
    generated_tag_count = sum(1 for c in workstations + servers if getattr(c, "new_tag", None))
    generated_tag_workstations = sum(1 for c in workstations if getattr(c, 'new_tag', None))
    generated_tag_servers = sum(1 for c in servers if getattr(c, 'new_tag', None))
    logger.info(f"Generated ring tags for {generated_tag_count} computers: {generated_tag_workstations} workstations and {generated_tag_servers} servers (with tags assigned)")
    return str(output_path)


def _process_workstations(workstations: List[Computer]) -> None:
    """Assign ring tags to workstations based on region and country."""
    region_country_groups = defaultdict(list)
    for ws in workstations:
        region = getattr(ws, "region")
        country = getattr(ws, "country")
        if region == "Unknown Region":
            region = _get_region_from_country(country)
            if not region:
                continue
        region_country_groups[(region, country)].append(ws)

    for (region, country), ws_group in region_country_groups.items():
        total = len(ws_group)
        if total == 0:
            continue
        ring_1_size = max(1, int(RING_1_PERCENT * total)) if total >= 10 else 0
        ring_2_size = max(1, int(RING_2_PERCENT * total)) if total >= 5 else 0
        ring_3_size = max(1, int(RING_3_PERCENT * total)) if total >= 3 else 0
        ring_4_size = total - ring_1_size - ring_2_size - ring_3_size
        ring_sizes = [ring_1_size, ring_2_size, ring_3_size, ring_4_size]
        ws_group.sort(key=lambda c: (c.eidLastSeen is None, c.eidLastSeen))
        current_index = 0
        for ring, size in enumerate(ring_sizes, start=1):
            for i in range(size):
                if current_index < len(ws_group):
                    setattr(ws_group[current_index], "new_tag", f"EPP_ECMTag_{region}_Wks_Ring{ring}")
                    current_index += 1


def _process_servers(servers: List[Computer]) -> None:
    """Process servers and assign ring tags based on environment."""
    for server in servers:
        # Normalize environment
        env = _normalize_environment(getattr(server, "environment"))

        # Determine ring based on environment
        if env in RING_1_ENVS:
            ring = 1
        elif env in RING_2_ENVS:
            ring = 2
        elif env in RING_3_ENVS:
            ring = 3
        else:  # production or unknown
            ring = 4
        # Assign tag in the required format
        region = getattr(server, "region", "Unknown")
        setattr(server, "new_tag", f"EPP_ECMTag_{region}_SRV_Ring{ring}")


def _normalize_environment(environment: Union[str, List[str], None]) -> str:
    """Normalize environment data to a single string value."""
    if not environment:
        return ""

    if isinstance(environment, list):
        if len(environment) >= 1:
            return environment[0].lower().strip()
        return ""

    return str(environment).lower().strip()


def _guess_country_from_hostname(computer: Computer) -> tuple[str, str]:
    """
    Guess country based on hostname patterns.

    Args:
        computer: The Computer object to analyze

    Returns:
        tuple: (country_name, explanation)
    """
    computer_name = computer.name
    computer_name_lower = computer_name.lower()

    # Check for specific patterns
    if 'pmli' in computer_name_lower:
        return 'India PMLI', "Country guessed from 'pmli' in hostname"

    # Check for VMVDI or team name prefix to identify US hosts
    if computer_name_lower.startswith('vmvdi') or (hasattr(CONFIG, 'team_name') and computer_name_lower.startswith(CONFIG.team_name.lower())):
        return 'United States', f"Country guessed from VMVDI/{CONFIG.team_name if hasattr(CONFIG, 'team_name') else ''} in hostname"

    # Infer country from hostname prefix (first two letters)
    country_code = computer_name[:2].upper()
    country_name = COUNTRY_NAMES_BY_ABBREVIATION.get(country_code, '')
    if country_name:
        return country_name, f"Country guessed from first two letters of hostname: {country_code} -> {country_name}"

    # Check for leading digits (Korean hosts)
    if computer_name[0].isdigit():
        return 'Korea', "Country guessed from leading digit in hostname"

    # Check for VMs with US tags
    if computer_name_lower.startswith('vm'):
        # In Tanium we look at custom tags rather than CrowdStrike tags
        for tag in computer.custom_tags:
            if 'US' in tag:
                return 'United States', "Country guessed from VM prefix and US tag"

    return '', ''


def _append_status(computer: Computer, message: str) -> None:
    """
    Append a status message to a computer object.

    This function ensures that the status message is updated in a way
    that it can be easily logged and tracked in the output reports.
    """
    if hasattr(computer, "status"):
        current_status = getattr(computer, "status")
        if current_status and message and message not in current_status:
            # Append new message, prefixed by a semicolon if not already present
            setattr(computer, "status", f"{current_status}; {message}")
        elif message and not current_status:
            # Set the status message if current status is empty
            setattr(computer, "status", message)
    else:
        # Initialize status if it doesn't exist
        setattr(computer, "status", message)


def _get_region_from_country(country: str) -> str:
    """
    Determine the region based on country name.

    Args:
        country: The country name to lookup

    Returns:
        The region code for the country, or empty string if not found
    """
    # Special cases first for efficiency and clarity
    if not country:
        return ''

    # Normalize country name to handle case and whitespace issues
    normalized_country = country.strip()

    if normalized_country.lower() in ('us', 'united states'):
        return 'US'

    # Load region mapping if not already loaded (caching for efficiency)
    if not hasattr(_get_region_from_country, 'regions_by_country'):
        try:
            with open(DATA_DIR / "regions_by_country", 'r') as f:
                _get_region_from_country.regions_by_country = json.load(f)
                logger.info(f"Loaded region data for {len(_get_region_from_country.regions_by_country)} countries")
        except Exception as e:
            logger.error(f"Error loading region data: {e}")
            _get_region_from_country.regions_by_country = {}

    # Check case-insensitive in the mapping
    for map_country, region in _get_region_from_country.regions_by_country.items():
        if normalized_country.lower() == map_country.lower():
            return region

    # Fall back to exact match if case-insensitive match fails
    region = _get_region_from_country.regions_by_country.get(country, '')
    if not region:
        logger.warning(f"Region unknown for country: '{country}' (normalized: '{normalized_country}') - mapping keys: {list(_get_region_from_country.regions_by_country.keys())}")
    return region


def main():
    get_tanium_hosts_without_ring_tag(filename="Tanium hosts without Ring tag.xlsx")


if __name__ == "__main__":
    main()
