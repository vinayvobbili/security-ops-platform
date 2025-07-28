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
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
CONFIG = get_config()
DEBUG = False  # Set to True for debugging

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
REGIONS_FILE = DATA_DIR / "regions_by_country.json"

# Load country and region data
with open(COUNTRIES_FILE, 'r') as f:
    COUNTRY_NAMES_BY_CODE = json.load(f)
logger.info(f"Loaded {len(COUNTRY_NAMES_BY_CODE)} country codes from {COUNTRIES_FILE}")

with open(REGIONS_FILE, 'r') as f:
    REGIONS_BY_COUNTRY = json.load(f)
logger.info(f"Loaded {len(REGIONS_BY_COUNTRY)} country-region mappings from {REGIONS_FILE}")


def is_valid_country(country_val):
    """Check if country value is valid (not null, nan, empty, etc.)"""
    if pd.isna(country_val) or country_val is None:
        return False
    country_str = str(country_val).strip()
    return country_str and country_str.lower() not in ['nan', 'none', 'null', '']


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
    if not all_hosts_filename:
        logger.warning("No computers retrieved from any instance!")
        return 'No computers retrieved from any instance!'

    all_computers = []
    wb = openpyxl.load_workbook(all_hosts_filename)
    ws = wb.active
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row or len(row) < 6:
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

    # Load and process the enriched report
    df_enriched = pd.read_excel(enriched_report)
    df_enriched['Region'] = None
    df_enriched['Was Country Guessed'] = False

    if DEBUG:
        debug_sample_size = 10
        print(f"\n=== DEBUGGING FIRST {debug_sample_size} ROWS ===")
        for index, row in df_enriched.head(debug_sample_size).iterrows():
            country_from_snow = row.get('SNOW_country')
            hostname = row.get('Hostname')
            print(f"\nRow {index}:")
            print(f"  Hostname: '{hostname}'")
            print(f"  SNOW_country: '{country_from_snow}' (type: {type(country_from_snow)})")
            print(f"  will guess country: {not is_valid_country(country_from_snow)}")
            if hostname:
                dummy_computer = Computer(name=hostname, id="", ip="", eidLastSeen="", source="")
                guessed_country, explanation = _guess_country_from_hostname(dummy_computer)
                print(f"  would guess: '{guessed_country}' ({explanation})")
        print(f"=== END DEBUG ===\n")

    # Process each row for country and region assignment
    for index, row in df_enriched.iterrows():
        country_from_snow = row.get('SNOW_country')
        hostname = row.get('Hostname')

        country_to_use = None
        was_country_guessed = False

        if is_valid_country(country_from_snow):
            country_to_use = country_from_snow
        elif pd.notna(hostname) and hostname:
            dummy_computer = Computer(name=hostname, id="", ip="", eidLastSeen="", source="")
            guessed_country, _ = _guess_country_from_hostname(dummy_computer)
            if guessed_country:
                country_to_use = guessed_country
                was_country_guessed = True

        if country_to_use:
            region = REGIONS_BY_COUNTRY.get(country_to_use, '')
            df_enriched.at[index, 'Region'] = region
            df_enriched.at[index, 'Was Country Guessed'] = was_country_guessed

    # Save the DataFrame with the new columns
    enriched_report_with_region = Path(enriched_report).parent / "Tanium hosts without ring tag - enriched with SNOW data.xlsx"
    df_enriched.to_excel(enriched_report_with_region, index=False)

    # Generate Ring tags
    tagged_report = generate_ring_tags(str(enriched_report_with_region))

    print(f'Completed enrichment and tag generation. The full report can be found at {tagged_report}')
    return tagged_report


def generate_ring_tags(filename: str) -> str:
    """Generate ring tags for a list of computers and export to Excel."""
    # Read the enriched data
    df = pd.read_excel(filename)
    logger.info(f"Processing {len(df)} computers for ring tag generation")

    workstations = []
    servers = []

    # Convert DataFrame rows to Computer objects and classify them
    for index, row in df.iterrows():
        name = str(row.get('Hostname', ''))
        computer_id = str(row.get('ID', ''))
        ip = str(row.get('IP Address', ''))
        eid_last_seen = row.get('Last Seen')
        source = str(row.get('Source', ''))
        current_tags_str = str(row.get('Current Tags', ''))
        custom_tags = [tag.strip() for tag in current_tags_str.split(',') if tag.strip()]

        computer = Computer(
            name=name,
            id=computer_id,
            ip=ip,
            eidLastSeen=eid_last_seen,
            source=source,
            custom_tags=custom_tags
        )

        # Set enrichment attributes
        setattr(computer, "region", row.get('Region', ''))
        setattr(computer, "country", row.get('SNOW_country', ''))
        setattr(computer, "environment", row.get('SNOW_environment', 'Production'))
        setattr(computer, "category", row.get('SNOW_category', ''))
        setattr(computer, "was_country_guessed", row.get('Was Country Guessed', False))
        setattr(computer, "new_tag", None)
        setattr(computer, "status", "")

        # Classify as server or workstation
        category = row.get('SNOW_category', '')
        if category and category.lower() in ("server", "srv"):
            servers.append(computer)
        elif category and category.lower() == "workstation":
            workstations.append(computer)
        else:
            setattr(computer, "status", "Category missing or unknown - skipping")

    logger.info(f"Classified {len(servers)} servers and {len(workstations)} workstations")
    _process_workstations(workstations)
    _process_servers(servers)

    # Create output Excel file
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

    # Add data rows
    for computer in workstations + servers:
        current_tags = ""
        if hasattr(computer, "custom_tags") and computer.custom_tags:
            filtered_tags = [tag for tag in computer.custom_tags if tag and str(tag).lower() != "nan"]
            if filtered_tags:
                current_tags = ", ".join(filtered_tags)

        computer_category = getattr(computer, "category", "")
        if computer_category and computer_category.lower() == "workstation":
            computer_category = "Workstation"
        elif computer_category and computer_category.lower() in ("server", "srv"):
            computer_category = "Server"

        region = getattr(computer, "region", "")
        new_tag = getattr(computer, "new_tag", None)

        if not region:
            new_tag = None
            _append_status(computer, "Region missing. Ring tag couldn't be generated")
        elif new_tag:
            _append_status(computer, "Ring tag generated successfully")

        output_ws.append([
            computer.name,
            computer.id,
            computer_category,
            getattr(computer, "environment", ""),
            getattr(computer, "country", ""),
            region,
            "Yes" if getattr(computer, "was_country_guessed", False) else "No",
            current_tags,
            new_tag,
            getattr(computer, "status", "")
        ])

    # Set column widths
    column_widths = {
        'A': 40, 'B': 25, 'C': 18, 'D': 22, 'E': 22,
        'F': 18, 'G': 14, 'H': 50, 'I': 28, 'J': 80
    }
    for col, width in column_widths.items():
        output_ws.column_dimensions[col].width = width

    output_ws.auto_filter.ref = f"A1:J{len(workstations) + len(servers) + 1}"
    output_ws.freeze_panes = "A2"

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_path = Path(filename).parent / f"Tanium hosts without ring tag - enriched with SNOW data and with tags generated - {timestamp}.xlsx"
    output_wb.save(output_path)

    # Log summary
    generated_tag_count = sum(1 for c in workstations + servers if getattr(c, "new_tag", None))
    generated_tag_workstations = sum(1 for c in workstations if getattr(c, 'new_tag', None))
    generated_tag_servers = sum(1 for c in servers if getattr(c, 'new_tag', None))

    logger.info(f"Generated ring tags for {generated_tag_count} computers: {generated_tag_workstations} workstations and {generated_tag_servers} servers")
    return str(output_path)


def _process_workstations(workstations: List[Computer]) -> None:
    """Assign ring tags to workstations based on region and country."""
    region_country_groups = defaultdict(list)
    for ws in workstations:
        region = getattr(ws, "region")
        country = getattr(ws, "country")
        if region:
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
        env = _normalize_environment(getattr(server, "environment"))

        if env in RING_1_ENVS:
            ring = 1
        elif env in RING_2_ENVS:
            ring = 2
        elif env in RING_3_ENVS:
            ring = 3
        else:  # production or unknown
            ring = 4

        region = getattr(server, "region", "Unknown")
        setattr(server, "new_tag", f"EPP_ECMTag_{region}_SRV_Ring{ring}")


def _normalize_environment(environment: Union[str, List[str], None]) -> str:
    """Normalize environment data to a single string value."""
    if not environment:
        return ""
    if isinstance(environment, list):
        value = environment[0] if environment else ""
    else:
        value = environment
    # Always convert to string before lower/strip
    return str(value).lower().strip()


def _guess_country_from_hostname(computer: Computer) -> tuple[str, str]:
    """Guess country based on hostname and tags."""
    computer_name = computer.name
    computer_name_lower = computer_name.lower()

    # Check for VMVDI or team name prefix
    if computer_name_lower.startswith('vmvdi') or (hasattr(CONFIG, 'team_name') and computer_name_lower.startswith(CONFIG.team_name.lower())):
        return 'United States', f"Country guessed from VMVDI/{getattr(CONFIG, 'team_name', '')} in hostname"

    # Infer from first two letters of hostname
    country_code = computer_name[:2].upper()
    country_name = COUNTRY_NAMES_BY_CODE.get(country_code, '')
    if country_name:
        return country_name, f"Country guessed from first two letters of hostname: {country_code} -> {country_name}"

    # If leading digit, Korea
    if computer_name and computer_name[0].isdigit():
        return 'Korea', "Country guessed from leading digit in hostname"

    # If starts with 'vm' and has US tag
    if computer_name_lower.startswith('vm'):
        for tag in getattr(computer, 'custom_tags', []):
            if 'US' in tag or 'SensorGroupingTags/US' in tag:
                return 'US', "Country guessed from leading characters VM in hostname and US tag"

    return '', ''


def _append_status(computer: Computer, message: str) -> None:
    """Append a status message to a computer object."""
    current_status = getattr(computer, "status", "")
    if current_status and message and message not in current_status:
        setattr(computer, "status", f"{current_status}; {message}")
    elif message and not current_status:
        setattr(computer, "status", message)


def main():
    get_tanium_hosts_without_ring_tag(filename="Tanium hosts without Ring tag.xlsx")


if __name__ == "__main__":
    main()
