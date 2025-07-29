import json
import logging
import logging.config
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Union

import openpyxl
import pandas as pd

from config import get_config
from services.service_now import enrich_host_report
from services.tanium import Computer, TaniumClient

# Setup enhanced logging
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        },
        'simple': {
            'format': '%(levelname)s - %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'simple'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': 'tanium_enrichment.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'encoding': 'utf-8'
        }
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

# Configuration
CONFIG = get_config()
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

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

# Load country and region data with error handling
try:
    with open(COUNTRIES_FILE, 'r', encoding='utf-8') as f:
        COUNTRY_NAMES_BY_CODE = json.load(f)
    logger.info(f"Loaded {len(COUNTRY_NAMES_BY_CODE)} country codes from {COUNTRIES_FILE}")
except FileNotFoundError:
    logger.error(f"Country codes file not found: {COUNTRIES_FILE}")
    COUNTRY_NAMES_BY_CODE = {}
except json.JSONDecodeError as e:
    logger.error(f"Invalid JSON in country codes file: {e}")
    COUNTRY_NAMES_BY_CODE = {}

try:
    with open(REGIONS_FILE, 'r', encoding='utf-8') as f:
        REGIONS_BY_COUNTRY = json.load(f)
    logger.info(f"Loaded {len(REGIONS_BY_COUNTRY)} country-region mappings from {REGIONS_FILE}")
except FileNotFoundError:
    logger.error(f"Regions file not found: {REGIONS_FILE}")
    REGIONS_BY_COUNTRY = {}
except json.JSONDecodeError as e:
    logger.error(f"Invalid JSON in regions file: {e}")
    REGIONS_BY_COUNTRY = {}


def validate_input_file(filepath):
    """Validate input file before processing."""
    file_path = Path(filepath)

    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {filepath}")

    if not str(filepath).lower().endswith(('.xlsx', '.xls')):
        raise ValueError("Input file must be an Excel file (.xlsx or .xls)")

    # Check if file is readable
    try:
        df = pd.read_excel(filepath, nrows=1, engine='openpyxl')
        if df.empty:
            raise ValueError("Input file appears to be empty")
    except Exception as e:
        raise ValueError(f"Cannot read input file: {e}")

    logger.info(f"Input file validation passed: {filepath}")
    return True


def is_valid_country(country_val):
    """Check if country value is valid (not null, nan, empty, etc.)"""
    if pd.isna(country_val) or country_val is None:
        return False
    country_str = str(country_val).strip()
    return country_str and country_str.lower() not in ['nan', 'none', 'null', '']


def calculate_ring_sizes(total):
    """Calculate ring distribution sizes based on total count."""
    if total == 1:
        return [0, 0, 0, 1]  # Single machine goes to Ring 4
    elif total == 2:
        return [0, 0, 1, 1]  # Split between Ring 3 and 4
    elif total <= 5:
        return [0, 1, 1, total - 2]  # Minimal Ring 2 and 3
    else:
        # Use percentage-based distribution
        ring_1 = max(1, int(RING_1_PERCENT * total))
        ring_2 = max(1, int(RING_2_PERCENT * total))
        ring_3 = max(1, int(RING_3_PERCENT * total))
        ring_4 = total - ring_1 - ring_2 - ring_3
        return [ring_1, ring_2, ring_3, ring_4]


def get_tanium_hosts_without_ring_tag(filename) -> str:
    """Get computers without ECM tag from all instances and export to Excel"""
    try:
        today = datetime.now().strftime('%m-%d-%Y')
        output_dir = Path(__file__).parent.parent.parent / "data" / "transient" / "epp_device_tagging" / today
        output_dir.mkdir(parents=True, exist_ok=True)
        all_hosts_file = output_dir / "All Tanium Hosts.xlsx"

        client = TaniumClient()

        if all_hosts_file.exists():
            all_hosts_filename = str(all_hosts_file)
            logger.info(f"Using existing hosts file: {all_hosts_filename}")
        else:
            all_hosts_filename = client.get_and_export_all_computers()

        if not all_hosts_filename:
            logger.warning("No computers retrieved from any instance!")
            return 'No computers retrieved from any instance!'

        # Validate the file before processing
        validate_input_file(all_hosts_filename)

        all_computers = []

        # Use read_only mode for better memory efficiency
        try:
            wb = openpyxl.load_workbook(all_hosts_filename, read_only=True, data_only=True)
            ws = wb.active

            for row_num, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                if not row:
                    continue

                if len(row) < 6:
                    logger.warning(f"Row {row_num}: Insufficient columns ({len(row)}/6 expected)")
                    continue

                # Validate critical fields before creating Computer object
                if not row[0]:  # name is required
                    logger.warning(f"Row {row_num}: Missing computer name, skipping")
                    continue

                try:
                    all_computers.append(
                        Computer(
                            name=str(row[0]).strip() if row[0] is not None else "",
                            id=str(row[1]).strip() if row[1] is not None else "",
                            ip=str(row[2]).strip() if row[2] is not None else "",
                            eidLastSeen=row[3],
                            source=str(row[4]).strip() if row[4] is not None else "",
                            custom_tags=[tag.strip() for tag in str(row[5]).split(',') if tag.strip()] if row[5] else []
                        )
                    )
                except (IndexError, TypeError, ValueError) as e:
                    logger.warning(f"Error processing row {row_num} {row}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error reading Excel file {all_hosts_filename}: {e}")
            return f'Error reading Excel file: {e}'
        finally:
            try:
                wb.close()
            except:
                pass

        if not all_computers:
            logger.warning("No valid computers retrieved from any instance!")
            return 'No valid computers retrieved from any instance!'

        logger.info(f"Successfully loaded {len(all_computers)} computers from Tanium")

        computers_without_ring_tag = [c for c in all_computers if not c.has_epp_ring_tag()]
        computers_without_ring_tag_filename = client.export_to_excel(computers_without_ring_tag, filename)

        print(f'Found {len(computers_without_ring_tag)} Tanium hosts without ring tag')
        print('Starting enrichment of these hosts with ServiceNow data')

        enriched_report = enrich_host_report(computers_without_ring_tag_filename)

        # Load and process the enriched report
        df_enriched = pd.read_excel(enriched_report, dtype=str, engine='openpyxl')
        df_enriched['Region'] = None
        df_enriched['Was Country Guessed'] = False

        if DEBUG:
            debug_sample_size = min(10, len(df_enriched))
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
            elif hostname and str(hostname).strip():
                dummy_computer = Computer(name=str(hostname), id="", ip="", eidLastSeen="", source="")
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
        df_enriched.to_excel(enriched_report_with_region, index=False, engine='openpyxl')

        # Generate Ring tags
        tagged_report = generate_ring_tags(str(enriched_report_with_region))

        print(f'Completed enrichment and tag generation. The full report can be found at {tagged_report}')
        return tagged_report

    except Exception as e:
        logger.error(f"Error in get_tanium_hosts_without_ring_tag: {e}")
        return f'Error: {e}'


def generate_ring_tags(filename: str) -> str:
    """Generate ring tags for a list of computers and export to Excel."""
    try:
        # Validate input file
        validate_input_file(filename)

        # Read the enriched data
        df = pd.read_excel(filename, dtype=str, engine='openpyxl')
        logger.info(f"Processing {len(df)} computers for ring tag generation")

        workstations = []
        servers = []

        # Convert DataFrame rows to Computer objects and classify them
        for index, row in df.iterrows():
            name = str(row.get('Hostname', '')).strip()
            if not name:
                logger.warning(f"Row {index}: Missing hostname, skipping")
                continue

            computer_id = str(row.get('ID', '')).strip()
            ip = str(row.get('IP Address', '')).strip()
            eid_last_seen = row.get('Last Seen')
            source = str(row.get('Source', '')).strip()
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
            setattr(computer, "region", str(row.get('Region', '')).strip())
            setattr(computer, "country", str(row.get('SNOW_country', '')).strip())
            setattr(computer, "environment", str(row.get('SNOW_environment', 'Production')).strip())
            setattr(computer, "category", str(row.get('SNOW_category', '')).strip())
            setattr(computer, "was_country_guessed", row.get('Was Country Guessed', False))
            setattr(computer, "new_tag", None)
            setattr(computer, "status", "")

            # Classify as server or workstation
            category = str(row.get('SNOW_category', '')).strip().lower()
            if category in ("server", "srv"):
                servers.append(computer)
            elif category == "workstation":
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
                current_tags = ", ".join(filtered_tags) if filtered_tags else ""

            computer_category = getattr(computer, "category", "")
            if computer_category.lower() == "workstation":
                computer_category = "Workstation"
            elif computer_category.lower() in ("server", "srv"):
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

    except Exception as e:
        logger.error(f"Error in generate_ring_tags: {e}")
        raise


def _process_workstations(workstations: List[Computer]) -> None:
    """Assign ring tags to workstations based on region and country."""
    region_country_groups = defaultdict(list)
    for ws in workstations:
        region = getattr(ws, "region", "")
        country = getattr(ws, "country", "")
        if region:
            region_country_groups[(region, country)].append(ws)

    for (region, country), ws_group in region_country_groups.items():
        total = len(ws_group)
        if total == 0:
            continue

        ring_sizes = calculate_ring_sizes(total)
        logger.debug(f"Region {region}, Country {country}: {total} workstations, ring sizes: {ring_sizes}")

        # Sort by last seen date (None/null values go to the end)
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
        env = _normalize_environment(getattr(server, "environment", ""))
        region = getattr(server, "region", "Unknown")

        if env in RING_1_ENVS:
            ring = 1
        elif env in RING_2_ENVS:
            ring = 2
        elif env in RING_3_ENVS:
            ring = 3
        else:  # production or unknown
            ring = 4

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
    """Enhanced country guessing with better fallback logic."""
    computer_name = computer.name.strip()
    if not computer_name:
        return '', 'Empty hostname'

    computer_name_lower = computer_name.lower()

    # Priority 1: Special prefixes
    if computer_name_lower.startswith('vmvdi'):
        return 'United States', "Country guessed from VMVDI prefix"

    if hasattr(CONFIG, 'team_name') and computer_name_lower.startswith(CONFIG.team_name.lower()):
        return 'United States', f"Country guessed from {CONFIG.team_name} prefix"

    # Priority 2: Country code from first 2 characters
    if len(computer_name) >= 2:
        country_code = computer_name[:2].upper()
        country_name = COUNTRY_NAMES_BY_CODE.get(country_code, '')
        if country_name:
            return country_name, f"Country code {country_code} from hostname"

    # Priority 3: Leading digit suggests Korea (based on current logic)
    if computer_name[0].isdigit():
        return 'Korea', "Country guessed from leading digit in hostname"

    # Priority 4: VM prefix with US tag validation
    if computer_name_lower.startswith('vm'):
        for tag in getattr(computer, 'custom_tags', []):
            tag_str = str(tag).upper()
            if 'US' in tag_str or 'SENSORGROUPTAGS/US' in tag_str:
                return 'United States', "Country guessed from VM prefix + US tag"

    # Priority 5: Check tags for country indicators
    for tag in getattr(computer, 'custom_tags', []):
        tag_upper = str(tag).upper()
        for code, name in COUNTRY_NAMES_BY_CODE.items():
            if code in tag_upper or name.upper() in tag_upper:
                return name, f"Country found in tag: {tag}"

    return '', 'No country indicators found'


def _append_status(computer: Computer, message: str) -> None:
    """Append a status message to a computer object."""
    if not message:
        return

    current_status = getattr(computer, "status", "")
    if current_status and message not in current_status:
        setattr(computer, "status", f"{current_status}; {message}")
    elif not current_status:
        setattr(computer, "status", message)


def main():
    """Main entry point."""
    try:
        result = get_tanium_hosts_without_ring_tag(filename="Tanium hosts without Ring tag.xlsx")
        logger.info(f"Process completed successfully: {result}")
    except Exception as e:
        logger.error(f"Process failed: {e}")
        raise


if __name__ == "__main__":
    main()
