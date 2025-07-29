import json
import logging.config
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


def get_tanium_hosts_without_ring_tag(filename, test_limit=None) -> str:
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
        wb = None
        error_message = None

        try:
            wb = openpyxl.load_workbook(all_hosts_filename, read_only=True, data_only=True)
            ws = wb.active

            for row_num, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                if not row:
                    continue

                # Ensure row has enough elements for direct indexing up to index 5 (6 columns)
                if len(row) < 6:
                    logger.warning(f"Row {row_num}: Insufficient columns ({len(row)}/6 expected), skipping. Row: {row}")
                    continue

                # Validate critical fields before creating Computer object
                if not row[0]:  # name is required
                    logger.warning(f"Row {row_num}: Missing computer name, skipping. Row: {row}")
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
            error_message = f'Error reading Excel file: {e}'
        finally:
            if wb is not None:
                try:
                    wb.close()
                except:
                    pass

        # Return error after cleanup if one occurred
        if error_message:
            return error_message

        if not all_computers:
            logger.warning("No valid computers retrieved from any instance!")
            return 'No valid computers retrieved from any instance!'

        logger.info(f"Successfully loaded {len(all_computers)} computers from Tanium")

        # Filter computers without ring tag and apply the test_limit
        filtered_computers_without_ring_tag = [c for c in all_computers if not c.has_epp_ring_tag()]
        if test_limit is not None and test_limit > 0:
            computers_without_ring_tag = filtered_computers_without_ring_tag[:test_limit]
            print(f'Found {len(filtered_computers_without_ring_tag)} Tanium hosts without ring tag, limiting to {len(computers_without_ring_tag)} for test.')
        else:
            computers_without_ring_tag = filtered_computers_without_ring_tag
            print(f'Found {len(computers_without_ring_tag)} Tanium hosts without ring tag')

        computers_without_ring_tag_filename = client.export_to_excel(computers_without_ring_tag, filename)

        print('Starting enrichment of these hosts with ServiceNow data')

        enriched_report_from_service_now = enrich_host_report(computers_without_ring_tag_filename)

        # Load the report that has been enriched by ServiceNow.
        # This df_enriched will have SNOW_ prefixed columns, and SNOW_country will be blank if it was 'nan'.
        df_enriched = pd.read_excel(enriched_report_from_service_now, dtype=str, engine='openpyxl')

        # Initialize 'Region' and 'Was Country Guessed' columns in df_enriched
        # If 'Country' column already exists from the Tanium export, this will overwrite it.
        # If not, it will create it.
        # Ensure 'Country' column is of type object to hold strings
        if 'Country' not in df_enriched.columns:
            df_enriched['Country'] = ''
        else:
            # Clean 'nan' from the existing 'Country' column directly when loading, if it originated from Tanium
            df_enriched['Country'] = df_enriched['Country'].apply(lambda x: '' if pd.isna(x) or str(x).lower() == 'nan' else str(x))

        df_enriched['Region'] = ''  # Initialize Region column
        df_enriched['Was Country Guessed'] = 'No'  # Initialize as 'No' string

        debug_sample_size = min(10, len(df_enriched))
        print(f"\n=== DEBUGGING FIRST {debug_sample_size} ROWS ===")
        for index, row in df_enriched.head(debug_sample_size).iterrows():
            country_from_snow = row.get('SNOW_country')
            hostname = row.get('Hostname')
            if hostname:
                dummy_computer = Computer(name=hostname, id="", ip="", eidLastSeen="", source="")
                guessed_country, explanation = _guess_country_from_hostname(dummy_computer)
                print(f"  would guess: '{guessed_country}' ({explanation})")

        # Process each row for country and region assignment and update Computer objects and df_enriched
        for index, row in df_enriched.iterrows():
            country_from_snow = row.get('SNOW_country')  # This will be blank if service_now.py cleared 'nan'
            hostname = row.get('Hostname')
            tanium_id = row.get('ID')  # Get Tanium ID to find the correct Computer object

            country_to_use = None
            was_country_guessed = False
            determined_region = ''

            # Logic to determine the country to use (SNOW > Guessed)
            if is_valid_country(country_from_snow):
                country_to_use = country_from_snow
            elif hostname and str(hostname).strip():
                dummy_computer = Computer(name=str(hostname), id="", ip="", eidLastSeen="", source="")
                guessed_country, _ = _guess_country_from_hostname(dummy_computer)
                if guessed_country and is_valid_country(guessed_country):  # Ensure guessed country is valid
                    country_to_use = guessed_country
                    was_country_guessed = True

            # Determine region based on country_to_use
            if country_to_use:
                determined_region = REGIONS_BY_COUNTRY.get(country_to_use, '')

            # Find the corresponding Computer object in the list that will be passed to generate_ring_tags
            computer = next((c for c in computers_without_ring_tag if c.id == tanium_id), None)

            if computer:
                # Update the DATAFRAME `df_enriched` columns
                # These columns will be saved to the intermediate Excel file
                df_enriched.at[index, 'Country'] = country_to_use if country_to_use else ''
                df_enriched.at[index, 'Region'] = determined_region
                df_enriched.at[index, 'Was Country Guessed'] = 'Yes' if was_country_guessed else 'No'

                # Also update the Computer OBJECT's attributes directly
                # These attributes are what `generate_ring_tags` will read when it iterates over `computers_without_ring_tag`
                computer.category = row.get('SNOW_category', '')
                computer.environment = row.get('SNOW_environment', '')
                computer.country = country_to_use if country_to_use else ''  # CRITICAL FIX: Set Computer object's country
                computer.region = determined_region  # Set region on the Computer object
                computer.was_country_guessed = was_country_guessed  # Set was_country_guessed on the Computer object

                # Ensure initial SNOW comments are transferred to the Computer object's status
                # If 'SNOW_comments' doesn't exist or is empty, ensure computer.status is initialized.
                if 'SNOW_comments' in row and row['SNOW_comments'] and str(row['SNOW_comments']).lower() != 'nan':
                    computer.status = str(row['SNOW_comments'])
                elif not hasattr(computer, 'status') or computer.status is None:
                    computer.status = ''  # Initialize if no valid SNOW comments
            else:
                logger.warning(f"Could not find Computer object for Tanium ID: {tanium_id} in list for enrichment updates.")

        # Save the DataFrame with the new 'Country', 'Region', 'Was Country Guessed' columns
        # This Excel file is what generate_ring_tags will read.
        enriched_report_with_region = Path(enriched_report_from_service_now).parent / "Tanium hosts without ring tag - enriched with SNOW data.xlsx"
        df_enriched.to_excel(enriched_report_with_region, index=False, engine='openpyxl')

        # Generate Ring tags
        # generate_ring_tags reads the Excel file, but also relies on the Computer objects
        # if it's designed to iterate over them directly.
        # The key is that the Excel file now has the correct 'Country' and 'Was Country Guessed' columns.
        tagged_report = generate_ring_tags(str(enriched_report_with_region))

        print(f'Completed enrichment and tag generation. The full report can be found at {tagged_report}')
        return tagged_report

    except Exception as e:
        logger.error(f"Error in get_tanium_hosts_without_ring_tag: {e}", exc_info=True)
        return f'Error: {e}'


def generate_ring_tags(filename: str) -> str:
    """Generate ring tags for a list of computers and export to Excel."""
    try:
        # Validate input file
        validate_input_file(filename)

        # Read the enriched data
        # This df should contain the 'Country', 'Region', 'Was Country Guessed' columns
        # correctly populated by get_tanium_hosts_without_ring_tag.
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

            # --- CRITICAL CORRECTIONS HERE ---
            # Use the 'Country' column from the DataFrame, which should now contain the guessed country or SNOW country
            setattr(computer, "country", str(row.get('Country', '')).strip())  # Use 'Country', NOT 'SNOW_country'

            # Use the 'Region' column from the DataFrame
            setattr(computer, "region", str(row.get('Region', '')).strip())

            # Use the 'SNOW_environment' and 'SNOW_category' for environment and category
            # FIX: Clean up nan values for environment
            environment_value = str(row.get('SNOW_environment', '')).strip()
            if environment_value.lower() in ['nan', 'none', 'null', '']:
                environment_value = ''  # No default, just empty
            setattr(computer, "environment", environment_value)

            setattr(computer, "category", str(row.get('SNOW_category', '')).strip())

            # Use the 'Was Country Guessed' column from the DataFrame and convert to boolean
            was_guessed_str = str(row.get('Was Country Guessed', 'No')).strip().lower()
            setattr(computer, "was_country_guessed", was_guessed_str == 'yes')  # Convert 'Yes'/'No' string to boolean

            setattr(computer, "new_tag", None)

            # Initialize status from SNOW_comments if available and not 'nan'
            snow_comments = str(row.get('SNOW_comments', '')).strip()
            if snow_comments.lower() == 'nan':
                setattr(computer, "status", "")
            else:
                setattr(computer, "status", snow_comments)

            # Classify as server or workstation
            category = getattr(computer, "category", "").strip().lower()  # Use the category just set on computer object
            if category in ("server", "srv"):
                servers.append(computer)
            elif category == "workstation":
                workstations.append(computer)
            else:
                _append_status(computer, "Category missing or unknown - skipping")

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

            # Determine the base comment based on tag generation status
            if not region:
                new_tag = None
                _append_status(computer, "Region missing. Ring tag couldn't be generated")
            elif new_tag:
                _append_status(computer, "Ring tag generated successfully")

            # Now, append the "Country was guessed" message if applicable
            if getattr(computer, "was_country_guessed", False):  # This attribute is now a boolean
                # Only append if it's not already part of the status (case-insensitive check)
                if "country was guessed" not in getattr(computer, "status", "").lower():
                    _append_status(computer, "Country was guessed")

            # FIX: Clean up environment value for display
            environment_display = getattr(computer, "environment", "")
            if environment_display.lower() in ['nan', 'none', 'null']:
                environment_display = ""  # Show empty instead of nan

            output_ws.append([
                computer.name,
                computer.id,
                computer_category,
                environment_display,  # Use cleaned environment value
                getattr(computer, "country", ""),  # This is now correctly populated from the 'Country' column of the intermediate DF
                region,
                "Yes" if getattr(computer, "was_country_guessed", False) else "No",  # This correctly converts boolean back to string "Yes"/"No"
                current_tags,
                new_tag,
                getattr(computer, "status", "")  # Directly use the computer's consolidated status
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
        result = get_tanium_hosts_without_ring_tag(filename="Tanium hosts without Ring tag.xlsx", test_limit=10)
        logger.info(f"Process completed successfully: {result}")
    except Exception as e:
        logger.error(f"Process failed: {e}")
        raise


if __name__ == "__main__":
    main()
