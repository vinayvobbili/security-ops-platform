import logging
from typing import List, Dict, Any

import pandas as pd

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the relevant region sheets (excluding informational sheets)
REGION_SHEETS = [
    'China', 'Russia', 'North Korea', 'Iran', 'Israel', 'NATO',
    'Middle East', 'Other Actors', 'Unknown / Unmapped Actors'
]

# Define columns that are NOT company names (these are metadata columns)
NON_COMPANY_COLUMNS = [
    'Operation 1', 'Operation 2', 'Operation 3', 'Operation 4', 'Operation 5',
    'Media Operated', 'Continent', 'Country', 'Sources', 'Comments', 'Notes',
    'Active', 'Status', 'First Seen', 'Last Seen', 'Attribution', 'Confidence',
    'Targets', 'Sectors', 'Geography', 'Malware', 'Tools', 'TTPs'
]


def is_company_column(column_name: str) -> bool:
    """
    Check if a column header represents a company name (not metadata).

    Args:
        column_name (str): The column header to check.

    Returns:
        bool: True if it's a company column, False if it's metadata.
    """
    if not column_name or not str(column_name).strip():
        return False

    column_name = str(column_name).strip()

    # Check if it's in the list of known non-company columns or contains "Link"
    if any(keyword.lower() in column_name.lower() for keyword in NON_COMPANY_COLUMNS):
        return False

    # NEW RULE: Exclude columns containing "Link" (case-insensitive)
    if "link" in column_name.lower():
        return False

    # Additional heuristics for non-company columns
    if any(keyword in column_name.lower() for keyword in [
        'operation', 'media', 'continent', 'country', 'source', 'comment',
        'note', 'active', 'status', 'seen', 'attribution', 'confidence',
        'target', 'sector', 'geography', 'malware', 'tool', 'ttp',  # Ensure 'link' is not here to avoid redundancy with new rule
    ]):
        return False

    return True


def get_company_columns(df: pd.DataFrame) -> Dict[int, str]:
    """
    Extract company columns from the header row, excluding metadata columns.

    Args:
        df (pd.DataFrame): The sheet dataframe.

    Returns:
        Dict[int, str]: Dictionary mapping column index to company name.
    """
    company_columns = {}

    # Row 2 (index 1) contains headers starting from column B
    for col_idx in range(1, len(df.columns)):
        header = df.iloc[1, col_idx]
        if pd.notna(header) and str(header).strip():
            header_str = str(header).strip()
            if is_company_column(header_str):
                company_columns[col_idx] = header_str

    return company_columns


def is_region_sheet(sheet_name: str) -> bool:
    """
    Check if a sheet is a region sheet containing APT data.

    Args:
        sheet_name (str): Name of the sheet to check.

    Returns:
        bool: True if it's a region sheet, False otherwise.
    """
    return sheet_name in REGION_SHEETS


def validate_sheet_structure(df: pd.DataFrame) -> bool:
    """
    Validate that a sheet has the expected structure with 'Common Name' in A2.

    Args:
        df (pd.DataFrame): DataFrame to validate.

    Returns:
        bool: True if structure is valid, False otherwise.
    """
    if len(df) < 3:  # Need at least 3 rows (region, headers, data)
        return False

    # Check if A2 contains 'Common Name' (case-insensitive)
    if pd.notna(df.iloc[1, 0]) and 'common name' in str(df.iloc[1, 0]).lower():
        return True

    return False


def get_workbook_info(file_path: str = '../../data/transient/de/APTAKAcleaned.xlsx') -> Dict[str, Any]:
    """
    Get information about the workbook structure, focusing only on region sheets.

    Args:
        file_path (str): Path to the Excel file.

    Returns:
        Dict[str, Any]: Workbook information including sheet names and structure.
    """
    try:
        xl = pd.ExcelFile(file_path)
        workbook_info = {
            'total_sheets': len(xl.sheet_names),
            'all_sheet_names': xl.sheet_names,
            'region_sheets': [],
            'skipped_sheets': [],
            'regions': [],
            'companies': set()
        }

        # Analyze each sheet structure
        for sheet_name in xl.sheet_names:
            try:
                # Skip non-region sheets
                if not is_region_sheet(sheet_name):
                    workbook_info['skipped_sheets'].append(sheet_name)
                    continue

                df = xl.parse(sheet_name, header=None)  # Don't use header row

                # Validate sheet structure
                if not validate_sheet_structure(df):
                    logger.warning(f"Sheet '{sheet_name}' doesn't have expected structure, skipping...")
                    workbook_info['skipped_sheets'].append(sheet_name)
                    continue

                workbook_info['region_sheets'].append(sheet_name)

                # A1 should be the region name
                region_name = df.iloc[0, 0] if pd.notna(df.iloc[0, 0]) else sheet_name
                workbook_info['regions'].append(region_name)

                # Get company columns (excluding metadata columns)
                company_columns = get_company_columns(df)
                company_names = list(company_columns.values())
                workbook_info['companies'].update(company_names)

            except Exception as e:
                logger.error(f"Error analyzing sheet '{sheet_name}': {str(e)}")
                workbook_info['skipped_sheets'].append(sheet_name)
                continue

        workbook_info['companies'] = sorted(list(workbook_info['companies']))
        return workbook_info

    except Exception as e:
        logger.error(f"Error reading workbook: {str(e)}")
        return {'error': str(e)}


def get_other_names_for_common_name(common_name: str,
                                    file_path: str = '../../data/transient/de/APTAKAcleaned.xlsx',
                                    should_include_metadata: bool = False) -> List[Dict[str, Any]]:
    """
    Searches only region sheets for the given common name and returns alternative names.

    Args:
        common_name (str): The common name to search for (case-insensitive).
        file_path (str): Path to the Excel file.
        should_include_metadata (bool): Whether to include additional metadata in results.

    Returns:
        List[Dict[str, Any]]: List of dictionaries containing match information.
    """
    try:
        xl = pd.ExcelFile(file_path)
        results = []

        region_sheets = [sheet for sheet in xl.sheet_names if is_region_sheet(sheet)]
        logger.info(f"Searching for '{common_name}' in {len(region_sheets)} region sheets")

        for sheet_name in region_sheets:
            try:
                df = xl.parse(sheet_name, header=None)  # Don't use header row

                # Validate sheet structure
                if not validate_sheet_structure(df):
                    logger.warning(f"Sheet '{sheet_name}' doesn't have expected structure, skipping...")
                    continue

                # Get region name from A1
                region_name = df.iloc[0, 0] if pd.notna(df.iloc[0, 0]) else sheet_name

                # Get company columns (excluding metadata columns)
                company_columns = get_company_columns(df)
                company_names = list(company_columns.values())

                # Search in data rows (starting from row 3, index 2)
                data_rows = df.iloc[2:]

                for idx, row in data_rows.iterrows():
                    # Check if column A (common name) matches
                    if pd.notna(row.iloc[0]) and str(row.iloc[0]).strip().lower() == common_name.lower():

                        # Collect alternative names from company columns only
                        alternative_names = {}
                        for col_idx, company in company_columns.items():
                            if col_idx < len(row):
                                alt_name = row.iloc[col_idx]
                                if pd.notna(alt_name) and str(alt_name).strip():
                                    alternative_names[company] = str(alt_name).strip()

                        result = {
                            'region': region_name,
                            'sheet_name': sheet_name,
                            'common_name': str(row.iloc[0]).strip(),
                            'alternative_names': alternative_names,
                            'total_alternatives': len(alternative_names)
                        }

                        if should_include_metadata:
                            result['row_index'] = idx
                            result['companies_in_sheet'] = ', '.join(company_names)
                            result['all_company_columns'] = company_columns
                            result['all_row_data'] = ', '.join([str(cell) if pd.notna(cell) else 'N/A' for cell in list(row)])

                        results.append(result)

            except Exception as e:
                logger.error(f"Error processing sheet '{sheet_name}': {str(e)}")
                continue

        logger.info(f"Found {len(results)} matches for '{common_name}'")
        return results

    except Exception as e:
        logger.error(f"Error reading file: {str(e)}")
        return []


def search_by_company_name(company_name: str,
                           alt_name: str,
                           file_path: str = '../../data/transient/de/APTAKAcleaned.xlsx') -> List[Dict[str, Any]]:
    """
    Search for APT groups by a specific company's alternative name in region sheets only.

    Args:
        company_name (str): The company name (e.g., "CrowdStrike", "Talos Group").
        alt_name (str): The alternative name used by that company.
        file_path (str): Path to the Excel file.

    Returns:
        List[Dict[str, Any]]: List of matches.
    """
    try:
        xl = pd.ExcelFile(file_path)
        results = []

        region_sheets = [sheet for sheet in xl.sheet_names if is_region_sheet(sheet)]

        for sheet_name in region_sheets:
            try:
                df = xl.parse(sheet_name, header=None)

                # Validate sheet structure
                if not validate_sheet_structure(df):
                    continue

                region_name = df.iloc[0, 0] if pd.notna(df.iloc[0, 0]) else sheet_name

                # Get company columns (excluding metadata columns)
                company_columns = get_company_columns(df)

                # Find the company column
                company_col_idx = None
                for col_idx, company in company_columns.items():
                    if company.lower() == company_name.lower():
                        company_col_idx = col_idx
                        break

                if company_col_idx is None:
                    continue

                # Search in that company's column
                data_rows = df.iloc[2:]
                for idx, row in data_rows.iterrows():
                    if (company_col_idx < len(row) and
                            pd.notna(row.iloc[company_col_idx]) and
                            str(row.iloc[company_col_idx]).strip().lower() == alt_name.lower()):
                        common_name = str(row.iloc[0]).strip() if pd.notna(row.iloc[0]) else 'N/A'

                        results.append({
                            'region': region_name,
                            'sheet_name': sheet_name,
                            'common_name': common_name,
                            'company': company_name,
                            'alternative_name': str(row.iloc[company_col_idx]).strip(),
                            'row_index': idx
                        })

            except Exception as e:
                logger.error(f"Error processing sheet '{sheet_name}': {str(e)}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error searching: {str(e)}")
        return []


def get_all_apt_groups_by_region(file_path: str = '../../data/transient/de/APTAKAcleaned.xlsx') -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all APT groups organized by region, processing only region sheets.

    Args:
        file_path (str): Path to the Excel file.

    Returns:
        Dict[str, List[Dict[str, Any]]]: Dictionary with regions as keys and APT groups as values.
    """
    try:
        xl = pd.ExcelFile(file_path)
        regional_groups = {}

        region_sheets = [sheet for sheet in xl.sheet_names if is_region_sheet(sheet)]

        for sheet_name in region_sheets:
            try:
                df = xl.parse(sheet_name, header=None)

                # Validate sheet structure
                if not validate_sheet_structure(df):
                    continue

                region_name = df.iloc[0, 0] if pd.notna(df.iloc[0, 0]) else sheet_name

                # Get company columns (excluding metadata columns)
                company_columns = get_company_columns(df)

                # Get APT groups
                apt_groups = []
                data_rows = df.iloc[2:]

                for idx, row in data_rows.iterrows():
                    if pd.notna(row.iloc[0]) and str(row.iloc[0]).strip():

                        # Collect alternative names from company columns only
                        alternative_names = {}
                        for col_idx, company in company_columns.items():
                            if col_idx < len(row):
                                alt_name = row.iloc[col_idx]
                                if pd.notna(alt_name) and str(alt_name).strip():
                                    alternative_names[company] = str(alt_name).strip()

                        apt_groups.append({
                            'common_name': str(row.iloc[0]).strip(),
                            'alternative_names': alternative_names,
                            'total_alternatives': len(alternative_names)
                        })

                regional_groups[region_name] = apt_groups

            except Exception as e:
                logger.error(f"Error processing sheet '{sheet_name}': {str(e)}")
                continue

        return regional_groups

    except Exception as e:
        logger.error(f"Error reading file: {str(e)}")
        return {}


def print_workbook_summary(file_path: str = '../../data/transient/de/APTAKAcleaned.xlsx'):
    """
    Print a comprehensive summary of the workbook, focusing only on region sheets.

    Args:
        file_path (str): Path to the Excel file.
    """
    print("=" * 70)
    print("APT WORKBOOK SUMMARY (REGION SHEETS ONLY)")
    print("=" * 70)

    try:
        xl = pd.ExcelFile(file_path)
        print(f"All sheets in workbook: {xl.sheet_names}")
        print(f"Expected region sheets: {REGION_SHEETS}")
        print()
    except Exception as e:
        print(f"Error reading workbook for initial check: {str(e)}")
        return

    # Get workbook info
    workbook_info = get_workbook_info(file_path)

    if 'error' in workbook_info:
        print(f"Error: {workbook_info['error']}")
        return

    print(f"Total Sheets in Workbook: {workbook_info['total_sheets']}")
    print(f"Region Sheets Processed: {len(workbook_info['region_sheets'])}")
    print(f"Skipped Sheets: {len(workbook_info['skipped_sheets'])}")
    print(f"Regions: {', '.join(workbook_info['regions'])}")
    print(f"Companies: {len(workbook_info['companies'])}")

    if workbook_info['skipped_sheets']:
        print(f"\nSkipped Sheets: {', '.join(workbook_info['skipped_sheets'])}")

    if workbook_info['region_sheets']:
        print(f"\nProcessed Region Sheets: {', '.join(workbook_info['region_sheets'])}")

    print("\n" + "=" * 40)
    print("COMPANIES TRACKING APT GROUPS:")
    print("=" * 40)
    for i, company in enumerate(workbook_info['companies'], 1):
        print(f"{i:2d}. {company}")

    # Get regional breakdown
    regional_groups = get_all_apt_groups_by_region(file_path)

    print("\n" + "=" * 40)
    print("APT GROUPS BY REGION:")
    print("=" * 40)

    total_apt_groups = 0
    for region, groups in regional_groups.items():
        print(f"\n🌍 {region}: {len(groups)} APT groups")
        total_apt_groups += len(groups)

        # Show first few groups as examples
        for group in groups[:3]:
            alt_count = group['total_alternatives']
            print(f"   • {group['common_name']} ({alt_count} alternative names)")

        if len(groups) > 3:
            print(f"   ... and {len(groups) - 3} more")

    print(f"\n📊 Total APT Groups: {total_apt_groups}")


# Example usage and testing
if __name__ == "__main__":
    file_path = '../../data/transient/de/APTAKAcleaned.xlsx'

    print("=== WORKBOOK SUMMARY ===")
    print_workbook_summary(file_path)

    apt_group = 'APT2'
    print(f"\n=== TESTING: Search for {apt_group} ===")
    results = get_other_names_for_common_name(apt_group, file_path, should_include_metadata=True)

    for result in results:
        print(f"\n🎯 Found {apt_group} in {result['region']} region:")
        print(f"   Common Name: {result['common_name']}")
        print(f"   Alternative Names ({result['total_alternatives']}):")
        for company, alt_name in result['alternative_names'].items():
            print(f"     • {company}: {alt_name}")

    print("\n=== TESTING: Search by company name ===")
    company_results = search_by_company_name("CrowdStrike", "Comment Crew", file_path)

    for result in company_results:
        print(f"\n🔍 CrowdStrike calls '{result['common_name']}' -> '{result['alternative_name']}' ({result['region']})")

    print("\n=== TESTING: Get workbook info ===")
    info = get_workbook_info(file_path)
    print(f"Found {len(info['companies'])} companies across {len(info['regions'])} regions")
    print(f"Processed {len(info['region_sheets'])} region sheets, skipped {len(info['skipped_sheets'])} non-region sheets")
