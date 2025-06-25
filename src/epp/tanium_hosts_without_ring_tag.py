import logging
from datetime import datetime
from pathlib import Path

import openpyxl

from services.service_now import enrich_host_report
from services.tanium import Computer, TaniumClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def get_and_export_computers_without_ring_tag(filename) -> str:
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
        all_computers.append(
            Computer(
                name=row[0],
                id=row[1],
                ip=row[2],
                eidLastSeen=row[3],
                source=row[4],
                custom_tags=[tag.strip() for tag in row[5].split(',')] if row[5] else []
            )
        )

    if not all_computers:
        logger.warning("No computers retrieved from any instance!")
        return 'No computers retrieved from any instance!'
    computers_without_ecm_tag = [c for c in all_computers if not c.has_epp_ring_tag()]
    return client.export_to_excel(computers_without_ecm_tag, filename)


def main():
    try:
        filename = get_and_export_computers_without_ring_tag(filename="Tanium hosts without Ring tag.xlsx")
        host_count = 0
        try:
            # Try to count the number of hosts in the Excel file
            import pandas as pd
            df = pd.read_excel(filename)
            host_count = len(df)
        except Exception as e:
            logger.warning(f"Could not count hosts in file: {e}")

        print(f'Found {host_count} Tanium hosts without ring tag')
        print('Starting enrichment of these hosts with ServiceNow data')
        enriched_report = enrich_host_report(filename)
        print(f'Completed enrichment. The full report can be found at {enriched_report}')
    except Exception as e:
        logger.error(f"Error during enrichment: {e}")
        # Continue execution, don't abort the entire process due to enrichment errors


if __name__ == "__main__":
    main()
