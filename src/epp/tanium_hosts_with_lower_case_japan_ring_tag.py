from services.tanium import TaniumClient
from pathlib import Path
import pandas as pd
from datetime import datetime
from tqdm import tqdm


def get_tanium_hosts_with_japan_ring_tag():
    """
    Fetch all Tanium hosts with a tag starting with 'FalconGroupingTags/JapanWksRing'.
    Returns a list of host objects (dicts).
    """
    today = datetime.now().strftime('%m-%d-%Y')
    cached_path = Path('/Users/user/PycharmProjects/IR/data/transient/epp_device_tagging') / today / 'All Tanium Hosts.xlsx'
    output_path = Path('/Users/user/PycharmProjects/IR/data/transient/epp_device_tagging') / today / "Tanium Hosts with FalconGroupingTags_JapanWksRing*.xlsx"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if cached_path.exists():
        df = pd.read_excel(cached_path)
        filtered_hosts = []
        for _, row in df.iterrows():
            tags = str(row.get('Current Tags', ''))
            if any(tag.startswith('FalconGroupingTags/JapanWksRing') for tag in tags.split(', ')):
                filtered_hosts.append(row.to_dict())
        # Save filtered hosts to spreadsheet with formatting
        if filtered_hosts:
            out_df = pd.DataFrame(filtered_hosts)
        else:
            # If no results, use the columns from the original DataFrame if available
            if 'df' in locals() and hasattr(df, 'columns'):
                out_df = pd.DataFrame(columns=df.columns)
            else:
                out_df = pd.DataFrame()
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            out_df.to_excel(writer, index=False, sheet_name='Hosts')
            worksheet = writer.sheets['Hosts']
            # Bold header, freeze header, add filter, set column width
            from openpyxl.styles import Font
            if out_df.shape[1] > 0:
                for cell in worksheet[1]:
                    cell.font = Font(bold=True)
                worksheet.auto_filter.ref = worksheet.dimensions
                worksheet.freeze_panes = worksheet['A2']
                for col in worksheet.columns:
                    max_length = max(len(str(cell.value)) if cell.value else 0 for cell in col)
                    worksheet.column_dimensions[col[0].column_letter].width = min(max_length + 2, 50)
        return filtered_hosts
    else:
        client = TaniumClient()
        hosts = client.get_and_export_all_computers()
        filtered_hosts = []
        for host in tqdm(hosts, desc="Filtering hosts"):  # Show progress bar
            tags = getattr(host, 'custom_tags', [])
            if any(tag.startswith('FalconGroupingTags/JapanWksRing') for tag in tags):
                filtered_hosts.append(host)
        # Save filtered hosts to spreadsheet with formatting, even if empty
        out_df = pd.DataFrame(filtered_hosts)
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            out_df.to_excel(writer, index=False, sheet_name='Hosts')
            worksheet = writer.sheets['Hosts']
            from openpyxl.styles import Font
            if out_df.shape[1] > 0:
                for cell in worksheet[1]:
                    cell.font = Font(bold=True)
                worksheet.auto_filter.ref = worksheet.dimensions
                worksheet.freeze_panes = worksheet['A2']
                for col in worksheet.columns:
                    max_length = max(len(str(cell.value)) if cell.value else 0 for cell in col)
                    worksheet.column_dimensions[col[0].column_letter].width = min(max_length + 2, 50)
        return filtered_hosts


if __name__ == "__main__":
    hosts = get_tanium_hosts_with_japan_ring_tag()
    print(f"Found {len(hosts)} hosts with FalconGroupingTags/JapanWksRing* tag.")
    for host in hosts:
        print(getattr(host, 'name', host))
