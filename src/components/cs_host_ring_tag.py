from pathlib import Path
from typing import List, Dict

import pandas as pd
from tqdm import tqdm
from webexteamssdk import WebexTeamsAPI

from config import get_config
from services.service_now import ServiceNowClient

CONFIG = get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent.parent

webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


def send_report():
    """
    Sends a file to a Webex room.
    """
    file_to_send = '/Users/user/PycharmProjects/IR/data/transient/epp_device_tagging/enriched_unique_hosts_without_ring_tag.xlsx'
    host_count = len(pd.read_excel(file_to_send, engine="openpyxl"))
    webex_api.messages.create(
        roomId=CONFIG.webex_room_id_epp_tagging,
        text=f"UNIQUE CS hosts without a Ring tag, enriched with SNOW details. Count={host_count}!",
        files=[file_to_send]
    )


def get_unique_hosts_without_ring_tag():
    """
    Group the records by hostname, get the record with the latest last_seen for each group,
    and write these results to a new file unique_hosts.xlsx.
    """
    try:
        # Read the input file
        df = pd.read_excel(ROOT_DIRECTORY / "data/transient/epp_device_tagging/cs_hosts_without_ring_tag.xlsx", engine="openpyxl")

        # Convert last_seen to datetime for proper sorting
        df["last_seen"] = pd.to_datetime(df["last_seen"]).dt.tz_localize(None)

        # Group by hostname and get the record with the latest last_seen
        unique_hosts = df.loc[df.groupby("hostname")["last_seen"].idxmax()]

        # Write the results to a new file
        unique_hosts.to_excel(ROOT_DIRECTORY / "data/transient/epp_device_tagging/unique_hosts_without_ring_tag.xlsx", index=False, engine="openpyxl")

        print(f"Successfully wrote {len(unique_hosts)} unique hosts to unique_hosts_without_ring_tag.xlsx")
    except FileNotFoundError:
        print("Error: Input file not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def list_cs_hosts_without_ring_tag(input_xlsx_filename: str = ROOT_DIRECTORY / "data/transient/epp_device_tagging/all_cs_hosts.xlsx",
                                   output_xlsx_filename: str = ROOT_DIRECTORY / "data/transient/epp_device_tagging/cs_hosts_without_ring_tag.xlsx") -> None:
    """
    List CrowdStrike hosts that do not have a FalconGroupingTags/*Ring* tag.
    Read from all_cs_hosts.xlsx, filter hosts, and write the results to a new XLSX file.
    """
    hosts_without_ring_tag: List[Dict[str, str]] = []

    try:
        df = pd.read_excel(input_xlsx_filename, engine='openpyxl')
        for index, row in df.iterrows():
            current_tags = row["current_tags"]
            if isinstance(current_tags, str):
                tags = current_tags.split(", ")
            else:
                tags = []
            has_ring_tag = False
            for tag in tags:
                if tag.startswith("FalconGroupingTags/") and "Ring" in tag:
                    has_ring_tag = True
                    break
            if not has_ring_tag:
                hosts_without_ring_tag.append(row.to_dict())

        output_df = pd.DataFrame(hosts_without_ring_tag)
        output_df.to_excel(output_xlsx_filename, index=False, engine='openpyxl')

        print(f"Found {len(hosts_without_ring_tag)} hosts without a Ring tag.")
        print(f"Wrote results to {output_xlsx_filename}")

    except FileNotFoundError:
        print(f"Error: Input file {input_xlsx_filename} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def enrich_host_report():
    # get hosts from unique_hosts.xlsx
    unique_hosts_df = pd.read_excel(f"{ROOT_DIRECTORY}/data/transient/epp_device_tagging/unique_hosts_without_ring_tag.xlsx", engine="openpyxl")
    service_now = ServiceNowClient(CONFIG.snow_base_url, CONFIG.snow_functional_account_id, CONFIG.snow_functional_account_password, CONFIG.snow_client_key)
    # get device details from SNOW
    hostnames = unique_hosts_df['hostname'].tolist()
    device_details = []
    for hostname in tqdm(hostnames, desc="Enriching hosts..."):
        device_details.append(service_now.get_host_details(hostname))

    # create a new df with device details
    device_details_df = pd.json_normalize(device_details)

    # merge the two dataframes
    merged_df = pd.merge(unique_hosts_df, device_details_df, left_on='hostname', right_on='name', how='left')

    # save the merged df
    merged_df.to_excel(f"{ROOT_DIRECTORY}/data/transient/epp_device_tagging/enriched_unique_hosts_without_ring_tag.xlsx", index=False, engine="openpyxl")

    print(f"Successfully wrote {len(merged_df)} enriched unique hosts to enriched_unique_hosts.xlsx")


def main():
    # enrich_host_report()
    # list_cs_hosts_without_ring_tag()
    # get_unique_hosts_without_ring_tag()
    # enrich_host_report()
    send_report()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
