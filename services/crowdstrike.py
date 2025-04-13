import time
from typing import List, Dict

import pandas as pd
import requests
from falconpy import Hosts
from falconpy import OAuth2
from webexteamssdk import WebexTeamsAPI

from config import get_config

CONFIG = get_config()
falcon_auth = OAuth2(
    client_id=CONFIG.cs_ro_client_id,
    client_secret=CONFIG.cs_ro_client_secret,
    base_url="api.us-2.crowdstrike.com",
    ssl_verify=False,
)
falcon_hosts = Hosts(auth_object=falcon_auth)

# webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


def fetch_all_hosts_and_write_to_xlsx(xlsx_filename: str = "all_cs_hosts.xlsx") -> None:
    """
    Fetches all hosts from CrowdStrike Falcon and writes their details (hostname, host ID, current tags) to an XLSX file.

    Args:
        xlsx_filename (str): The name of the XLSX file to write to. Defaults to "all_cs_hosts.xlsx".
    """

    all_host_data: List[Dict[str, str]] = []
    offset: str | None = None
    limit: int = 5000  # Maximum allowed by the API

    print("Fetching ALL host data...")
    start_time = time.time()

    try:
        while True:
            response = falcon_hosts.query_devices_by_filter_scroll(
                limit=limit, offset=offset
            )

            if response["status_code"] == 200:
                host_ids = response["body"].get("resources", [])
                if not host_ids:
                    break

                # Get details for each host ID
                details_response = falcon_hosts.get_device_details(ids=host_ids)
                if details_response["status_code"] == 200:
                    host_details = details_response["body"].get("resources", [])
                    for host in host_details:
                        all_host_data.append(
                            {
                                "hostname": host.get("hostname"),
                                "host_id": host.get("device_id"),
                                "current_tags": ", ".join(host.get("tags", [])),
                                "last_seen": host.get("last_seen"),
                                "status": host.get("status"),
                                "chassis_type_desc": host.get("chassis_type_desc"),
                            }
                        )
                else:
                    print(
                        f"Error retrieving details for host IDs: {details_response}"
                    )
                    break

                offset = (
                    response["body"]
                    .get("meta", {})
                    .get("pagination", {})
                    .get("offset")
                )
                if not offset:
                    break  # No more pages
            else:
                print(f"Error retrieving host IDs: {response}")
                break

    except Exception as e:
        print(f"An error occurred: {e}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Finished fetching host data in {elapsed_time:.2f} seconds.")

    print(f"Writing host data to {xlsx_filename}...")
    try:
        df = pd.DataFrame(all_host_data)
        df.to_excel('../data/transient/epp_device_tagging/' + xlsx_filename, index=False, engine='openpyxl')
        print(
            f"Successfully wrote {len(all_host_data)} host records to {xlsx_filename}"
        )
    except Exception as e:
        print(f"An error occurred while writing to XLSX: {e}")


def get_device_id(hostname):
    """Retrieve the first device ID matching the filter."""
    host_filter = f"hostname:'{hostname}'"
    response = falcon_hosts.query_devices_by_filter(filter=host_filter, sort='last_seen.desc', limit=1)

    if response.get("status_code") == 200:
        devices = response["body"].get("resources", [])
        if devices:
            return devices[0]  # Return the first matching device ID
        print(f"No devices found for filter: {host_filter}")
    else:
        print(f"Error getting device ID: {response.get('status_code')}, {response.get('body', {}).get('errors')}")

    return None


def get_device_details(device_id):
    """Retrieve device details."""
    return falcon_hosts.get_device_details(ids=device_id)


def get_access_token():
    """get CS access token"""
    url = 'https://api.us-2.crowdstrike.com/oauth2/token'
    body = {
        'client_id': CONFIG.cs_ro_client_id,
        'client_secret': CONFIG.cs_ro_client_secret
    }
    response = requests.post(url, data=body)
    json_data = response.json()
    return json_data['access_token']


def get_device_id_api(host_name):
    """get CS asset ID"""
    url = 'https://api.us-2.crowdstrike.com/devices/queries/devices/v1?filter=hostname:' + '\'' + host_name + '\''
    headers = {
        'Authorization': f'Bearer {get_access_token()}'
    }
    response = requests.get(url, headers=headers, verify=False)
    json_data = response.json()
    return json_data['resources'][0]


def get_device_status_api(host_name):
    """get device containment status"""
    url = 'https://api.us-2.crowdstrike.com/devices/entities/devices/v1'
    headers = {
        'content-type': 'application/json',
        'Authorization': f'Bearer {get_access_token()}'
    }
    params = {
        "ids": get_device_id(host_name)
    }
    response = requests.get(url, headers=headers, params=params)
    json_data = response.json()
    return json_data['resources'][0]['status']


def main() -> None:
    print(get_device_id('EGCAI1METJMP01'))


if __name__ == "__main__":
    main()
