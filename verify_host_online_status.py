import time

import requests
import schedule
from falconpy import OAuth2, Hosts
from webexteamssdk import WebexTeamsAPI

from config import get_config

offline_hosts_list_name: str = 'Offline_Hosts'

config = get_config()

xsoar_headers = {
    'Authorization': config.xsoar_auth_token,
    'x-xdr-auth-id': config.xsoar_auth_id,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Initialize FalconPy OAuth2 and Hosts
falcon = OAuth2(client_id=config.cs_ro_client_id, client_secret=config.cs_ro_client_secret)
hosts = Hosts(auth_object=falcon)


def save(data, version):
    api_url = config.xsoar_api_base_url + '/lists/save'
    requests.post(api_url, headers=xsoar_headers, json={
        "data": ','.join(data),
        "name": offline_hosts_list_name,
        "type": "plain_text",
        "id": offline_hosts_list_name,
        "version": version
    })


def get_all_lists() -> list:
    api_url = config.xsoar_api_base_url + '/lists'
    return requests.get(api_url, headers=xsoar_headers).json()


def get_list_by_name(all_lists, list_name):
    list_contents = list(filter(lambda item: item['id'] == list_name, all_lists))[0]
    return list_contents['data'], list_contents['version']


def send_webex_notification(host_name, ticket_id):
    incident_url = config.xsoar_ui_base_url + "/#/Custom/caseinfoid/" + ticket_id
    webex_teams_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_soar)
    webex_teams_api.messages.create(
        roomId=config.webex_host_announcements_room_id,
        markdown=f'Host {host_name} associated with ticket [#{ticket_id}]({incident_url}) is now online'
    )


def get_device_id(host_name):
    response = hosts.QueryDevicesByFilter(filter=f"hostname:'{host_name}'")
    return response['resources']


def get_device_online_status(host_name):
    device_ids = get_device_id(host_name)
    if not device_ids:
        return None
    response = hosts.GetDeviceDetails(ids=device_ids)
    if 'resources' not in response:
        return None
    return response['resources'][0]['state']


def start():
    try:
        all_lists: list = get_all_lists()
        online_hosts = []
        offline_hosts_data, offline_hosts_list_version = get_list_by_name(all_lists, offline_hosts_list_name)
        offline_hosts = offline_hosts_data.split(',')
        for host_name_ticket_id in offline_hosts:
            if '-' in host_name_ticket_id:
                host_name, ticket_id = [item for item in host_name_ticket_id.split('-')]
                status = get_device_online_status(host_name)
                if status == "online":
                    send_webex_notification(host_name, ticket_id)
                    online_hosts.append(host_name_ticket_id)
                elif status is None:
                    online_hosts.append(host_name_ticket_id)

        if len(online_hosts) > 0:
            save(list(set(offline_hosts).difference(online_hosts)), offline_hosts_list_version)

    except Exception as ex:
        print(f"There was an issue in the VerifyHostOnlineStatus integration. Error: {str(ex)}")


def main():
    schedule.every(5).minutes.do(start)
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
