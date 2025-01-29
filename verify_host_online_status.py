import json
import time

import requests
import schedule

from config import get_config

offline_hosts_list_name: str = 'Offline_Hosts'

config = get_config()

xsoar_headers = {
    'Authorization': config.xsoar_auth_token,
    'x-xdr-auth-id': config.xsoar_auth_id,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}


def save(data, version):
    # write information back to Offline_Hosts list; "data" is what is to be written back to Offline_Hosts (in string form)
    api_url = config.xsoar_api_base_url + '/lists/save'

    response = requests.post(api_url, headers=xsoar_headers, json={
        "data": ','.join(data),
        "name": offline_hosts_list_name,
        "type": "plain_text",
        "id": offline_hosts_list_name,
        "version": version
    })

    # print(response.json())


def get_all_lists() -> list:
    api_url = config.xsoar_api_base_url + '/lists'
    return requests.get(api_url, headers=xsoar_headers).json()


def get_list_by_name(all_lists, list_name):
    list_contents = list(filter(lambda item: item['id'] == list_name, all_lists))[0]
    return list_contents['data'], list_contents['version']


def send_webex_notification(host_name, ticket_ID):
    # send Webex message to notify host is online
    incident_url = config.xsoar_ui_base_url + "/#/Custom/caseinfoid/" + ticket_ID
    webex_headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {config.webex_bot_access_token_xsoar}"
    }
    payload_json = {
        'roomId': config.webex_host_announcements_room_id,
        'markdown': f'Host {host_name} associated with ticket [#{ticket_ID}]({incident_url}) is back online'
    }
    requests.post(config.webex_api_url, headers=webex_headers, json=payload_json)


def get_access_token():
    """get CS access token"""
    url = 'https://api.us-2.crowdstrike.com/oauth2/token'
    body = {
        'client_id': config.cs_client_id,
        'client_secret': config.cs_client_secret
    }
    response = requests.post(url, data=body, verify=False)
    json_data = response.json()
    return json_data['access_token']


def get_device_id(host_name):
    """get CS asset ID"""
    url = 'https://api.us-2.crowdstrike.com/devices/queries/devices/v1?filter=hostname:' + '\'' + host_name + '\''
    headers = {
        'Authorization': f'Bearer {get_access_token()}'
    }
    response = requests.get(url, headers=headers, verify=False)
    json_data = response.json()
    return json_data['resources']


def get_device_online_status(host_name):
    """get device's online status in Crowd Strike"""
    url = 'https://api.us-2.crowdstrike.com/devices/entities/online-state/v1'
    headers = {
        'content-type': 'application/json',
        'Authorization': f'Bearer {get_access_token()}'
    }
    params = {
        "ids": get_device_id(host_name)
    }
    response = requests.get(url, headers=headers, params=params, verify=False)
    json_data = response.json()
    if 'resources' not in json_data:
        return
    return json_data['resources'][0]['state']


def start():
    try:
        print('Starting host online status verification....')
        all_lists: list = get_all_lists()
        online_hosts = []
        offline_hosts_data, offline_hosts_list_version = get_list_by_name(all_lists, offline_hosts_list_name)
        print(f'{offline_hosts_data=}, {offline_hosts_list_version=}')
        offline_hosts = offline_hosts_data.split(',')
        for host_name_ticket_ID in offline_hosts:
            if '-' in host_name_ticket_ID:
                host_name, ticket_ID = [item for item in host_name_ticket_ID.split('-')]
                status = get_device_online_status(host_name)  # crowdstrike API
                print(f'{host_name=}, {ticket_ID=}, {status=}')
                if status == "online":
                    send_webex_notification(host_name, ticket_ID)  # webex API
                    online_hosts.append(host_name_ticket_ID)
                elif status is None:
                    online_hosts.append(host_name_ticket_ID)

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
