from falconpy import OAuth2, Hosts
from webexteamssdk import WebexTeamsAPI

from config import get_config
from services.xsoar import ListHandler

offline_hosts_list_name: str = 'Offline_Hosts'

config = get_config()

xsoar_headers = {
    'Authorization': config.xsoar_prod_auth_key,
    'x-xdr-auth-id': config.xsoar_prod_auth_id,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Initialize FalconPy OAuth2 and Hosts
falcon = OAuth2(client_id=config.cs_ro_client_id, client_secret=config.cs_ro_client_secret)
hosts = Hosts(auth_object=falcon)

list_handler = ListHandler()


def send_webex_notification(host_name, ticket_id):
    incident_url = config.xsoar_prod_ui_base_url + "/#/Custom/caseinfoid/" + ticket_id
    webex_teams_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_soar)
    webex_teams_api.messages.create(
        roomId=config.webex_room_id_vinay_test_space,
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
        online_hosts = []
        offline_hosts_data = list_handler.get_list_data_by_name(offline_hosts_list_name)
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
            list_handler.save(offline_hosts_list_name, list(set(offline_hosts).difference(online_hosts)))

    except Exception as ex:
        print(f"There was an issue in the VerifyHostOnlineStatus integration. Error: {str(ex)}")


def main():
    start()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
