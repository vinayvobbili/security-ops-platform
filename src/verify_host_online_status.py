from falconpy import OAuth2, Hosts
from webexteamssdk import WebexTeamsAPI

from my_config import get_config
from services.crowdstrike import CrowdStrikeClient
from services.xsoar import ListHandler, XsoarEnvironment

offline_hosts_list_name: str = 'Offline_Hosts'

config = get_config()

xsoar_headers = {
    'Authorization': config.xsoar_prod_auth_key,
    'x-xdr-auth-id': config.xsoar_prod_auth_id,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

crowdstrike = CrowdStrikeClient()

prod_list_handler = ListHandler(XsoarEnvironment.PROD)


def send_webex_notification(host_name, ticket_id):
    incident_url = config.xsoar_prod_ui_base_url + "/Custom/caseinfoid/" + ticket_id
    webex_teams_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_soar)
    webex_teams_api.messages.create(
        roomId=config.webex_room_id_host_announcements,
        markdown=f'Host {host_name} associated with ticket [#{ticket_id}]({incident_url}) is now online'
    )


def start():
    try:
        offline_hosts_data = prod_list_handler.get_list_data_by_name(offline_hosts_list_name)
        if not offline_hosts_data:
            return
        # Always treat as comma-separated string
        if isinstance(offline_hosts_data, str):
            offline_hosts = [item.strip() for item in offline_hosts_data.split(',') if '-' in item]
        elif isinstance(offline_hosts_data, list):
            # Defensive: flatten any accidental list (shouldn't happen with save_as_text)
            offline_hosts = [item.strip() for item in offline_hosts_data if '-' in item]
        else:
            offline_hosts = []
        host_ticket_map = dict(item.split('-', 1) for item in offline_hosts)
        online_hosts = []
        for hostname, ticket_id in host_ticket_map.items():
            if crowdstrike.get_device_online_state(hostname) == "online":
                send_webex_notification(hostname, ticket_id)
                online_hosts.append(f"{hostname}-{ticket_id}")
        if online_hosts:
            prod_list_handler.save_as_text(offline_hosts_list_name, list(set(offline_hosts) - set(online_hosts)))
    except Exception as ex:
        print(f"There was an issue in the VerifyHostOnlineStatus integration. Error: {str(ex)}")


def main():
    start()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
