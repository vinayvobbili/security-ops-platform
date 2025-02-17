import requests

from config import get_config

config = get_config()
id = "531774"
url = f"{config.xsoar_api_base_url}/incident/load/{id}"

headers = {
    "authorization": config.xsoar_auth_token,
    "x-xdr-auth-id": config.xsoar_auth_id,
    "Accept": "application/json"
}

response = requests.get(url, headers=headers)
print(response.json())

incident_entries_url = config.xsoar_api_base_url + f'/incidents/{id}/entries'
response_entries = requests.get(incident_entries_url, headers=headers)
print(response_entries.text)