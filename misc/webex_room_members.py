import requests

from config import get_config

config = get_config()
room_id = ''
access_token = config.webex_bot_access_token_xsoar

headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

response = requests.get(f'https://webexapis.com/v1/memberships?roomId={room_id}', headers=headers)
members = response.json()

for member in members['items']:
    print(f"Name: {member['personDisplayName']}, Email: {member['personEmail']}")
