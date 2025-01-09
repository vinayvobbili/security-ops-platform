import requests

room_id = ''
access_token = 'your_access_token_here'

headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

response = requests.get(f'https://webexapis.com/v1/memberships?roomId={room_id}', headers=headers)
members = response.json()

for member in members['items']:
    print(f"Name: {member['personDisplayName']}, Email: {member['personEmail']}")
