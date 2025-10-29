import requests

from my_config import get_config

CONFIG = get_config()
url = 'https://api-msoardev.crtx.us.paloaltonetworks.com/xsoar/investigation/1374041/workplan'
dev_headers = {
    'Authorization': CONFIG.xsoar_dev_auth_key,
    'x-xdr-auth-id': CONFIG.xsoar_dev_auth_id,
    'Content-Type': 'application/json'
}

response = requests.request("GET", url, headers=dev_headers)
tasks = response.json()['invPlaybook']['tasks']
for k, v in tasks.items():
    if v.get('task', {}).get('name') == 'Does the user recognize the alerted activity?':
        print("State:", v['state'])
        print("Task ID:", v['id'])
        # print("\nFull Task Details:")
        # print(json.dumps(v, indent=2))
        break
