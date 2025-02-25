import base64

import requests

from config import get_config

config = get_config()


class ServiceNowClient:
    def __init__(self, base_url, user_name, password, client_id):
        self.base_url = base_url
        self.user_name = user_name
        self.password = password
        self.client_id = client_id

    def get_token(self):
        url = self.base_url + '/authorization/token'
        credentials = self.user_name + ':' + self.password
        cred_bytes = credentials.encode("utf-8")
        encoded_u = base64.b64encode(cred_bytes)
        header = {'Authorization': 'Basic %s' % encoded_u, 'Content-Type': 'application/json', 'X-IBM-Client-Id': self.client_id}
        response = requests.get(url, headers=header, auth=(self.user_name, self.password), verify=False)
        print(response.text)
        return response.json()['access_token']


snow_base_url = config.snow_base_url
client_id = config.snow_client_key
user_name = config.snow_functional_account_id
password = config.snow_functional_account_password

client = ServiceNowClient(snow_base_url, user_name, password, client_id)
token = client.get_token()
print(token)
