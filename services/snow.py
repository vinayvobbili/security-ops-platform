import base64
import json

import requests

from config import get_config

environment = 'dev'
config = get_config()
snow_creds = json.loads(config.snow_creds)[environment]
CLIENT_KEY = snow_creds['CLIENT_KEY']
CLIENT_SECRET = snow_creds['CLIENT_SECRET']
USERNAME = snow_creds['FUNCTIONAL_ACCOUNT_ID']
PASSWORD = snow_creds['FUNCTIONAL_ACCOUNT_PASSWORD']
BASE_URL = snow_creds['BASE_URL']
print(CLIENT_KEY, CLIENT_SECRET, USERNAME, PASSWORD, BASE_URL)


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
        response = requests.get(url, headers=header, auth=(self.user_name, self.password))
        print(response.text)
        return response.json()['access_token']


client = ServiceNowClient(BASE_URL, USERNAME, PASSWORD, CLIENT_KEY)
token = client.get_token()
print(token)
