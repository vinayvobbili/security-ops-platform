import base64

import requests


class ServiceNowClient:
    def __init__(self, base_url, user_name, password, client_id):
        self.base_url = base_url
        self.user_name = user_name
        self.password = password
        self.client_id = client_id

    def get_token_request(self):
        url = self.base_url + '/authorization/token'
        credentials = self.user_name + ':' + self.password
        cred_bytes = credentials.encode("utf-8")
        encoded_u = base64.b64encode(cred_bytes)
        header = {'Authorization': 'Basic %s' % encoded_u, 'Content-Type': 'application/json', 'X-IBM-Client-Id': self.client_id}
        token_response = requests.get(url, headers=header, auth=(self.user_name, self.password), verify=False)
        if not token_response:
            err_msg = 'Authorization Error: User has no authorization to create a token.' \
                      ' Please make sure you entered the credentials correctly.'
            raise Exception(err_msg)
        return token_response.json()['access_token']


base_url = 'https://portal.internal.amer.apic.company.com/acme/production'
client_id = ''
user_name = ''
password = ''
client = ServiceNowClient(base_url, user_name, password, client_id)

print(client.get_token_request())
