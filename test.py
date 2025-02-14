from falconpy import OAuth2

from config import get_config

config = get_config()

client_id = config.cs_rtr_client_id
client_secret = config.cs_rtr_client_secret

auth = OAuth2(client_id=client_id, client_secret=client_secret, base_url="https://api.us-2.crowdstrike.com")

token_response = auth.token()
print(token_response)
