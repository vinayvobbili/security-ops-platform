from vonage import Vonage, Auth
from vonage_sms import SmsMessage, SmsResponse

from config import get_config

CONFIG = get_config()
# Create authentication
auth = Auth(api_key=CONFIG.vonage_api_key, api_secret=CONFIG.vonage_api_secret)

# Create Vonage client
vonage_client = Vonage(auth=auth)

# Create SMS message
message = SmsMessage(
    to='14792507504',  # Phone number to send to
    from_='12406348168',  # Sender ID or phone number
    text='Don\'t Panic. METCIRT\'s here!!'  # Message text
)

# Send the message
try:
    response: SmsResponse = vonage_client.sms.send(message)
    print(response.model_dump(exclude_unset=True))
except Exception as e:
    print(f"Error sending SMS: {e}")
