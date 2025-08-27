from twilio.rest import Client

from my_config import get_config

try:
    CONFIG = get_config()
    account_sid = CONFIG.twilio_account_sid
    auth_token = CONFIG.twilio_auth_token
    client = Client(account_sid, auth_token)

    # Send a regular SMS text message using a Twilio phone number as the sender
    message = client.messages.create(
        body='This is a test SMS message from your IR application',
        from_=CONFIG.twilio_whatsapp_number,  # Your Twilio phone number
        to=CONFIG.whatsapp_receiver_numbers  # Recipient's phone number
    )

    print(message.sid)
except KeyError as e:
    print(f"Error: Missing environment variable: {e}")
    print("Please make sure all required environment variables are set in your .env file.")
    print("Required variables for Twilio SMS: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER")
except Exception as e:
    print(f"Error sending SMS: {e}")
    print("Make sure your Twilio account is properly set up and the phone numbers are in the correct format.")
    print("For SMS messages, you need either a valid 'from' phone number or a 'messagingServiceSid'.")
    print("The from number must be a Twilio phone number capable of sending SMS.")
