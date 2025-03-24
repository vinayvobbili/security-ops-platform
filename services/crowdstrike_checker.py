# crowdstrike_checker.py
import spacy
from falconpy import Hosts

# Load pre-trained Spacy model (no training needed)
nlp = spacy.load("en_core_web_sm")

# Your CrowdStrike API credentials
CLIENT_ID = "YOUR_CLIENT_ID"  # Replace with your Client ID
CLIENT_SECRET = "YOUR_CLIENT_SECRET"  # Replace with your Client Secret

# Initialize CrowdStrike API client
falcon = Hosts(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


def get_containment_status(hostname):
    """Fetch containment status for a given hostname using CrowdStrike API."""
    try:
        response = falcon.query_devices_by_filter(filter=f"hostname:'{hostname}'")
        if response["status_code"] != 200 or not response["body"]["resources"]:
            return f"Host {hostname} not found in CrowdStrike."

        host_id = response["body"]["resources"][0]
        host_details = falcon.get_device_details(ids=host_id)
        if host_details["status_code"] != 200:
            return f"Error fetching details for {hostname}."

        status = host_details["body"]["resources"][0]["status"]
        return f"Containment status of {hostname}: {status}"

    except Exception as e:
        return f"Error checking {hostname}: {str(e)}"


def process_input(user_input):
    """Process the user's prompt using Spacy for intent and argument extraction."""
    doc = nlp(user_input.lower())

    # Intent detection: look for "status" and "crowdstrike" in tokens
    has_status = any(token.text in ["status", "containment"] for token in doc)
    has_crowdstrike = any(token.text == "crowdstrike" for token in doc)

    if has_status and has_crowdstrike:
        # Extract hostname: look for "host" and take the next token
        hostname = None
        for i, token in enumerate(doc):
            if token.text == "host" and i + 1 < len(doc):
                hostname = doc[i + 1].text
                break

        if hostname:
            return get_containment_status(hostname)
        return "Please specify a hostname (e.g., 'host US12345')."

    return "Sorry, I only handle containment status checks for CrowdStrike hosts!"


# Test it
if __name__ == "__main__":
    test_prompts = [
        "what's the containment status of the host US12345 in CrowdStrike",
        "check containment status for host MYHOST123 in CrowdStrike",
        "get the status of host TESTHOST in CrowdStrike",
        "add 5 and 3",
        "what's the weather in Tokyo",
        "tell me about host XYZ789 containment in CrowdStrike"
    ]
    for prompt in test_prompts:
        print(f"Input: {prompt}")
        print(f"Output: {process_input(prompt)}\n")
