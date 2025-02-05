import base64

from falconpy import Hosts, RealTimeResponse

from config import get_config

config = get_config()
# CrowdStrike API credentials
CLIENT_ID = config.cs_client_id
CLIENT_SECRET = config.cs_client_secret

# Initialize the Hosts and RealTimeResponse services
hosts_api = Hosts(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
rtr_api = RealTimeResponse(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


def get_host_id(hostname):
    """Get the host ID using the hostname."""
    response = hosts_api.query_devices_by_filter(filter=f"hostname:'{hostname}'")
    if response['status_code'] == 200 and response['body']['resources']:
        return response['body']['resources'][0]
    else:
        raise Exception(f"Host '{hostname}' not found or error occurred: {response['body']['errors']}")


def execute_script_on_host(hostname, script_name):
    """Execute a script on the host using RTR."""
    host_id = get_host_id(hostname)
    if not host_id:
        raise Exception(f"Host '{hostname}' not found.")

    session_response = rtr_api.init_session(device_id=host_id)
    if session_response['status_code'] != 201:
        raise Exception(f"Failed to initiate RTR session: {session_response['body']['errors']}")

    session_id = session_response['body']['resources'][0]['session_id']

    try:
        with open(script_name, 'rb') as script_file:
            script_content = script_file.read()
            # Encode the script content in base64
            b64_script_content = base64.b64encode(script_content).decode('utf-8')

        # Use the 'upload' command to send and execute the script
        command_string = f"upload -f -; echo {script_name} | /usr/bin/awk -F '/' '{{print $NF}}' > uploaded_script.sh; chmod +x uploaded_script.sh; ./uploaded_script.sh"

        execute_response = rtr_api.execute_command(session_id=session_id, command_string=command_string, file=script_content)  # Pass the file content directly
        print(f"Script '{script_name}' executed successfully on host with ID '{host_id}'.")

        # Optionally, retrieve the results
        result_response = rtr_api.check_command_status(session_id=session_id, sequence_id=execute_response['body']['resources'][0]['sequence_id'])
        if result_response['status_code'] == 200:
            print("Command Result:", result_response['body']['resources'][0]['stdout'])
        else:
            print("Failed to retrieve command result:", result_response['body']['errors'])

    finally:
        # Close the RTR session
        rtr_api.delete_session(session_id=session_id)


if __name__ == "__main__":

    hostname = 'C02G7C7LMD6R'
    script_name = 'test_script_mac.sh'

    try:
        execute_script_on_host(hostname, script_name)
    except Exception as e:
        print(f"Error: {e}")
