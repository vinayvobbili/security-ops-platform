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
    """Execute a script on the host using RTR.
        - Takes a script from your local machine.
        - Uploads it to the target host using CrowdStrike's Real Time Response (RTR).
        - Executes the script on the target host.
    """
    host_id = get_host_id(hostname)
    if not host_id:
        raise Exception(f"Host '{hostname}' not found.")
    print(f"Host ID for '{hostname}': {host_id}")

    # Initiate an RTR session
    session_response = rtr_api.init_session(device_id=host_id)
    if session_response['status_code'] != 201:
        raise Exception(f"Failed to initiate RTR session: {session_response['body']['errors']}")

    session_id = session_response['body']['resources'][0]['session_id']

    try:
        # Read the script from the local file
        with open(script_path, 'rb') as script_file:
            script_content = script_file.read().decode('utf-8')  # Decode to string for RTR

        # Upload the script to the host
        upload_command = f"put {script_path}"
        upload_response = rtr_api.execute_active_responder_command(session_id=session_id, base_command=upload_command, command_string=script_content)
        if upload_response['status_code'] != 201:
            raise Exception(f"Failed to upload script: {upload_response['body']['errors']}")

        print(f"Script '{script_path}' uploaded successfully to host with ID '{host_id}'.")

        # Execute the script on the host
        execute_command = f"runscript -Raw=```{script_content}```"
        execute_response = rtr_api.execute_active_responder_command(session_id=session_id, base_command="runscript", command_string=execute_command)
        if execute_response['status_code'] != 201:
            raise Exception(f"Failed to execute script: {execute_response['body']['errors']}")

        print(f"Script '{script_path}' executed successfully on host with ID '{host_id}'.")

        # Retrieve the command results
        sequence_id = execute_response['body']['resources'][0]['sequence_id']
        result_response = rtr_api.check_command_status(session_id=session_id, sequence_id=sequence_id)
        if result_response['status_code'] == 200:
            print("Command Result:", result_response['body']['resources'][0]['stdout'])
        else:
            print("Failed to retrieve command result:", result_response['body']['errors'])

    finally:
        # Close the RTR session
        rtr_api.delete_session(session_id=session_id)


if __name__ == "__main__":

    hostname = 'C02G7C6VMD6R'
    script_path = 'test_script_mac.sh'

    try:
        execute_script_on_host(hostname, script_path)
    except Exception as e:
        print(f"Error: {e}")
