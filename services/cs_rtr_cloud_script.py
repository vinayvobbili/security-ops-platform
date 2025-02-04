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
        - The script is already uploaded to CrowdStrike's cloud.
        - Downloads the script from CrowdStrike's cloud onto the target host.
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
        # Download the script from CrowdStrike's cloud and execute it
        command = f"runscript -CloudFile='{script_name}'"
        execute_response = rtr_api.execute_command(session_id=session_id, command_string=command)
        if execute_response['status_code'] != 201:
            raise Exception(f"Failed to execute script: {execute_response['body']['errors']}")

        print(f"Script '{script_name}' executed successfully on host with ID '{host_id}'.")

        # Optionally, retrieve the results
        result_response = rtr_api.get_command_result(session_id=session_id, sequence_id=execute_response['body']['resources'][0]['sequence_id'])
        if result_response['status_code'] == 200:
            print("Command Result:", result_response['body']['resources'][0]['stdout'])
        else:
            print("Failed to retrieve command result:", result_response['body']['errors'])

    finally:
        # Close the RTR session
        rtr_api.delete_session(session_id=session_id)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python execute_rtr_script.py <hostname> <script_name>")
        sys.exit(1)

    hostname = sys.argv[1]
    script_name = sys.argv[2]

    try:
        execute_script_on_host(hostname, script_name)
    except Exception as e:
        print(f"Error: {e}")
