from falconpy import OAuth2, Hosts, RealTimeResponse

from config import get_config

config = get_config()

# Authenticate
falcon_auth = OAuth2(client_id=config.cs_client_id, client_secret=config.cs_client_secret, ssl_verify=False)
falcon_rtr = RealTimeResponse(auth_object=falcon_auth)
falcon_hosts = Hosts(auth_object=falcon_auth)


def execute_script(device_id, script_content):
    rtr_execute_result = falcon_rtr.execute_command(
        device_id=device_id,
        command="runscript",
        arguments=f"-Command \"{script_content}\"",  # Script content as argument
        # timeout=120 # Optional timeout
    )
    print(f"RTR Execution Result: {rtr_execute_result}")
    request_id = rtr_execute_result['resources'][0]  # Request ID to track execution status
    print(f"RTR Script Execution Request ID: {request_id}")

    # Check the execution status
    status_result = falcon_rtr.get_command_status(request_id=request_id)
    print(f"RTR Execution Status: {status_result}")


def get_rtr_sessions():
    # Example: Listing sessions (you'll likely need to filter)
    sessions = falcon_rtr.list_sessions()
    if sessions and sessions['resources']:
        session_id_to_delete = sessions['resources'][0]  # Get the first session ID (handle as needed)
        print(f"Session ID to delete: {session_id_to_delete}")
        deletion_result = falcon_rtr.delete_session(session_id=session_id_to_delete)
        print(f"Session deletion result: {deletion_result}")
    else:
        print("No active RTR sessions found.")


def delete_rtr_session():
    # Delete the session
    session_id_to_delete = "YOUR_SESSION_ID"  # Replace with the actual session ID
    deletion_result = falcon_rtr.delete_session(session_id=session_id_to_delete)
    print(f"Session deletion result: {deletion_result}")


def get_device_id(host_filter):
    # Identify the Target Host

    response = falcon_hosts.query_devices_by_filter(filter=host_filter)
    if response["status_code"] == 200:
        devices = response["body"].get("resources", [])  # Handle potential empty result
        if devices:  # Check if any devices where found
            return devices  # Return the list of device IDs
        else:
            print(f"No devices found for filter: {host_filter}")
            return None
    else:
        print(f"Error getting device ID: {response['status_code']}, {response['body']['errors']}")
        return None


def main():
    host_filter = "hostname:'C02G7C6VMD6R'"
    device_id = get_device_id(host_filter)
    script_content = """
    # Your script content here (e.g., PowerShell, Bash, Python, etc.)
    # Example PowerShell:
    Write-Host "Hello from my script!"
    """
    execute_script(device_id, script_content)


if __name__ == "__main__":
    main()
