import base64

from falconpy import OAuth2, Hosts, RealTimeResponse

from config import get_config

config = get_config()

falcon_auth = OAuth2(client_id=config.cs_rtr_client_id, client_secret=config.cs_rtr_client_secret, ssl_verify=False)
falcon_rtr = RealTimeResponse(auth_object=falcon_auth)
falcon_hosts = Hosts(auth_object=falcon_auth)


def execute_script(device_id, script_content):
    if not device_id:
        print("No valid device ID provided. Skipping execution.")
        return

    print(f"Executing script on device: {device_id}")

    # Explicitly use UTF-16LE encoding and -EncodedCommand
    encoded_script = base64.b64encode(script_content.encode('utf-16le')).decode()
    command_args = f"-EncodedCommand {encoded_script}"

    session_result = falcon_rtr.init_session(device_id=device_id)
    if session_result['status_code'] != 201:  # Check status code directly
        print(f"Failed to create RTR session: {session_result}")  # More detailed error
        return

    session_id = session_result['body']["resources"][0]['session_id']
    print(f"RTR session started: {session_id}")

    rtr_execute_result = falcon_rtr.execute_command(
        session_id=session_id,
        base_command="runscript",
        command_string=command_args
    )

    if rtr_execute_result['status_code'] != 201:  # Check for success (201 Created)
        print(f"Failed to execute script: {rtr_execute_result['body']['errors']}")  # Print full response for debugging
        # Consider raising an exception here if you need to halt further processing
    else:
        print(f"Script executed successfully: {rtr_execute_result}")

    cleanup_result = falcon_rtr.delete_session(session_id=session_id)
    if cleanup_result["status_code"] != 204:  # Expected code for successful deletion
        print(f"Failed to close session: {cleanup_result}")


def get_device_id(host_filter):
    """Retrieve the first device ID matching the filter."""
    response = falcon_hosts.query_devices_by_filter(filter=host_filter)

    if response.get("status_code") == 200:
        devices = response["body"].get("resources", [])
        if devices:
            return devices[0]  # Return the first matching device ID
        print(f"No devices found for filter: {host_filter}")
    else:
        print(f"Error getting device ID: {response.get('status_code')}, {response.get('body', {}).get('errors')}")

    return None


def main():
    host_filter = "hostname:'C02G7C7LMD6R'"
    device_id = get_device_id(host_filter)
    print(f"Device ID: {device_id}")

    script_content = """
    Write-Host "Hello from my script!"
    """  # PowerShell example

    execute_script(device_id, script_content)


if __name__ == "__main__":
    main()
