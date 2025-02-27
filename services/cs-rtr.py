from falconpy import OAuth2, Hosts, RealTimeResponse

from config import get_config

config = get_config()

falcon_auth = OAuth2(client_id=config.cs_rtr_client_id, client_secret=config.cs_rtr_client_secret, base_url="api.us-2.crowdstrike.com", ssl_verify=False)
falcon_rtr = RealTimeResponse(auth_object=falcon_auth)
falcon_hosts = Hosts(auth_object=falcon_auth)


def execute_script(device_id, script_content):
    if not device_id:
        print("No valid device ID provided. Skipping execution.")
        return

    # print(f"Executing script on device: {device_id}")

    session_result = falcon_rtr.init_session(device_id=device_id)
    if session_result['status_code'] != 201:  # Check status code directly
        print(f"Failed to create RTR session: {session_result}")  # More detailed error
        return

    session_id = session_result['body']["resources"][0]['session_id']
    print(f"RTR session started. Session ID: {session_id}")

    command_string = script_content

    print(f"Executing command: {command_string}")
    rtr_execute_result = falcon_rtr.execute_command(
        session_id=session_id,
        base_command="run",
        command_string=command_string
    )
    print(f"RTR execution result: {rtr_execute_result}")

    if rtr_execute_result['status_code'] != 201:  # Check for success (201 Created)
        print(f"Failed to execute script: {rtr_execute_result['body']['errors']}")
        # Consider raising an exception here if you need to halt further processing

    # get the execution result
    cloud_request_id = rtr_execute_result['body']['resources'][0]['cloud_request_id']
    sequence_id = 0  # Start with the first sequence
    complete = False

    while not complete:
        status_result = falcon_rtr.check_command_status(cloud_request_id=cloud_request_id, sequence_id=sequence_id)
        print(status_result)
        if status_result['status_code'] != 200:
            print(f"Failed to get command status: {status_result}")
            break

        stdout = status_result['body']['resources'][0].get('stdout', '')
        stderr = status_result['body']['resources'][0].get('stderr', '')
        complete = status_result['body']['resources'][0]['complete']
        # print(f"Sequence {sequence_id}: stdout={stdout}, stderr={stderr}, complete={complete}")

        if not complete:
            sequence_id += 1

    # Cleanup: Close the session
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

    # script_content = """Write-Host 'Test RTR script execution'"""  # Simple test script
    # execute_script(device_id, script_content)

    test_commands = ["ls"]

    for command in test_commands:
        execute_script(device_id, command)


if __name__ == "__main__":
    main()
