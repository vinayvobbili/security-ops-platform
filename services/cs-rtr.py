from falconpy import OAuth2, Hosts, RealTimeResponse
from config import get_config
import base64

config = get_config()

# Authenticate
falcon_auth = OAuth2(
    client_id=config.cs_ro_client_id,
    client_secret=config.cs_ro_client_secret,
    base_url="https://api.us-2.crowdstrike.com",
    ssl_verify=False
)
falcon_rtr = RealTimeResponse(auth_object=falcon_auth)
falcon_hosts = Hosts(auth_object=falcon_auth)


def execute_script(device_id, script_content):
    if not device_id:
        print("No valid device ID provided. Skipping execution.")
        return

    print(f"Executing script on device: {device_id}")

    # Encode script for safer execution
    encoded_script = base64.b64encode(script_content.encode()).decode()
    command_args = f"-Base64 {encoded_script}"

    # Open an RTR session first
    session_result = falcon_rtr.init_session(device_id=device_id)
    if not session_result["resources"]:
        print(f"Failed to create RTR session: {session_result}")
        return

    session_id = session_result["resources"][0]
    print(f"RTR session started: {session_id}")

    # Execute script
    rtr_execute_result = falcon_rtr.execute_command(
        session_id=session_id,
        base_command="runscript",
        command_string=command_args
    )
    print(f"RTR Execution Result: {rtr_execute_result}")

    # Clean up the session
    falcon_rtr.delete_session(session_id=session_id)
    print(f"RTR session {session_id} closed.")


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
    host_filter = "hostname:'c02g7c7lmd6r'"
    device_id = get_device_id(host_filter)
    print(f"Device ID: {device_id}")

    script_content = """
    Write-Output "Hello from my script!"
    """  # PowerShell example

    execute_script(device_id, script_content)


if __name__ == "__main__":
    main()
