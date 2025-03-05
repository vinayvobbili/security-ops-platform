import time  # Import the time module

from falconpy import OAuth2, Hosts, RealTimeResponse, RealTimeResponseAdmin

from config import get_config

config = get_config()

falcon_auth = OAuth2(client_id=config.cs_rtr_client_id, client_secret=config.cs_rtr_client_secret, base_url="api.us-2.crowdstrike.com", ssl_verify=False)
falcon_rtr = RealTimeResponse(auth_object=falcon_auth)
falcon_rtr_admin = RealTimeResponseAdmin(auth_object=falcon_auth)
falcon_hosts = Hosts(auth_object=falcon_auth)


def execute_command(device_id, script_content):
    if not device_id:
        print("No valid device ID provided. Skipping execution.")
        return

    session_result = falcon_rtr.init_session(device_id=device_id)
    if session_result['status_code'] != 201:  # Check status code directly
        print(f"Failed to create RTR session: {session_result}")
        return

    session_id = session_result['body']["resources"][0]['session_id']
    print(f"RTR session started. Session ID: {session_id}")

    command_string = script_content

    print(f"Executing command: {command_string}")
    rtr_execute_response = falcon_rtr.execute_command(
        session_id=session_id,
        base_command="run",
        command_string=command_string
    )
    print(f"RTR execution response: {rtr_execute_response}")

    if rtr_execute_response['status_code'] != 201:  # Check for success (201 Created)
        print(f"Failed to execute script: {rtr_execute_response['body']['errors']}")
        return

    # get the execution result
    cloud_request_id = rtr_execute_response['body']['resources'][0]['cloud_request_id']
    sequence_id = 0  # Start with the first sequence
    complete = False
    all_stdout = ""
    all_stderr = ""

    while not complete:
        status_result = falcon_rtr.check_command_status(cloud_request_id=cloud_request_id, sequence_id=sequence_id)

        if status_result['status_code'] != 200:
            print(f"Failed to get command status: {status_result}")
            break

        # check if there is resources object
        if 'resources' in status_result['body'] and status_result['body']['resources']:
            stdout = status_result['body']['resources'][0].get('stdout', '')
            stderr = status_result['body']['resources'][0].get('stderr', '')
            complete = status_result['body']['resources'][0]['complete']

            all_stdout += stdout
            all_stderr += stderr

            print(f"Sequence {sequence_id}:")
            if stdout:
                print(f"  stdout: {stdout}")
                sequence_id += 1
            if stderr:
                print(f"  stderr: {stderr}")
            print(f"  complete: {complete}")
            if complete:
                break
        else:
            print(f"No resources found in sequence {sequence_id}, waiting...")

        time.sleep(1)  # Wait before checking again. Increase if needed

    print(f"Command Execution output: stdout: {all_stdout}, stderr: {all_stderr}")

    # Cleanup: Close the session
    cleanup_result = falcon_rtr.delete_session(session_id=session_id)
    if cleanup_result["status_code"] != 204:  # Expected code for successful deletion
        print(f"Failed to close session: {cleanup_result}")


def get_device_id(hostname):
    """Retrieve the first device ID matching the filter."""
    host_filter = f"hostname:'{hostname}'"
    response = falcon_hosts.query_devices_by_filter(filter=host_filter)

    if response.get("status_code") == 200:
        devices = response["body"].get("resources", [])
        if devices:
            return devices[0]  # Return the first matching device ID
        print(f"No devices found for filter: {host_filter}")
    else:
        print(f"Error getting device ID: {response.get('status_code')}, {response.get('body', {}).get('errors')}")

    return None


def execute_script(hostnames, cloud_script_name):
    if not hostnames:
        print("No valid hostnames provided. Skipping execution.")
        return
    host_ids = [get_device_id(hostname) for hostname in hostnames]
    body = {
        "host_ids": host_ids,
        "queue_offline": True
    }
    session_init_result = falcon_rtr.batch_init_sessions(body=body)
    # print(f"RTR session init response: {session_init_result}")
    if session_init_result['status_code'] != 201:  # Check status code directly
        print(f"Failed to create RTR session: {session_init_result}")
        return
    batch_id = session_init_result['body'].get("batch_id")

    if not batch_id:
        print("Could not find 'session_id' in the RTR session response.")
        return

    # print(f"RTR session started. Batch ID: {batch_id}")

    batch_active_responder_payload = {
        "base_command": "runscript",
        "batch_id": batch_id,
        "command_string": "runscript -CloudFile='" + cloud_script_name + "' -CommandLine=''"
    }
    # use the session_id to execute the script_content on the target host via RTR
    resources = falcon_rtr.batch_active_responder_command(body=batch_active_responder_payload)['body']['combined']['resources']
    key = list(resources.keys())[0]
    batch_active_responder_command_response = resources[key]['stdout'] or resources[key]['errors']
    # batch_active_responder_command_response = batch_active_responder_command_response.encode('unicode_escape').decode('utf-8')
    print(f"RTR script execution response: {batch_active_responder_command_response}")


def upload_script(script_name):
    # use RTR admin to upload the script_content
    file_name = f'../data/scripts/{script_name}.ps1'
    with open(file_name, 'rb') as upload_file:
        file_upload = [('file', (script_name, upload_file.read(), 'application/script'))]

    response = falcon_rtr_admin.create_scripts(
        comments_for_audit_log="A script to detect and remove common RMM tools",
        description="A script to detect and remove common RMM tools",
        name=script_name,
        files=file_upload,
        platform=["windows"],
        permission_type="private",
        content=file_upload,
        comments="Script to detect and remove common RMM tools"
    )
    print(f"Script upload response: {response}")
    script_id = response['body']['resources'][0]['id']
    print(f"Script uploaded successfully. Script ID: {script_id}")


def update_script(script_name, script_id):
    # use RTR admin to update the script_content
    file_name = f'../data/scripts/{script_name}.ps1'
    with open(file_name, 'rb') as upload_file:
        file_upload = [('file', (file_name, upload_file.read(), 'application/script'))]

    response = falcon_rtr_admin.update_scripts(
        comments_for_audit_log="A script to detect and remove common RMM tools",
        description="A script to detect and remove common RMM tools",
        id=script_id,
        name=script_name,
        files=file_upload,
        platform=["windows"],
        permission_type="group",
        content=file_upload,
        comments="Script to detect and remove common RMM tools"
    )
    print(f"Script update response: {response}")


def main():
    """"""

    all_script_ids = falcon_rtr_admin.list_scripts(limit=200)['body']['resources']
    print(f"All scripts: {all_script_ids}", flush=True, end="\n\n")
    all_scripts = falcon_rtr_admin.get_scripts(all_script_ids)
    print(f"All scripts: {all_scripts}", flush=True, end="\n\n")

    # upload_script("METCIRT_RMM_Tool_Removal")

    # update_script("RMM_Tool_Removal", '7cc64c3cf9f911ef86e712648f985aff_25596f2a3c164ed28d8de6670a89b442')

    hostname = 'USHNTDTQ3'
    device_id = get_device_id(hostname)
    print(f"Device ID: {device_id}")

    device_online_state = falcon_hosts.get_online_state(ids=device_id)['body']['resources'][0]['state']
    print(f"Device {hostname}'s online status: {device_online_state}")

    if device_online_state:
        test_commands = ["ls", "whoami", "systeminfo"]
        '''
        for command in test_commands:
            execute_command(device_id, command)
        '''
        cloud_script_name = 'METCIRT_RMM_Tool_Removal'
        print(f'Running the script {cloud_script_name} on {hostname}')
        execute_script([hostname], cloud_script_name)


if __name__ == "__main__":
    main()
