import logging
import time

from falconpy import Hosts, RealTimeResponse, RealTimeResponseAdmin

from my_config import get_config
from services.crowdstrike import CrowdStrikeClient, CSCredentialProfile

logger = logging.getLogger(__name__)
config = get_config()

# Initialize client with RTR credentials (proxy config inherited from auth object)
cs_client = CrowdStrikeClient(credential_profile=CSCredentialProfile.RTR)
falcon_rtr = RealTimeResponse(auth_object=cs_client.auth)
falcon_rtr_admin = RealTimeResponseAdmin(auth_object=cs_client.auth)
falcon_hosts = Hosts(auth_object=cs_client.auth)


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


def execute_script(hostnames, cloud_script_name):
    if not hostnames:
        print("No valid hostnames provided. Skipping execution.")
        return
    host_ids = [cs_client.get_device_id(hostname) for hostname in hostnames]
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


def run_rtr_script(hostname: str, cloud_script_name: str, command_line: str = "") -> dict:
    """Execute an RTR script on a host and return the results.

    Args:
        hostname: Target hostname
        cloud_script_name: Name of the script uploaded to CrowdStrike
        command_line: Command line arguments to pass to the script

    Returns:
        dict with 'success', 'output', and 'error' keys
    """
    if not hostname:
        return {"success": False, "output": "", "error": "No hostname provided"}

    device_id = cs_client.get_device_id(hostname.strip().upper())
    if not device_id:
        return {"success": False, "output": "", "error": f"Hostname '{hostname}' not found in CrowdStrike"}

    # Check if device is online
    online_state = falcon_hosts.get_online_state(ids=device_id)
    if online_state.get('status_code') == 200:
        resources = online_state.get('body', {}).get('resources', [])
        if resources and resources[0].get('state') == 'offline':
            return {"success": False, "output": "", "error": f"Device '{hostname}' is offline. RTR requires the device to be online."}

    # Initialize RTR session
    body = {"host_ids": [device_id], "queue_offline": False}
    session_init_result = falcon_rtr.batch_init_sessions(body=body)

    if session_init_result['status_code'] != 201:
        error_msg = session_init_result.get('body', {}).get('errors', [])
        return {"success": False, "output": "", "error": f"Failed to create RTR session: {error_msg}"}

    batch_id = session_init_result['body'].get("batch_id")
    if not batch_id:
        return {"success": False, "output": "", "error": "Could not get batch_id from RTR session"}

    # Build command string
    if command_line:
        cmd_string = f"runscript -CloudFile='{cloud_script_name}' -CommandLine='{command_line}'"
    else:
        cmd_string = f"runscript -CloudFile='{cloud_script_name}'"

    batch_payload = {
        "base_command": "runscript",
        "batch_id": batch_id,
        "command_string": cmd_string
    }

    try:
        # Use Admin RTR for custom CloudFile scripts
        response = falcon_rtr_admin.batch_admin_command(body=batch_payload)
        resources = response.get('body', {}).get('combined', {}).get('resources', {})

        if not resources:
            return {"success": False, "output": "", "error": "No response from RTR execution"}

        key = list(resources.keys())[0]
        stdout = resources[key].get('stdout', '')
        stderr = resources[key].get('stderr', '')
        errors = resources[key].get('errors', [])

        if errors:
            return {"success": False, "output": stdout, "error": str(errors)}

        return {"success": True, "output": stdout or stderr, "error": ""}

    except Exception as e:
        logger.error(f"RTR script execution failed: {e}")
        return {"success": False, "output": "", "error": str(e)}


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


def download_rtr_file(hostname: str, remote_path: str, local_path: str) -> dict:
    """Download a file from a remote host using RTR get command.

    Files are returned as password-protected 7z archives (password: 'infected').
    This function handles extraction automatically.

    Args:
        hostname: Target hostname
        remote_path: Full path to file on remote host
        local_path: Local path to save the extracted file

    Returns:
        dict with 'success', 'error', and 'local_path' keys
    """
    import os
    import tempfile
    import py7zr

    device_id = cs_client.get_device_id(hostname.strip().upper())
    if not device_id:
        return {"success": False, "error": f"Hostname '{hostname}' not found", "local_path": None}

    # Init session
    session_result = falcon_rtr.init_session(device_id=device_id)
    if session_result['status_code'] != 201:
        return {"success": False, "error": "Failed to create RTR session", "local_path": None}

    session_id = session_result['body']['resources'][0]['session_id']

    try:
        # Execute get command using active responder
        get_response = falcon_rtr.execute_active_responder_command(
            session_id=session_id,
            base_command="get",
            command_string=f"get \"{remote_path}\""
        )

        if get_response['status_code'] != 201:
            return {"success": False, "error": f"Get command failed: {get_response}", "local_path": None}

        cloud_request_id = get_response['body']['resources'][0]['cloud_request_id']

        # Poll for get command completion
        for _ in range(30):
            time.sleep(2)
            status = falcon_rtr.check_active_responder_command_status(
                cloud_request_id=cloud_request_id,
                sequence_id=0
            )
            resources = status.get('body', {}).get('resources', [])
            if resources and resources[0].get('complete'):
                break
        else:
            return {"success": False, "error": "Timeout waiting for get command", "local_path": None}

        result = resources[0]
        if result.get('stderr'):
            return {"success": False, "error": result['stderr'], "local_path": None}

        # Poll list_files_v2 for SHA256 and wait for upload to complete
        sha256 = None
        filename = os.path.basename(remote_path.replace('\\', '/'))
        upload_requested_count = 0
        for i in range(90):  # Wait up to ~3 minutes for upload
            time.sleep(2)
            files_response = falcon_rtr.list_files_v2(session_id=session_id)
            found_file = False
            for f in files_response.get('body', {}).get('resources', []):
                name = f.get('name') or ''
                if filename in name and f.get('sha256'):
                    found_file = True
                    stage = f.get('stage', '')
                    progress = f.get('progress', 0) * 100
                    logger.info(f"RTR file upload: {progress:.0f}% - {stage}")

                    # Track how long we're stuck in upload_requested
                    if stage == 'upload_requested':
                        upload_requested_count += 1
                        if upload_requested_count > 15:  # ~30 seconds stuck
                            return {"success": False, "error": "File upload stuck in requested state", "local_path": None}
                    else:
                        upload_requested_count = 0

                    # Wait for upload to complete
                    if stage in ['complete', 'compression_completed', 'upload_completed'] or progress >= 100:
                        sha256 = f['sha256']
                        break
            if sha256:
                break
            if not found_file and i > 10:
                return {"success": False, "error": "File not found in RTR session", "local_path": None}
        else:
            return {"success": False, "error": "Timeout waiting for file upload to cloud", "local_path": None}

        # Download the 7z archive
        file_response = falcon_rtr.get_extracted_file_contents(
            session_id=session_id,
            sha256=sha256
        )

        # Response can be bytes directly or dict with body
        if isinstance(file_response, bytes):
            archive_content = file_response
        elif isinstance(file_response, dict):
            archive_content = file_response.get('body', b'')
            if not isinstance(archive_content, bytes):
                return {"success": False, "error": f"Unexpected body type: {type(archive_content)}", "local_path": None}
        else:
            return {"success": False, "error": f"Unexpected response format: {type(file_response)}", "local_path": None}

        if len(archive_content) < 100:
            return {"success": False, "error": "Downloaded file too small", "local_path": None}

        # Save archive to temp file
        archive_path = tempfile.mktemp(suffix='.7z', dir='/tmp')
        with open(archive_path, 'wb') as f:
            f.write(archive_content)

        # Extract with password 'infected' (CrowdStrike standard)
        extract_dir = tempfile.mkdtemp(dir='/tmp')
        try:
            with py7zr.SevenZipFile(archive_path, mode='r', password='infected') as z:
                z.extractall(path=extract_dir)
        except Exception as e:
            return {"success": False, "error": f"Failed to extract archive: {e}", "local_path": None}
        finally:
            os.remove(archive_path)

        # Find the extracted file and move to target location
        extracted_file = None
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                extracted_file = os.path.join(root, f)
                break
            if extracted_file:
                break

        if not extracted_file:
            return {"success": False, "error": "No file found in archive", "local_path": None}

        # Move to target location
        os.makedirs(os.path.dirname(local_path) if os.path.dirname(local_path) else '.', exist_ok=True)
        import shutil
        shutil.move(extracted_file, local_path)
        shutil.rmtree(extract_dir, ignore_errors=True)

        return {"success": True, "error": None, "local_path": local_path}

    except Exception as e:
        logger.error(f"RTR download error: {e}", exc_info=True)
        return {"success": False, "error": str(e), "local_path": None}

    finally:
        try:
            falcon_rtr.delete_session(session_id=session_id)
        except:
            pass


def main():
    """"""
    all_script_ids = falcon_rtr_admin.list_scripts(limit=200)['body']['resources']
    print(f"All scripts: {all_script_ids}", flush=True, end="\n\n")
    all_scripts = falcon_rtr_admin.get_scripts(all_script_ids)
    print(f"All scripts: {all_scripts}", flush=True, end="\n\n")

    # upload_script(f"{config.team_name}_RMM_Tool_Removal")

    # update_script("RMM_Tool_Removal", '<script_id>')

    hostname = 'YOURHOSTNAME'
    device_id = cs_client.get_device_id(hostname)
    print(f"Device ID: {device_id}")

    device_online_state = falcon_hosts.get_online_state(ids=device_id)['body']['resources'][0]['state']
    print(f"Device {hostname}'s online status: {device_online_state}")

    if device_online_state:
        test_commands = ["ls", "whoami", "systeminfo"]

        for command in test_commands:
            execute_command(device_id, command)

        cloud_script_name = f'{config.team_name}_RMM_Tool_Removal'
        print(f'Running the script {cloud_script_name} on {hostname}')
        execute_script([hostname], cloud_script_name)


if __name__ == "__main__":
    main()
