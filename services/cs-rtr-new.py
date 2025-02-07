from falconpy import OAuth2, Hosts, RealTimeResponse  # For normal RTR operations
from falconpy import RealTimeResponseAdmin # If you need admin privileges for RTR

from config import get_config

config = get_config()
# Your CrowdStrike API credentials
CLIENT_ID = config.cs_client_id
CLIENT_SECRET = config.cs_client_secret

# Authenticate
falcon_auth = OAuth2(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

# Identify the Target Host
falcon_hosts = Hosts(auth_object=falcon_auth)

# Example: Search for hosts (you'll likely want to refine your search)
host_search_result = falcon_hosts.query_devices_by_filter(filter="hostname:'C02G7C6VMD6R'")  # Replace with your filter
device_id = host_search_result['resources'] # Get the device ID. Handle multiple results as needed.
print(f"Target device ID: {device_id}")

# Upload the Script (Optional but Recommended)
falcon_rtr = RealTimeResponse(auth_object=falcon_auth)

with open("your_script.ps1", "rb") as script_file:  # Replace with your script path
    upload_result = falcon_rtr.upload_script(file_obj=script_file, name="your_script_name.ps1", description="Description of the script")
    script_id = upload_result['resources']
    print(f"Uploaded script ID: {script_id}")

# Executing an uploaded script
rtr_execute_result = falcon_rtr.execute_script(
    device_id=device_id,
    script_id=script_id, # ID of the script you uploaded
    # Optional parameters:
    #   timeout: Timeout in seconds (default is 30 seconds, max 5 minutes)
    #   arguments: String containing script arguments.  Format depends on the script.
)
request_id = rtr_execute_result['resources'][0] # Request ID to track execution status
print(f"RTR Script Execution Request ID: {request_id}")

# Executing a command (for very short scripts or if upload isn't feasible)
rtr_execute_result = falcon_rtr.execute_command(
   device_id=device_id,
   command="runscript",
   arguments="-Command \"Your Inline Script Here\"", # Or the name of the script if it exists on the host
   # Optional:
    #   timeout: Timeout
)
request_id = rtr_execute_result['resources'][0] # Request ID to track execution status
print(f"RTR Command Execution Request ID: {request_id}")

# Check Execution Status (Important)
status_result = falcon_rtr.get_command_status(request_id=request_id)
print(f"RTR Execution Status: {status_result}")
# Check the status for success/failure. You might need to poll until completion.
