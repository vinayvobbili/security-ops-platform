import requests

from my_config import get_config


def complete_playbook_task(
        investigation_id: str,
        task_id: str,
        file_comment: str = "Completing via API",
        task_input: str = "Completed successfully",
        file_name: str = ""
) -> dict:
    """Complete a playbook task in XSOAR.

    Args:
        investigation_id: XSOAR investigation/incident ID
        task_id: Task ID to complete
        file_comment: Comment about the file/completion (default: "Completing via API")
        task_input: Task input/completion message (default: "Completed successfully")
        file_name: Optional file name (default: "")

    Returns:
        dict: API response JSON
    """
    CONFIG = get_config()
    url = 'https://api-msoardev.crtx.us.paloaltonetworks.com/xsoar/public/v1/inv-playbook/task/complete'

    # Using exact format from API documentation with manual multipart/form-data boundary
    payload = (
        "-----011000010111000001101001\r\n"
        "Content-Disposition: form-data; name=\"investigationId\"\r\n\r\n"
        f"{investigation_id}\r\n"
        "-----011000010111000001101001\r\n"
        "Content-Disposition: form-data; name=\"fileName\"\r\n\r\n"
        f"{file_name}\r\n"
        "-----011000010111000001101001\r\n"
        "Content-Disposition: form-data; name=\"fileComment\"\r\n\r\n"
        f"{file_comment}\r\n"
        "-----011000010111000001101001\r\n"
        "Content-Disposition: form-data; name=\"taskId\"\r\n\r\n"
        f"{task_id}\r\n"
        "-----011000010111000001101001\r\n"
        "Content-Disposition: form-data; name=\"taskInput\"\r\n\r\n"
        f"{task_input}\r\n"
        "-----011000010111000001101001--\r\n"
    )

    headers = {
        'Authorization': CONFIG.xsoar_dev_auth_key,
        'x-xdr-auth-id': CONFIG.xsoar_dev_auth_id,
        'Content-Type': 'multipart/form-data; boundary=---011000010111000001101001',
        'Accept': 'application/json'
    }

    response = requests.post(url, data=payload, headers=headers)

    print(f"Status Code: {response.status_code}")
    print(f"Response Text: {response.text}")

    if response.text:
        return response.json()
    else:
        print("Empty response received")
        return {}


if __name__ == "__main__":
    # Configure your task details here
    investigation_id = '1374041'
    task_id = "3"  # '4f85629d-ba5f-4db7-8914-eab182c2ddfe'
    file_comment = "Completing via API"
    # For conditional tasks, task_input should be the route name
    # Available routes for this task: "Yes" or "else"
    # "Yes" -> Close ticket (task #4)
    # "else" -> Notify analyst (task #5)
    task_input = "Yes"  # Change to "Yes" or "else" to choose the route
    file_name = ""

    result = complete_playbook_task(
        investigation_id=investigation_id,
        task_id=task_id,
        file_comment=file_comment,
        task_input=task_input,
        file_name=file_name
    )

    print(result)
