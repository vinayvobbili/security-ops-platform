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
    config = get_config()
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
        'Authorization': config.xsoar_dev_auth_key,
        'x-xdr-auth-id': config.xsoar_dev_auth_id,
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
    # Test completing "Acknowledge Ticket" task
    investigation_id = '1375188'
    task_id = "276"  # From get_playbook_task_id.py - Acknowledge Ticket
    file_comment = "Completing via API"
    # Data Collection task requires "Yes" answer
    task_input = "Yes"
    file_name = ""

    print(f"Attempting to complete task ID {task_id} in ticket {investigation_id}")
    print(f"Task input: {task_input}\n")

    result = complete_playbook_task(
        investigation_id=investigation_id,
        task_id=task_id,
        file_comment=file_comment,
        task_input=task_input,
        file_name=file_name
    )

    print("\nResult:")
    print(result)
