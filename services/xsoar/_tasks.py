"""
XSOAR Playbook Task Operations

Handles playbook task operations including finding and completing tasks.
"""
import logging
import time
from typing import Any, Dict, Optional

import requests

from ._client import ApiException, DISABLE_SSL_VERIFY
from ._retry import truncate_error_message
from ._utils import _parse_generic_response

log = logging.getLogger(__name__)


def get_playbook_task_id(
    client,
    ticket_id: str,
    target_task_name: str
) -> Optional[str]:
    """
    Search for a task by name in the playbook, including sub-playbooks.

    Args:
        client: XSOAR demisto-py client
        ticket_id: The XSOAR incident/investigation ID
        target_task_name: Name of the task to find

    Returns:
        Task ID if found, None otherwise
    """
    try:
        response = client.generic_request(
            path=f'/investigation/{ticket_id}/workplan',
            method='GET'
        )
    except ApiException as e:
        log.error(f"Error fetching workplan for ticket {ticket_id}: {truncate_error_message(e)}")
        return None

    data = _parse_generic_response(response)
    tasks = data.get('invPlaybook', {}).get('tasks', {})

    # Recursive function to search through tasks and sub-playbooks
    def search_tasks(tasks_dict: Dict[str, Any], depth: int = 0) -> Optional[str]:
        for k, v in tasks_dict.items():
            task_info = v.get('task', {})
            playbook_task_id = v.get('id')
            found_task_name = task_info.get('name')

            # Check if this is the task we're looking for
            if found_task_name == target_task_name:
                log.debug(f"Found task '{target_task_name}' with ID: {playbook_task_id} in ticket {ticket_id}")
                return playbook_task_id

            # Check if this task has a sub-playbook
            if 'subPlaybook' in v:
                sub_tasks = v.get('subPlaybook', {}).get('tasks', {})
                if sub_tasks:
                    result = search_tasks(sub_tasks, depth + 1)
                    if result:
                        return result

        return None

    # Search through all tasks recursively
    task_id = search_tasks(tasks)

    if not task_id:
        log.warning(f"Task '{target_task_name}' not found in ticket {ticket_id}")

    return task_id


def complete_task(
    client,
    base_url: str,
    auth_key: str,
    auth_id: str,
    ticket_id: str,
    task_name: str,
    task_input: str = ''
) -> Optional[Dict[str, Any]]:
    """
    Complete a task in a playbook.

    Args:
        client: XSOAR demisto-py client
        base_url: XSOAR API base URL
        auth_key: XSOAR API auth key
        auth_id: XSOAR API auth ID
        ticket_id: The XSOAR incident/investigation ID
        task_name: Name of the task to complete
        task_input: Optional input/completion message for the task

    Returns:
        Response from the API

    Raises:
        ValueError: If task not found or already completed
    """
    log.debug(f"Completing task {task_name} in the ticket {ticket_id} with response: {task_input}")

    task_id = get_playbook_task_id(client, ticket_id, task_name)
    if not task_id:
        log.error(f"Task '{task_name}' not found in ticket {ticket_id}")
        raise ValueError(f"Task '{task_name}' not found in ticket {ticket_id}")

    # Build full URL using instance variables
    url = f'{base_url}/xsoar/public/v1/inv-playbook/task/complete'

    # Retry logic for server errors
    max_retries = 5
    retry_count = 0

    while retry_count <= max_retries:
        try:
            from requests_toolbelt.multipart.encoder import MultipartEncoder

            # Build multipart/form-data payload
            multipart_data = MultipartEncoder(
                fields={
                    'investigationId': ticket_id,
                    'fileName': '',
                    'fileComment': 'Completing via API',
                    'taskId': task_id,
                    'taskInput': task_input
                }
            )

            headers = {
                'Authorization': auth_key,
                'x-xdr-auth-id': auth_id,
                'Content-Type': multipart_data.content_type,
                'Accept': 'application/json'
            }

            response = requests.post(url, data=multipart_data, headers=headers, verify=not DISABLE_SSL_VERIFY, timeout=30)

            # Check for server errors BEFORE calling raise_for_status()
            if response.status_code in [500, 502, 503, 504]:
                retry_count += 1
                if retry_count > max_retries:
                    log.error(f"Error completing task '{task_name}' in ticket {ticket_id} after {max_retries} retries: {response.status_code} {response.reason}")
                    response.raise_for_status()

                backoff_time = 5 * (2 ** (retry_count - 1))
                log.warning(f"Server error {response.status_code} completing task '{task_name}' in ticket {ticket_id}. "
                            f"Retry {retry_count}/{max_retries}. Backing off for {backoff_time} seconds...")
                time.sleep(backoff_time)
                continue

            response.raise_for_status()

            # Parse response and check for XSOAR-specific errors
            if response.text:
                response_data = response.json()

                # Check if response contains an error field
                if isinstance(response_data, dict) and 'error' in response_data:
                    error_msg = response_data['error']

                    # Check for "Task is completed already" error
                    if 'Task is completed already' in str(error_msg):
                        log.warning(f"Task '{task_name}' (ID: {task_id}) in ticket {ticket_id} is already completed: {error_msg}")
                        raise ValueError(f"Task '{task_name}' is already completed: {error_msg}")
                    else:
                        log.error(f"Error from XSOAR when completing task '{task_name}': {error_msg}")
                        raise ValueError(f"XSOAR error: {error_msg}")

                log.debug(f"Successfully completed task '{task_name}' (ID: {task_id}) in ticket {ticket_id}")
                return response_data
            else:
                log.debug(f"Successfully completed task '{task_name}' (ID: {task_id}) in ticket {ticket_id}")
                return {}

        except requests.exceptions.RequestException as e:
            # Handle connection errors with retry
            retry_count += 1
            if retry_count > max_retries:
                log.error(f"Error completing task '{task_name}' in ticket {ticket_id} after {max_retries} retries: {e}")
                raise

            backoff_time = 5 * (2 ** (retry_count - 1))
            log.warning(f"Connection error completing task '{task_name}' in ticket {ticket_id}: {type(e).__name__}: {e}. "
                        f"Retry {retry_count}/{max_retries}. Backing off for {backoff_time} seconds...")
            time.sleep(backoff_time)
            continue

    return None
