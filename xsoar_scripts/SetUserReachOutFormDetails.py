"""
XSOAR Script: Set User Verification Task ID

This script finds the conditional task ID (by task name) and sets it in the context
so it can be used in the email template.

Arguments:
- task_name: Name of the conditional task (e.g., "Does the user recognize the alert?")

Returns:
- Sets ${user_verification_task_id} in context

Example usage in XSOAR playbook:
  Before the email task, run this script:
  !SetUserVerificationTaskId task_name="Does the user recognize the alert?"

  Then in the email task, use: ${user_verification_task_id}
"""
import uuid




def generate_unique_from_uuid():
    """Generate unique number from UUID."""
    return int(str(uuid.uuid4().int))


def save_form_details(form_id, incident_id, task_name, user_verification_task_id):
    response = demisto.internalHttpRequest('GET', '/lists', body=None)
    all_lists = json.loads(response.get("body", "[]"))
    matching_list = next((item for item in all_lists if item.get('id') == list_name), None)

    if not matching_list:
        raise ValueError(f"No list found with the name '{list_name}'.")

    api_url = xsoar_api_base_url + '/lists/save'
    headers = {'Authorization': xsoar_api_key, 'x-xdr-auth-id': auth_id}
    result = requests.post(api_url, headers=headers, json={
        "data": json.dumps(data, indent=4),
        "name": list_name,
        "type": "json",
        "id": list_name,
        "version": matching_list.get('version')
    })

    if result.status_code != 200:
        raise RuntimeError(f"Failed to save list. Status code: {result.status_code}")


def main():
    """Find the conditional task ID and set it in context."""
    task_name = 'Does the user recognize the alert?'
    form_id = generate_unique_from_uuid()
    incident_id = incident().get('id')

    # Get tasks that are in progress
    in_progress_tasks = demisto.executeCommand("GetIncidentTasksByState", {
        'inc_id': incident_id,
        'states': 'inProgress'
    })
    user_verification_task_id = [task for task in in_progress_tasks if task.get('name') == task_name][0].get('id')

    save_form_details(form_id, incident_id, task_name, user_verification_task_id)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
