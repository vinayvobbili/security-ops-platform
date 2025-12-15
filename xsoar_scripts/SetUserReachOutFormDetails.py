"""
XSOAR Script: Set User Reach Out Form Details

Generates a unique form ID and saves user reach out form details to the
"METCIRT User Reach Out Forms" list for tracking user verification workflows.

Workflow:
- Generates unique form ID from UUID
- Retrieves current incident ID
- Finds in-progress task ID by name ("Does the user recognize the alert?")
- Appends form details to "METCIRT User Reach Out Forms" list using setList command

Arguments:
- None

Example usage in XSOAR playbook:
  !SetUserReachOutFormDetails
"""
import json
import uuid

# These should be configurable via environment, but for XSOAR scripts we keep them dynamic
from my_config import get_config
CONFIG = get_config()

USER_REACH_OUT_FORMS_LIST_NAME = f"{CONFIG.team_name} User Reach Out Forms"
USER_REACH_OUT_FORMS_HISTORY_LIST_NAME = f"{CONFIG.team_name} User Reach Out Forms History"
TASK_NAME = "Does the user recognize the alert?"


def generate_unique_form_id() -> int:
    """Generate unique form ID from UUID.

    Returns:
        int: Unique form identifier
    """
    return int(str(uuid.uuid4().int))


def save_form_details(form_id: int, incident_id: str, user_verification_task_id: str) -> None:
    """Save form details to XSOAR list.

    Args:
        form_id: Unique form identifier
        incident_id: XSOAR incident ID
        user_verification_task_id: Task ID for user verification
    """
    list_contents = demisto.executeCommand("getList", {
        "listName": USER_REACH_OUT_FORMS_LIST_NAME
    })[0].get('Contents', '[]')
    user_reach_out_forms = json.loads(list_contents) if list_contents else []

    user_reach_out_forms.append({
        "form_id": form_id,
        "incident_id": incident_id,
        "user_verification_task_id": user_verification_task_id
    })

    demisto.executeCommand("setList", {
        "listName": USER_REACH_OUT_FORMS_LIST_NAME,
        "listData": json.dumps(user_reach_out_forms, indent=4)
    })


def get_user_verification_task_id(incident_id: str, task_name: str) -> str:
    """Find in-progress task ID by name.

    Args:
        incident_id: XSOAR incident ID
        task_name: Name of task to find

    Returns:
        str: Task ID
    """
    in_progress_tasks = demisto.executeCommand("GetIncidentTasksByState", {
        'inc_id': incident_id,
        'states': 'inProgress'
    })

    matching_task = next(
        (task for task in in_progress_tasks if task.get('name') == task_name),
        None
    )

    return matching_task.get('id') if matching_task else None


def main() -> None:
    """Generate form ID and save user reach out form details to XSOAR list."""
    form_id = generate_unique_form_id()
    incident_id = demisto.incident().get('id')
    user_verification_task_id = get_user_verification_task_id(incident_id, TASK_NAME)

    save_form_details(form_id, incident_id, user_verification_task_id)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
