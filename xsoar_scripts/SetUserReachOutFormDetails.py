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


def main():
    """Find the conditional task ID and set it in context."""
    task_name = 'Does the user recognize the alert?'
    form_id = ''  # generate a random 10-digit number each time
    incident_id = incident().get('id')

    # Get tasks that are in progress
    in_progress_tasks = demisto.executeCommand("GetIncidentTasksByState", {
        'inc_id': incident_id,
        'states': 'inProgress'
    })
    user_verification_task_id = [task for task in in_progress_tasks if task.get('name') == task_name][0].get('id')




if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
