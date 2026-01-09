import requests

from my_config import get_config

CONFIG = get_config()


# Recursive function to search through tasks and sub-playbooks
def search_tasks(tasks_dict, target_task_name, depth=0, ):
    indent = "  " * depth
    for k, v in tasks_dict.items():
        task_info = v.get('task', {})
        task_id = v.get('id')
        found_task_name = task_info.get('name')
        state = v.get('state', 'N/A')

        # Check if this is the task we're looking for
        if found_task_name == target_task_name:
            print(f"{indent}✓ FOUND!")
            print(f"{indent}  Task ID: {task_id}")
            print(f"{indent}  Name: {found_task_name}")
            print(f"{indent}  State: {state}")
            return task_id

        # Check if this task has a sub-playbook
        if 'subPlaybook' in v:
            sub_tasks = v.get('subPlaybook', {}).get('tasks', {})
            if sub_tasks:
                print(f"{indent}→ Searching sub-playbook '{found_task_name}' ({len(sub_tasks)} tasks)")
                result = search_tasks(sub_tasks, depth + 1)
                if result:
                    return result

    return None


def get_task_id(investigation_id, task_name):
    url = f'https://api-name.crtx.us.paloaltonetworks.com/xsoar/investigation/{investigation_id}/workplan'
    dev_headers = {
        'Authorization': CONFIG.xsoar_dev_auth_key,
        'x-xdr-auth-id': CONFIG.xsoar_dev_auth_id,
        'Content-Type': 'application/json'
    }

    response = requests.request("GET", url, headers=dev_headers)
    tasks = response.json()['invPlaybook']['tasks']

    print(f"Searching for task '{task_name}' in ticket {investigation_id}...\n")
    print(f"Total tasks in main playbook: {len(tasks)}\n")

    # Search through all tasks recursively
    task_id = search_tasks(tasks, target_task_name=task_name)

    if task_id:
        print(f"\n✅ Success! Found task '{task_name}' with ID: {task_id}")
    else:
        print(f"\n❌ Task '{task_name}' not found in ticket {investigation_id}")

    return search_tasks(tasks, target_task_name=task_name)


def main():
    ticket_id = '1377930'  # Example ticket ID
    target_task_name = "Does the employee recognize the alerted activity?"  # Example task name
    task_id = get_task_id(ticket_id, target_task_name)
    print(f"\nTask ID: {task_id}")


if __name__ == "__main__":
    main()
