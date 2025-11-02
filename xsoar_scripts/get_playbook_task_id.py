import requests

from my_config import get_config

CONFIG = get_config()
ticket_id = '1375188'
target_task_name = 'Acknowledge Ticket'
url = f'https://api-msoardev.crtx.us.paloaltonetworks.com/xsoar/investigation/{ticket_id}/workplan'
dev_headers = {
    'Authorization': CONFIG.xsoar_dev_auth_key,
    'x-xdr-auth-id': CONFIG.xsoar_dev_auth_id,
    'Content-Type': 'application/json'
}

response = requests.request("GET", url, headers=dev_headers)
tasks = response.json()['invPlaybook']['tasks']

print(f"Searching for task '{target_task_name}' in ticket {ticket_id}")
print(f"Total tasks in main playbook: {len(tasks)}\n")


# Recursive function to search through tasks and sub-playbooks
def search_tasks(tasks_dict, depth=0):
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


# Search through all tasks recursively
task_id = search_tasks(tasks)

if task_id:
    print(f"\n✅ Success! Found task '{target_task_name}' with ID: {task_id}")
else:
    print(f"\n❌ Task '{target_task_name}' not found in ticket {ticket_id}")
