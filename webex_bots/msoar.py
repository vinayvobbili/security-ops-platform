import json

import requests
from webex_bot.models.command import Command
from webex_bot.models.response import Response
from webex_bot.webex_bot import WebexBot

metcirt_webex = demisto.executeCommand("getList", {
    "listName": "METCIRT Webex"
})[0]['Contents']
metcirt_webex = json.loads(metcirt_webex)
notification_room_id = metcirt_webex['channels']['new_ticket_notifs']
BOT_ACCESS_TOKEN = metcirt_webex['bot_access_token']
WEBEX_API_URL = metcirt_webex['api_url']

class ProcessAcknowledgement(Command):
    """confirm acknowledgement"""

    def __init__(self):
        super().__init__(
            command_keyword="process_acknowledgement",
            help_message="",
            card=None
        )

    def execute(self, message, attachment_actions, activity):

        # get acknowledger's details and set him as the owner of the incident
        acknowledger_emailAddress = activity['actor']['emailAddress']


        # close acknowledgement task
        waiting_tasks = demisto.executeCommand("GetIncidentTasksByState", {
            'inc_id': incident_id,
            'states': 'waiting'
        })
        waiting_tasks = waiting_tasks[0]['EntryContext']['Tasks']
        ack_task = [task for task in waiting_tasks if task['name'] == 'Acknowledge Ticket']
        ack_task_id = ack_task[0]['id']
        demisto.executeCommand("taskComplete", {
            'incidentId': incident_id,
            'id': ack_task_id
        })

def main():
    """the main"""

    bot = WebexBot(BOT_ACCESS_TOKEN)
    bot.add_command(ProcessAcknowledgement())
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()