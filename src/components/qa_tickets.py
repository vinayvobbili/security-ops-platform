"""
qa_tickets.py

This module automates the creation of QA (Quality Assurance) tickets for closed METCIRT tickets in XSOAR and notifies designated QA leads via Webex.

Main Features:
- Fetches recently closed METCIRT tickets (excluding job category and those with owners).
- Groups tickets by their impact level.
- Randomly selects a ticket from each impact group and assigns it to a QA lead in a round-robin fashion.
- QA leads are loaded from and rotated in a JSON file (data/qa_leads.json) to ensure fair distribution.
- Creates a new QA ticket in XSOAR with relevant details and custom fields.
- Notifies the assigned QA lead in a specified Webex room with a direct link to the QA ticket.

Usage:
- Can be run as a script, using the configured Webex room for notifications.
- Intended for use in automation or scheduled QA review processes.
- To update the QA leads, edit the data/qa_leads.json file directly.

Dependencies:
- webexpythonsdk
- config.py (for configuration)
- services.xsoar (for ticket handling)
- data/qa_leads.json (for QA lead rotation)

"""

import json
import os
import random
from datetime import datetime, timedelta

from tabulate import tabulate
from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar import TicketHandler

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)

qa_leads_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'transient', 're', 'qa_leads.json')


def load_qa_leads():
    with open(qa_leads_file_path, 'r') as f:
        return json.load(f), qa_leads_file_path


def save_qa_leads(leads):
    with open(qa_leads_file_path, 'w') as f:
        json.dump(leads, f, indent=4)


def summarize_tickets_by_impact(tickets):
    summary = {}
    for ticket in tickets:
        impact = ticket['CustomFields'].get('impact', 'Unknown')
        summary[impact] = summary.get(impact, 0) + 1
    return summary


def format_summary_message(summary, total):
    table = [(impact, count) for impact, count in summary.items()]
    md_table = tabulate(table, headers=["Impact", "Count"], tablefmt="github")
    return f"**Tickets Closed This Week: {total}**\n\n```\n{md_table}\n```"


def generate(room_id):
    try:
        ticket_handler = TicketHandler()
        # Calculate the start of the week (previous Sunday)
        # Since this script runs on Saturday, we go back 6 days to get to Sunday
        today = datetime.now()
        week_start = today - timedelta(days=6)  # Saturday (6) back to Sunday (0)
        week_start_str = week_start.strftime('%Y-%m-%dT00:00:00 -0400')

        query = f'status:closed -category:job type:METCIRT -owner:"" closed:>="{week_start_str}"'

        tickets = ticket_handler.get_tickets(query)
        if not tickets:
            print("No METCIRT tickets were closed this week. Not creating QA tickets this week...")
            return
        # --- Summary logic ---
        summary = summarize_tickets_by_impact(tickets)
        total = len(tickets)
        summary_message = format_summary_message(summary, total)
        webex_api.messages.create(room_id, markdown=summary_message)
        # --- End summary logic ---

        tickets_by_impact = {}
        for ticket in tickets:
            impact = ticket['CustomFields'].get('impact', 'Unknown')
            tickets_by_impact.setdefault(impact, []).append(ticket)

        qa_leads, leads_path = load_qa_leads()
        lead_index = 0
        for impact, group in tickets_by_impact.items():
            if impact == 'Security Testing':
                continue  # Skip QA ticket creation for 'Security Testing' impact
            source_ticket = random.choice(group)
            owner = qa_leads[lead_index % len(qa_leads)]
            detectionsource = source_ticket.get('CustomFields').get('detectionsource', 'Unknown')
            if not detectionsource:
                detectionsource = 'Unknown'
            new_ticket_payload = {
                'type': 'METCIRT Ticket QA',
                'owner': owner,
                'name': 'QA ticket for --> ' + source_ticket.get('name'),
                'details': source_ticket.get('details'),
                'CustomFields': {
                    'detectionsource': detectionsource,
                    'isusercontacted': False,
                    'securitycategory': 'CAT-7: Investigation',
                    'businessservicesprovided': 'Unknown',
                    'isbusinessimpacted': False,
                    'thirdparty': 'unknown'
                }
            }
            print(f"new_ticket_payload: {new_ticket_payload}")  # Debug: print payload before sending
            qa_ticket = ticket_handler.create(new_ticket_payload)
            print(f"qa_ticket: {qa_ticket}")  # Debug: print the created ticket object
            if isinstance(qa_ticket, dict) and 'error' in qa_ticket:
                print(f"Ticket creation failed: {qa_ticket['error']}")
                continue
            if 'id' not in qa_ticket:
                print("Ticket creation failed: No 'id' in response.")
                continue
            ticket_handler.link_tickets(qa_ticket['id'], source_ticket['id'])
            ticket_handler.add_participant(qa_ticket['id'], source_ticket['owner'])
            qa_ticket_url = CONFIG.xsoar_prod_ui_base_url + "/Custom/caseinfoid/" + qa_ticket['id']
            source_ticket_url = CONFIG.xsoar_prod_ui_base_url + "/Custom/caseinfoid/" + source_ticket['id']
            webex_api.messages.create(room_id,
                                      markdown=f"Hello <@personEmail:{owner}>👋🏾\n[X#{qa_ticket['id']}]({qa_ticket_url}) has been assigned to you for QA\nSource ticket-->\nID: [X#{source_ticket['id']}]({source_ticket_url})\nType: {source_ticket['type']}\nImpact: {impact}")
            lead_index += 1
        qa_leads = qa_leads[lead_index % len(qa_leads):] + qa_leads[:lead_index % len(qa_leads)]
        save_qa_leads(qa_leads)
    except Exception as e:
        import traceback
        print(f"Error while generating QA tickets: {e}")
        traceback.print_exc()
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"API response: {e.response.text}")


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    generate(room_id)
