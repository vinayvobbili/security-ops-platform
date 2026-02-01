import logging
from datetime import datetime, timedelta

import pandas as pd
import pytz
from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar import TicketHandler, XsoarEnvironment

config = get_config()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone
NOTE_MAX_LENGTH = 50  # Maximum length for note text in summary table


def get_last_entry_details(incident_id):
    """Fetch the last touched date (last entry date) and note content of an incident."""
    incident_fetcher = TicketHandler(XsoarEnvironment.PROD)
    user_notes = incident_fetcher.get_user_notes(incident_id)
    logger.debug(f'User entries: {user_notes}')

    if not user_notes:
        return None, None  # No entries found

    # user_notes is already sorted with the latest note first by get_user_notes
    latest_note = user_notes[0]
    # Convert the 'created_at' string (e.g., '12/10/2025 03:30 PM ET') to a datetime object
    created_at_str = latest_note["created_at"]
    note_content = latest_note.get("note_text", "")
    try:
        last_entry_date = datetime.strptime(created_at_str, '%m/%d/%Y %I:%M %p ET')
        last_entry_date = eastern.localize(last_entry_date)
        return last_entry_date, note_content
    except ValueError as e:
        logger.error(f"Error parsing date '{created_at_str}' for incident {incident_id}: {e}")
        return None, None


def generate_daily_summary(tickets) -> str | None:
    try:
        if not tickets:  # Check for empty list
            return pd.DataFrame(columns=['id', 'created', 'last note', 'owner', 'note']).to_markdown(index=False)

        df = pd.DataFrame(tickets)

        if 'owner' in df.columns:
            df['owner'] = df['owner'].fillna('Unassigned').astype(str).str.replace(f'@{config.my_web_domain}', '', regex=False)
        else:
            df['owner'] = 'Unassigned'

        df['created'] = pd.to_datetime(df['created'], format='mixed')
        df['last_entry_date'] = pd.to_datetime(df['last_entry_date'], format='mixed')
        df['created'] = df['created'].dt.strftime('%m/%d/%Y')
        df['last_entry_date'] = df['last_entry_date'].dt.strftime('%m/%d/%Y')

        # Remove newline characters and truncate note to maximum length
        df['note'] = df['note'].fillna('').astype(str).str.replace('\n', ' ').str.replace('\r', ' ').apply(lambda x: x[:NOTE_MAX_LENGTH] + '...' if len(x) > NOTE_MAX_LENGTH else x)

        # Rename column for display to save space
        df = df[['id', 'created', 'last_entry_date', 'owner', 'note']]
        df = df.rename(columns={'last_entry_date': 'last note'})
        df = df.sort_values(by='last note', ascending=True)

        return df.to_markdown(index=False)

    except (TypeError, ValueError) as e:
        logger.error(f"Error generating daily summary: {e}")
        return "Error generating report. Please check the logs."


def send_report(room_id=config.webex_room_id_dev_test_space):
    webex_api = WebexAPI(access_token=config.webex_bot_access_token_soar)

    today_minus_5 = datetime.now(tz=eastern) - timedelta(days=5)

    # Query for all open tickets (no time filter needed for abandoned tickets check)
    query = f'-status:closed type:{config.team_name} -type:"{config.team_name} Third Party Compromise" created:<{today_minus_5.strftime("%Y-%m-%d")}'
    logger.debug(f'Query for tickets: {query}')

    tickets = TicketHandler(XsoarEnvironment.PROD).get_tickets(query=query)
    logger.debug(f'Number of tickets found: {len(tickets)}')

    if not tickets:
        logger.info("No tickets found.")
        webex_api.messages.create(
            roomId=room_id,
            text="No abandoned tickets today!",
            markdown="🎉 **Zero abandoned tickets today!** 🎊\n\nAll tickets are being actively worked. Keep it up! 💪"
        )
        return

    # Filter incidents where last entry was more than 5 days ago
    abandoned_tickets = []
    for ticket in tickets:
        last_entry_date, note_content = get_last_entry_details(ticket["id"])
        if last_entry_date and last_entry_date < today_minus_5:
            ticket["last_entry_date"] = last_entry_date
            ticket["note"] = note_content or ""
            abandoned_tickets.append(ticket)
    logger.info(f'Number of abandoned tickets found: {len(abandoned_tickets)}')

    if abandoned_tickets:
        daily_summary = generate_daily_summary(abandoned_tickets)
        logger.debug(f'Daily Summary:\n{daily_summary}')
        webex_api.messages.create(
            roomId=room_id,
            text="Abandoned Tickets!",
            markdown=f'**Abandoned Tickets** (Type={config.team_name} - TP, Last Touched=5+ days ago)\n ``` \n {daily_summary}'
        )
    else:
        webex_api.messages.create(
            roomId=room_id,
            text="No abandoned tickets today!",
            markdown="🎉 **Zero abandoned tickets today!** 🎊\n\nAll tickets are being actively worked. Keep it up! 💪"
        )


def main():
    send_report(room_id=config.webex_room_id_dev_test_space)


if __name__ == "__main__":
    logger.setLevel(level=logging.DEBUG)
    main()
