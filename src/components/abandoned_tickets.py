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

webex_headers = {
    'Content-Type': 'application/json',
    'Authorization': f"Bearer {config.webex_bot_access_token_moneyball}"
}
eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone


def get_last_entry_date(incident_id):
    """Fetch the last touched date (last entry date) of an incident."""
    incident_fetcher = TicketHandler(XsoarEnvironment.PROD)
    user_notes = incident_fetcher.get_user_notes(incident_id)
    logger.debug(f'User entries: {user_notes}')

    if not user_notes:
        return None  # No entries found

    # user_notes is already sorted with the latest note first by get_user_notes
    latest_note = user_notes[0]
    # Convert the 'created_at' string (e.g., '12/10/2025 03:30 PM ET') to a datetime object
    created_at_str = latest_note.get("created_at", "").replace(' ET', '')
    if created_at_str:
        return pd.to_datetime(created_at_str, format='%m/%d/%Y %I:%M %p')
    return None


def generate_daily_summary(tickets) -> str | None:
    try:
        if not tickets:  # Check for empty list
            return pd.DataFrame(columns=['id', 'created', 'modified', 'owner']).to_markdown(index=False)

        df = pd.DataFrame(tickets)

        if 'owner' in df.columns:
            df['owner'] = df['owner'].fillna('Unassigned').astype(str).str.replace('@company.com', '', regex=False)
        else:
            df['owner'] = 'Unassigned'

        df['created'] = pd.to_datetime(df['created'], format='mixed')
        df['modified'] = pd.to_datetime(df['modified'], format='mixed')
        df['created'] = df['created'].dt.strftime('%m/%d/%Y')
        df['modified'] = df['modified'].dt.strftime('%m/%d/%Y')

        df = df[['id', 'created', 'modified', 'owner']]
        df = df.sort_values(by='modified', ascending=True)

        return df.to_markdown(index=False)

    except (TypeError, ValueError) as e:
        logger.error(f"Error generating daily summary: {e}")
        return "Error generating report. Please check the logs."


def send_report(room_id=config.webex_room_id_vinay_test_space):
    webex_api = WebexAPI(access_token=config.webex_bot_access_token_soar)

    today_minus_7 = datetime.now(tz=eastern) - timedelta(days=7)

    # Query for all open tickets (no time filter needed for abandoned tickets check)
    query = f'-status:closed type:{config.team_name} -type:"{config.team_name} Third Party Compromise" created:<{today_minus_7.strftime("%Y-%m-%d")}'
    logger.debug(f'Query for tickets: {query}')

    tickets = TicketHandler(XsoarEnvironment.PROD).get_tickets(query=query)
    logger.debug(f'Number of tickets found: {len(tickets)}')

    if not tickets:
        logger.info("No tickets found.")
        return

    # Filter incidents where last entry was more than 7 days ago
    abandoned_tickets = []
    for ticket in tickets:
        last_entry_date = get_last_entry_date(ticket["id"])
        if last_entry_date and last_entry_date < today_minus_7:
            abandoned_tickets.append(ticket)
    logger.info(f'Number of abandoned tickets found: {len(abandoned_tickets)}')

    if abandoned_tickets:
        daily_summary = generate_daily_summary(abandoned_tickets)
        logger.debug(f'Daily Summary:\n{daily_summary}')
        webex_api.messages.create(
            roomId=room_id,
            text="Abandoned Tickets Summary!",
            markdown=f'Abandoned Tickets Summary (Type=METCIRT - TP, Last Touched=7+ days ago)\n ``` \n {daily_summary}'
        )


def main():
    send_report()


if __name__ == "__main__":
    logger.setLevel(level=logging.DEBUG)
    main()
