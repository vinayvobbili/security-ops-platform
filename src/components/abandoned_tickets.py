import logging
import pandas as pd
import pytz
from webexpythonsdk import WebexAPI
import config
from services.xsoar import IncidentHandler

config = config.get_config()

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
    incident_fetcher = IncidentHandler()
    entries = incident_fetcher.get_entries(incident_id)  # Ensure `get_entries` fetches incident entries

    if not entries:
        return None  # No entries found

    last_entry = max(entries, key=lambda e: e.get("created", ""))
    return pd.to_datetime(last_entry.get("created")) if "created" in last_entry else None


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


def send_report():
    webex_api = WebexAPI(access_token=config.webex_bot_access_token_xsoar)
    room_id = config.webex_room_id_vinay_test_space

    today_minus_7 = pd.Timestamp.now(tz=eastern) - pd.Timedelta(days=7)

    query = f'-status:closed type:{config.ticket_type_prefix} -type:"{config.ticket_type_prefix} Third Party Compromise"'
    period = {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": None}
    tickets = IncidentHandler().get_tickets(query=query, period=period)

    if not tickets:
        logger.info("No tickets found.")
        return

    # Filter incidents where last entry was more than 7 days ago
    abandoned_tickets = [
        ticket for ticket in tickets if get_last_entry_date(ticket["id"]) and get_last_entry_date(ticket["id"]) < today_minus_7
    ]

    webex_api.messages.create(
        roomId=room_id,
        text="Abandoned Tickets Summary!",
        markdown=f'Abandoned Tickets Summary (Type=MTCIRT - TP, Last Touched=7+ days ago)\n ``` \n {generate_daily_summary(abandoned_tickets)}'
    )


def main():
    send_report()


if __name__ == "__main__":
    main()
