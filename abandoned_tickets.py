import logging

import pandas as pd
import pytz
from webexpythonsdk import WebexAPI

import config
from incident_fetcher import IncidentFetcher

config = config.get_config()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

webex_headers = {
    'Content-Type': 'application/json',
    'Authorization': f"Bearer {config.webex_bot_access_token_moneyball}"
}
eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone


def generate_daily_summary(tickets) -> str | None:
    try:
        if tickets is None or not tickets:  # Check for None or empty list
            return pd.DataFrame(columns=['id', 'created', 'modified', 'owner']).to_markdown(index=False)

        df = pd.DataFrame(tickets)

        # Check if the 'owner' column exists before processing
        if 'owner' in df.columns:
            df['owner'] = df['owner'].fillna('Unassigned').astype(str).str.replace('@company.com', '', regex=False)
        else:
            df['owner'] = 'Unassigned'  # Add the 'owner' column if it doesn't exist
        df['created'] = pd.to_datetime(df['created'], format='mixed')  # Use 'mixed' format
        df['modified'] = pd.to_datetime(df['modified'], format='mixed')  # Use 'mixed' format
        df['created'] = pd.to_datetime(df['created']).dt.strftime('%m/%d/%Y')
        df['modified'] = pd.to_datetime(df['modified']).dt.strftime('%m/%d/%Y')

        df = df[['id', 'created', 'modified', 'owner']]  # Ensure columns are present, even if empty
        df = df.sort_values(by='modified', ascending=True)  # Sort by 'modified' date in ascending order

        return df.to_markdown(index=False)

    except (TypeError, ValueError) as e:  # KeyError is unlikely now
        logger.error(f"Error generating daily summary: {e}")
        return "Error generating report. Please check the logs."


def send_report():
    webex_api = WebexAPI(access_token=config.webex_bot_access_token_xsoar)
    room_id = config.webex_room_id_aging_tickets
    room_id = config.webex_room_id_vinay_test_space

    query = f'-status:closed -category:job type:{config.ticket_type_prefix} -type:"{config.ticket_type_prefix} Third Party Compromise" modified:<now-7d>'
    period = {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": None}
    tickets = IncidentFetcher().get_tickets(query=query, period=period)

    webex_api.messages.create(
        roomId=room_id,
        text=f"Abandoned Tickets Summary!",
        markdown=f'Abandoned Tickets Summary (Type=MTCIRT - TP, Last Modified=7+ days ago)\n ``` \n {generate_daily_summary(tickets)}'
    )


def main():
    send_report()


if __name__ == "__main__":
    main()
