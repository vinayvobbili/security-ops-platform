import json
import logging
from datetime import datetime
from typing import List, Dict, Any

import matplotlib.pyplot as plt
import matplotlib.transforms as transforms
import pandas as pd
import pytz
from webexpythonsdk import WebexAPI

import config
from constants import TICKET_TYPE_MAPPING
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

fun_messages = []
with open('data/fun_messages.json', 'r') as f:
    messages_data = json.load(f)
    fun_messages.extend(messages_data.get("messages", []))  # Modify the global list


def get_df(tickets: List[Dict[Any, Any]]) -> pd.DataFrame:
    if not tickets:
        return pd.DataFrame(columns=['created', 'type', 'phase'])

    df = pd.DataFrame(tickets)
    df['created'] = pd.to_datetime(df['created'])
    # Clean up type names by removing repeating prefix
    df['type'] = df['type'].str.replace(config.ticket_type_prefix, '', regex=False, case=False)
    df['type'] = df['type'].map(TICKET_TYPE_MAPPING).fillna(df['type'])
    # Set 'phase' to 'Unknown' if it's missing
    df['phase'] = df['phase'].fillna('Unknown')
    return df


def generate_plot(tickets):
    """Generate a bar plot of open ticket types older than 30 days, returned as a base64 string."""
    df = get_df(tickets)

    if df.empty:
        # Create a simple figure with a message
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.text(0.5, 0.5, 'No tickets found!',
                horizontalalignment='center',
                verticalalignment='center',
                transform=ax.transAxes,
                fontsize=12)
    else:
        # Group and count tickets by 'type' and 'phase'
        grouped_data = df.groupby(['type', 'phase']).size().unstack(fill_value=0)

        # Sort types by total count in descending order
        grouped_data['total'] = grouped_data.sum(axis=1)
        grouped_data = grouped_data.sort_values(by='total', ascending=False).drop(columns='total')

        colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#bcbd22', '#17becf', '#7f7f7f', '#ff9896']

        # Adjust figure size to control overall width
        fig, ax = plt.subplots(figsize=(8, 6))  # Example: plt.subplots(figsize=(10, 6)) makes 10 inches wide, 6 inches tall. Adjust these values.

        # Plotting
        grouped_data.plot(
            kind='bar',
            stacked=True,
            color=colors,
            edgecolor='black',
            ax=ax,
            width=0.1,  # Controls bar width
        )

        ax.set_yticks(range(0, int(grouped_data.sum(axis=1).max()) + 2))  # +2 ensures enough

    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.1, -0.1, now_eastern, transform=trans, ha='left', va='bottom', fontsize=8)

    # Annotate each segment of the stacked bars
    for container in ax.containers:  # ax.containers contains the bar segments
        for bar in container:
            height = bar.get_height()
            # Only annotate if height is non-zero
            if height > 0:  # Skip annotating bars with zero height
                ax.annotate(f'{int(height)}',  # just height is showing the decimal part too
                            xy=(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2),
                            xytext=(0, 3),  # 3 points vertical offset for better visibility. Adjust as needed
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=10, color='black', fontweight='bold')

    plt.title('Tickets created 30+ days ago', fontweight='bold')
    plt.xlabel('Type', fontweight='bold')
    plt.ylabel('Count', fontweight='bold')
    plt.xticks(rotation=0, ha='right', fontsize=8)  # Rotate X-axis labels by 45 degrees

    # Update legend
    plt.legend(title='Phase', loc='upper right')
    plt.tight_layout()

    plt.savefig('web/static/charts/Aging Tickets.png')
    plt.close(fig)


def make_chart():
    query = f'-status:closed -category:job type:{config.ticket_type_prefix} -type:"{config.ticket_type_prefix} Third Party Compromise"'
    period = {"byTo": "months", "toValue": 1, "byFrom": "months", "fromValue": None}

    tickets = IncidentFetcher().get_tickets(query=query, period=period)

    query = f'-status:closed -category:job type:"{config.ticket_type_prefix} Third Party Compromise"'
    period = {"byTo": "months", "toValue": 3, "byFrom": "months", "fromValue": None}
    tickets = tickets + IncidentFetcher().get_tickets(query=query, period=period)

    generate_plot(tickets)


def generate_daily_summary(tickets) -> str | None:
    try:
        if tickets is None:
            return pd.DataFrame(columns=['Owner', 'Count', 'Average Age (days)']).to_markdown(index=False)
        df = pd.DataFrame(tickets)
        df['owner'] = df['owner'].astype(str).str.replace('@company.com', '', regex=False)
        now = pd.Timestamp.now(tz=eastern)
        df['created'] = pd.to_datetime(df['created'])
        df['age'] = (now - df['created']).dt.days
        table = df.groupby('owner').agg({'id': 'count', 'age': 'mean'})
        table = table.reset_index()
        table = table.rename(columns={'owner': 'Owner', 'id': 'Count', 'age': 'Average Age (days)'})
        return table.to_markdown(index=False)
    except (KeyError, TypeError, ValueError) as e:  # Catch potential data errors
        logger.error(f"Error generating daily summary: {e}")  # Log the error
        return "Error generating report. Please check the logs."  # Return a user-friendly message


def send_report():
    webex_api = WebexAPI(access_token=config.webex_bot_access_token_xsoar)
    room_id = config.webex_room_id_aging_tickets
    # room_id = config.webex_room_id_vinay_test_space

    query = f'-status:closed -category:job type:{config.ticket_type_prefix} -type:"{config.ticket_type_prefix} Third Party Compromise"'
    period = {"byTo": "months", "toValue": 1, "byFrom": "months", "fromValue": None}
    tickets = IncidentFetcher().get_tickets(query=query, period=period)

    webex_api.messages.create(
        roomId=room_id,
        text=f"Aging Tickets Summary!",
        markdown=f'Summary (Type={config.ticket_type_prefix}* - TP, Created=30+ days ago)\n ``` \n {generate_daily_summary(tickets)}'
    )

    query = f'-status:closed -category:job type:"{config.ticket_type_prefix} Third Party Compromise"'
    period = {"byTo": "months", "toValue": 3, "byFrom": "months", "fromValue": None}
    tickets = IncidentFetcher().get_tickets(query=query, period=period)

    if tickets:
        webex_api.messages.create(
            roomId=room_id,
            text=f"Aging Tickets Summary!",
            markdown=f'Summary (Type=Third Party Compromise, Created=90+ days ago)\n ``` \n {generate_daily_summary(tickets)}'
        )


def main():
    make_chart()


if __name__ == "__main__":
    main()
