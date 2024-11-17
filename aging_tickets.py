import base64
import io
import logging

import matplotlib.pyplot as plt
import pandas as pd
from webex_bot.models.command import Command
from webex_bot.models.response import response_from_adaptive_card
from webexteamssdk.models.cards import AdaptiveCard, Image, TextBlock

from incident_fetcher import IncidentFetcher

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_plot(df: pd.DataFrame) -> str | None:
    """Generate a bar plot of open ticket types older than 30 days, returned as a base64 string."""

    if df.empty:
        return "No data available for plotting."

    try:
        with plt.style.context('default'):
            fig, ax = plt.subplots(figsize=(10, 6))  # Use fig, ax for better control

            tickets_by_type = df.groupby('type')['id'].count()
            tickets_by_type.plot(kind='bar', color='skyblue', width=0.7, ax=ax)

            ax.set_title(
                'Currently Open Tickets Created 30+ Days Ago',
                fontsize=14, fontweight='bold', pad=20
            )
            ax.set_xlabel('Ticket Type', fontsize=12, fontweight='bold')
            ax.set_ylabel('Count of Tickets', fontsize=12, fontweight='bold')
            ax.grid(axis='y', linestyle='--', alpha=0.7)

            ax.tick_params(axis='x', rotation=45, labelsize=10) # Rotate and size x-axis labels


            for i, v in enumerate(tickets_by_type):
                ax.text(i, v, str(v), ha='center', va='bottom', fontsize=10, fontweight='bold')

            fig.tight_layout()  # Improve spacing

            buffer = io.BytesIO()
            fig.savefig(buffer, format='png', dpi=300)  # Save figure directly to buffer
            plt.close(fig) # Close the figure after saving
            return base64.b64encode(buffer.read()).decode('utf-8')

    except Exception as e:
        logger.exception(f"Failed to generate plot: {e}")
        return None


def get_aging_tickets_card(tickets) -> AdaptiveCard:
    """Generate an Adaptive Card containing the aging tickets graph or an error message."""

    if not tickets:
        logger.warning("No tickets found.")
        return AdaptiveCard(body=[TextBlock(text="No aging tickets found.")]) # Simplified message

    try:
        df = pd.DataFrame(tickets['data'])
        image_base64 = generate_plot(df)
        print(image_base64)
        return AdaptiveCard(body=[Image(url=f"data:image/png;base64,{image_base64}")])

    except Exception as e:
        logger.exception(f"Failed to generate aging tickets graph: {e}")
        return AdaptiveCard(body=[TextBlock(text=str(e))])



class AgingTickets(Command):
    """Webex Bot command to display a graph of aging tickets."""

    def __init__(self):
        super().__init__(command_keyword="aging_tickets", help_message="Aging Tickets")

    def execute(self, message, attachment_actions, activity):
        query = "-status:closed -category:job type:METCIRT"
        period = {"byTo": "months", "toValue": 1, "byFrom": "months", "fromValue": None}

        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query=query, period=period)
        card = get_aging_tickets_card(tickets)
        return response_from_adaptive_card(card)