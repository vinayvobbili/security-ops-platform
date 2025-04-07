import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms
from webexpythonsdk import WebexAPI

from config import get_config
from services.xsoar import IncidentHandler
from src.data_maps import impact_colors

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# Constants
EASTERN_TZ = pytz.timezone('US/Eastern')
CONFIG = get_config()
DATA_DIR = '../../data'
RULE_ABBR_FILE = os.path.join(DATA_DIR, 'rule_name_abbreviations.json')

# Initialize Webex API
webex = WebexAPI(access_token=CONFIG.webex_bot_access_token_moneyball)

# Load rule name abbreviations
root_directory = Path(__file__).parent.parent.parent
QR_RULE_NAMES_ABBREVIATION_FILE = root_directory / 'data' / 'rule_name_abbreviations.json'
today_date = datetime.now().strftime('%m-%d-%Y')
OUTPUT_DIR = root_directory / "web" / "static" / "charts" / today_date

with open(QR_RULE_NAMES_ABBREVIATION_FILE, 'r') as f:
    rule_name_abbreviations = json.load(f)


class QRadarEfficacyChart:
    """Class to generate QRadar rule efficacy charts for different time periods."""

    def __init__(self, ticket_type_prefix: str):
        """Initialize with ticket type prefix."""
        self.ticket_type_prefix = ticket_type_prefix
        self.incident_fetcher = IncidentHandler()

    def get_tickets(self, period: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch tickets for the specified period."""
        query = f'type:"{self.ticket_type_prefix} Qradar Alert" -owner:""'
        tickets = self.incident_fetcher.get_tickets(query=query, period=period)

        if not tickets:
            log.warning("No tickets found matching the query.")

        return tickets

    def process_tickets(self, tickets: List[Dict[str, Any]]) -> pd.DataFrame:
        """Process tickets to create a DataFrame with rule efficacy data."""
        correlation_rule_counts = {}

        # Count tickets by correlation rule and impact
        for ticket in tickets:
            correlation_rule = ticket['CustomFields'].get('correlationrule', 'Unknown')
            impact = ticket['CustomFields'].get('impact', 'Unknown')

            if correlation_rule not in correlation_rule_counts:
                correlation_rule_counts[correlation_rule] = {}

            if impact not in correlation_rule_counts[correlation_rule]:
                correlation_rule_counts[correlation_rule][impact] = 0

            correlation_rule_counts[correlation_rule][impact] += 1

        # Calculate noise percentage for each rule
        for rule, impacts in correlation_rule_counts.items():
            total = sum(impacts.values())
            confirmed = impacts.get('Confirmed', 0)
            testing = impacts.get('Testing', 0)
            prevented = impacts.get('Prevented', 0)

            noise = round((total - confirmed - testing - prevented) / total * 100) if total > 0 else 0
            correlation_rule_counts[rule]['Noise'] = noise

        # Log unabbreviated rule names
        unabbreviated_rules = self._find_unabbreviated_rules(list(correlation_rule_counts.keys()))
        log.info("Unabbreviated Rule Names:")
        for rule in unabbreviated_rules:
            log.info(rule)

        # Create and process DataFrame
        df = pd.DataFrame.from_dict(correlation_rule_counts, orient='index').fillna(0)
        df['Total'] = df.sum(axis=1)
        df = df.sort_values(by='Total', ascending=False)

        # Apply abbreviations to index
        for pattern, replacement in rule_name_abbreviations.items():
            df.index = df.index.str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

        # Convert index to a string type
        df.index = df.index.astype(str)

        return df

    @staticmethod
    def _find_unabbreviated_rules(rules: List[str]) -> List[str]:
        """Find rules that don't have abbreviations defined."""
        unabbreviated = []
        for rule in rules:
            found = False
            for pattern in rule_name_abbreviations.keys():
                if re.search(pattern, rule, re.IGNORECASE):
                    found = True
                    break
            if not found:
                unabbreviated.append(rule)
        return unabbreviated

    def create_chart(self, df: pd.DataFrame, title: str, time_period_label: str, output_filename: str) -> None:
        """Create and save a chart for the given DataFrame."""
        # Extract noise series and prepare data for plotting
        noise_series = df['Noise'].head(20)
        plot_df = df.head(20).drop(columns=['Noise', 'Total'])

        # Create figure and axis
        fig, ax = plt.subplots(figsize=(14, 8))

        # Plot with explicit index positions
        plot_df.plot(
            kind='barh',
            stacked=True,
            ax=ax,
            color=[impact_colors.get(x, "#cccccc") for x in plot_df.columns]
        )

        # Set y-ticks with numeric positions
        y_labels = plot_df.index.tolist()
        ax.set_yticks(range(len(y_labels)))
        ax.set_yticklabels(y_labels)

        # Add legend
        ax.legend(title="Impact", loc='upper right', fontsize=10, title_fontsize=10)

        # Add timestamp and formula explanation
        now_eastern = datetime.now(EASTERN_TZ).strftime('%m/%d/%Y %I:%M %p %Z')
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
        fig.text(0.02, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)
        fig.text(0.68, 0.01, 'Noise = (Total - Confirmed - Testing - Prevented) / Total * 100%',
                 ha='left', va='bottom', fontsize=10, transform=trans)

        # Add text labels to bars
        self._add_bar_labels(ax, plot_df)

        # Set titles and labels
        plt.title(title, fontsize=12, pad=10, fontweight='bold', loc='left')
        plt.xlabel(f'Number of Tickets ({time_period_label})', fontsize=10, labelpad=10, fontweight='bold', loc='left')
        plt.ylabel('Correlation Rule', fontweight='bold', fontsize=10)

        # Add noise percentage labels
        self._add_noise_labels(ax, plot_df, noise_series)

        # Add a thin black border around the figure
        fig.patch.set_edgecolor('black')
        fig.patch.set_linewidth(5)

        # Save the chart
        output_path = os.path.join(OUTPUT_DIR, output_filename)
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close(fig)  # Close the figure explicitly
        log.info(f"Chart saved to: {output_path}")

    @staticmethod
    def _add_bar_labels(ax, df: pd.DataFrame) -> None:
        """Add value labels to bars."""
        for i, row in enumerate(df.iterrows()):
            left = 0
            for value in row[1].values:
                if int(value) > 0:
                    ax.text(left + value / 2, i, str(int(value)), ha='center', va='center')
                left += float(value)

    @staticmethod
    def _add_noise_labels(ax, df: pd.DataFrame, noise_series: pd.Series) -> None:
        """Add noise percentage labels."""
        for i, noise in enumerate(noise_series):
            total_width = df.iloc[i].sum()
            # Make sure i is an integer index
            ax.text(total_width, i, f'  {int(noise)}% noise', va='center', ha='left', fontsize=10)

    def generate_chart_for_period(self, period: Dict[str, Any], title: str, time_period_label: str, output_filename: str) -> None:
        """Generate a chart for the specified time period."""
        try:
            tickets = self.get_tickets(period)
            if not tickets:
                return

            df = self.process_tickets(tickets)
            self.create_chart(df, title, time_period_label, output_filename)
        except Exception as e:
            log.error(f"Error generating chart for {time_period_label}: {e}", exc_info=True)

    def generate_all_charts(self) -> None:
        """Generate charts for all time periods (quarter, month, and week)."""
        # Define chart configurations
        chart_configs = [
            {
                "period": {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": 3},
                "title": "QR Rule Efficacy (Top 20 rules by Offense Volume, past Quarter)",
                "time_period_label": "last 3 months",
                "output_filename": "QR Rule Efficacy-Quarter.png"
            },
            {
                "period": {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": 1},
                "title": "QR Rule Efficacy (Top 20 rules by Offense Volume, past Month)",
                "time_period_label": "last 1 month",
                "output_filename": "QR Rule Efficacy-Month.png"
            },
            {
                "period": {"byTo": "days", "toValue": None, "byFrom": "days", "fromValue": 7},
                "title": "QR Rule Efficacy (Top 20 rules by Offense Volume, past Week)",
                "time_period_label": "last 7 days",
                "output_filename": "QR Rule Efficacy-Week.png"
            }
        ]

        # Generate charts for each configuration
        for config in chart_configs:
            log.info(f"Generating chart for {config['time_period_label']}...")
            self.generate_chart_for_period(**config)

        log.info(f"Successfully generated {len(chart_configs)} charts")


def send_charts() -> None:
    """Send chart via Webex."""
    recipient_email = CONFIG.qradar_efficacy_chart_receiver
    files = ['QR Rule Efficacy-Quarter.png', 'QR Rule Efficacy-Month.png', 'QR Rule Efficacy-Week.png']
    try:
        for file in files:
            webex.messages.create(toPersonEmail=recipient_email, files=[f'{OUTPUT_DIR / file}'])
        log.info(f"Chart sent to {recipient_email}")
    except Exception as e:
        log.error(f"Error sending chart: {e}", exc_info=True)


def make_chart() -> None:
    """Main function to generate all charts."""
    efficacy_chart = QRadarEfficacyChart(ticket_type_prefix=CONFIG.ticket_type_prefix)
    efficacy_chart.generate_all_charts()

    # Optionally send chart
    # send_chart(CONFIG.qradar_efficacy_chart_receiver, os.path.join(OUTPUT_DIR, 'QR Rule Efficacy-Quarter.png'))


if __name__ == '__main__':
    make_chart()
    # send_charts()
