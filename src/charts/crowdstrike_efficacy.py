import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from services.xsoar import IncidentHandler
from src.data_maps import impact_colors

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# Constants
EASTERN_TZ = pytz.timezone('US/Eastern')
CONFIG = get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATE_FORMAT = '%m-%d-%Y'
TIMESTAMP_FORMAT = '%m/%d/%Y %I:%M %p %Z'


def process_tickets(tickets: List[Dict[str, Any]]) -> pd.DataFrame:
    """Process tickets to create a DataFrame with technique efficacy data."""
    technique_counts = {}

    for ticket in tickets:
        technique = ticket['CustomFields'].get('technique')[0]
        impact = ticket['CustomFields'].get('impact', 'Unknown')

        if technique not in technique_counts:
            technique_counts[technique] = {}

        technique_counts[technique][impact] = technique_counts[technique].get(impact, 0) + 1

    for technique, impacts in technique_counts.items():
        total = sum(impacts.values())
        confirmed = impacts.get('Confirmed', 0)
        testing = impacts.get('Testing', 0)
        prevented = impacts.get('Prevented', 0)
        noise = round((total - confirmed - testing - prevented) / total * 100) if total > 0 else 0
        technique_counts[technique]['Noise'] = noise

    df = pd.DataFrame.from_dict(technique_counts, orient='index').fillna(0)
    df['Total'] = df.sum(axis=1)
    df = df.sort_values(by='Total', ascending=False)
    df.index = df.index.astype(str)

    return df


def _save_chart(fig, output_filename: str) -> None:
    """Save the chart to the output directory."""
    today_date = datetime.now().strftime(DATE_FORMAT)
    output_dir = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_filename)
    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


class CrowdstrikeEfficacyChart:
    """Class to generate efficacy charts for different time periods."""

    def __init__(self):
        self.incident_fetcher = IncidentHandler()

    def get_tickets(self, period: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch tickets for the specified period."""
        query = f'(type:"{CONFIG.ticket_type_prefix} CrowdStrike Falcon Detection" or type:"{CONFIG.ticket_type_prefix} CrowdStrike Falcon Incident") -owner:""'
        try:
            tickets = self.incident_fetcher.get_tickets(query=query, period=period)
            if not tickets:
                log.warning("No tickets found matching the query.")
            return tickets
        except Exception as e:
            log.error(f"Error fetching tickets: {e}", exc_info=True)
            return []

    def create_chart(self, df: pd.DataFrame, title: str, time_period_label: str, output_filename: str) -> None:
        """Create and save a chart for the given DataFrame."""
        try:
            noise_series = df['Noise'].head(20)
            plot_df = df.head(20).drop(columns=['Noise', 'Total'])

            fig, ax = plt.subplots(figsize=(14, 8))
            plot_df.plot(
                kind='barh',
                stacked=True,
                ax=ax,
                color=[impact_colors.get(x, "#cccccc") for x in plot_df.columns]
            )

            ax.set_yticks(range(len(plot_df.index)))
            ax.set_yticklabels(plot_df.index.tolist())
            ax.legend(title="Impact", loc='upper right', fontsize=10, title_fontsize=10)

            # Add a thin black border around the figure
            fig.patch.set_edgecolor('black')
            fig.patch.set_linewidth(5)

            self._add_timestamp(fig)
            self._add_bar_labels(ax, plot_df)
            self._add_noise_labels(ax, plot_df, noise_series)

            plt.title(title, fontsize=12, pad=10, fontweight='bold', loc='left')
            plt.xlabel(f'Number of Tickets ({time_period_label})', fontsize=10, labelpad=10, fontweight='bold', loc='left')
            plt.ylabel('Detection Technique', fontweight='bold', fontsize=10)

            _save_chart(fig, output_filename)
        except Exception as e:
            log.error(f"Error creating chart: {e}", exc_info=True)

    @staticmethod
    def _add_timestamp(fig) -> None:
        """Add a timestamp to the chart."""
        now_eastern = datetime.now(EASTERN_TZ).strftime(TIMESTAMP_FORMAT)
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
        fig.text(0.02, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)
        fig.text(0.68, 0.01, 'Noise = (Total - Confirmed - Testing - Prevented) / Total * 100%',
                 ha='left', va='bottom', fontsize=10, transform=trans)

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
            ax.text(total_width, i, f'  {int(noise)}% noise', va='center', ha='left', fontsize=10)

    def generate_chart_for_period(self, period: Dict[str, Any], title: str, time_period_label: str, output_filename: str) -> None:
        """Generate a chart for the specified time period."""
        tickets = self.get_tickets(period)
        if not tickets:
            return

        df = process_tickets(tickets)
        self.create_chart(df, title, time_period_label, output_filename)

    def generate_all_charts(self) -> None:
        """Generate charts for all time periods (quarter, month, and week)."""
        chart_configs = [
            {
                "period": {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": 3},
                "title": "Crowdstrike Detection Efficacy (Top 20 Techniques by Alert Volume, past Quarter)",
                "time_period_label": "last 3 months",
                "output_filename": "CS Detection Efficacy-Quarter.png"
            },
            {
                "period": {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": 1},
                "title": "Crowdstrike Detection Efficacy (Top 20 Techniques by Alert Volume, past Month)",
                "time_period_label": "last 1 month",
                "output_filename": "CS Detection Efficacy-Month.png"
            },
            {
                "period": {"byTo": "days", "toValue": None, "byFrom": "days", "fromValue": 7},
                "title": "Crowdstrike Detection Efficacy (Top 20 Techniques by Alert Volume, past Week)",
                "time_period_label": "last 7 days",
                "output_filename": "CS Detection Efficacy-Week.png"
            }
        ]

        for config in chart_configs:
            self.generate_chart_for_period(**config)

        log.info(f"Successfully generated {len(chart_configs)} charts")


def make_chart() -> None:
    """Main function to generate all charts."""
    efficacy_chart = CrowdstrikeEfficacyChart()
    efficacy_chart.generate_all_charts()


if __name__ == '__main__':
    make_chart()
