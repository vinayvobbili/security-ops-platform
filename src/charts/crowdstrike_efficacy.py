import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms
from webexpythonsdk import WebexAPI

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import my_config as config
from data.data_maps import impact_colors
from services.xsoar import TicketHandler, XsoarEnvironment

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# Constants
EASTERN_TZ = pytz.timezone('US/Eastern')
CONFIG = config.get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATE_FORMAT = '%m-%d-%Y'
TIMESTAMP_FORMAT = '%m/%d/%Y %I:%M %p %Z'

webex = WebexAPI(access_token=CONFIG.webex_bot_access_token_moneyball)


def process_tickets(tickets: List[Dict[str, Any]]) -> pd.DataFrame:
    """Process tickets to create a DataFrame with alert name efficacy data."""
    alertname_counts = {}

    for ticket in tickets:
        alertname_field = ticket['CustomFields'].get('alertname', 'Unknown')
        # Handle if alertname is a list (like technique was)
        alertname = alertname_field[0] if isinstance(alertname_field, list) and alertname_field else alertname_field
        impact = ticket['CustomFields'].get('impact', 'Unknown')

        # Replace blank/empty impact with "Unknown" for clarity
        if not impact or impact.strip() == '':
            impact = 'Unknown'

        if alertname not in alertname_counts:
            alertname_counts[alertname] = {}

        alertname_counts[alertname][impact] = alertname_counts[alertname].get(impact, 0) + 1

    for alertname, impacts in alertname_counts.items():
        total = sum(impacts.values())
        confirmed = impacts.get('Confirmed', 0)
        testing = impacts.get('Security Testing', 0)
        prevented = impacts.get('Prevented', 0)
        malicious_true_positives = impacts.get('Malicious True Positive', 0)
        noise = round((total - confirmed - testing - prevented - malicious_true_positives) / total * 100) if total > 0 else 0
        alertname_counts[alertname]['Noise'] = noise

    df = pd.DataFrame.from_dict(alertname_counts, orient='index').fillna(0)
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

    # Enhanced layout adjustments - balanced space for bars and legend
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.12, left=0.25, right=0.78)  # Balanced space for bars and legend

    fig.savefig(output_path, dpi=300, bbox_inches='tight', pad_inches=0, facecolor='#f8f9fa')
    plt.close(fig)


class CrowdstrikeEfficacyChart:
    """Class to generate efficacy charts for different time periods."""

    def __init__(self):
        self.prod_incident_fetcher = TicketHandler(XsoarEnvironment.PROD)

    def get_tickets(self, days: int) -> List[Dict[str, Any]]:
        """Fetch tickets for the specified number of days using explicit timestamps."""
        # Calculate exact time window
        end_date = datetime.now(EASTERN_TZ).replace(hour=23, minute=59, second=59, microsecond=999999)
        start_date = end_date - timedelta(days=days)
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

        # Convert to UTC for API query
        start_str = start_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_str = end_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        query = f'(type:"{CONFIG.team_name} CrowdStrike Falcon Detection" or type:"{CONFIG.team_name} CrowdStrike Falcon Incident") -owner:"" created:>={start_str} created:<={end_str}'
        try:
            tickets = self.prod_incident_fetcher.get_tickets(query=query)
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

            # Enhanced color scheme with distinct, professional colors
            enhanced_impact_colors = {
                'Malicious True Positive': '#D32F2F',  # Red - Critical
                'Confirmed': '#FF5722',  # Deep Orange - High impact
                'Detected': '#FF9800',  # Orange - Medium-high impact
                'Testing': '#2196F3',  # Blue - Testing phase
                'Prevented': '#4CAF50',  # Green - Successfully prevented
                'False Positive': '#8BC34A',  # Light Green - False alarm
                'Benign True Positive': '#CDDC39',  # Lime - Benign but detected
                'Ignore': '#795548',  # Brown - Ignored items
                'Significant': '#E91E63',  # Pink - Significant impact
                'Security Testing': '#00BCD4',  # Cyan - Security testing
                'Unknown': '#9E9E9E',  # Grey - Unknown impact
                '': '#BDBDBD',  # Light Grey - Undefined/empty (shouldn't occur now)
                None: '#BDBDBD',  # Light Grey - Null values (shouldn't occur now)
            }

            # Use enhanced colors, fallback to original mapping, then default
            colors = []
            for col in plot_df.columns:
                if col in enhanced_impact_colors:
                    colors.append(enhanced_impact_colors[col])
                elif col in impact_colors:
                    colors.append(impact_colors[col])
                else:
                    colors.append('#CCCCCC')

            # Create larger figure with modern styling
            fig, ax = plt.subplots(figsize=(28, 14), facecolor='#f8f9fa')
            fig.patch.set_facecolor('#f8f9fa')

            # Enhanced plotting with better styling
            plot_df.plot(
                kind='barh',
                stacked=True,
                ax=ax,
                color=colors,
                edgecolor='white',
                linewidth=1.2,
                alpha=0.9
            )

            # Enhance the axes styling
            ax.set_facecolor('#ffffff')
            ax.grid(False)  # Remove gridlines for cleaner look
            ax.set_axisbelow(True)

            # Calculate totals for each alert name
            alertname_totals = plot_df.sum(axis=1)
            total_all_alertnames = int(alertname_totals.sum())

            # Enhanced y-axis labels
            y_labels = []
            for i, (idx, total) in enumerate(alertname_totals.items()):
                y_labels.append(f"{idx}")

            ax.set_yticks(range(len(plot_df.index)))
            ax.set_yticklabels(y_labels, fontsize=13, color='#1A237E', fontweight='bold')

            # Enhanced legend with counts and better positioning
            impact_totals = plot_df.sum(axis=0)
            legend_labels = []
            for impact in plot_df.columns:
                count = int(impact_totals.loc[impact])
                legend_labels.append(f"{impact} ({count})")

            legend = ax.legend(labels=legend_labels, title="Impact",
                               bbox_to_anchor=(1.05, 1), loc='upper left',
                               fontsize=13, title_fontsize=15,
                               frameon=True, fancybox=True, shadow=True)
            legend.get_frame().set_facecolor('white')
            legend.get_frame().set_alpha(0.95)
            legend.get_frame().set_edgecolor('#1A237E')
            legend.get_frame().set_linewidth(2)
            legend.get_title().set_fontweight('bold')
            legend.get_title().set_color('#1A237E')

            # Keep legend text normal weight to avoid clutter
            for text in legend.get_texts():
                text.set_fontweight('normal')

            # Enhanced border with rounded corners
            from matplotlib.patches import FancyBboxPatch
            border_width = 4
            fig.patch.set_edgecolor('none')
            fig.patch.set_linewidth(0)

            fancy_box = FancyBboxPatch(
                (0, 0), width=1.0, height=1.0,
                boxstyle="round,pad=0,rounding_size=0.01",
                edgecolor='#1A237E',
                facecolor='none',
                linewidth=border_width,
                transform=fig.transFigure,
                zorder=1000,
                clip_on=False
            )
            fig.patches.append(fancy_box)

            self._add_enhanced_timestamp(fig)
            self._add_bar_labels(ax, plot_df)
            self._add_noise_labels(ax, plot_df, noise_series)

            # Enhanced title and labels
            plt.suptitle('CrowdStrike Detection Efficacy',
                         fontsize=24, fontweight='bold', color='#1A237E', y=0.96)
            # Extract subtitle from original title and add total count
            if "(" in title:
                subtitle_part = title.split("(", 1)[1].rstrip(")")  # Remove trailing parenthesis
                plt.title(f'{subtitle_part} (Total: {total_all_alertnames})',
                          fontsize=16, fontweight='bold', color='#3F51B5', pad=30)
            else:
                plt.title(f'(Total: {total_all_alertnames})',
                          fontsize=16, fontweight='bold', color='#3F51B5', pad=30)
            plt.xlabel(f'Number of Tickets ({time_period_label})',
                       fontsize=14, labelpad=15, fontweight='bold', color='#1A237E')
            plt.ylabel('Alert Name', fontweight='bold',
                       fontsize=14, color='#1A237E')

            # Style the spines
            for spine in ax.spines.values():
                spine.set_color('#CCCCCC')
                spine.set_linewidth(1.5)

            # Enhanced tick styling
            ax.tick_params(axis='x', colors='#1A237E', labelsize=11, width=1.5)
            ax.tick_params(axis='y', colors='#1A237E', labelsize=11, width=1.5)

            _save_chart(fig, output_filename)
        except Exception as e:
            log.error(f"Error creating chart: {e}", exc_info=True)

    @staticmethod
    def _add_timestamp(fig) -> None:
        """Add a timestamp to the chart."""
        now_eastern = datetime.now(EASTERN_TZ).strftime(TIMESTAMP_FORMAT)
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
        fig.text(0.02, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)
        fig.text(0.68, 0.01, 'Noise = (Total - MTP - Testing) / Total * 100%',
                 ha='left', va='bottom', fontsize=10, transform=trans)

    @staticmethod
    def _add_enhanced_timestamp(fig) -> None:
        """Add an enhanced timestamp with styling and total count."""
        now_eastern = datetime.now(EASTERN_TZ).strftime(TIMESTAMP_FORMAT)
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)

        # Enhanced timestamp with background box
        fig.text(0.02, 0.02, f"Generated@ {now_eastern}",
                 ha='left', va='bottom', fontsize=10, color='#1A237E', fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                           edgecolor='#1A237E', linewidth=1.5),
                 transform=trans)

        # Enhanced noise formula with background
        fig.text(0.58, 0.02, 'Noise = (Total - Confirmed - Testing - Prevented) / Total × 100%',
                 ha='left', va='bottom', fontsize=10, color='#1A237E', fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                           edgecolor='#1A237E', linewidth=1.5),
                 transform=trans)

        # Add GS-DnR branding
        fig.text(0.98, 0.02, 'GS-DnR', ha='right', va='bottom', fontsize=10,
                 alpha=0.7, color='#3F51B5', style='italic', fontweight='bold',
                 transform=trans)

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
        for i, (idx, noise) in enumerate(noise_series.items()):
            total_width = float(df.iloc[i].sum())
            ax.text(total_width, i, f'  {int(noise)}% noise', va='center', ha='left', fontsize=10)

    def generate_chart_for_period(self, days: int, title: str, time_period_label: str, output_filename: str) -> None:
        """Generate a chart for the specified time period."""
        tickets = self.get_tickets(days)
        if not tickets:
            return

        df = process_tickets(tickets)
        self.create_chart(df, title, time_period_label, output_filename)

    def generate_all_charts(self) -> None:
        """Generate charts for all time periods (quarter, month, and week)."""
        chart_configs = [
            {
                "days": 90,
                "title": "Crowdstrike Detection Efficacy (Top 20 Alert Names by Alert Volume, past Quarter)",
                "time_period_label": "last 3 months",
                "output_filename": "CrowdStrike Detection Efficacy-Quarter.png"
            },
            {
                "days": 30,
                "title": "Crowdstrike Detection Efficacy (Top 20 Alert Names by Alert Volume, past Month)",
                "time_period_label": "last 1 month",
                "output_filename": "CrowdStrike Detection Efficacy-Month.png"
            },
            {
                "days": 7,
                "title": "Crowdstrike Detection Efficacy (Top 20 Alert Names by Alert Volume, past Week)",
                "time_period_label": "last 7 days",
                "output_filename": "CrowdStrike Detection Efficacy-Week.png"
            }
        ]

        for chart_config in chart_configs:
            self.generate_chart_for_period(**chart_config)


def send_charts() -> None:
    """Send chart via Webex."""
    recipient_email = CONFIG.efficacy_charts_receiver
    files = ['CrowdStrike Detection Efficacy-Quarter.png', 'CrowdStrike Detection Efficacy-Month.png', 'CrowdStrike Detection Efficacy-Week.png']
    today_date = datetime.now().strftime('%m-%d-%Y')
    output_dir = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date
    try:
        for file in files:
            webex.messages.create(toPersonEmail=recipient_email, files=[f'{output_dir / file}'])
        log.info(f"Chart sent to {recipient_email}")
    except Exception as e:
        log.error(f"Error sending chart: {e}", exc_info=True)


def make_chart() -> None:
    """Main function to generate all charts."""
    efficacy_chart = CrowdstrikeEfficacyChart()
    efficacy_chart.generate_all_charts()


if __name__ == '__main__':
    make_chart()
