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

from data.data_maps import impact_colors
from my_config import get_config
from services.xsoar import TicketHandler

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
QR_RULE_NAMES_ABBREVIATION_FILE = root_directory / 'data' / 'metrics' / 'qr_rule_name_abbreviations.json'

with open(QR_RULE_NAMES_ABBREVIATION_FILE, 'r') as f:
    rule_name_abbreviations = json.load(f)


class QRadarEfficacyChart:
    """Class to generate QRadar rule efficacy charts for different time periods."""

    def __init__(self):
        """Initialize with ticket type prefix."""
        self.incident_fetcher = TicketHandler()

    def get_tickets(self, period: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch tickets for the specified period."""
        query = f'type:"{CONFIG.team_name} Qradar Alert" -owner:""'
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

            # Set empty or None impact to Unknown
            if not impact or impact.strip() == '':
                impact = 'Unknown'

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
        if unabbreviated_rules:
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

        # Set up enhanced plot style without grids
        plt.style.use('default')

        # Configure matplotlib fonts
        import matplotlib
        matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

        # Create enhanced figure with better proportions and styling
        fig, ax = plt.subplots(figsize=(20, 12), facecolor='#f8f9fa')
        fig.patch.set_facecolor('#f8f9fa')

        # Enhanced color scheme matching CrowdStrike chart
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
            '': '#BDBDBD',  # Light Grey - Undefined/empty
            None: '#BDBDBD',  # Light Grey - Null values
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

        # Plot with enhanced styling
        plot_df.plot(
            kind='barh',
            stacked=True,
            ax=ax,
            color=colors,
            edgecolor='white',
            linewidth=1.2,
            alpha=0.9
        )

        # Enhanced axes styling
        ax.set_facecolor('#ffffff')
        ax.grid(False)  # Explicitly disable grid
        ax.set_axisbelow(True)

        # Style the spines
        for spine in ax.spines.values():
            spine.set_color('#CCCCCC')
            spine.set_linewidth(1.5)

        # Set y-ticks with numeric positions
        y_labels = plot_df.index.tolist()
        ax.set_yticks(range(len(y_labels)))
        ax.set_yticklabels(y_labels, fontsize=10, color='#1A237E')

        # Enhanced legend with counts like CrowdStrike chart - only show impacts with counts > 0
        impact_totals = plot_df.sum(axis=0)
        legend_labels = []
        legend_handles = []
        for i, impact in enumerate(plot_df.columns):
            count = int(impact_totals.loc[impact])
            if count > 0:  # Only include impacts that have actual tickets
                legend_labels.append(f"{impact} ({count})")
                # Get the corresponding color patch from the original legend
                legend_handles.append(plt.Rectangle((0, 0), 1, 1, color=colors[i]))

        legend = ax.legend(handles=legend_handles, labels=legend_labels, title="Impact",
                           loc='upper left', bbox_to_anchor=(1.02, 1),
                           frameon=True, fancybox=True, shadow=True,
                           title_fontsize=12, fontsize=10)
        legend.get_frame().set_facecolor('white')
        legend.get_frame().set_alpha(0.95)
        legend.get_frame().set_edgecolor('#1A237E')
        legend.get_frame().set_linewidth(2)

        # Make legend title bold with CrowdStrike styling
        legend.get_title().set_fontweight('bold')
        legend.get_title().set_color('#1A237E')

        # Keep legend text normal weight like CrowdStrike chart
        for text in legend.get_texts():
            text.set_fontweight('normal')

        # Enhanced timestamp with modern styling
        now_eastern = datetime.now(EASTERN_TZ).strftime('%m/%d/%Y %I:%M %p %Z')
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)

        plt.text(0.02, 0.02, f"Generated@ {now_eastern}",
                 transform=trans, ha='left', va='bottom',
                 fontsize=10, color='#1A237E', fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                           edgecolor='#1A237E', linewidth=1.5))

        plt.text(0.68, 0.02, 'Noise = (Total - BTP - Testing) / Total * 100%',
                 transform=trans, ha='left', va='bottom',
                 fontsize=10, color='#1A237E', fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                           edgecolor='#1A237E', linewidth=1.5))

        # Add text labels to bars
        self._add_bar_labels(ax, plot_df)

        # Enhanced titles and labels
        plt.suptitle(title, fontsize=20, fontweight='bold', color='#1A237E', y=0.95)
        ax.set_xlabel(f'Number of Tickets ({time_period_label})', fontweight='bold',
                      fontsize=12, labelpad=10, color='#1A237E')
        ax.set_ylabel('Correlation Rule', fontweight='bold', fontsize=12, color='#1A237E')

        # Add noise percentage labels
        self._add_noise_labels(ax, plot_df, noise_series)

        # Enhanced border with rounded corners like other charts
        from matplotlib.patches import FancyBboxPatch
        border_width = 4
        fig.patch.set_edgecolor('none')
        fig.patch.set_linewidth(0)

        # Create border around the entire figure with increased width
        fancy_box = FancyBboxPatch(
            (-0.05, 0), width=1.1, height=1.0,
            boxstyle="round,pad=0,rounding_size=0.01",
            edgecolor='#1A237E',
            facecolor='none',
            linewidth=border_width,
            transform=fig.transFigure,
            zorder=-10,  # Put behind everything
            clip_on=False
        )
        fig.patches.append(fancy_box)

        # Add GS-DnR watermark
        fig.text(0.99, 0.01, 'GS-DnR',
                 ha='right', va='bottom', fontsize=10,
                 alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

        # Save the chart with enhanced layout
        today_date = datetime.now().strftime('%m-%d-%Y')
        output_dir = root_directory / "web" / "static" / "charts" / today_date
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / output_filename

        # Enhanced layout with space for external legend
        # Adjust layout with proper spacing for rule names and legend - expand plot area
        plt.tight_layout()
        plt.subplots_adjust(top=0.90, bottom=0.12, left=0.28, right=0.83)

        plt.savefig(output_path, format="png", dpi=300, bbox_inches='tight',
                    pad_inches=0, facecolor='#f8f9fa')
        plt.close(fig)  # Close the figure explicitly

    @staticmethod
    def _add_bar_labels(ax, df: pd.DataFrame) -> None:
        """Add value labels to bars."""
        for i, (index, row) in enumerate(df.iterrows()):
            left = 0
            for value in row.values:
                if int(value) > 0:
                    ax.text(left + value / 2, i, str(int(value)), ha='center', va='center')
                left += float(value)

    @staticmethod
    def _add_noise_labels(ax, df: pd.DataFrame, noise_series: pd.Series) -> None:
        """Add noise percentage labels."""
        for i, (index, noise) in enumerate(noise_series.items()):
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
            self.generate_chart_for_period(**config)


def send_charts() -> None:
    """Send chart via Webex."""
    recipient_email = CONFIG.efficacy_charts_receiver
    files = ['QR Rule Efficacy-Quarter.png', 'QR Rule Efficacy-Month.png', 'QR Rule Efficacy-Week.png']
    today_date = datetime.now().strftime('%m-%d-%Y')
    output_dir = root_directory / "web" / "static" / "charts" / today_date
    try:
        for file in files:
            webex.messages.create(toPersonEmail=recipient_email, files=[f'{output_dir / file}'])
        log.info(f"Chart sent to {recipient_email}")
    except Exception as e:
        log.error(f"Error sending chart: {e}", exc_info=True)


def make_chart() -> None:
    """Main function to generate all charts."""
    efficacy_chart = QRadarEfficacyChart()
    efficacy_chart.generate_all_charts()

    # Optionally send chart
    # send_chart(CONFIG.efficacy_charts_receiver, os.path.join(OUTPUT_DIR, 'QR Rule Efficacy-Quarter.png'))


if __name__ == '__main__':
    make_chart()
    # send_charts()
