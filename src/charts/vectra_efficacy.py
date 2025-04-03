from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from config import get_config
from services.xsoar import IncidentFetcher

CONFIG = get_config()

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
OUTPUT_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / "Vectra Alert Efficacy.png"


def generate_chart(tickets):
    """
    Generate and optionally save daily alert count chart with impact stacking

    Args:
        tickets: List of ticket data
        save_path: Optional path to save the chart image
    """
    if not tickets:
        print("No tickets found for the specified query.")
        return

    try:
        # Convert tickets to DataFrame
        df = pd.DataFrame(tickets)

        # Ensure 'created' is in datetime format
        df['created'] = pd.to_datetime(df['created'])

        # Extract just the date (no time component)
        df['date'] = df['created'].dt.date

        # Extract impact from CustomFields
        df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown'))

        # Define Colors for impacts
        impact_colors = {
            "Significant": "#ff0000",  # Red
            "Confirmed": "#ffa500",  # Orange
            "Detected": "#ffd700",  # Gold
            "Prevented": "#008000",  # Green
            "Ignore": "#808080",  # Gray
            "Testing": "#add8e6",  # Light Blue
            "False Positive": "#90ee90",  # Light green
            "Unknown": "#000000"  # Black for any missing values
        }

        # Check which impacts are present in the data
        present_impacts = df['impact'].unique()
        print(f"Impacts present in data: {present_impacts}")

        # Create pivot table: dates as rows, impacts as columns
        pivot_data = pd.pivot_table(
            df,
            index='date',
            columns='impact',
            aggfunc='size',
            fill_value=0
        )

        # Sort pivot table by date
        pivot_data = pivot_data.sort_index()

        # Limit the date range to the last 90 days to reduce the number of data points
        pivot_data = pivot_data.loc[pivot_data.index[-90:]]

        # Generate stacked bar chart
        plt.figure(figsize=(14, 8))

        # Get all present impact types
        impact_types = [imp for imp in impact_colors.keys() if imp in pivot_data.columns]

        # Create the stacked bar chart using only impacts that exist in our data
        bottom = np.zeros(len(pivot_data))
        bars = []
        bar_labels = []

        for impact in impact_types:
            if impact in pivot_data.columns:
                bar = plt.bar(
                    pivot_data.index,
                    pivot_data[impact],
                    bottom=bottom,
                    color=impact_colors[impact],
                    label=impact,
                    width=0.8
                )
                bottom += pivot_data[impact].values
                bars.append(bar)
                bar_labels.append(impact)

        # Format x-axis dates in MM/DD/YYYY format
        plt.gcf().autofmt_xdate()
        plt.xticks(rotation=45)
        ax = plt.gca()
        ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%m/%d/%Y'))

        # Set reasonable x-axis limits if there are many dates
        if len(pivot_data) > 20:
            # Show fewer x-ticks to avoid overcrowding
            plt.xticks(pivot_data.index[::5])

        # Set y-axis to start at 0
        max_height = bottom.max() if len(bottom) > 0 else 0
        plt.ylim(0, max_height * 1.1)

        # Add value labels on top of each stacked bar (total count)
        total_counts = pivot_data.sum(axis=1)
        for i, total in enumerate(total_counts):
            if total > 0:  # Only label bars with values
                plt.text(
                    i,
                    total + (max_height * 0.02),
                    f'{int(total)}',
                    ha='center',
                    va='bottom'
                )

        # Add labels and title
        plt.xlabel('Date')
        plt.ylabel('Alert Count')
        plt.title('Vectra Alerts by Date and Impact')

        # Add grid for better readability
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # Add legend with impact levels
        plt.legend(title='Impact Level')

        # Ensure there's enough space for labels
        plt.tight_layout()

        plt.savefig(OUTPUT_PATH, dpi=300, bbox_inches='tight')

    except Exception as e:
        print(f"Error generating chart: {e}")
        import traceback
        traceback.print_exc()


def make_chart(months_back=3, save_chart=True):
    """
    Fetch tickets and generate a chart

    Args:
        months_back: Number of months to look back for data
        save_chart: Whether to save the chart to file
    """
    try:
        query = f'type:"{CONFIG.ticket_type_prefix} Vectra Detection"'
        period = {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": months_back}

        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query, period)

        print(f"Retrieved {len(tickets)} tickets")

        generate_chart(tickets)

    except Exception as e:
        print(f"Error fetching tickets or generating chart: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    make_chart()
