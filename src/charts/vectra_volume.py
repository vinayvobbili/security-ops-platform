from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from services.xsoar import IncidentHandler

eastern = pytz.timezone('US/Eastern')

CONFIG = get_config()

ROOT_DIRECTORY = Path(__file__).parent.parent.parent


def generate_chart(tickets):
    """
    Generates a chart showing Vectra ticket volume over time.

    Args:
        tickets (list): A list of ticket dictionaries.
    """
    if not tickets:
        print("No tickets found to generate chart.")
        return

    # Data Preparation
    try:
        df = pd.DataFrame(tickets)
        df['creation_date'] = pd.to_datetime(df['created']).dt.date  # Convert to date only
        daily_counts = df.groupby('creation_date').size().reset_index(name='Ticket Count')
        df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact'))
        impact_counts = df.groupby(['creation_date', 'impact']).size().reset_index(name='count')
    except (KeyError, ValueError) as e:
        print(f"Error processing ticket data: {e}")
        return

    # Define custom order and colors
    CUSTOM_IMPACT_ORDER = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "False Positive"]
    impact_colors = {
        "Significant": "#ff0000",  # Red
        "Confirmed": "#ffa500",  # Orange
        "Detected": "#ffd700",  # Gold
        "Prevented": "#008000",  # Green
        "Ignore": "#808080",  # Gray
        "Testing": "#add8e6",  # Light Blue
        "False Positive": "#90ee90",  # Light green
    }

    impacts = impact_counts['impact'].unique()
    sorted_impacts = [impact for impact in CUSTOM_IMPACT_ORDER if impact in impacts]

    # Prepare data for stacked bar chart
    impact_data_dict = {}
    for impact in sorted_impacts:
        impact_data = impact_counts[impact_counts['impact'] == impact]
        counts = []
        for date in daily_counts['creation_date']:
            count = impact_data.loc[impact_data['creation_date'] == date, 'count'].iloc[0] if date in impact_data['creation_date'].values else 0
            counts.append(count)
        impact_data_dict[impact] = counts

    # Create the figure and subplots
    fig, ax = plt.subplots(1, 1, figsize=(20, 12), sharex=True)
    fig.suptitle(f'Vectra', fontweight='bold', fontsize=14)
    ax.set_title(f'{len(tickets)} Tickets from past 3 months', fontsize=12)

    # Stacked Bar Chart (Vectra Ticket Volume)
    bottom = [0] * len(daily_counts['creation_date'])
    for impact in sorted_impacts:
        counts = impact_data_dict[impact]
        bars = ax.bar(daily_counts['creation_date'], counts, bottom=bottom, label=impact, color=impact_colors.get(impact, "#808080"), edgecolor="black", linewidth=0.3)
        for i, count in enumerate(counts):
            if count > 0:
                x_pos = daily_counts['creation_date'].iloc[i]
                y_pos = bottom[i] + count / 2
                ax.text(x_pos, y_pos, str(count), ha='center', va='center', color='black' if impact in ("Ignore", "Testing", "False Positive") else 'white', fontsize=10, fontweight='bold')
        bottom = [b + c for b, c in zip(bottom, counts)]

    legend = ax.legend(title='Impact', loc='upper right', fontsize=10, title_fontsize=12)
    legend.get_title().set_fontweight('bold')
    ax.set_xlabel('Detection Date', fontsize=10, fontweight='bold', labelpad=10)
    ax.set_ylabel('Alert Counts', fontweight='bold', fontsize=10, labelpad=10)
    ax.set_yticks(list(ax.get_yticks()))

    # Add an average solid line
    total_alerts = sum(sum(counts) for counts in impact_data_dict.values())
    num_days = len(daily_counts['creation_date'])
    if num_days > 0:
        average_alerts_per_day = total_alerts / num_days
        ax.axhline(y=average_alerts_per_day, color='red', linestyle='--', label=f'Avg: {average_alerts_per_day:.2f}')
        ax.legend()

    # Format x-axis as dates
    ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%m/%d/%Y'))
    plt.xticks(rotation=90)

    # Add the current time
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Customize the chart
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)
    plt.tight_layout()

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Vectra Volume.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    plt.savefig(OUTPUT_PATH, format='png', bbox_inches='tight', pad_inches=0.2, dpi=300)
    plt.close()


def make_chart(months_back=3):
    """
    Fetches tickets and generates a chart.

    Args:
        months_back (int): Number of months to look back for data.
    """
    try:
        query = f'type:"{CONFIG.team_name} Vectra Detection" -owner:""'
        period = {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": months_back}

        incident_fetcher = IncidentHandler()
        tickets = incident_fetcher.get_tickets(query, period)

        generate_chart(tickets)

    except Exception as e:
        print(f"Error fetching tickets or generating chart: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    make_chart()
