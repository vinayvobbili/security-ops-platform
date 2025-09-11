from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from my_config import get_config
from services.xsoar import TicketHandler

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

    # Define custom order and enhanced colors (matching CrowdStrike chart)
    custom_impact_order = ["Malicious True Positive", "Significant", "Confirmed", "Detected", "Prevented",
                           "False Positive", "Benign True Positive", "Security Testing", "Testing", "Ignore"]
    enhanced_impact_colors = {
        'Malicious True Positive': '#D32F2F',  # Red - Critical
        'Significant': '#E91E63',  # Pink - Significant impact
        'Confirmed': '#FF5722',  # Deep Orange - High impact
        'Detected': '#FF9800',  # Orange - Medium-high impact
        'Prevented': '#4CAF50',  # Green - Successfully prevented
        'False Positive': '#AB47BC',  # Purple - False alarm (problematic)
        'Benign True Positive': '#FFA726',  # Orange - Benign but still noise
        'Security Testing': '#00BCD4',  # Cyan - Security testing
        'Testing': '#2196F3',  # Blue - Testing
        'Ignore': '#9E9E9E',  # Gray - Ignored
    }

    impacts = impact_counts['impact'].unique()
    sorted_impacts = [impact for impact in custom_impact_order if impact in impacts]

    # Prepare data for stacked bar chart
    impact_data_dict = {}
    for impact in sorted_impacts:
        impact_data = impact_counts[impact_counts['impact'] == impact]
        counts = []
        for date in daily_counts['creation_date']:
            count = impact_data.loc[impact_data['creation_date'] == date, 'count'].iloc[0] if date in impact_data['creation_date'].values else 0
            counts.append(count)
        impact_data_dict[impact] = counts

    # Create enhanced figure with modern styling
    fig, ax = plt.subplots(1, 1, figsize=(22, 14), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Enhanced titles with MetLife branding
    plt.suptitle('Vectra',
                 fontsize=24, fontweight='bold', color='#1A237E', y=0.96)
    ax.set_title(f'{len(tickets)} Tickets from past 3 months',
                 fontsize=16, color='#3F51B5', fontweight='bold', pad=20)

    # Stacked Bar Chart (Vectra Ticket Volume)
    bottom = [0] * len(daily_counts['creation_date'])
    for impact in sorted_impacts:
        counts = impact_data_dict[impact]
        bars = ax.bar(daily_counts['creation_date'], counts, bottom=bottom, label=impact, color=enhanced_impact_colors.get(impact, "#808080"), edgecolor="black", linewidth=0.3)
        for i, count in enumerate(counts):
            if count > 0:
                x_pos = daily_counts['creation_date'].iloc[i]
                y_pos = bottom[i] + count / 2
                ax.text(x_pos, y_pos, str(count), ha='center', va='center', color='black' if impact in ("Ignore", "Testing", "False Positive") else 'white', fontsize=10, fontweight='bold')
        bottom = [b + c for b, c in zip(bottom, counts)]

    # Enhanced legend with MetLife styling - positioned outside chart area
    legend = ax.legend(title='Impact', bbox_to_anchor=(1.02, 1), loc='upper left',
                       fontsize=12, title_fontsize=14, frameon=True, fancybox=True, shadow=True)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)
    legend.get_title().set_fontweight('bold')
    legend.get_title().set_color('#1A237E')

    # Enhanced axis labels
    ax.set_xlabel('Detection Date', fontsize=14, fontweight='bold',
                  labelpad=15, color='#1A237E')
    ax.set_ylabel('Alert Counts', fontweight='bold', fontsize=14,
                  labelpad=15, color='#1A237E')
    # Set Y-axis to show only integer values and add extra space at top
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    current_ylim = ax.get_ylim()
    ax.set_ylim(current_ylim[0], current_ylim[1] + 1)

    # Add an average solid line
    total_alerts = sum(sum(counts) for counts in impact_data_dict.values())
    num_days = len(daily_counts['creation_date'])
    if num_days > 0:
        average_alerts_per_day = total_alerts / num_days
        ax.axhline(y=average_alerts_per_day, color='red', linestyle='--', label=f'Avg: {average_alerts_per_day:.2f}')

    # Format x-axis as dates with increased frequency
    ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%m/%d/%Y'))
    ax.xaxis.set_major_locator(plt.matplotlib.dates.DayLocator(interval=2))  # Show every 2 days
    plt.xticks(rotation=90)

    # Adjust layout FIRST to make room for legend - expand chart area
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.12, left=0.08, right=0.85)

    # Add MetLife branding elements
    from matplotlib.patches import FancyBboxPatch

    # Add decorative border
    fancy_box = FancyBboxPatch((0.01, 0.01), 0.98, 0.98,
                               boxstyle="round,pad=0.02",
                               facecolor='none',
                               edgecolor='#1A237E',
                               linewidth=3,
                               transform=fig.transFigure)
    fig.patches.append(fancy_box)

    # Enhanced timestamp and branding
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    fig.text(0.02, 0.02, f"Generated {now_eastern}",
             ha='left', va='bottom', fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.2", facecolor='white', alpha=0.9,
                       edgecolor='#1A237E', linewidth=1.5),
             transform=trans)

    # Add GS-DnR branding
    fig.text(0.98, 0.02, 'GS-DnR', ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold',
             transform=trans)

    today_date = datetime.now().strftime('%m-%d-%Y')
    output_path = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Vectra Volume.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    plt.savefig(output_path, format='png', bbox_inches='tight', pad_inches=0, dpi=300)
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

        incident_fetcher = TicketHandler()
        tickets = incident_fetcher.get_tickets(query, period)

        generate_chart(tickets)

    except Exception as e:
        print(f"Error fetching tickets or generating chart: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    make_chart()
