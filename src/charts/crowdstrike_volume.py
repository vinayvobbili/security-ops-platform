import sys
from datetime import datetime
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import my_config as config
from services.xsoar import TicketHandler

eastern = pytz.timezone('US/Eastern')

CONFIG = config.get_config()

ROOT_DIRECTORY = Path(__file__).parent.parent.parent


def generate_chart(tickets):
    """
    Generates a chart showing CrowdStrike ticket volume over time.

    Args:
        tickets (list): A list of ticket dictionaries.
    """
    if not tickets:
        print("No tickets found to generate chart.")
        return

    # Data Preparation
    try:
        df = pd.DataFrame(tickets)
        # Use ISO8601 format to handle varying timestamp formats
        df['creation_date'] = pd.to_datetime(df['created'], format='ISO8601').dt.date  # Convert to date-only format
        daily_counts = df.groupby('creation_date').size().reset_index(name='Ticket Count')
        daily_counts = daily_counts.sort_values('creation_date')  # Ensure chronological order
        df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact'))
        impact_counts = df.groupby(['creation_date', 'impact']).size().reset_index(name='count')
    except (KeyError, ValueError) as e:
        print(f"Error processing ticket data: {e}")
        return

    # Enhanced color scheme with distinct, professional colors
    CUSTOM_IMPACT_ORDER = ["Malicious True Positive", "Significant", "Confirmed", "Detected", "Prevented", 
                          "False Positive", "Benign True Positive", "Security Testing", "Testing", "Ignore", "Unknown"]
    enhanced_impact_colors = {
        'Malicious True Positive': '#D32F2F',  # Red - Critical
        'Significant': '#E91E63',  # Pink - Significant impact
        'Confirmed': '#FF5722',  # Deep Orange - High impact
        'Detected': '#FF9800',  # Orange - Medium-high impact
        'Prevented': '#4CAF50',  # Green - Successfully prevented
        'False Positive': '#8BC34A',  # Light Green - False alarm
        'Benign True Positive': '#CDDC39',  # Lime - Benign but detected
        'Security Testing': '#00BCD4',  # Cyan - Security testing
        'Testing': '#2196F3',  # Blue - Testing phase
        'Ignore': '#795548',  # Brown - Ignored items
        'Unknown': '#9E9E9E',  # Grey - Unknown impact
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

    # Create enhanced figure with modern styling
    fig, ax = plt.subplots(1, 1, figsize=(22, 14), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')
    
    # Enhanced titles
    plt.suptitle('CrowdStrike Alert Volume',
                 fontsize=24, fontweight='bold', color='#1A237E', y=0.96)
    ax.set_title(f'{len(tickets)} Tickets from past 3 months (Avg: {len(tickets)/90:.1f} per day)',
                 fontsize=16, fontweight='bold', color='#3F51B5', pad=30)

    # Enhanced axes styling
    ax.set_facecolor('#ffffff')
    ax.grid(False)  # Remove gridlines for cleaner look
    ax.set_axisbelow(True)
    
    # Enhanced Stacked Bar Chart with better styling
    bottom = [0] * len(daily_counts['creation_date'])
    for impact in sorted_impacts:
        counts = impact_data_dict[impact]
        color = enhanced_impact_colors.get(impact, "#9E9E9E")
        ax.bar(daily_counts['creation_date'], counts, bottom=bottom, 
               label=impact, color=color, edgecolor='white', 
               linewidth=1.2, alpha=0.9)
        
        # Add count labels on bars
        for i, count in enumerate(counts):
            if count > 0:
                x_pos = daily_counts['creation_date'].iloc[i]
                y_pos = bottom[i] + count / 2
                # Smart text color based on background
                text_color = 'white' if impact in ['Malicious True Positive', 'Significant', 'Confirmed', 'Ignore'] else 'black'
                ax.text(x_pos, y_pos, str(count), ha='center', va='center', 
                       color=text_color, fontsize=10, fontweight='bold')
        bottom = [b + c for b, c in zip(bottom, counts)]

    # Enhanced legend with counts and better positioning
    impact_totals = {}
    for impact in sorted_impacts:
        total_count = sum(impact_data_dict[impact])
        impact_totals[impact] = total_count
    
    # Create legend labels with counts
    legend_labels = [f"{impact} ({impact_totals[impact]})" for impact in sorted_impacts]
    legend = ax.legend(labels=legend_labels, title='Impact', 
                      bbox_to_anchor=(1.02, 1), loc='upper left',
                      fontsize=12, title_fontsize=14,
                      frameon=True, fancybox=True, shadow=True)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)
    legend.get_title().set_fontweight('bold')
    legend.get_title().set_color('#1A237E')
    
    # Enhanced axis labels
    ax.set_xlabel('Detection Date', fontsize=14, fontweight='bold', 
                  labelpad=15, color='#1A237E')
    ax.set_ylabel('Alert Count', fontweight='bold', fontsize=14, 
                  labelpad=15, color='#1A237E')
    ax.set_yticks(list(ax.get_yticks()))

    # Enhanced average line
    total_alerts = sum(sum(counts) for counts in impact_data_dict.values())
    num_days = len(daily_counts['creation_date'])
    if num_days > 0:
        average_alerts_per_day = total_alerts / num_days
        ax.axhline(y=average_alerts_per_day, color='#E91E63', linestyle='--', 
                   linewidth=2, alpha=0.8, label=f'Daily Avg: {average_alerts_per_day:.1f}')

    # Enhanced x-axis formatting
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
    ax.tick_params(axis='x', rotation=45, colors='#1A237E', labelsize=11)
    ax.tick_params(axis='y', colors='#1A237E', labelsize=11)
    
    # Style the spines
    for spine in ax.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)

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

    # Enhanced timestamp and branding
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    fig.text(0.02, 0.02, f"Generated@ {now_eastern}", 
             ha='left', va='bottom', fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                      edgecolor='#1A237E', linewidth=1.5),
             transform=trans)
    
    # Add GS-DnR branding
    fig.text(0.98, 0.02, 'GS-DnR', ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold',
             transform=trans)
             
    # Enhanced layout adjustments
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.12, left=0.08, right=0.78)

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "CrowdStrike Volume.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    plt.savefig(OUTPUT_PATH, format='png', bbox_inches='tight', pad_inches=0, dpi=300, facecolor='#f8f9fa')
    plt.close()


def make_chart(months_back=3):
    """
    Fetches tickets and generates a chart.

    Args:
        months_back (int): Number of months to look back for data.
    """
    try:
        query = f'(type:"{CONFIG.team_name} CrowdStrike Falcon Detection" or type:"{CONFIG.team_name} CrowdStrike Falcon Incident") -owner:""'
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
