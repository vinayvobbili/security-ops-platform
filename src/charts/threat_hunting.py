from datetime import datetime

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib import transforms

import services.azdo as azdo

eastern = pytz.timezone('US/Eastern')


def process_hunt_data(hunt_details):
    """Process raw hunt data into a structured DataFrame."""
    processed_data = []

    for hunt in hunt_details:
        created_date = datetime.strptime(hunt.fields['System.CreatedDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        week = created_date.strftime('%m/%d/%y')
        priority = hunt.fields['Microsoft.VSTS.Common.Priority']

        # Map numeric priority to text labels
        priority_labels = {1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low'}
        priority_text = priority_labels.get(priority, 'Unknown')

        processed_data.append({
            'Week': week,
            'WeekDate': created_date,
            'Priority': priority_text,
            'Ticket': hunt.fields.get('System.Id', ''),
            'Title': hunt.fields.get('System.Title', ''),
            'XSOAR_Link': hunt.fields.get('XSOAR_Link', '')
        })

    return pd.DataFrame(processed_data)


def create_summary_data(df):
    """Create summary data for the bar chart."""
    # Group by week and priority, count occurrences
    summary = df.groupby(['Week', 'Priority']).size().unstack(fill_value=0)

    # Convert string dates to datetime objects for better plotting
    summary.index = pd.to_datetime(summary.index, format='%m/%d/%y')
    summary = summary.sort_index()

    # Ensure all priority columns exist
    for priority in ['Critical', 'High', 'Medium', 'Low']:
        if priority not in summary.columns:
            summary[priority] = 0

    # Calculate total hunts per week
    summary['Total'] = summary.sum(axis=1)

    return summary


def plot_stacked_bar(fig, summary_data, colors, priority_counts):
    """Create the stacked bar chart."""
    # Create chart area taking up most of the figure
    chart_ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

    bottom = np.zeros(len(summary_data.index))
    handles = []
    labels = []

    # Plot each priority level - reversed order to match example (Low at bottom)
    for priority in ['Low', 'Medium', 'High', 'Critical']:
        if priority in summary_data.columns:
            bars = chart_ax.bar(summary_data.index, summary_data[priority], bottom=bottom,
                                label=f"{priority} ({priority_counts.get(priority, 0)})", color=colors[priority])
            handles.append(bars[0])
            labels.append(f"{priority} ({priority_counts.get(priority, 0)})")
            bottom += np.array(summary_data[priority])

    # Format the x-axis with better date spacing
    chart_ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d/%y'))
    plt.setp(chart_ax.get_xticklabels(), rotation=45, ha='right')

    # Add data labels for total counts in the middle of the bars
    for i, (date, row) in enumerate(summary_data.iterrows()):
        total_height = 0
        for priority in ['Low', 'Medium', 'High', 'Critical']:
            if priority in summary_data.columns and row[priority] > 0:
                total_height += row[priority]
        if row['Total'] > 0:
            chart_ax.text(mdates.date2num(date), total_height / 2, str(int(row['Total'])),
                          ha='center', va='center', fontweight='bold')

    # Add labels and title
    chart_ax.set_title('Weekly Threat Hunts by Priority', fontsize=16, fontweight='bold', pad=20)
    chart_ax.set_xlabel('Week', fontsize=12)
    chart_ax.set_ylabel('Number of Threat Hunts', fontsize=12)
    chart_ax.grid(axis='y', linestyle='-', alpha=0.2)

    # Add legend in upper left with updated labels
    chart_ax.legend(handles, labels, title='Priority', loc='upper left')

    # Add some padding at the top for the total labels
    y_max = max(summary_data['Total'].max() * 1.15, 4)  # At least 4, or 15% above max
    chart_ax.set_ylim(0, y_max)

    return chart_ax


def generate_threat_hunt_report(hunt_details, output_file='weekly_threat_hunts_legend_counts.png'):
    """Main function to generate the threat hunt report with counts in the legend."""
    # Define priority colors to match the example
    colors = {
        'Critical': '#ef4444',  # Red
        'High': '#f97316',  # Orange
        'Medium': '#fbbf24',  # Yellow
        'Low': '#60a5fa'  # Blue
    }

    # Process data
    df = process_hunt_data(hunt_details)
    summary_data = create_summary_data(df)

    # Calculate total counts for each priority
    priority_counts = df['Priority'].value_counts().to_dict()

    # Create figure
    fig = plt.figure(figsize=(10, 6))  # Adjust figure size as needed

    # Create the main chart axes
    plot_stacked_bar(fig, summary_data, colors, priority_counts)

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.02, -0.1, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Save with tight layout and display
    plt.savefig(output_file, dpi=300, bbox_inches='tight')


if __name__ == "__main__":
    # Get hunt details from Azure DevOps
    hunt_details = azdo.get_stories_from_area_path("Detection-Engineering\\DE Rules\\Threat Hunting")

    # Generate the report
    generate_threat_hunt_report(hunt_details)
