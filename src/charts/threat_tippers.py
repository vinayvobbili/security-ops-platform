import logging
import os
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib.ticker import MaxNLocator

import services.azdo as azdo
from data.data_maps import azdo_area_paths

eastern = pytz.timezone('US/Eastern')
ROOT_DIRECTORY = Path(__file__).parent.parent.parent

# Define constants for priority and action values
PRIORITY_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Info']
ACTION_TYPES = ['Detection Opportunity', 'Hunt Opportunity', 'None Required']

# Original colors for Priority with improved contrast
PRIORITY_COLORS = {
    'Critical': '#dc2626',  # Slightly darker red for better contrast
    'High': '#ea580c',  # Adjusted orange
    'Medium': '#eab308',  # Adjusted yellow
    'Low': '#2563eb',  # Darker blue for better contrast
    'Info': '#9ca3af'  # Adjusted gray
}

# Distinct colors for Action with colorblind-friendly options
ACTION_COLORS = {
    'Detection Opportunity': '#0284c7',  # Distinct blue shade
    'Hunt Opportunity': '#059669',  # Green that stands out from blues
    'None Required': '#4b5563'  # Medium gray
}


def process_tipper_data(threat_tippers):
    """Process raw tipper data into a structured DataFrame."""
    processed_data = []

    for tipper in threat_tippers:
        try:
            created_date = datetime.strptime(tipper.fields['System.CreatedDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError:
            created_date = datetime.strptime(tipper.fields['System.CreatedDate'], '%Y-%m-%dT%H:%M:%SZ')
        week = created_date.strftime('%m/%d/%y')

        tags = tipper.fields.get('System.Tags', '')
        priority_text = next((tag for tag in PRIORITY_LEVELS if tag in tags), 'Unknown')
        action_text = next((tag for tag in ACTION_TYPES if tag in tags), 'None Required')  # Fixed: Now defaults to "None Required"

        processed_data.append({
            'Week': week,
            'WeekDate': created_date,
            'Priority': priority_text,
            'Action': action_text,
            'Ticket': tipper.fields.get('System.Id', ''),
            'Title': tipper.fields.get('System.Title', ''),
            'XSOAR_Link': tipper.fields.get('XSOAR_Link', '')
        })

    return pd.DataFrame(processed_data)


def create_summary_data_by_priority(df):
    """Create summary data for the priority bar chart."""
    # Group by week and priority, count occurrences
    summary = df.groupby(['Week', 'Priority']).size().unstack(fill_value=0)

    # Convert string dates to datetime objects for better plotting
    summary.index = pd.to_datetime(summary.index, format='%m/%d/%y')
    summary = summary.sort_index()

    # Ensure all priority columns exist
    for priority in PRIORITY_LEVELS:
        if priority not in summary.columns:
            summary[priority] = 0

    # Calculate total tippers per week
    summary['Total'] = summary.sum(axis=1)

    return summary


def create_summary_data_by_action(df):
    """Create summary data for the action bar chart."""
    # Group by week and action, count occurrences
    summary = df.groupby(['Week', 'Action']).size().unstack(fill_value=0)

    # Convert string dates to datetime objects for better plotting
    summary.index = pd.to_datetime(summary.index, format='%m/%d/%y')
    summary = summary.sort_index()

    # Ensure all action columns exist
    for action in ACTION_TYPES:
        if action not in summary.columns:
            summary[action] = 0

    # Calculate total tippers per week
    summary['Total'] = summary.sum(axis=1)

    return summary


def plot_stacked_bar_by_priority(ax, summary_data, colors, priority_counts):
    """Create the stacked bar chart for priorities with data labels."""
    bottom = np.zeros(len(summary_data.index))
    handles = []
    labels = []

    bar_width = 0.35  # Width of the bar
    bar_positions = np.arange(len(summary_data.index)) - bar_width / 2  # Position bars on the left side

    # Plot each priority level - reversed order to match example (Low at bottom)
    for priority in ['Info', 'Low', 'Medium', 'High', 'Critical']:
        if priority in summary_data.columns:
            bars = ax.bar(bar_positions, summary_data[priority], width=bar_width, bottom=bottom,
                          label=f"{priority} ({priority_counts.get(priority, 0)})", color=colors[priority])

            # Add count labels to each segment
            for i, (pos, height) in enumerate(zip(bar_positions, summary_data[priority])):
                if height > 0:  # Only add label if there's data
                    # Position label in middle of bar segment
                    label_y = bottom[i] + height / 2
                    ax.text(pos, label_y, str(int(height)),
                            ha='center', va='center',
                            color='white', fontweight='bold', fontsize=8)

            handles.append(bars[0])
            labels.append(f"{priority} ({priority_counts.get(priority, 0)})")
            bottom += np.array(summary_data[priority])

    # Add enhanced legend for the priority chart positioned outside
    legend1 = ax.legend(handles, labels, title='Priority', loc='upper left', 
                       bbox_to_anchor=(1.02, 1),
                       frameon=True, fancybox=True, shadow=True,
                       title_fontsize=12, fontsize=10)
    legend1.get_frame().set_facecolor('white')
    legend1.get_frame().set_alpha(0.95)
    legend1.get_frame().set_edgecolor('#1A237E')
    legend1.get_frame().set_linewidth(2)
    legend1.get_title().set_fontweight('bold')
    legend1.get_title().set_color('#1A237E')
    ax.add_artist(legend1)  # Add the legend to the axes

    return bar_positions


def plot_stacked_bar_by_action(ax, summary_data, colors, action_counts):
    """Create the stacked bar chart for actions with data labels."""
    bottom = np.zeros(len(summary_data.index))
    handles = []
    labels = []

    bar_width = 0.35  # Width of the bar
    bar_positions = np.arange(len(summary_data.index)) + bar_width / 2  # Position bars on the right side

    # Plot each action level - from bottom to top
    for action in ACTION_TYPES[::-1]:  # Reverse the list to display None Required at bottom
        if action in summary_data.columns:
            bars = ax.bar(bar_positions, summary_data[action], width=bar_width, bottom=bottom,
                          label=f"{action} ({action_counts.get(action, 0)})", color=colors[action])

            # Add count labels to each segment
            for i, (pos, height) in enumerate(zip(bar_positions, summary_data[action])):
                if height > 0:  # Only add label if there's data
                    # Position label in middle of bar segment
                    label_y = bottom[i] + height / 2
                    ax.text(pos, label_y, str(int(height)),
                            ha='center', va='center',
                            color='white', fontweight='bold', fontsize=8)

            handles.append(bars[0])
            labels.append(f"{action} ({action_counts.get(action, 0)})")
            bottom += np.array(summary_data[action])

    # Add enhanced legend for the action chart positioned outside
    legend2 = ax.legend(handles, labels, title='Action', loc='upper left', 
                       bbox_to_anchor=(1.02, 0.6),
                       frameon=True, fancybox=True, shadow=True,
                       title_fontsize=12, fontsize=10)
    legend2.get_frame().set_facecolor('white')
    legend2.get_frame().set_alpha(0.95)
    legend2.get_frame().set_edgecolor('#1A237E')
    legend2.get_frame().set_linewidth(2)
    legend2.get_title().set_fontweight('bold')
    legend2.get_title().set_color('#1A237E')
    ax.add_artist(legend2)  # Add the legend to the axes

    return bar_positions


def add_trend_line(ax, all_dates, summary_priority):
    """Add trend line showing the moving average of totals."""
    # Create a moving average of the totals (3-day window)
    if len(summary_priority) >= 3:
        totals = summary_priority['Total'].values
        # Use numpy's convolve for moving average
        window_size = min(3, len(totals))
        weights = np.ones(window_size) / window_size
        moving_avg = np.convolve(totals, weights, mode='valid')

        # Plot the trend line
        trend_x = np.arange(len(all_dates))[window_size - 1:]
        ax.plot(trend_x, moving_avg, 'k--', alpha=0.6, label='Trend (3-day avg)')


def generate_threat_tipper_chart(tippers):
    # Process data
    df = process_tipper_data(tippers)

    # Create summaries for both priority and action
    summary_priority = create_summary_data_by_priority(df)
    summary_action = create_summary_data_by_action(df)

    # Get counts for legend
    priority_counts = df['Priority'].value_counts().to_dict()
    action_counts = df['Action'].value_counts().to_dict()

    # Get all unique dates from both summaries to ensure alignment
    all_dates = sorted(set(summary_priority.index) | set(summary_action.index))

    # Reindex both summaries to have the same dates
    summary_priority = summary_priority.reindex(all_dates, fill_value=0)
    summary_action = summary_action.reindex(all_dates, fill_value=0)

    # Create enhanced figure with modern styling
    fig, ax = plt.subplots(figsize=(16, 10), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Plot both charts on the same axes
    plot_stacked_bar_by_priority(ax, summary_priority, PRIORITY_COLORS, priority_counts)
    plot_stacked_bar_by_action(ax, summary_action, ACTION_COLORS, action_counts)

    # Add trend line
    # add_trend_line(ax, all_dates, summary_priority)

    # Enhanced axes styling
    ax.set_facecolor('#ffffff')
    ax.grid(False)  # Remove gridlines for cleaner look
    ax.set_axisbelow(True)

    # Format x-axis with dates
    ax.set_xticks(np.arange(len(all_dates)))
    ax.set_xticklabels([date.strftime('%m/%d/%y') for date in all_dates], rotation=45, ha='right', 
                       fontsize=12, color='#1A237E')

    # Enhanced labels and title
    plt.suptitle('Threat Tippers Summary', fontsize=24, fontweight='bold', color='#1A237E', y=0.95)
    ax.set_xlabel(f'Last 30 days (Total: {len(tippers)})', fontsize=14, fontweight='bold', labelpad=15, color='#1A237E')
    ax.set_ylabel('Counts', fontsize=14, fontweight='bold', labelpad=15, color='#1A237E')
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.tick_params(axis='y', colors='#1A237E', labelsize=12, width=1.5)

    # Set y-axis limit with some padding
    max_height = max(
        summary_priority['Total'].max(),
        summary_action['Total'].max()
    )
    y_max = max(max_height * 1.2, 4)  # At least 4, or 20% above max for labels
    ax.set_ylim(0, y_max)

    # Enhanced border with rounded corners like other charts
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

    # Style the spines
    for spine in ax.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)

    # Enhanced timestamp and branding
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    fig.text(0.02, 0.02, f"Generated@ {now_eastern}",
             ha='left', va='bottom', fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                       edgecolor='#1A237E', linewidth=1.5))

    # Add GS-DnR branding
    fig.text(0.98, 0.02, 'GS-DnR', ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Save chart files
    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date
    os.makedirs(OUTPUT_PATH, exist_ok=True)

    # Enhanced layout with space for external legends
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.15, left=0.08, right=0.72)

    # Save as PNG for static display
    plt.savefig(OUTPUT_PATH / 'Threat Tippers.png', dpi=300, bbox_inches='tight', 
               pad_inches=0, facecolor='#f8f9fa')
    plt.savefig(OUTPUT_PATH / 'Threat Tippers.svg', format='svg', bbox_inches='tight')

    # Create interactive version with tooltips (code remains the same)
    from matplotlib.backends.backend_svg import FigureCanvasSVG

    # Save HTML with embedded SVG and tooltip JS
    with open(OUTPUT_PATH / 'Threat Tippers.html', 'w') as f:
        canvas = FigureCanvasSVG(fig)
        svg_data = canvas.print_svg(OUTPUT_PATH / 'temp.svg')

        with open(OUTPUT_PATH / 'temp.svg', 'r') as svg_file:
            svg_content = svg_file.read()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Tippers Chart</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .chart-container {{ max-width: 1000px; margin: 0 auto; }}
            </style>
        </head>
        <body>
            <div class="chart-container">
                {svg_content}
            </div>
            <script>
                // Add tooltips for interactive browser display
                document.addEventListener('DOMContentLoaded', function() {{
                    const bars = document.querySelectorAll('rect');
                    bars.forEach(function(bar) {{
                        bar.addEventListener('mouseover', function(e) {{
                            const tooltip = document.getElementById('tooltip');
                            tooltip.innerHTML = this.getAttribute('data-info');
                            tooltip.style.display = 'block';
                            tooltip.style.left = e.pageX + 10 + 'px';
                            tooltip.style.top = e.pageY + 10 + 'px';
                        }});

                        bar.addEventListener('mouseout', function() {{
                            document.getElementById('tooltip').style.display = 'none';
                        }});
                    }});
                }});
            </script>
            <div id="tooltip" style="display:none; position:absolute; background:white; padding:5px; border:1px solid black;"></div>
        </body>
        </html>
        """
        f.write(html_content)

        # Clean up temporary file
        try:
            os.remove(OUTPUT_PATH / 'temp.svg')
        except:
            pass


def make_chart():
    try:
        threat_tippers = azdo.get_stories_from_area_path(azdo_area_paths['threat_hunting'])
        # print thippers that don't have one of these tags - Info, Low, Mediium, High, Critical. Set a default tag of Info
        for tipper in threat_tippers:
            tags = tipper.fields.get('System.Tags', '')
            if not any(tag in tags for tag in ['Info', 'Low', 'Medium', 'High', 'Critical']):
                print(f"Tipper {tipper.id} missing priority tag. Current tags: {tags}. Setting a default tag of Info")
                tipper.fields['System.Tags'] = 'Info'

        generate_threat_tipper_chart(threat_tippers)
    except Exception as e:
        logging.error(f"An error occurred while generating the chart: {e}")


if __name__ == "__main__":
    make_chart()
