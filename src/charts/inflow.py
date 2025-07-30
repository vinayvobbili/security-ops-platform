import json
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib import transforms
from matplotlib.patches import FancyBboxPatch

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import get_config
from services.xsoar import TicketHandler

eastern = pytz.timezone('US/Eastern')

config = get_config()

QUERY_TEMPLATE = 'type:{ticket_type_prefix} -owner:"" created:>={start} created:<{end}'

root_directory = Path(__file__).parent.parent.parent
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = root_directory / 'data' / 'metrics' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
    detection_source_codes_by_name = json.load(f)


def create_stacked_bar_chart(df, x_label, y_label, title):
    """Creates a stacked bar chart from a pandas DataFrame."""
    # Set up enhanced plot style without grids
    plt.style.use('default')

    # Configure matplotlib fonts
    import matplotlib
    matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

    # Enhanced figure with better proportions and styling
    fig, ax = plt.subplots(figsize=(14, 10), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Pivot the DataFrame to get the counts of each severity per source
    df_pivot = df.pivot_table(index='source', columns='severity', values='count', fill_value=0)

    # Enhanced color palette for severity levels (updated to handle all common severity values)
    severity_colors = {
        "Critical": "#DC2626",  # Modern red
        "High": "#EA580C",  # Modern orange
        "Medium": "#CA8A04",  # Modern amber
        "Low": "#16A34A",  # Modern green
        "Informational": "#3B82F6",  # Modern blue
        "Info": "#3B82F6",  # Modern blue (alternative name)
        "Unknown": "#6B7280",  # Medium gray
        # Handle numeric severity levels
        "4": "#DC2626",  # Critical - red
        "3": "#EA580C",  # High - orange
        "2": "#CA8A04",  # Medium - amber
        "1": "#16A34A",  # Low - green
        "0": "#3B82F6",  # Informational - blue
        # Handle any other values
        "": "#6B7280"  # Empty/null - gray
    }

    # Get available severities and assign colors
    available_severities = df_pivot.columns.tolist()
    colors = [severity_colors.get(str(sev), "#6B7280") for sev in available_severities]

    # Plot the stacked bar chart with enhanced styling
    bars = df_pivot.plot(kind='bar', stacked=True, ax=ax, color=colors, width=0.6,
                         edgecolor="white", linewidth=1.5, alpha=0.95)

    # Enhanced axes styling
    ax.set_facecolor('#ffffff')
    ax.grid(False)  # Explicitly disable grid
    ax.set_axisbelow(True)

    # Style the spines
    for spine in ax.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)

    # Enhanced labels and title
    ax.set_xlabel(x_label, fontweight='bold', fontsize=12, color='#1A237E', labelpad=10)
    ax.set_ylabel(y_label, fontweight='bold', fontsize=12, color='#1A237E')
    ax.set_title(title, fontweight='bold', fontsize=20, color='#1A237E', pad=20)

    # Increase the y-axis limit a few units over the max value
    max_value = df_pivot.sum(axis=1).max()
    ax.set_ylim(0, max_value + 3)

    # Ensure y-ticks are integers
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))

    # Enhanced value labels with black circles (matching outflow style)
    for container in bars.containers:
        for bar in container:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2,
                        f'{int(height)}', ha='center', va='center',
                        color='white', fontsize=14, fontweight='bold',
                        bbox=dict(boxstyle="circle,pad=0.2", facecolor='black',
                                  alpha=0.8, edgecolor='white', linewidth=1))

    # Enhanced legend
    legend = ax.legend(title='Severity', loc='upper right', frameon=True, fancybox=True, shadow=True,
                       title_fontsize=12, fontsize=10)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)

    # Enhanced x-axis labels
    ax.set_xticklabels(df_pivot.index, rotation=45, ha='right', fontsize=10, color='#1A237E')
    ax.tick_params(axis='y', labelsize=10, colors='#1A237E')

    # Increase the space between x-ticks and the bars to avoid legend overlap
    ax.tick_params(axis='x', pad=20)  # Increase padding between x-ticks and bars

    # Enhanced border
    border_width = 4

    # Create a rounded rectangular border that extends to the very edge
    # Remove the standard border to avoid conflicts
    fig.patch.set_edgecolor('none')  # Remove default border
    fig.patch.set_linewidth(0)

    # Calculate the exact position to ensure the border appears correctly at the corners
    fig_width, fig_height = fig.get_size_inches()
    corner_radius = 15  # Adjust this value to control the roundness of corners

    # Add a custom FancyBboxPatch that extends to the full figure bounds
    fancy_box = FancyBboxPatch(
        (0, 0),  # Start at figure bounds
        width=1.0, height=1.0,  # Full figure dimensions
        boxstyle=f"round,pad=0,rounding_size={corner_radius / max(fig_width * fig.dpi, fig_height * fig.dpi)}",
        edgecolor='#1A237E',  # Deep blue border
        facecolor='none',
        linewidth=border_width,
        transform=fig.transFigure,
        zorder=1000,  # Ensure it's on top of other elements
        clip_on=False  # Don't clip the border
    )
    fig.patches.append(fancy_box)

    plt.tight_layout()
    return fig


def plot_yesterday():
    """Plots the ticket inflow by source."""
    start_time = time.time()

    # Calculate fresh values EACH TIME the command is run
    et = pytz.timezone("US/Eastern")
    yesterday_start = datetime.now(et).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.team_name, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = TicketHandler().get_tickets(query=query)

    # Create a DataFrame from the tickets
    if not tickets:
        print('No tickets found matching the current query')
        execution_time = time.time() - start_time
        return execution_time

    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' from the 'CustomFields' dictionary and 'severity' directly from the ticket
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))
    df['severity'] = df['severity']

    # Handle missing values:
    df['source'] = df['source'].fillna('Unknown')
    df['severity'] = df['severity'].fillna('Unknown')

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Normalize empty strings to "Unknown"
    df['source'] = df['source'].replace('', 'Unknown')

    # Count the occurrences of each source and severity
    source_severity_counts = df.groupby(['source', 'severity']).size().reset_index(name='count')

    # Create the stacked bar chart with enhanced styling
    fig = create_stacked_bar_chart(source_severity_counts, "Detection Source", "Number of Alerts", f"Inflow Yesterday ({len(tickets)})")

    # Enhanced timestamp with modern styling - moved to left end (matching outflow style)
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')

    plt.text(0.01, 0.02, f"Generated@ {now_eastern}",
             transform=trans, ha='left', va='bottom',
             fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                       edgecolor='#1A237E', linewidth=1.5))

    # Add GS-DnR watermark (matching outflow style)
    fig.text(0.99, 0.01, 'GS-DnR',
             ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Adjust layout
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.15, left=0.08, right=0.92)

    today_date = datetime.now().strftime('%m-%d-%Y')
    output_path = root_directory / "web" / "static" / "charts" / today_date / "Inflow Yesterday.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, format='png', bbox_inches=None, pad_inches=0, dpi=300)
    plt.close(fig)

    execution_time = time.time() - start_time
    return execution_time


def plot_period(period_config, title, output_filename):
    """
    Creates a chart for ticket inflow over a specified period.

    Args:
        period_config: Dictionary containing period configuration
        title: Chart title
        output_filename: Output file name
    """
    start_time = time.time()

    query = f'type:{config.team_name} -owner:""'
    tickets = TicketHandler().get_tickets(query=query, period=period_config)

    if not tickets:
        print(f"No tickets found for {title}.")
        execution_time = time.time() - start_time
        return execution_time

    df = pd.DataFrame(tickets)

    # Extract 'created_date' and 'impact' fields
    df['created_date'] = pd.to_datetime(df['created'], format='ISO8601', errors='coerce').dt.date
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown'))

    # Set missing or empty impact values to 'Unknown'
    df['impact'] = df['impact'].fillna('Unknown').replace('', 'Unknown')

    # Define custom order and colors - add 'Unknown' category
    custom_impact_order = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "False Positive", "Unknown"]
    impact_colors = {
        "Significant": "#ff0000",  # Red
        "Confirmed": "#ffa500",  # Orange
        "Detected": "#ffd700",  # Gold
        "Prevented": "#008000",  # Green
        "Ignore": "#808080",  # Gray
        "Testing": "#add8e6",  # Light Blue
        "False Positive": "#90ee90",  # Light green
        "Unknown": "#d3d3d3",  # Light gray
    }

    # Ensure all impacts are in our predefined list
    df['impact'] = df['impact'].apply(lambda x: x if x in custom_impact_order else 'Unknown')

    # Group by 'created_date' and 'impact', then count occurrences
    date_impact_counts = df.groupby(['created_date', 'impact'], observed=True).size().reset_index(name='count')

    # Ensure impacts follow the custom order
    date_impact_counts['impact'] = pd.Categorical(date_impact_counts['impact'], categories=custom_impact_order, ordered=True)

    # Create pivot data structure
    unique_dates = sorted(df['created_date'].unique())
    pivot_data = {impact: np.zeros(len(unique_dates)) for impact in custom_impact_order}
    daily_totals = np.zeros(len(unique_dates))

    # Fill in the values
    for _, row in date_impact_counts.iterrows():
        # Ensure native types for indexing
        created_date = row['created_date']
        if hasattr(created_date, 'item'):
            created_date = created_date.item()
        impact = row['impact']
        if hasattr(impact, 'item'):
            impact = impact.item()
        count = row['count']
        if hasattr(count, 'item'):
            count = count.item()
        date_idx = list(unique_dates).index(created_date)
        pivot_data[impact][date_idx] += count
        daily_totals[date_idx] += count

    # Verify all tickets are accounted for
    total_in_chart = sum(daily_totals)
    if total_in_chart != len(tickets):
        print(f"Warning: Chart shows {total_in_chart} tickets but dataset has {len(tickets)} tickets")

    # Create a figure with proper size
    fig, ax = plt.subplots(figsize=(20, 12))

    # Format dates for display
    dates = [date.strftime('%m/%d') for date in unique_dates]
    x = np.arange(len(dates))

    # Plot each impact category as a separate bar component
    bottom = np.zeros(len(dates))
    for impact in custom_impact_order:
        impact_key = impact.item() if hasattr(impact, 'item') else impact
        values = pivot_data[impact_key]
        # Ensure values is a numpy array of floats
        if hasattr(values, 'astype'):
            values = values.astype(float)
        ax.bar(x, values, bottom=bottom, label=impact_key, color=impact_colors.get(impact_key, '#000000'))
        bottom = bottom + values

    # Show daily totals at the top of each bar
    for i, total in enumerate(daily_totals):
        # Fix: handle tuple case for total
        if isinstance(total, tuple):
            # Fix: handle tuple case for total
            if len(total) > 0 and isinstance(total[0], (int, float)):
                total_val = float(total[0])
            else:
                total_val = 0.0
        elif hasattr(total, 'item'):
            total_val = total.item()
        elif isinstance(total, np.ndarray):
            # Fix: flatten and convert ndarray to float
            flat = total.flatten()
            if flat.size > 0:
                total_val = float(flat[0])
            else:
                total_val = 0.0
        else:
            try:
                if isinstance(total, tuple):
                    total_val = float(total[0]) if len(total) > 0 else 0.0
                else:
                    total_val = float(total)
            except Exception:
                total_val = 0.0
        # Fix: handle tuple case for x[i]
        if isinstance(x[i], tuple):
            x_val = float(x[i][0])
        elif hasattr(x[i], 'item'):
            x_val = x[i].item()
        elif isinstance(x[i], np.ndarray):
            x_val = float(x[i].flatten()[0])
        else:
            x_val = float(x[i])
        if total_val > 0:
            ax.text(x_val, total_val + 2, f'{int(total_val)}', ha='center', va='center', fontsize=10, fontweight='bold',
                    bbox=dict(boxstyle="circle,pad=0.2", facecolor='black',
                              alpha=0.8, edgecolor='white', linewidth=1))

    # Plot a horizontal line for the daily average
    daily_average = date_impact_counts.groupby('created_date')['count'].sum().mean()
    ax.axhline(daily_average, color='blue', linestyle='--', linewidth=1.5, label=f'Daily Average ({int(daily_average)})')

    # Set x-ticks at the correct positions
    ax.set_xticks(x)
    ax.set_ylim(0, bottom.max() * 1.1)  # Add 10% extra space above the tallest bar

    plot_yesterday()
    ax.tick_params(axis='x', pad=20)  # Increase padding between x-ticks and bars

    # Show only every nth label to prevent crowding
    n = 5  # Show every 5th label
    date_labels = dates.copy()
    for i in range(len(dates)):
        if i % n != 0:
            date_labels[i] = ""

    ax.set_xticklabels(date_labels, rotation=45, ha='right', fontsize=8)

    # Add labels and title with total count subtitle
    ax.set_xlabel("Created Date", fontweight='bold', fontsize=12, labelpad=10)
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=10)
    fig.suptitle(f"{title}", fontweight='bold', fontsize=14, ha='center', x=0.55)
    ax.set_title(f"Total: {len(tickets)} tickets", fontsize=12, ha='center', x=0.5)

    # Add legend
    ax.legend(title='Impact', title_fontproperties={'weight': 'bold'})

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Save the chart
    today_date = datetime.now().strftime('%m-%d-%Y')
    output_path = root_directory / "web" / "static" / "charts" / today_date / output_filename

    # Ensure directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)

    execution_time = time.time() - start_time
    return execution_time


def plot_past_60_days():
    start_time = time.time()
    period = {
        "by": "day",
        "fromValue": 60
    }
    exec_time = plot_period(
        period_config=period,
        title="Inflow Over the Past 60 Days",
        output_filename="Inflow Past 60 Days.png"
    )

    # If plot_period returned a time, use it; otherwise calculate from our start time
    if exec_time is not None:
        return exec_time
    else:
        return time.time() - start_time


def plot_past_12_months():
    """Creates charts for ticket inflow over the past 12 months, grouped by month."""
    start_time = time.time()

    query = f'type:{config.team_name} -owner:""'
    tickets = []

    # Fetch data in chunks to handle potential volume
    for i in range(0, 13, 3):
        period = {
            "byFrom": "months",
            "fromValue": 12 - i,
            "byTo": "months",
            "toValue": max(0, 9 - i)
        }
        quarter_tickets = TicketHandler().get_tickets(query=query, period=period, size=10000)
        tickets.extend(quarter_tickets)

    # Deduplicate tickets
    tickets = list({t['id']: t for t in tickets}.values())
    # print(f"Total tickets retrieved: {len(tickets)}")

    if not tickets:
        print("No tickets found for Past 12 Months.")
        return time.time() - start_time

    df = pd.DataFrame(tickets)

    # Extract created_month
    df['created_dt'] = pd.to_datetime(df['created'], format='ISO8601', errors='coerce').dt.tz_convert('UTC')
    df['created_month'] = df['created_dt'].dt.tz_localize(None).dt.to_period('M')

    # Generate expected months (past 12 months)
    current_month = pd.Period(datetime.now(), freq='M')
    expected_months = [current_month - i for i in range(11, -1, -1)]
    month_labels = [month.strftime('%b %Y') for month in expected_months]
    np.arange(len(month_labels)) * 1.0

    # Process ticket type data
    df['ticket_type'] = df['type'].fillna('Unknown').replace('', 'Unknown')
    df['ticket_type'] = df['ticket_type'].str.replace(config.team_name, '').str.strip()
    ticket_types = sorted(df['ticket_type'].unique())

    # Ensure ticket_types are strings
    ticket_types = [str(t.item()) if hasattr(t, 'item') else str(t) for t in ticket_types]
    # Ensure expected_months are Periods
    expected_months = [m.item() if hasattr(m, 'item') else m for m in expected_months]
    month_ticket_counts = df.groupby(['created_month', 'ticket_type'], observed=True).size().reset_index(name='count')

    # Create ticket type data structure
    ticket_pivot_data = {ticket_type: np.zeros(len(expected_months)) for ticket_type in ticket_types}
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2',
              '#7f7f7f', '#bcbd22', '#17becf', '#aec7e8', '#ffbb78', '#98df8a', '#ff9896']
    ticket_type_color_map = {ticket_type: colors[i % len(colors)] for i, ticket_type in enumerate(ticket_types)}

    # Fill ticket type values
    for _, row in month_ticket_counts.iterrows():
        if row['created_month'] in expected_months:
            month_idx = expected_months.index(row['created_month'])
            ticket_type = row['ticket_type']
            count = row['count']
            ticket_pivot_data[ticket_type][month_idx] += count

    # Process impact data
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown'))
    df['impact'] = df['impact'].fillna('Unknown').replace('', 'Unknown')
    custom_impact_order = ["Significant", "Malicious True Positive", "Confirmed", "Detected", "Prevented", "Benign True Positive", "False Positive", "Ignore", "Testing", "Security Testing", "Unknown"]
    impact_colors = {
        "Significant": "#ff0000",  # Red
        "Confirmed": "#ffa500",  # Orange
        "Malicious True Positive": "#b71c1c",  # Dark Red
        "Detected": "#ffd700",  # Gold
        "Prevented": "#008000",  # Green
        "Ignore": "#808080",  # Gray
        "Benign True Positive": "#388e3c",  # Dark Green
        "Testing": "#add8e6",  # Light Blue
        "Security Testing": "#1976d2",  # Blue
        "False Positive": "#90ee90",  # Light green
        "Unknown": "#d3d3d3",  # Light gray
    }

    # Ensure impacts follow predefined list
    df['impact'] = df['impact'].apply(lambda x: x if x in custom_impact_order else 'Unknown')
    month_impact_counts = df.groupby(['created_month', 'impact'], observed=True).size().reset_index(name='count')

    # Create impact data structure
    impact_pivot_data = {impact: np.zeros(len(expected_months)) for impact in custom_impact_order}
    monthly_totals = np.zeros(len(expected_months))

    # Fill impact values
    for _, row in month_impact_counts.iterrows():
        if row['created_month'] in expected_months:
            month_idx = expected_months.index(row['created_month'])
            impact = row['impact']
            count = row['count']
            impact_pivot_data[impact][month_idx] += count
            monthly_totals[month_idx] += count

    monthly_average = monthly_totals.mean()
    today_date = datetime.now().strftime('%m-%d-%Y')
    output_dir = root_directory / "web" / "static" / "charts" / today_date
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create combined chart (original)
    create_combined_chart(expected_months, month_labels, ticket_pivot_data,
                          ticket_type_color_map, custom_impact_order, impact_pivot_data, impact_colors,
                          monthly_totals, monthly_average, tickets, output_dir)

    # 2. Create impact-only chart
    create_impact_chart(expected_months, month_labels, custom_impact_order, impact_pivot_data,
                        impact_colors, monthly_totals, monthly_average, tickets, output_dir)

    # 3. Create ticket type-only chart
    create_ticket_type_chart(expected_months, month_labels, ticket_types, ticket_pivot_data,
                             ticket_type_color_map, monthly_totals, monthly_average, tickets, output_dir)

    return time.time() - start_time


def create_combined_chart(expected_months, month_labels, ticket_pivot_data,
                          ticket_type_color_map, custom_impact_order, impact_pivot_data, impact_colors,
                          monthly_totals, monthly_average, tickets, output_dir):
    """Creates the original combined chart with both ticket types and impacts."""
    fig, ax = plt.subplots(figsize=(22, 14))

    # Setup positions
    group_width = 0.6
    bar_width = group_width / 2
    spacing = 0.4
    x_pos = np.arange(len(month_labels)) * (group_width + spacing)
    type_x = x_pos - bar_width / 2
    impact_x = x_pos + bar_width / 2

    # Plot ticket type bars (left)
    type_bottom = np.zeros(len(expected_months))
    for ticket_type, values in ticket_pivot_data.items():
        if values.sum() > 0:
            ax.bar(type_x, values, bottom=type_bottom, width=bar_width,
                   label=f"{ticket_type}", color=ticket_type_color_map[ticket_type],
                   edgecolor='black', linewidth=0.5)
            type_bottom += values

    # Plot impact bars (right)
    impact_bottom = np.zeros(len(expected_months))
    for impact in custom_impact_order:
        values = impact_pivot_data[impact]
        if values.sum() > 0:
            ax.bar(impact_x, values, bottom=impact_bottom, width=bar_width,
                   label=f"{impact}", color=impact_colors[impact])
            impact_bottom += values

    # Monthly average line
    ax.axhline(monthly_average, color='blue', linestyle='--', linewidth=2,
               label=f'Monthly Average ({int(monthly_average)})')

    # Trend line
    ax.plot(x_pos.astype(float), monthly_totals.astype(float), color='red', marker='o', markersize=8,
            linewidth=2.5, label='Monthly Volume', zorder=10)

    # Add count labels
    for i in range(len(x_pos)):
        total = monthly_totals[i]
        if total > 0:
            # Ensure total is a native Python type
            if isinstance(total, tuple):
                total_val = float(total[0])
            elif hasattr(total, 'item'):
                total_val = total.item()
            elif isinstance(total, np.ndarray):
                total_val = float(total.flatten()[0])
            else:
                total_val = float(total)
            ax.text(float(x_pos[i]), total_val + 20, f'{int(total_val)}',
                    ha='center', va='bottom', fontsize=12, fontweight='bold',
                    bbox=dict(facecolor='white', alpha=0.9, edgecolor='none', pad=2), zorder=20)

    # Formatting
    ax.set_xticks(x_pos)
    y_max = max(max(type_bottom), max(impact_bottom), 100) * 1.15
    ax.set_ylim(0, y_max)
    ax.set_xticklabels(month_labels, rotation=45, ha='right', fontsize=12)
    ax.tick_params(axis='y', labelsize=12)

    # Titles and labels
    ax.set_xlabel("Month", fontweight='bold', fontsize=12)
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=12)
    fig.suptitle(f'Inflow Over the Past 12 Months', fontweight='bold', fontsize=14, x=0.5)
    ax.set_title(f"Total: {len(tickets)} tickets", fontsize=12, x=0.5)

    # Create separate legends
    handles, labels = ax.get_legend_handles_labels()

    # Add counts to labels
    ticket_type_totals = {ticket_type: values.sum() for ticket_type, values in ticket_pivot_data.items()}
    impact_totals = {impact: impact_pivot_data[impact].sum() for impact in custom_impact_order}

    type_handles = [h for h, l in zip(handles, labels) if "Monthly" not in l and l not in custom_impact_order]
    type_labels = [l for l in labels if "Monthly" not in l and l not in custom_impact_order]
    impact_handles = [h for h, l in zip(handles, labels) if "Monthly" in l or l in custom_impact_order]
    impact_labels = [l for l in labels if "Monthly" in l or l in custom_impact_order]

    type_labels_with_counts = [f"{l} ({int(ticket_type_totals[l])})" for l in type_labels]
    impact_labels_with_counts = []
    for l in impact_labels:
        if l in custom_impact_order:
            impact_labels_with_counts.append(f"{l} ({int(impact_totals[l])})")
        else:
            impact_labels_with_counts.append(l)

    type_legend = ax.legend(type_handles, type_labels_with_counts,
                            title="Ticket Types", title_fontproperties={'weight': 'bold', 'size': 12},
                            loc='upper left', fontsize=10)
    ax.add_artist(type_legend)
    ax.legend(impact_handles, impact_labels_with_counts,
              title="Impact", title_fontproperties={'weight': 'bold', 'size': 12},
              loc='upper right', fontsize=10)

    # Add border and timestamp
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Save the figure
    output_path = output_dir / "Inflow Past 12 Months.png"
    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def create_impact_chart(expected_months, month_labels, custom_impact_order, impact_pivot_data,
                        impact_colors, monthly_totals, monthly_average, tickets, output_dir):
    """Creates a chart showing only impact data."""
    fig, ax = plt.subplots(figsize=(20, 12))

    # Plot impact bars (full width)
    bar_width = 0.4
    x_pos = np.arange(len(month_labels))
    impact_bottom = np.zeros(len(expected_months))

    for impact in custom_impact_order:
        values = impact_pivot_data[impact]
        if values.sum() > 0:
            ax.bar(x_pos, values, bottom=impact_bottom, width=bar_width,
                   label=f"{impact}", color=impact_colors[impact])
            impact_bottom += values

    # Monthly average line
    ax.axhline(monthly_average, color='blue', linestyle='--', linewidth=2,
               label=f'Monthly Average ({int(monthly_average)})')

    # Trend line
    ax.plot(x_pos.astype(float), monthly_totals.astype(float), color='red', marker='o', markersize=8,
            linewidth=2.5, label='Monthly Volume', zorder=10)

    # Add count labels
    for i in range(len(x_pos)):
        total = monthly_totals[i]
        if total > 0:
            # Ensure total is a native Python type
            if isinstance(total, tuple):
                total_val = float(total[0])
            elif hasattr(total, 'item'):
                total_val = total.item()
            elif isinstance(total, np.ndarray):
                total_val = float(total.flatten()[0])
            else:
                total_val = float(total)
            ax.text(x_pos[i], total_val + 20, f'{int(total_val)}',
                    ha='center', va='bottom', fontsize=12, fontweight='bold',
                    bbox=dict(facecolor='white', alpha=0.9, edgecolor='none', pad=2), zorder=20)

    # Formatting
    ax.set_xticks(x_pos)
    y_max = max(impact_bottom.max(), 100) * 1.15
    ax.set_ylim(0, y_max)
    ax.set_xticklabels(month_labels, rotation=45, ha='right', fontsize=12)
    ax.tick_params(axis='y', labelsize=12)

    # --- Apply SLA Breaches style ---
    # Blue border with rounded edges
    fig.patch.set_edgecolor('#1A237E')  # Deep blue
    fig.patch.set_linewidth(3)
    fig.patch.set_facecolor('#F7F8FA')  # Very light gray
    # Add rounded rectangle border using FancyBboxPatch
    from matplotlib.patches import FancyBboxPatch
    fig_width, fig_height = fig.get_size_inches()
    corner_radius = 30  # More pronounced rounding
    fancy_box = FancyBboxPatch(
        (0, 0), 1, 1,
        boxstyle=f"round,pad=0.02,rounding_size={corner_radius}",
        edgecolor='#1A237E', facecolor='none', linewidth=3,
        transform=fig.transFigure, zorder=1000, clip_on=False
    )
    fig.patches.append(fancy_box)

    # Blue title
    fig.suptitle('Impact Distribution Over the Past 12 Months', fontweight='bold', fontsize=22, color='#1A237E', x=0.5)
    ax.set_title(f"Total: {len(tickets)} tickets", fontsize=14, color='#1A237E', x=0.5)

    # Blue axis labels
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=14, color='#1A237E')
    ax.set_xlabel(ax.get_xlabel(), fontweight='bold', fontsize=14, color='#1A237E')

    # Blue tick labels
    ax.tick_params(axis='x', colors='#1A237E', labelsize=12)
    ax.tick_params(axis='y', colors='#1A237E', labelsize=12)

    # Legend styling (border, font, position)
    handles, labels = ax.get_legend_handles_labels()
    impact_totals = {impact: impact_pivot_data[impact].sum() for impact in custom_impact_order}
    custom_labels = []
    for l in labels:
        if l in custom_impact_order:
            custom_labels.append(f"{l} ({int(impact_totals[l])})")
        else:
            custom_labels.append(l)
    legend = ax.legend(handles, custom_labels, title="Impact",
                       title_fontproperties={'weight': 'bold', 'size': 14},
                       loc='upper left', bbox_to_anchor=(1.02, 1), fontsize=12, borderaxespad=0)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)
    legend.get_frame().set_boxstyle('round,pad=0.4')

    # Timestamp box (bottom left, blue border)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.01, 0.01, f"Generated@ {now_eastern}", ha='left', va='bottom', fontsize=12, color='#1A237E',
             bbox=dict(facecolor='#F7F8FA', edgecolor='#1A237E', boxstyle='round,pad=0.4', linewidth=2),
             transform=trans)

    # Add GS-DnR watermark (matching SLA Breaches style)
    fig.text(0.99, 0.01, 'GS-DnR',
             ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Save the figure
    output_path = output_dir / "Inflow Past 12 Months - Impact Only.png"
    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def create_ticket_type_chart(expected_months, month_labels, ticket_types, ticket_pivot_data,
                             ticket_type_color_map, monthly_totals, monthly_average, tickets, output_dir):
    """Creates a chart showing only ticket type data."""
    fig, ax = plt.subplots(figsize=(20, 12))

    # Plot ticket type bars (full width)
    bar_width = 0.7
    x_pos = np.arange(len(month_labels))
    type_bottom = np.zeros(len(expected_months))

    for ticket_type, values in ticket_pivot_data.items():
        if values.sum() > 0:
            ax.bar(x_pos, values, bottom=type_bottom, width=bar_width,
                   label=f"{ticket_type}", color=ticket_type_color_map[ticket_type],
                   edgecolor='black', linewidth=0.5)
            type_bottom += values

    # Monthly average line
    ax.axhline(monthly_average, color='blue', linestyle='--', linewidth=2,
               label=f'Monthly Average ({int(monthly_average)})')

    # Trend line
    ax.plot(x_pos.astype(float), monthly_totals.astype(float), color='red', marker='o', markersize=8,
            linewidth=2.5, label='Monthly Volume', zorder=10)

    # Add count labels
    for i in range(len(x_pos)):
        total = monthly_totals[i]
        if total > 0:
            # Ensure total is a native Python type
            if isinstance(total, tuple):
                total_val = float(total[0])
            elif hasattr(total, 'item'):
                total_val = total.item()
            elif isinstance(total, np.ndarray):
                total_val = float(total.flatten()[0])
            else:
                total_val = float(total)
            ax.text(x_pos[i], total_val + 20, f'{int(total_val)}',
                    ha='center', va='bottom', fontsize=12, fontweight='bold',
                    bbox=dict(facecolor='white', alpha=0.9, edgecolor='none', pad=2), zorder=20)

    # Formatting
    ax.set_xticks(x_pos)
    y_max = max(type_bottom.max(), 100) * 1.15
    ax.set_ylim(0, y_max)
    ax.set_xticklabels(month_labels, rotation=45, ha='right', fontsize=12)
    ax.tick_params(axis='y', labelsize=12)

    # Titles and labels
    ax.set_xlabel("Month", fontweight='bold', fontsize=12)
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=12)
    fig.suptitle(f'Ticket Type Distribution Over the Past 12 Months', fontweight='bold', fontsize=14, x=0.5)
    ax.set_title(f"Total: {len(tickets)} tickets", fontsize=12, x=0.5)

    # Create legend with counts
    ticket_type_totals = {ticket_type: values.sum() for ticket_type, values in ticket_pivot_data.items()}
    handles, labels = ax.get_legend_handles_labels()

    custom_labels = []
    for l in labels:
        if l in ticket_types:
            custom_labels.append(f"{l} ({int(ticket_type_totals[l])})")
        else:
            custom_labels.append(l)

    ax.legend(handles, custom_labels, title="Ticket Types",
              title_fontproperties={'weight': 'bold', 'size': 12},
              loc='upper left', fontsize=10)

    # Add border and timestamp
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Save the figure
    output_path = output_dir / "Inflow Past 12 Months - Ticket Type Only.png"
    plt.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def make_chart():
    try:
        plot_yesterday()
        plot_past_60_days()
        plot_past_12_months()

    except Exception as e:
        print(f"An error occurred while generating charts: {e}")


if __name__ == '__main__':
    plot_past_12_months()
