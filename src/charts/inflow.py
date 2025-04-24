import json
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from services.xsoar import IncidentHandler

eastern = pytz.timezone('US/Eastern')

config = get_config()

QUERY_TEMPLATE = 'type:{ticket_type_prefix} -owner:"" created:>={start} created:<{end}'

root_directory = Path(__file__).parent.parent.parent
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = root_directory / 'data' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
    detection_source_codes_by_name = json.load(f)


def create_stacked_bar_chart(df, x_label, y_label, title):
    """Creates a stacked bar chart from a pandas DataFrame."""
    fig, ax = plt.subplots(figsize=(20, 12))

    # Pivot the DataFrame to get the counts of each severity per source
    df_pivot = df.pivot_table(index='source', columns='severity', values='count', fill_value=0)

    # Plot the stacked bar chart with lighter shades
    bars = df_pivot.plot(kind='bar', stacked=True, ax=ax, color=['#6989e8', '#ffbb78', '#98df8a', '#ff9896'])

    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.set_title(title, fontweight='bold', fontsize=12)

    # Increase the y-axis limit a few units over the max value
    max_value = df_pivot.sum(axis=1).max()
    ax.set_ylim(0, max_value + 3)

    # Ensure y-ticks are integers
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))

    # Add count labels on top of each stack
    for container in bars.containers:
        for bar in container:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2, f'{int(height)}', ha='center', va='center', fontsize=10, fontweight='bold')

    plt.xticks(rotation=45, ha='right')
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

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = IncidentHandler().get_tickets(query=query)

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

    # Create the stacked bar chart
    fig = create_stacked_bar_chart(source_severity_counts, "Detection Source", "Number of Alerts", f"Inflow Yesterday ({len(tickets)})")

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.08, 0.03, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "Inflow Yesterday.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT_PATH)
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

    query = f'type:{config.ticket_type_prefix} -owner:""'
    tickets = IncidentHandler().get_tickets(query=query, period=period_config)

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
    CUSTOM_IMPACT_ORDER = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "False Positive", "Unknown"]
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
    df['impact'] = df['impact'].apply(lambda x: x if x in CUSTOM_IMPACT_ORDER else 'Unknown')

    # Group by 'created_date' and 'impact', then count occurrences
    date_impact_counts = df.groupby(['created_date', 'impact'], observed=True).size().reset_index(name='count')

    # Ensure impacts follow the custom order
    date_impact_counts['impact'] = pd.Categorical(date_impact_counts['impact'], categories=CUSTOM_IMPACT_ORDER, ordered=True)

    # Create pivot data structure
    unique_dates = sorted(df['created_date'].unique())
    pivot_data = {impact: np.zeros(len(unique_dates)) for impact in CUSTOM_IMPACT_ORDER}
    daily_totals = np.zeros(len(unique_dates))

    # Fill in the values
    for _, row in date_impact_counts.iterrows():
        date_idx = list(unique_dates).index(row['created_date'])
        impact = row['impact']
        count = row['count']
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
    for impact in CUSTOM_IMPACT_ORDER:
        values = pivot_data[impact]
        ax.bar(x, values, bottom=bottom, label=impact, color=impact_colors.get(impact, '#000000'))
        bottom += values

    # Plot a horizontal line for the daily average
    daily_average = date_impact_counts.groupby('created_date')['count'].sum().mean()
    ax.axhline(daily_average, color='blue', linestyle='--', linewidth=1.5, label=f'Daily Average ({int(daily_average)})')

    # Set x-ticks at the correct positions
    ax.set_xticks(x)
    ax.set_ylim(0, bottom.max() * 1.1)  # Add 10% extra space above the tallest bar

    # Show only every nth label to prevent crowding
    n = 5  # Show every 5th label
    date_labels = dates.copy()
    for i in range(len(dates)):
        if i % n != 0:
            date_labels[i] = ""

    ax.set_xticklabels(date_labels, rotation=45, ha='right', fontsize=8)

    # Add labels and title with total count subtitle
    ax.set_xlabel("Created Date", fontweight='bold', fontsize=10)
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=10)
    ax.set_title(f"{title}\nTotal: {len(tickets)} tickets", fontweight='bold', fontsize=12)

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
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / output_filename

    # Ensure directory exists
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    plt.tight_layout()
    fig.savefig(OUTPUT_PATH)
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
    """Creates a chart for ticket inflow over the past 12 months, grouped by month."""
    start_time = time.time()

    query = f'type:{config.ticket_type_prefix} -owner:""'
    tickets = []

    period = {
        "byFrom": "months",
        "fromValue": 12,
        "byTo": "months",
        "toValue": 10
    }
    quarter_tickets = IncidentHandler().get_tickets(query=query, period=period, size=10000)
    tickets.extend(quarter_tickets)

    period = {
        "byFrom": "months",
        "fromValue": 10,
        "byTo": "months",
        "toValue": 7
    }
    quarter_tickets = IncidentHandler().get_tickets(query=query, period=period, size=10000)
    tickets.extend(quarter_tickets)

    period = {
        "byFrom": "months",
        "fromValue": 7,
        "byTo": "months",
        "toValue": 4
    }
    quarter_tickets = IncidentHandler().get_tickets(query=query, period=period, size=10000)
    tickets.extend(quarter_tickets)

    period = {
        "byFrom": "months",
        "fromValue": 4,
        "byTo": "months",
        "toValue": 0
    }
    quarter_tickets = IncidentHandler().get_tickets(query=query, period=period, size=10000)
    tickets.extend(quarter_tickets)

    # Deduplicate tickets
    tickets = list({t['id']: t for t in tickets}.values())
    print(f"Total tickets retrieved: {len(tickets)}")

    if tickets:
        created_dates = [pd.to_datetime(t['created'], format='ISO8601', errors='coerce') for t in tickets]
        min_date = min(created_dates).strftime('%Y-%m-%d')
        max_date = max(created_dates).strftime('%Y-%m-%d')
        print(f"Date range: {min_date} to {max_date}")

    if not tickets:
        print("No tickets found for Past 12 Months.")
        execution_time = time.time() - start_time
        return execution_time

    df = pd.DataFrame(tickets)

    # Extract 'created_month' and 'ticket_type' fields
    df['created_month'] = pd.to_datetime(df['created'], format='ISO8601', errors='coerce').dt.tz_convert('UTC').dt.to_period('M')
    df['ticket_type'] = df['type']  # Assuming 'type' field represents ticket type

    # Handle missing or empty ticket types
    df['ticket_type'] = df['ticket_type'].fillna('Unknown').replace('', 'Unknown')

    # Remove METCIRT from ticket type names
    df['ticket_type'] = df['ticket_type'].str.replace(config.ticket_type_prefix, '').str.strip()

    # Group by month and ticket type, then count occurrences
    month_ticket_counts = df.groupby(['created_month', 'ticket_type'], observed=True).size().reset_index(name='count')

    # Generate expected months (past 12 months)
    current_month = pd.Period(datetime.now(), freq='M')
    expected_months = [current_month - i for i in range(11, -1, -1)]

    # Create pivot data structure for ticket types
    ticket_types = sorted(df['ticket_type'].unique())
    ticket_pivot_data = {ticket_type: np.zeros(len(expected_months)) for ticket_type in ticket_types}

    # Define explicit colors for ticket types
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
              '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf',
              '#aec7e8', '#ffbb78', '#98df8a', '#ff9896', '#c5b0d5']
    # Extend colors if needed
    while len(colors) < len(ticket_types):
        colors.extend(colors)
    ticket_type_color_map = {ticket_type: colors[i % len(colors)] for i, ticket_type in enumerate(ticket_types)}

    # Fill in ticket type values
    for _, row in month_ticket_counts.iterrows():
        if row['created_month'] in expected_months:
            month_idx = expected_months.index(row['created_month'])
            ticket_type = row['ticket_type']
            count = row['count']
            ticket_pivot_data[ticket_type][month_idx] += count

    # Debug info - print to see if there's data
    print(f"Ticket types: {ticket_types}")
    for ticket_type, values in ticket_pivot_data.items():
        print(f"Ticket type {ticket_type} values: {values.sum()}")

    # Extract 'created_month' as month-year and 'impact' fields
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown'))

    # Set missing or empty impact values to 'Unknown'
    df['impact'] = df['impact'].fillna('Unknown').replace('', 'Unknown')

    # Define custom order and colors - add 'Unknown' category
    CUSTOM_IMPACT_ORDER = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "False Positive", "Unknown"]
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
    df['impact'] = df['impact'].apply(lambda x: x if x in CUSTOM_IMPACT_ORDER else 'Unknown')

    # Group by month and impact, then count occurrences
    month_impact_counts = df.groupby(['created_month', 'impact'], observed=True).size().reset_index(name='count')

    # Ensure impacts follow the custom order
    month_impact_counts['impact'] = pd.Categorical(month_impact_counts['impact'], categories=CUSTOM_IMPACT_ORDER, ordered=True)

    # Create pivot data structure with zeros for all expected months
    pivot_data = {impact: np.zeros(len(expected_months)) for impact in CUSTOM_IMPACT_ORDER}
    monthly_totals = np.zeros(len(expected_months))

    # Fill in values where we have data
    for _, row in month_impact_counts.iterrows():
        if row['created_month'] in expected_months:
            month_idx = expected_months.index(row['created_month'])
            impact = row['impact']
            count = row['count']
            if impact in pivot_data:
                pivot_data[impact][month_idx] += count
                monthly_totals[month_idx] += count  # Update monthly totals here

    # Verify totals match
    total_in_viz = sum(monthly_totals)
    if total_in_viz != len(tickets):
        print(f"Warning: Visualization shows {total_in_viz} tickets but dataset has {len(tickets)} tickets")

    # Create single figure - increase figure size for better readability
    fig, ax = plt.subplots(figsize=(22, 14))

    # Format months for display
    month_labels = [month.strftime('%b %Y') for month in expected_months]

    # Set up the positions for bars
    group_width = 0.6  # Width of each month's group
    bar_width = group_width / 2  # Width of each bar (type and impact)
    spacing = 0.4  # Space between months

    # Calculate x positions
    x = np.arange(len(month_labels)) * (group_width + spacing)

    # Position for type bars (left) and impact bars (right)
    type_x = x - bar_width / 2
    impact_x = x + bar_width / 2

    # Plot ticket type bars (left side)
    type_bottom = np.zeros(len(expected_months))
    for ticket_type, values in ticket_pivot_data.items():
        if values.sum() > 0:  # Only show ticket types with data
            ax.bar(type_x, values, bottom=type_bottom, width=bar_width,
                   label=f"{ticket_type}", color=ticket_type_color_map[ticket_type],
                   edgecolor='black', linewidth=0.5)
            type_bottom += values

    # Plot impact bars (right side)
    impact_bottom = np.zeros(len(expected_months))
    for impact in CUSTOM_IMPACT_ORDER:
        values = pivot_data[impact]
        if values.sum() > 0:  # Only add to legend if there are values
            ax.bar(impact_x, values, bottom=impact_bottom, width=bar_width,
                   label=f"{impact}", color=impact_colors[impact])
            impact_bottom += values

    # Plot horizontal line for monthly average
    monthly_average = monthly_totals.mean() if monthly_totals.size > 0 else 0
    ax.axhline(monthly_average, color='blue', linestyle='--', linewidth=2,
               label=f'Monthly Average ({int(monthly_average)})')

    # Add trend line to show volume changes - increased marker size
    trend_line = ax.plot(x, monthly_totals, color='red', marker='o', markersize=8,
                         linewidth=2.5, label='Monthly Volume', zorder=10)

    # Add count labels above the trend line dots
    for i in range(len(x)):
        if monthly_totals[i] > 0:
            ax.text(x[i], monthly_totals[i] + 20,  # Position above the trend line dot
                    f'{int(monthly_totals[i])}',
                    ha='center', va='bottom',
                    fontsize=12, fontweight='bold',
                    bbox=dict(facecolor='white', alpha=0.9, edgecolor='none', pad=2),
                    zorder=20)  # Ensure labels are drawn on top

    # Set x-ticks and other formatting - increased tick size
    ax.set_xticks(x)
    y_max = max(max(type_bottom), max(impact_bottom), 100) * 1.15
    ax.set_ylim(0, y_max)
    ax.set_xticklabels(month_labels, rotation=45, ha='right', fontsize=12)  # Increased fontsize

    # Increase y-tick font size
    ax.tick_params(axis='y', labelsize=12)

    # Add note about data limit
    if len(tickets) == 10000:
        ax.text(0.5, 0.97, "Note: Data limited to 10,000 records",
                ha='center', va='top', transform=ax.transAxes,
                fontsize=10, fontstyle='italic', color='red')

    # Add labels and title - increased font sizes
    ax.set_xlabel("Month", fontweight='bold', fontsize=12)
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=12)
    ax.set_title(f"Inflow Over the Past 12 Months\nTotal: {len(tickets)} tickets",
                 fontweight='bold', fontsize=16)

    # Create separate legends for ticket types and impacts
    handles, labels = ax.get_legend_handles_labels()

    # Calculate total counts for each ticket type and impact
    ticket_type_totals = {ticket_type: values.sum() for ticket_type, values in ticket_pivot_data.items()}
    impact_totals = {impact: pivot_data[impact].sum() for impact in CUSTOM_IMPACT_ORDER}

    # Separate handles and labels as before
    type_handles = [h for h, l in zip(handles, labels) if "Monthly" not in l and l not in CUSTOM_IMPACT_ORDER]
    type_labels = [l for l in labels if "Monthly" not in l and l not in CUSTOM_IMPACT_ORDER]

    impact_handles = [h for h, l in zip(handles, labels) if "Monthly" in l or l in CUSTOM_IMPACT_ORDER]
    impact_labels = [l for l in labels if "Monthly" in l or l in CUSTOM_IMPACT_ORDER]

    # Add counts to type labels
    type_labels_with_counts = [f"{l} ({int(ticket_type_totals[l])})" for l in type_labels]

    # Add counts to impact labels (but not to Monthly Average/Volume)
    impact_labels_with_counts = []
    for l in impact_labels:
        if l in CUSTOM_IMPACT_ORDER:
            impact_labels_with_counts.append(f"{l} ({int(impact_totals[l])})")
        else:
            impact_labels_with_counts.append(l)  # Preserve labels like "Monthly Average"

    # Create legends with count-enhanced labels
    type_legend = ax.legend(type_handles, type_labels_with_counts,
                            title="Ticket Types",
                            title_fontproperties={'weight': 'bold', 'size': 12},
                            loc='upper left',
                            fontsize=10)

    # Add second legend in top right with counts
    ax.add_artist(type_legend)
    ax.legend(impact_handles, impact_labels_with_counts,
              title="Impact",
              title_fontproperties={'weight': 'bold', 'size': 12},
              loc='upper right',
              fontsize=10)

    # Add border and timestamp
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=11, transform=trans)

    # Save the chart
    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "Inflow Past 12 Months.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    plt.tight_layout()
    fig.savefig(OUTPUT_PATH)
    plt.close(fig)

    execution_time = time.time() - start_time
    return execution_time


def make_chart():
    try:
        print(f"Starting chart generation at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        start_time = time.time()

        print("Generating 'Yesterday' chart...")
        yesterday_time = plot_yesterday()
        print(f"  - Completed in {yesterday_time:.2f} seconds")

        print("Generating 'Past 60 Days' chart...")
        days60_time = plot_past_60_days()
        print(f"  - Completed in {days60_time:.2f} seconds")

        print("Generating 'Past 12 Months' chart...")
        months12_time = plot_past_12_months()
        print(f"  - Completed in {months12_time:.2f} seconds")

        total_time = time.time() - start_time
        print(f"All charts generated. Total time: {total_time:.2f} seconds")

    except Exception as e:
        print(f"An error occurred while generating charts: {e}")


if __name__ == '__main__':
    plot_past_12_months()
