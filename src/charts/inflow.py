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
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = root_directory / 'data' / 'transient' / 'metrics' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
    detection_source_codes_by_name = json.load(f)


def create_stacked_bar_chart(df, x_label, y_label, title):
    """Creates a stacked bar chart from a pandas DataFrame."""
    fig, ax = plt.subplots(figsize=(20, 12))

    # Pivot the DataFrame to get the counts of each severity per source
    df_pivot = df.pivot_table(index='source', columns='severity', values='count', fill_value=0)

    # Plot the stacked bar chart with lighter shades
    bars = df_pivot.plot(kind='bar', stacked=True, ax=ax, color=['#6989e8', '#ffbb78', '#98df8a', '#ff9896'], width=0.3)

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

    # Show daily totals at the top of each bar
    for i, total in enumerate(daily_totals):
        if total > 0:
            ax.text((x[i]), total + 2, f'{int(total)}', ha='center', va='center', fontsize=10, fontweight='bold')

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
    """Creates charts for ticket inflow over the past 12 months, grouped by month."""
    start_time = time.time()

    query = f'type:{config.ticket_type_prefix} -owner:""'
    tickets = []

    # Fetch data in chunks to handle potential volume
    for i in range(0, 13, 3):
        period = {
            "byFrom": "months",
            "fromValue": 12 - i,
            "byTo": "months",
            "toValue": max(0, 9 - i)
        }
        quarter_tickets = IncidentHandler().get_tickets(query=query, period=period, size=10000)
        tickets.extend(quarter_tickets)

    # Deduplicate tickets
    tickets = list({t['id']: t for t in tickets}.values())
    print(f"Total tickets retrieved: {len(tickets)}")

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
    x = np.arange(len(month_labels)) * 1.0  # Position for bars

    # Process ticket type data
    df['ticket_type'] = df['type'].fillna('Unknown').replace('', 'Unknown')
    df['ticket_type'] = df['ticket_type'].str.replace(config.ticket_type_prefix, '').str.strip()
    ticket_types = sorted(df['ticket_type'].unique())
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

    # Ensure impacts follow predefined list
    df['impact'] = df['impact'].apply(lambda x: x if x in CUSTOM_IMPACT_ORDER else 'Unknown')
    month_impact_counts = df.groupby(['created_month', 'impact'], observed=True).size().reset_index(name='count')

    # Create impact data structure
    impact_pivot_data = {impact: np.zeros(len(expected_months)) for impact in CUSTOM_IMPACT_ORDER}
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
    create_combined_chart(expected_months, month_labels, x, ticket_types, ticket_pivot_data,
                          ticket_type_color_map, CUSTOM_IMPACT_ORDER, impact_pivot_data, impact_colors,
                          monthly_totals, monthly_average, tickets, output_dir)

    # 2. Create impact-only chart
    create_impact_chart(expected_months, month_labels, x, CUSTOM_IMPACT_ORDER, impact_pivot_data,
                        impact_colors, monthly_totals, monthly_average, tickets, output_dir)

    # 3. Create ticket type-only chart
    create_ticket_type_chart(expected_months, month_labels, x, ticket_types, ticket_pivot_data,
                             ticket_type_color_map, monthly_totals, monthly_average, tickets, output_dir)

    return time.time() - start_time


def create_combined_chart(expected_months, month_labels, x, ticket_types, ticket_pivot_data,
                          ticket_type_color_map, CUSTOM_IMPACT_ORDER, impact_pivot_data, impact_colors,
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
    for impact in CUSTOM_IMPACT_ORDER:
        values = impact_pivot_data[impact]
        if values.sum() > 0:
            ax.bar(impact_x, values, bottom=impact_bottom, width=bar_width,
                   label=f"{impact}", color=impact_colors[impact])
            impact_bottom += values

    # Monthly average line
    ax.axhline(monthly_average, color='blue', linestyle='--', linewidth=2,
               label=f'Monthly Average ({int(monthly_average)})')

    # Trend line
    ax.plot(x_pos, monthly_totals, color='red', marker='o', markersize=8,
            linewidth=2.5, label='Monthly Volume', zorder=10)

    # Add count labels
    for i in range(len(x_pos)):
        if monthly_totals[i] > 0:
            ax.text(float(x_pos[i]), float(monthly_totals[i]) + 20, f'{int(monthly_totals[i])}',
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
    impact_totals = {impact: impact_pivot_data[impact].sum() for impact in CUSTOM_IMPACT_ORDER}

    type_handles = [h for h, l in zip(handles, labels) if "Monthly" not in l and l not in CUSTOM_IMPACT_ORDER]
    type_labels = [l for l in labels if "Monthly" not in l and l not in CUSTOM_IMPACT_ORDER]
    impact_handles = [h for h, l in zip(handles, labels) if "Monthly" in l or l in CUSTOM_IMPACT_ORDER]
    impact_labels = [l for l in labels if "Monthly" in l or l in CUSTOM_IMPACT_ORDER]

    type_labels_with_counts = [f"{l} ({int(ticket_type_totals[l])})" for l in type_labels]
    impact_labels_with_counts = []
    for l in impact_labels:
        if l in CUSTOM_IMPACT_ORDER:
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
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=11, transform=trans)

    plt.tight_layout()
    fig.savefig(output_dir / "Inflow Past 12 Months.png")
    plt.close(fig)


def create_impact_chart(expected_months, month_labels, x, CUSTOM_IMPACT_ORDER, impact_pivot_data,
                        impact_colors, monthly_totals, monthly_average, tickets, output_dir):
    """Creates a chart showing only impact data."""
    fig, ax = plt.subplots(figsize=(20, 12))

    # Plot impact bars (full width)
    bar_width = 0.4
    x_pos = np.arange(len(month_labels))
    impact_bottom = np.zeros(len(expected_months))

    for impact in CUSTOM_IMPACT_ORDER:
        values = impact_pivot_data[impact]
        if values.sum() > 0:
            ax.bar(x_pos, values, bottom=impact_bottom, width=bar_width,
                   label=f"{impact}", color=impact_colors[impact])
            impact_bottom += values

    # Monthly average line
    ax.axhline(monthly_average, color='blue', linestyle='--', linewidth=2,
               label=f'Monthly Average ({int(monthly_average)})')

    # Trend line
    ax.plot(x_pos, monthly_totals, color='red', marker='o', markersize=8,
            linewidth=2.5, label='Monthly Volume', zorder=10)

    # Add count labels
    for i in range(len(x_pos)):
        if monthly_totals[i] > 0:
            ax.text(x_pos[i], monthly_totals[i] + 20, f'{int(monthly_totals[i])}',
                    ha='center', va='bottom', fontsize=12, fontweight='bold',
                    bbox=dict(facecolor='white', alpha=0.9, edgecolor='none', pad=2), zorder=20)

    # Formatting
    ax.set_xticks(x_pos)
    y_max = max(impact_bottom.max(), 100) * 1.15
    ax.set_ylim(0, y_max)
    ax.set_xticklabels(month_labels, rotation=45, ha='right', fontsize=12)
    ax.tick_params(axis='y', labelsize=12)

    # Titles and labels
    ax.set_xlabel("Month", fontweight='bold', fontsize=12)
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=12)
    fig.suptitle(f'Impact Distribution Over the Past 12 Months', fontweight='bold', fontsize=14, x=0.5)
    ax.set_title(f"Total: {len(tickets)} tickets", fontsize=12, x=0.5)

    # Create legend with counts
    handles, labels = ax.get_legend_handles_labels()
    impact_totals = {impact: impact_pivot_data[impact].sum() for impact in CUSTOM_IMPACT_ORDER}

    custom_labels = []
    for l in labels:
        if l in CUSTOM_IMPACT_ORDER:
            custom_labels.append(f"{l} ({int(impact_totals[l])})")
        else:
            custom_labels.append(l)

    ax.legend(handles, custom_labels, title="Impact",
              title_fontproperties={'weight': 'bold', 'size': 12},
              loc='upper right', fontsize=10)

    # Add border and timestamp
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=11, transform=trans)

    plt.tight_layout()
    fig.savefig(output_dir / "Inflow Past 12 Months - Impact Only.png")
    plt.close(fig)


def create_ticket_type_chart(expected_months, month_labels, x, ticket_types, ticket_pivot_data,
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
    ax.plot(x_pos, monthly_totals, color='red', marker='o', markersize=8,
            linewidth=2.5, label='Monthly Volume', zorder=10)

    # Add count labels
    for i in range(len(x_pos)):
        if monthly_totals[i] > 0:
            ax.text(x_pos[i], monthly_totals[i] + 20, f'{int(monthly_totals[i])}',
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

    plt.tight_layout()
    fig.savefig(output_dir / "Inflow Past 12 Months - Ticket Type Only.png")
    plt.close(fig)


def make_chart():
    try:
        plot_yesterday()
        plot_past_60_days()
        plot_past_12_months()

    except Exception as e:
        print(f"An error occurred while generating charts: {e}")


if __name__ == '__main__':
    plot_past_60_days()
