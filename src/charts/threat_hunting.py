from datetime import datetime

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import services.azdo as azdo

hunt_details = azdo.get_stories_from_area_path()
# group the user stories by the week they are created in
dates = []
critical_counts = []
high_counts = []
medium_counts = []
low_counts = []

for hunt in hunt_details:
    week = datetime.strptime(hunt.fields['System.CreatedDate'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%m/%d/%y')
    priority = hunt.fields['Microsoft.VSTS.Common.Priority']
    if week not in dates:
        dates.append(week)
        critical_counts.append(0)
        high_counts.append(0)
        medium_counts.append(0)
        low_counts.append(0)
    index = dates.index(week)
    if priority == 1:
        critical_counts[index] += 1
    elif priority == 2:
        high_counts[index] += 1
    elif priority == 3:
        medium_counts[index] += 1
    elif priority == 4:
        low_counts[index] += 1

# Convert string dates to datetime objects for better plotting
date_objects = [datetime.strptime(date, '%m/%d/%y') for date in dates]

# Create DataFrame for the graph
df_graph = pd.DataFrame({
    'Date': date_objects,
    'Critical': critical_counts,
    'High': high_counts,
    'Medium': medium_counts,
    'Low': low_counts
})

# Calculate total hunts per week
df_graph['Total'] = df_graph['Critical'] + df_graph['High'] + df_graph['Medium'] + df_graph['Low']

# Create DataFrame for the details table
df_table = pd.DataFrame(hunt_details)

# Colors for each priority
colors = {
    'Critical': '#ef4444',  # Red
    'High': '#f97316',  # Orange
    'Medium': '#fbbf24',  # Yellow
    'Low': '#60a5fa'  # Blue
}

# Create figure with more explicit sizing to ensure table visibility
fig = plt.figure(figsize=(14, 20))  # Increased height to make table more visible
gs = fig.add_gridspec(2, 1, height_ratios=[1, 2], hspace=0.1)  # More space for table (2:1 ratio)

# Create the bar chart subplot
ax = fig.add_subplot(gs[0])

# Plot stacked bars
bottom = np.zeros(len(dates))
for priority in ['Low', 'Medium', 'High', 'Critical']:  # Start with low priority at bottom
    ax.bar(df_graph['Date'], df_graph[priority], bottom=bottom,
           label=priority, color=colors[priority])
    bottom += np.array(df_graph[priority])

# Format the x-axis
ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d/%y'))
plt.setp(ax.get_xticklabels(), rotation=45, ha='right')

# Add data labels for total counts
for i, total in enumerate(df_graph['Total']):
    ax.text(mdates.date2num(date_objects[i]), total + 0.5, str(total),
            ha='center', va='bottom', fontweight='bold')

# Add labels and title
ax.set_title('Weekly Threat Hunts by Priority', fontsize=16, fontweight='bold')
ax.set_xlabel('Week', fontsize=12)
ax.set_ylabel('Number of Threat Hunts', fontsize=12)
ax.grid(axis='y', linestyle='--', alpha=0.3)

# Add legend
ax.legend(title='Priority', loc='upper left')

# Calculate overall statistics
total_hunts = df_graph['Total'].sum()
stats_text = (
    f"Total Threat Hunts: {total_hunts}\n"
    f"Critical: {sum(critical_counts)} ({sum(critical_counts) / total_hunts * 100:.1f}%)\n"
    f"High: {sum(high_counts)} ({sum(high_counts) / total_hunts * 100:.1f}%)\n"
    f"Medium: {sum(medium_counts)} ({sum(medium_counts) / total_hunts * 100:.1f}%)\n"
    f"Low: {sum(low_counts)} ({sum(low_counts) / total_hunts * 100:.1f}%)"
)

# Add the text box
props = dict(boxstyle='round', facecolor='white', alpha=0.9)
ax.text(1.02, 0.5, stats_text, transform=ax.transAxes, fontsize=10,
        verticalalignment='center', bbox=props)

# Create the table subplot with more space
ax_table = fig.add_subplot(gs[1])
ax_table.axis('tight')  # This helps with table sizing
ax_table.axis('off')  # Hide axes

# Sort table data by date (newest first) and then by priority
df_table['Sort_Date'] = pd.to_datetime(df_table['Week'], format='%m/%d/%y')
priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
df_table['Priority_Order'] = df_table['Priority'].map(priority_order)
df_table = df_table.sort_values(['Sort_Date', 'Priority_Order'], ascending=[False, True])
df_table = df_table.drop(['Sort_Date', 'Priority_Order'], axis=1)  # Remove helper columns

# Create combined ticket and title column to match your format
df_table['Hunt Details'] = df_table.apply(
    lambda row: f"{row['Ticket']} {row['Title']}", axis=1
)

# Select and reorder columns for display
display_df = df_table[['Week', 'Priority', 'Hunt Details', 'XSOAR_Link']]

# Create table data for display
table_data = display_df.values.tolist()
column_headers = ['Week', 'Priority', 'Hunt Details', 'XSOAR Link']

# Create table with more explicit sizing and controlling cell wrapping
table = plt.table(
    cellText=table_data,
    colLabels=column_headers,
    loc='center',
    cellLoc='left',
    colWidths=[0.1, 0.1, 0.55, 0.25]  # Adjusted to give more room for the XSOAR link
)

# Style the table for better visibility
table.auto_set_font_size(False)
table.set_fontsize(9)  # Slightly smaller font to fit content
table.scale(1, 2)  # Make rows taller for better readability

# Set word wrap for long text columns (details and links)
# This helps prevent text from extending beyond cell boundaries
for i in range(len(table_data) + 1):  # +1 for header row
    for j in [2, 3]:  # Hunt Details and XSOAR Link columns
        if i > 0:  # Skip header row for data formatting
            cell = table._cells[(i, j)]
            cell._text.set_wrap(True)  # Enable text wrapping

# Truncate XSOAR links to ensure they fit in the cell
for i in range(len(table_data)):
    link_cell = table._cells[(i + 1, 3)]  # XSOAR Link column, +1 for header
    link_text = table_data[i][3]
    if len(link_text) > 40:  # If link is too long
        truncated = link_text[:37] + "..."
        link_cell.get_text().set_text(truncated)

# Style the header row
for j, cell in enumerate(table._cells[(0, j)] for j in range(len(column_headers))):
    cell.set_text_props(weight='bold', color='white')
    cell.set_facecolor('#4b5563')  # Dark gray background for headers

# Color code priority cells
for i in range(len(table_data)):
    priority = table_data[i][1]  # Priority is now in the second column
    if priority in colors:
        cell = table._cells[(i + 1, 1)]  # +1 to account for header row
        cell.set_facecolor(colors[priority])  # Set background color
        if priority in ['Critical', 'High']:  # For darker colors, use white text
            cell.set_text_props(color='white')

# Add a clear title for the table
plt.figtext(0.5, 0.54, 'Threat Hunt Details', fontsize=14, fontweight='bold', ha='center')

# Adjust layout - increased bottom margin to ensure all table content is visible
plt.subplots_adjust(left=0.05, right=0.85, top=0.95, bottom=0.08)

# Save the figure
plt.savefig('weekly_threat_hunts_with_details.png', dpi=300, bbox_inches='tight')

# Display the plot
plt.show()
