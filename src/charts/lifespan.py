import json
import logging
import re
import tempfile
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from my_config import get_config
from services.xsoar import TicketHandler

eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone

config = get_config()

root_directory = Path(__file__).parent.parent.parent
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = root_directory / 'data' / 'metrics' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
    detection_source_codes_by_name = json.load(f)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

QUERY = f'type:{config.team_name} -owner:"" status:closed'
PERIOD = {
    "byFrom": "months",
    "fromValue": 1
}


def get_lifespan_chart(tickets):
    if not tickets:
        fig, ax = plt.subplots(figsize=(8, 6))  # set the default file size here
        ax.text(0.5, 0.5, 'No tickets found!', ha='center', va='center', fontsize=12)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            plt.savefig(tmpfile.name, format="png")
        plt.close()
        return tmpfile.name

    data = []
    for ticket in tickets:
        custom_fields = ticket.get('CustomFields', {})
        data.append({
            'type': ticket.get('type').replace(f'{config.team_name} ', ''),
            'triage': custom_fields.get(config.triage_timer, {}).get('totalDuration', 0) / 3600,
            'lessons': custom_fields.get(config.lessons_learned_time, {}).get('totalDuration', 0) / 3600,
            'investigate': custom_fields.get(config.investigation_time, {}).get('totalDuration', 0) / 3600,
            'eradicate': custom_fields.get(config.eradication_time, {}).get('totalDuration', 0) / 3600,
            'closure': custom_fields.get(config.closure_time, {}).get('totalDuration', 0) / 3600,
        })

    df = pd.DataFrame(data)
    df['lifespan'] = df[['triage', 'lessons', 'investigate', 'eradicate', 'closure']].sum(axis=1)
    df['count'] = 1
    for pattern, replacement in detection_source_codes_by_name.items():
        df['type'] = df['type'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)
    df = df.groupby('type').sum().reset_index()
    df = df[df['lifespan'] > 0].sort_values('lifespan', ascending=False)

    # Enhanced professional color scheme for IR workflow phases
    colors = {
        'closure': '#2E7D32',      # Dark green - final completion
        'lessons': '#1976D2',      # Blue - lessons learned
        'eradicate': '#FF9800',    # Orange - eradication phase
        'investigate': '#F44336',   # Red - investigation phase  
        'triage': '#9C27B0'        # Purple - initial triage
    }
    
    fig, ax = plt.subplots(figsize=(14, 10), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')
    ax.set_facecolor('#ffffff')
    ax.grid(False)

    # Convert hours to days for better readability
    df_days = df.copy()
    phase_order = ['closure', 'lessons', 'eradicate', 'investigate', 'triage']
    for col in phase_order:
        df_days[col] = df[col] / 24  # Convert hours to days
    
    bar_width = 0.6
    bottoms = pd.Series(0, index=df_days.index)
    
    for col in phase_order:
        ax.bar(df_days['type'], df_days[col], label=col.capitalize(), bottom=bottoms,
               color=colors[col], width=bar_width, edgecolor='white', linewidth=1.5, alpha=0.9)
        bottoms += df_days[col]

    # Enhanced titles and styling
    total_tickets = df['count'].sum()
    plt.suptitle('Cumulative Lifespan by Type',
                 fontsize=24, fontweight='bold', color='#1A237E', y=0.96)
    ax.set_title(f'Ticket processing time distribution (last 30 days) - Total: {int(total_tickets)} tickets',
                 fontsize=14, color='#3F51B5', pad=25, fontweight='bold')
    
    ax.set_xlabel("Ticket Type", fontweight='bold', fontsize=14, labelpad=15, color='#1A237E')
    ax.set_ylabel("Days", fontweight='bold', fontsize=14, labelpad=15, color='#1A237E')
    
    # Enhanced tick styling
    ax.tick_params(axis='x', rotation=45, colors='#1A237E', labelsize=12, width=1.5, pad=10)
    ax.tick_params(axis='y', colors='#1A237E', labelsize=12, width=1.5)
    plt.setp(ax.get_xticklabels(), ha='right', fontweight='bold')
    
    # Enhanced legend with counts in days
    legend_labels = []
    for phase in phase_order:
        total_days = df[phase].sum() / 24  # Convert hours to days
        legend_labels.append(f"{phase.capitalize()} ({total_days:.1f}d)")
    
    legend = ax.legend(legend_labels, title='Phase (Total Days)', 
                       title_fontproperties={'weight': 'bold', 'size': 14},
                       loc='upper left', bbox_to_anchor=(1.01, 1), fontsize=12, 
                       frameon=True, fancybox=True, shadow=True)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)

    # Enhanced total days labels on top of bars (matching Y-axis)
    for i, (_, row) in enumerate(df_days.iterrows()):
        total_height_days = row[phase_order].sum()
        total_days = int(total_height_days)
        ticket_count = int(row['count'])
        ax.text(i, total_height_days + max(df_days[phase_order].sum(axis=1)) * 0.02, 
                f'{total_days}d\n({ticket_count} tickets)',
                ha='center', va='bottom', fontsize=10, fontweight='bold', color='#1A237E',
                bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.95,
                          edgecolor='#1A237E', linewidth=1.5))

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
             
    # Style the spines
    for spine in ax.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)

    plt.tight_layout()
    plt.subplots_adjust(top=0.85, bottom=0.18, left=0.10, right=0.75)

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "Lifespan.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUTPUT_PATH, format="png", dpi=300, bbox_inches='tight', pad_inches=0.1, facecolor='#f8f9fa')
    plt.close()


def make_chart():
    incident_fetcher = TicketHandler()
    tickets = incident_fetcher.get_tickets(query=QUERY, period=PERIOD)
    get_lifespan_chart(tickets)


if __name__ == '__main__':
    make_chart()
