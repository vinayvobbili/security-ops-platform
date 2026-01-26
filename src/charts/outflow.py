import sys
from pathlib import Path

# Add the project root to Python path FIRST
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import json
import re
import ssl
import urllib.request
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from PIL import Image
from matplotlib import transforms
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from matplotlib.ticker import MaxNLocator

from src.charts.chart_style import apply_chart_style

apply_chart_style()

from my_config import get_config
from services.xsoar import TicketHandler, XsoarEnvironment

eastern = pytz.timezone('US/Eastern')

config = get_config()

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = ROOT_DIRECTORY / 'data' / 'metrics' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
    detection_source_codes_by_name = json.load(f)

QUERY_TEMPLATE = 'type:{ticket_type_prefix} -owner:"" closed:>={start} closed:<{end}'


def download_and_cache_logo(logo_url, logo_filename):
    """Download a logo from URL and cache it locally"""
    logo_path = LOGO_DIR / logo_filename

    # If logo already exists, return the path
    if logo_path.exists():
        return logo_path

    try:
        # Create SSL context that doesn't verify certificates
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Create request with User-Agent to avoid 403 errors
        request = urllib.request.Request(logo_url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Download and save logo
        with urllib.request.urlopen(request, context=ssl_context) as response:
            image_data = response.read()

        # Save the original logo data directly without processing
        with open(logo_path, 'wb') as f:
            f.write(image_data)
        print(f"Downloaded and cached logo: {logo_filename}")
        return logo_path

    except Exception as e:
        print(f"Error downloading logo from {logo_url}: {e}")
        return None


# Define a custom order for the impacts
CUSTOM_IMPACT_ORDER = ["Confirmed", "Detected", "Prevented", "Ignore", "Testing", "Security Testing", "False Positive", "Benign True Positive", "Malicious True Positive", "Unknown", "Resolved"]

# --- Logo Configuration ---
LOGO_DIR = ROOT_DIRECTORY / "web" / "static" / "logos"  # Directory where logos are stored

# Individual logo sizes for optimal appearance
CROWDSTRIKE_LOGO_SIZE = 0.02  # CrowdStrike falcon logos
VECTRA_LOGO_SIZE = 0.06  # Vectra logos
PRISMA_LOGO_SIZE = 0.08  # Prisma Cloud logos
THIRD_PARTY_LOGO_SIZE = 0.02  # Third party compromise
EMPLOYEE_REPORT_LOGO_SIZE = 0.1  # Employee report
CASE_LOGO_SIZE = 0.03  # Case logos (smaller)
QRADAR_LOGO_SIZE = 0.07  # QRadar logos
DEFAULT_LOGO_SIZE = 0.05  # Default for others
LOST_STOLEN_DEVICE = 0.1  # Lost/Stolen Device logos
SPLUNK_LOGO_SIZE = 0.02  # Splunk logos
IOC_HUNT_LOGO_SIZE = 0.03  # IOC Hunt logos
AREA1_LOGO_SIZE = 0.06  # Area1 logos
LEAKED_CREDS_LOGO_SIZE = 0.04  # Leaked Credentials logos
AKAMAI_LOGO_SIZE = 0.04
VARONIS_LOGO_SIZE = 0.08

# Create a mapping of detection sources to logo URLs and filenames
LOGO_URL_MAPPING = {
    "cs detection": ("https://companieslogo.com/img/orig/CRWD-442a5e7d.png?t=1648651763", "crowdstrike.png"),
    "cs incident": ("https://companieslogo.com/img/orig/CRWD-442a5e7d.png?t=1648651763", "crowdstrike.png"),
    "crowdstrike detection": ("https://companieslogo.com/img/orig/CRWD-442a5e7d.png?t=1648651763", "crowdstrike.png"),
    "crowdstrike incident": ("https://companieslogo.com/img/orig/CRWD-442a5e7d.png?t=1648651763", "crowdstrike.png"),
    "prisma compute": ("https://images.g2crowd.com/uploads/product/image/social_landscape/social_landscape_f24901e9b516e0c419136a22214e9e4f/palo-alto-networks-prisma-cloud.png", "prisma_cloud.png"),
    "prisma runtime": ("https://images.g2crowd.com/uploads/product/image/social_landscape/social_landscape_f24901e9b516e0c419136a22214e9e4f/palo-alto-networks-prisma-cloud.png", "prisma_cloud.png"),
    "prisma cloud": ("https://images.g2crowd.com/uploads/product/image/social_landscape/social_landscape_f24901e9b516e0c419136a22214e9e4f/palo-alto-networks-prisma-cloud.png", "prisma_cloud.png"),
    "ueba prisma": ("https://images.g2crowd.com/uploads/product/image/social_landscape/social_landscape_f24901e9b516e0c419136a22214e9e4f/palo-alto-networks-prisma-cloud.png", "prisma_cloud.png"),
    "splunk alert": ("https://miro.medium.com/v2/resize:fit:1200/1*pUe_Skk6iOVvGdPKTio12g.jpeg", "splunk.png"),
    "qradar alert": ("https://tse3.mm.bing.net/th/id/OIP.CAdOtgtsDWXIx1oIBPQ55QAAAA?r=0&rs=1&pid=ImgDetMain&o=7&rm=3", "qradar.png"),
    "vectra detection": ("https://images.g2crowd.com/uploads/product/image/social_landscape/social_landscape_0851751a52d7a99e332527e5918d321b/vectra-ai.png", "vectra.png"),
    "third party compromise": ("https://png.pngtree.com/png-clipart/20230819/original/pngtree-third-party-icon-on-white-background-picture-image_8053292.png", "third_party.png"),
    "employee report": ("https://cdn.iconscout.com/icon/premium/png-256-thumb/employee-report-4849241-4030934.png", "employee_report.png"),
    "case": ("https://static.vecteezy.com/system/resources/previews/006/593/081/non_2x/security-alert-concepts-vector.jpg", "case.png"),
    "lost/stolen device": ("https://clipground.com/images/theft-protection-clipart-14.jpg", "lost_stolen_device.png"),
    "ioc hunt": ("https://www.pngitem.com/pimgs/b/104-1049518_detective-silhouette-png.png", "ioc_hunt.png"),
    "area1 alert": ("https://logowik.com/content/uploads/images/area-1-security8161.jpg", "area1.png"),
    "leaked creds": ("https://www.shutterstock.com/image-vector/data-personal-leak-vector-identity-600nw-2143054971.jpg", "leaked_credentials.png"),
    "akamai alert": ("https://www.vhv.rs/dpng/d/79-796343_akamai-logo-png-transparent-png.png", "akamai.png"),
    "varonis alert": ("https://logowik.com/content/uploads/images/varonis6799.jpg", "varonis.png"),
    "unknown": ("https://cdn-icons-png.flaticon.com/512/2534/2534590.png", "unknown.png")
}


def create_graph(tickets, period_label="Yesterday"):
    if not tickets:
        print("No tickets to plot.")
        return

    # Set up enhanced plot style without grids
    plt.style.use('default')

    # Configure matplotlib fonts
    # import matplotlib
    # matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

    # Process data
    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' and 'impact' from the 'CustomFields' dictionary
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact'))

    # Fill missing values in a source with "Unknown" at the beginning
    df['source'] = df['source'].fillna('Unknown')
    df['impact'] = df['impact'].fillna('Unknown')
    df['impact'] = df['impact'].replace('', 'Unknown')

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Use case-insensitive regex replacement for team name
    team_name_pattern = re.compile(re.escape(config.team_name), re.IGNORECASE) if config.team_name else None

    def process_source(row):
        # First strip team name (case-insensitive)
        source = team_name_pattern.sub('', row['type']).strip() if team_name_pattern else row['type']
        # Then apply all the replacements
        source = source.replace('CrowdStrike Falcon Detection', 'CS Detection')
        source = source.replace('CrowdStrike Falcon Incident', 'CS Incident')
        source = source.replace('Prisma Cloud Compute Runtime Alert', 'Prisma Compute')
        source = source.replace('Prisma Cloud Runtime Alert', 'Prisma Runtime')
        source = source.replace('Lost or Stolen Computer', 'Lost/Stolen Device')
        source = source.replace('Employee Reported Incident', 'Employee Report')
        source = source.replace('UEBA Prisma Cloud', 'UEBA Prisma')
        source = source.replace('Leaked Credentials', 'Leaked Creds')
        return source.strip()

    df['source'] = df.apply(process_source, axis=1)

    # Count the occurrences of each source and impact
    source_impact_counts = df.groupby(['source', 'impact']).size().reset_index(name='count')

    # Sort sources by total ticket count (descending)
    source_totals = source_impact_counts.groupby('source')['count'].sum().sort_values(ascending=False)
    sorted_sources = source_totals.index.tolist()

    # Reorder sources to form a pyramid shape
    mid_index = len(sorted_sources) // 2
    pyramid_sources = sorted_sources[mid_index::-1] + sorted_sources[mid_index + 1:]

    # Define Colors for impacts matching the target chart
    impact_colors = {
        "Confirmed": "#ff6b6b",  # Red
        "Detected": "#ffa726",  # Orange  
        "Prevented": "#66bb6a",  # Green
        "Ignore": "#424242",  # Dark gray
        "Testing": "#4dd0e1",  # Light cyan
        "Security Testing": "#26a69a",  # Teal
        "False Positive": "#ef5350",  # Light red
        "Benign True Positive": "#9e9e9e",  # Gray
        "Malicious True Positive": "#d32f2f",  # Dark red
        "Unknown": "#7986cb",  # Blue
        "Resolved": "#ab47bc"  # Purple
    }

    # Enhanced figure with better proportions and styling
    fig, ax = plt.subplots(figsize=(14, 10), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Plot data
    bottom = [0] * len(pyramid_sources)
    impacts = source_impact_counts['impact'].unique()

    # Sort impacts based on the custom order, including any impacts not in the custom order
    sorted_impacts = [impact for impact in CUSTOM_IMPACT_ORDER if impact in impacts]
    # Add any impacts that are in the data but not in the custom order
    for impact in impacts:
        if impact not in sorted_impacts:
            sorted_impacts.append(impact)

    for impact in sorted_impacts:
        impact_data = source_impact_counts[source_impact_counts['impact'] == impact]

        # Use the pre-sorted sources
        counts = []
        for source in pyramid_sources:
            if source in impact_data['source'].values:
                count = impact_data.loc[impact_data['source'] == source, 'count'].iloc[0]
                counts.append(count)
            else:
                counts.append(0)

        ax.barh(pyramid_sources, counts, height=0.6, left=bottom, label=impact,
                color=impact_colors.get(impact, "#6B7280"),
                edgecolor="white", linewidth=1.5, alpha=0.95)

        # Enhanced value labels with black circles (matching MTTR style)
        for i, count in enumerate(counts):
            if count > 0:
                x_pos = bottom[i] + count / 2

                ax.text(x_pos, i, str(count), ha='center', va='center',
                        color='white', fontsize=10, fontweight='bold',
                        bbox=dict(boxstyle="circle,pad=0.2", facecolor='black',
                                  alpha=0.8, edgecolor='white', linewidth=1))

        bottom = [b + c for b, c in zip(bottom, counts)]

    # --- Add Logos at the End of Bars (after all impacts are plotted) ---
    for i, source in enumerate(pyramid_sources):
        if bottom[i] == 0:  # Skip rows with no data
            continue

        logo_info = LOGO_URL_MAPPING.get(source.lower())  # match logo with a source

        if logo_info:  # If a logo mapping is found for the source
            logo_url, logo_filename = logo_info

            # Download and cache the logo (or use existing cached version)
            logo_path = download_and_cache_logo(logo_url, logo_filename)

            if logo_path and logo_path.exists():
                try:
                    # Load image from local file
                    image = Image.open(logo_path)

                    # Convert to RGBA and add white background
                    if image.mode != 'RGBA':
                        image = image.convert('RGBA')

                    # Create white background
                    white_bg = Image.new('RGBA', image.size, (255, 255, 255, 255))
                    # Composite the logo onto white background
                    image_with_bg = Image.alpha_composite(white_bg, image)
                    # Convert back to RGB for matplotlib
                    image_with_bg = image_with_bg.convert('RGB')

                    # Determine logo size based on source type
                    source_lower = source.lower()
                    if any(crowdstrike_key in source_lower for crowdstrike_key in ["cs detection", "cs incident", "crowdstrike"]):
                        logo_size = CROWDSTRIKE_LOGO_SIZE
                    elif "vectra" in source_lower:
                        logo_size = VECTRA_LOGO_SIZE
                    elif any(prisma_key in source_lower for prisma_key in ["prisma", "ueba prisma"]):
                        logo_size = PRISMA_LOGO_SIZE
                    elif "third party" in source_lower:
                        logo_size = THIRD_PARTY_LOGO_SIZE
                    elif "employee report" in source_lower:
                        logo_size = EMPLOYEE_REPORT_LOGO_SIZE
                    elif "case" in source_lower:
                        logo_size = CASE_LOGO_SIZE
                    elif "qradar" in source_lower:
                        logo_size = QRADAR_LOGO_SIZE
                    elif "lost/stolen device" in source_lower:
                        logo_size = LOST_STOLEN_DEVICE
                    elif "splunk" in source_lower:
                        logo_size = SPLUNK_LOGO_SIZE
                    elif "ioc hunt" in source_lower:
                        logo_size = IOC_HUNT_LOGO_SIZE
                    elif "area1" in source_lower:
                        logo_size = AREA1_LOGO_SIZE
                    elif "leaked cred" in source_lower:
                        logo_size = LEAKED_CREDS_LOGO_SIZE
                    elif "akamai" in source_lower:
                        logo_size = AKAMAI_LOGO_SIZE
                    elif "varonis" in source_lower:
                        logo_size = VARONIS_LOGO_SIZE
                    else:
                        logo_size = DEFAULT_LOGO_SIZE

                    # Create matplotlib image
                    imagebox = OffsetImage(image_with_bg, zoom=logo_size)  # Use source-specific logo size
                    # Smaller offset for larger logos to keep them closer to bars
                    offset = 0.1 if logo_size >= 0.07 else 0.3
                    x_pos = bottom[i] + offset
                    ab = AnnotationBbox(imagebox, (x_pos, i), frameon=False, xycoords='data',
                                        box_alignment=(0, 0.5))
                    ax.add_artist(ab)
                except Exception as e:
                    print(f"Error adding logo {logo_filename}: {e}")

    # Enhanced axes styling
    ax.set_facecolor('#ffffff')
    ax.grid(False)  # Explicitly disable grid
    ax.set_axisbelow(True)

    # Style the spines
    for spine in ax.spines.values():
        spine.set_visible(False)

    ax.xaxis.set_major_locator(MaxNLocator(integer=True))

    # Extend the x-axis
    max_x_value = max(bottom)
    ax.set_xlim((0, max_x_value * 1.1))  # Extend 10% beyond the maximum x-value

    # Enhanced border with rounded corners like MTTR chart
    from matplotlib.patches import FancyBboxPatch
    border_width = 2
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

    # Enhanced titles and labels
    plt.suptitle(f'Outflow {period_label} ({len(tickets)})', fontsize=20, fontweight='bold', color='#1A237E', y=0.95)

    # Add labels with enhanced styling
    ax.set_yticks(range(len(pyramid_sources)))
    ax.set_yticklabels(pyramid_sources, fontsize=10, color='#1A237E')
    ax.set_ylabel('Ticket Type', fontweight='bold', fontsize=12, color='#1A237E')
    ax.set_xlabel('Alert Counts', fontweight='bold', fontsize=12, labelpad=10, color='#1A237E')

    # Calculate impact totals for legend
    impact_totals = df.groupby('impact')['impact'].count().to_dict()

    # Update legend labels with counts
    impact_labels = []
    for impact in sorted_impacts:
        count = impact_totals.get(impact, 0)
        impact_labels.append(f"{impact} ({count})")

    # Enhanced legend positioned outside like MTTR chart
    legend = ax.legend(impact_labels, title='Impact', loc='upper left', bbox_to_anchor=(1.15, 1),
                       frameon=True, fancybox=True, shadow=True,
                       title_fontsize=12, fontsize=10)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)

    # Make legend title bold
    legend.get_title().set_fontweight('bold')

    # Enhanced timestamp with modern styling - moved to left end
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')

    plt.text(0.02, 0.02, f"Generated@ {now_eastern}",
             transform=trans, ha='left', va='bottom',
             fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                       edgecolor='#1A237E', linewidth=1.5))

    # Add GS-DnR watermark
    fig.text(0.99, 0.01, 'GS-DnR',
             ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Adjust layout with space for external legend and Y-axis labels
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.15, left=0.20, right=0.73)

    today_date = datetime.now().strftime('%m-%d-%Y')
    output_path = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Outflow Yesterday.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    plt.savefig(output_path, format='png', bbox_inches='tight', pad_inches=0.0, dpi=300)
    plt.close(fig)


def make_chart() -> None:
    # Calculate exact yesterday window in Eastern time, then convert to UTC for query
    # On Mondays, include both Saturday and Sunday
    now = datetime.now(eastern).replace(hour=0, minute=0, second=0, microsecond=0)

    # If today is Monday (weekday 0), include both Saturday and Sunday
    if now.weekday() == 0:
        # Saturday is 2 days ago, Sunday is 1 day ago
        yesterday_start = now - timedelta(days=2)
        yesterday_end = now  # End at Monday 00:00
        period_label = "Weekend"
    else:
        # Regular case: just yesterday
        yesterday_start = now - timedelta(days=1)
        yesterday_end = now
        period_label = "Yesterday"

    # Convert Eastern time to UTC for the API query
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.team_name, start=yesterday_start_utc, end=yesterday_end_utc)
    prod_ticket_handler = TicketHandler(XsoarEnvironment.PROD)
    tickets = prod_ticket_handler.get_tickets(query=query)
    create_graph(tickets, period_label)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    make_chart()
