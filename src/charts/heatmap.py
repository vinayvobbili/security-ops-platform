import json
import ssl
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

import cartopy.crs as ccrs
import cartopy.feature as cfeature
import cartopy.io.shapereader as shpreader
import matplotlib.cm as cm
import matplotlib.colors as colors
import matplotlib.pyplot as plt
from matplotlib import transforms
from pytz import timezone

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import my_config as config_module
from services.xsoar import TicketHandler

config = config_module.get_config()

eastern = timezone('US/Eastern')

QUERY_TEMPLATE = f'status:closed type:{config.team_name} -owner:""'
PERIOD = {"byFrom": "days", "fromValue": 30}

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATA_DIR = ROOT_DIRECTORY / 'data' / 'metrics'


# Set up a custom SSL context that doesn't verify certificates
def fix_ssl_verification():
    ssl_context = ssl._create_unverified_context()
    # Replace the default HTTPS opener with one that uses our custom SSL context
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))
    urllib.request.install_opener(opener)


# Call this function at the beginning of your script, before any Cartopy calls
fix_ssl_verification()


def create_choropleth_map():
    """Create a world choropleth map using Cartopy."""

    with open(DATA_DIR / 'host_counts_by_country.json', 'r') as f:
        host_counts_by_country = json.load(f)

    with open(DATA_DIR / 'country_name_abbreviations.json', 'r') as f:
        country_name_abbreviations = json.load(f)

    with open(DATA_DIR / 'x_cartopy_country_name_mapping.json', 'r') as f:
        x_cartopy_country_name_mapping = json.load(f)

    query = QUERY_TEMPLATE
    tickets = TicketHandler().get_tickets(query=query, period=PERIOD)
    ticket_counts_by_country = {}

    for ticket in tickets:
        country = ticket.get("CustomFields", {}).get("affectedcountry")
        ticket_counts_by_country[country] = ticket_counts_by_country.get(country, 0) + 1

    data = {}
    for country in ticket_counts_by_country.keys():
        host_count = host_counts_by_country.get(country, 0) / 1000  # Get host count, default to 0
        if host_count > 0:  # Avoid ZeroDivisionError
            country_key = x_cartopy_country_name_mapping.get(country, country)
            data[country_key] = ticket_counts_by_country[country] / host_count

    # print(ticket_counts_by_country)

    cmap = cm.YlOrRd
    norm = colors.Normalize(vmin=min(data.values()), vmax=max(data.values()))

    # Create enhanced map with modern styling
    fig, ax = plt.subplots(figsize=(18, 12), subplot_kw={'projection': ccrs.PlateCarree()},
                           facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

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

    ax.add_feature(cfeature.COASTLINE, linewidth=0.01, zorder=1, linestyle='None')
    ax.add_feature(cfeature.BORDERS, linestyle='None', zorder=1, linewidth=0.01)
    ax.set_global()  # Important for proper display with PlateCarree

    # Set ocean color to a more professional blue
    ax.add_feature(cfeature.OCEAN, color='#E3F2FD')  # Light blue that matches our theme

    # Country size threshold (experiment to find a good value)
    area_threshold = 50  # Example: Treat countries smaller than this as "small"

    # Get country shapes
    shapefile_path = shpreader.natural_earth(resolution='50m', category='cultural', name='admin_0_countries')
    reader = shpreader.Reader(shapefile_path)
    countries = reader.records()

    for country in countries:

        country_name = country.attributes['NAME_EN']
        country_name = x_cartopy_country_name_mapping.get(country_name, country_name)

        if country_name in data:  # This is the crucial check
            face_color = cmap(norm(data[country_name]))
            ax.add_geometries(country.geometry, ccrs.PlateCarree(),
                              facecolor=face_color, edgecolor='black')
        else:  # Handle cases when there's no ticket data for country
            face_color = "lightgray"  # Set to gray to indicate no data
            ax.add_geometries(country.geometry, ccrs.PlateCarree(),
                              facecolor=face_color, edgecolor='black', linewidth=0.1)

        if country_name in data and country_name in country_name_abbreviations:
            if country.geometry.area < area_threshold:  # Check if country is "small"
                centroid = country.geometry.centroid

                # Leader Line calculations:
                lon = centroid.x
                lat = centroid.y
                offset_lon = lon + 1
                offset_lat = lat + 0.5

                # Draw the leader line
                ax.plot([lon, offset_lon], [lat, offset_lat], color='black',
                        linewidth=1, transform=ccrs.Geodetic(), zorder=2)

                # Place label at the offset position
                ax.text(offset_lon, offset_lat, country_name_abbreviations[country_name],
                        transform=ccrs.PlateCarree(), ha='left', va='center',
                        color='black', fontsize=6, zorder=3, fontweight='bold')
            else:  # Larger countries, direct label
                centroid = country.geometry.centroid  # Use centroid
                ax.text(centroid.x, centroid.y, country_name_abbreviations[country_name],
                        transform=ccrs.PlateCarree(), ha='center', va='center',
                        color='black', fontsize=6, zorder=3)

    # Colorbar
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])  # This is necessary for the colorbar to work correctly

    # Calculate total alerts for subtitle context
    total_tickets = sum(ticket_counts_by_country.values())

    # Enhanced colorbar styling - shorter width and reduced height
    cbar = plt.colorbar(sm, ax=ax, orientation="horizontal", pad=0.02, shrink=0.8,
                        aspect=50)  # Higher aspect ratio = thinner colorbar, shorter width
    cbar.ax.tick_params(labelsize=10, labelcolor='#1A237E', width=1.5)
    cbar.set_label(f"Alert counts per thousand hosts (last 30 days) - Total: {total_tickets} alerts",
                   fontsize=12, fontweight='bold', color='#1A237E', labelpad=15)

    # Style the colorbar frame
    cbar.outline.set_edgecolor('#1A237E')
    cbar.outline.set_linewidth(1.5)

    # Enhanced title with padding around it
    plt.suptitle('Incident Response Heat Map',
                 fontsize=22, fontweight='bold', color='#1A237E', y=0.985)

    # Enhanced timestamp and branding
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)

    fig.text(0.02, 0.005, f"Generated@ {now_eastern}",
             ha='left', va='bottom', fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                       edgecolor='#1A237E', linewidth=1.5),
             transform=trans)

    # Add GS-DnR branding - closer to bottom
    fig.text(0.98, 0.005, 'GS-DnR', ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold',
             transform=trans)

    # Enhanced layout adjustments - bring map and colorbar down further
    plt.tight_layout()
    plt.subplots_adjust(top=0.92, bottom=0.15, left=0.005, right=0.995)

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Heat Map.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUTPUT_PATH, dpi=300, bbox_inches='tight', pad_inches=0, facecolor='#f8f9fa')
    plt.close(fig)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    create_choropleth_map()
