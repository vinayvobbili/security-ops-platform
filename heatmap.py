import json
import tempfile
from datetime import datetime

import cartopy.crs as ccrs
import cartopy.feature as cfeature
import cartopy.io.shapereader as shpreader
import matplotlib.cm as cm
import matplotlib.colors as colors
import matplotlib.pyplot as plt
from matplotlib import transforms
from pytz import timezone
from webex_bot.models.command import Command
from webexteamssdk import WebexTeamsAPI

from config import get_config
from helper_methods import log_activity
from incident_fetcher import IncidentFetcher

from bot_rooms import get_room_name

config = get_config()
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)

eastern = timezone('US/Eastern')  # Define the Eastern time zone

QUERY_TEMPLATE = '-category:job status:closed type:{ticket_type_prefix} -owner:""'
PERIOD = {"byFrom": "days", "fromValue": 30}

with open('data/host_counts_by_country.json', 'r') as f:
    host_counts_by_country = json.load(f)

with open('data/country_name_abbreviations.json', 'r') as f:
    country_name_abbreviations = json.load(f)

with open('data/x_cartopy_country_name_mapping.json', 'r') as f:
    x_cartopy_country_name_mapping = json.load(f)


def create_choropleth_map():
    """Create a world choropleth map using Cartopy."""
    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix)
    tickets = IncidentFetcher().get_tickets(query=query, period=PERIOD)
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

    print(ticket_counts_by_country)

    cmap = cm.YlOrRd
    norm = colors.Normalize(vmin=min(data.values()), vmax=max(data.values()))

    # Create the map
    fig, ax = plt.subplots(figsize=(15, 10), subplot_kw={'projection': ccrs.PlateCarree()})
    ax.add_feature(cfeature.COASTLINE, linewidth=0.01, zorder=1, linestyle='None')
    ax.add_feature(cfeature.BORDERS, linestyle='None', zorder=1, linewidth=0.01)
    ax.set_global()  # Important for proper display with PlateCarree

    # Set ocean color to Global density or light blue
    ax.add_feature(cfeature.OCEAN, color='lightblue')

    # Country size threshold (experiment to find a good value)
    area_threshold = 50  # Example: Treat countries smaller than this as "small"

    # Get country shapes
    shapefile_path = shpreader.natural_earth(resolution='50m', category='cultural', name='admin_0_countries')
    reader = shpreader.Reader(shapefile_path)
    countries = reader.records()

    for country in countries:
        # print(country.attributes['NAME_EN'])

        country_name = country.attributes['NAME_EN']
        country_name = x_cartopy_country_name_mapping.get(country_name, country_name)

        if country_name in data:  # This is the crucial check
            face_color = cmap(norm(data[country_name]))
            ax.add_geometries(country.geometry, ccrs.PlateCarree(), facecolor=face_color, edgecolor='black')
        else:  # Handle cases when there's no ticket data for country
            # You might want to set a default color or skip drawing
            face_color = "lightgray"  # Example, set to gray to indicate no data
            ax.add_geometries(country.geometry, ccrs.PlateCarree(), facecolor=face_color, edgecolor='black', linewidth=0.1)

        if country_name in data and country_name in country_name_abbreviations:
            if country.geometry.area < area_threshold:  # Check if country is "small"
                centroid = country.geometry.centroid

                # Leader Line calculations:
                lon = centroid.x
                lat = centroid.y
                offset_lon = lon + 1
                offset_lat = lat + 0.5

                # Draw the leader line
                ax.plot([lon, offset_lon], [lat, offset_lat], color='black', linewidth=1, transform=ccrs.Geodetic(), zorder=2)

                # Place label at the offset position
                ax.text(offset_lon, offset_lat, country_name_abbreviations[country_name],
                        transform=ccrs.PlateCarree(), ha='left', va='center',
                        color='black', fontsize=6, zorder=3, fontweight='bold')
            else:  # Larger countries, direct label
                centroid = country.geometry.centroid  # Use centroid
                ax.text(centroid.x, centroid.y, country_name_abbreviations[country_name],
                        transform=ccrs.PlateCarree(),  # Use PlateCarree
                        ha='center', va='center', color='black', fontsize=6, zorder=3)

    # Colorbar
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])  # This is necessary for the colorbar to work correctly

    # Colorbar (stylish and colorful)
    cbar = plt.colorbar(sm, ax=ax, orientation="horizontal", pad=0.01, shrink=0.5)

    cbar_font = {'family': 'serif',
                 'color': 'dimgray',  # Label color
                 'weight': 'bold',
                 'size': 10}  # Increased font size
    cbar.set_label("Ticket counts per thousand hosts (last 30 days)", fontdict=cbar_font)  # Set label with fontdict
    cbar.ax.tick_params(labelsize=8, labelcolor='gray')  # Adjust tick label size and color

    # Stylish and colorful title
    title_font = {'family': 'serif',  # Or choose another font family
                  'color': 'darkblue',  # Set title color
                  'weight': 'bold',
                  'size': 20,  # Adjust size as needed
                  'style': 'italic',  # Add a style
                  'alpha': 0.8}  # Make it slightly transparent
    plt.title(f"IR Heat Map", fontdict=title_font)

    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.1, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name  # Get the full path
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=600)
        plt.close(fig)

    return filepath  # Return the full path


class HeatMap(Command):
    def __init__(self):
        super().__init__(command_keyword="heat_map", help_message="Heat Map")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        map_file_path = create_choropleth_map()  # Store the full path

        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest heat map!",
            files=[map_file_path]  # Path to the file
        )
