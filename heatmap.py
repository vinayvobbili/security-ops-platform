import json
import tempfile

import cartopy.crs as ccrs
import cartopy.feature as cfeature
import cartopy.io.shapereader as shpreader
import matplotlib.cm as cm
import matplotlib.colors as colors
import matplotlib.pyplot as plt
from webex_bot.models.command import Command
from webexteamssdk import WebexTeamsAPI

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
webex_api = WebexTeamsAPI(access_token=config.bot_api_token)

QUERY_TEMPLATE = '-category:job status:closed type:{ticket_type_prefix} -owner:"" created:>-30d'

with open('host_counts_by_country.json', 'r') as f:
    host_counts_by_country = json.load(f)

with open('country_name_abbreviations.json', 'r') as f:
    abbreviations = json.load(f)


def create_choropleth_map():
    """Create a world choropleth map using Cartopy."""
    tickets = IncidentFetcher().get_tickets(query=QUERY_TEMPLATE)
    tickets_by_country = {}

    for ticket in tickets:
        country = ticket.get("CustomFields", {}).get("affectedCountry")
        tickets_by_country.setdefault(country, []).append(ticket)

    data = {}
    for country in tickets_by_country.keys():
        data[country] = tickets_by_country[country] / host_counts_by_country[country]

    fig, ax = plt.subplots(figsize=(15, 10), subplot_kw={'projection': ccrs.PlateCarree()})  # Use PlateCarree here
    ax.add_feature(cfeature.COASTLINE)
    ax.add_feature(cfeature.BORDERS, linestyle=':')
    ax.set_global()  # Important for proper display with PlateCarree

    cmap = cm.YlOrRd
    norm = colors.Normalize(vmin=min(data.values()), vmax=max(data.values()))

    # Get country shapes
    shape_file_name = shpreader.natural_earth(resolution='110m',
                                              category='cultural',
                                              name='admin_0_countries')
    reader = shpreader.Reader(shape_file_name)
    countries = reader.records()

    for country in countries:
        country_name = country.attributes['NAME']
        if country_name in data:
            face_color = cmap(norm(data[country_name]))
            ax.add_geometries(country.geometry, ccrs.PlateCarree(), facecolor=face_color, edgecolor='black')

            # Add abbreviation text
            if country_name in abbreviations:
                centroid = country.geometry.centroid  # Use centroid for better placement
                ax.text(centroid.x, centroid.y, abbreviations[country_name],
                        transform=ccrs.PlateCarree(),  # Important: Use the correct transform
                        ha='center', va='center', color='black', fontsize=8, weight='bold')  # Adjust as needed

    # Colorbar
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])  # This is necessary for the colorbar to work correctly
    plt.colorbar(sm, ax=ax, orientation="horizontal", label="Ti")

    plt.title("X Tickets Heat Map")

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

    def execute(self, message, attachment_actions, activity):
        # Example usage

        filepath = create_choropleth_map()  # Store the full path

        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest SLA Breaches chart!",
            files=[filepath]  # Path to the file
        )
