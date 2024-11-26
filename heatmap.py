import cartopy.crs as ccrs
import cartopy.feature as cfeature
import cartopy.io.shapereader as shpreader
import matplotlib.cm as cm
import matplotlib.colors as colors
import matplotlib.pyplot as plt
from webex_bot.models.command import Command


def create_choropleth_map(data):
    """Create a world choropleth map using Cartopy."""

    fig, ax = plt.subplots(figsize=(15, 10), subplot_kw={'projection': ccrs.Robinson()})
    ax.add_feature(cfeature.COASTLINE)
    ax.add_feature(cfeature.BORDERS, linestyle=':')

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
            facecolor = cmap(norm(data[country_name]))
            ax.add_geometries(country.geometry, ccrs.PlateCarree(),
                              facecolor=facecolor, edgecolor='black')

    # Colorbar
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])  # This is necessary for the colorbar to work correctly
    plt.colorbar(sm, ax=ax, orientation="horizontal", label="Ti")

    plt.title("X Tickets Heat Map")
    plt.show()


class HeatMap(Command):
    def __init__(self):
        super().__init__(command_keyword="heat_map", help_message="Heat Map")

    def execute(self, message, attachment_actions, activity):
        # Example usage
        example_data = {
            'United States of America': 75,
            'China': 60,
            'Russia': 45,
            'Brazil': 30,
            'India': 90
        }

        create_choropleth_map(example_data)
