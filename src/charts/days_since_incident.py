import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytesseract
import pytz
from PIL import Image, ImageDraw, ImageFont

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import my_config as config
from services.xsoar import TicketHandler

eastern = pytz.timezone('US/Eastern')
config = config.get_config()

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
BASE_IMAGE_PATH = ROOT_DIRECTORY / "web" / "static" / "images" / "base" / "Days Since Last Incident.jpg"


def _setup_logger():
    """Configure logging"""
    logger = logging.getLogger('CounterImageModifier')
    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    return logger


class CounterImageModifier:
    def __init__(self, tesseract_path=None):
        """Initialize with better default styling"""
        self.logger = _setup_logger()

        if tesseract_path:
            pytesseract.pytesseract.tesseract_cmd = tesseract_path

        # Updated default styling
        self.default_font_size = 48  # Slightly smaller default
        self.default_font_color = "#1a365d"  # Darker, more muted blue
        self.default_background = "#e8e6e1"  # Slightly off-white to match sign

        self.font_paths = [
            "arial.ttf",
            "DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "Futura.ttc"  # Added Futura for a more modern look
        ]

        self.number_position = (255, 155)  # Back to original position that fills gray rectangle

    def update_counter(self, image_path, days_since_last_incident, last_incident_date, last_incident_id, output_path=None, font_size=None, font_color=None, background_color=None):
        """Updated counter with improved styling and positioning"""
        try:
            img = Image.open(image_path)
            img = img.resize((800, 600))
            draw = ImageDraw.Draw(img)

            number_position = self.number_position

            # Use custom or default styling
            font_size = font_size or self.default_font_size
            font_color = font_color or self.default_font_color
            background_color = background_color or self.default_background

            # Try to get Futura first, fall back to other fonts
            font = self._get_font(font_size)

            # Draw with slight transparency for better blending
            text = str(days_since_last_incident)
            bbox = draw.textbbox(number_position, text, font=font, anchor="mm")
            padding = 8

            # Fix the None values in bottom text and avoid overlapping watermark
            incident_text = f'X#{last_incident_id or "N/A"} was declared as an incident on {last_incident_date or "N/A"}'
            incident_font = self._get_font(14)
            draw.text((20, img.height - 50), incident_text, fill='black', font=incident_font)

            # Create slightly transparent background
            background = Image.new('RGBA', img.size, (0, 0, 0, 0))
            background_draw = ImageDraw.Draw(background)
            background_draw.rectangle([
                bbox[0] - padding,
                bbox[1] - padding,
                bbox[2] + padding,
                bbox[3] + padding
            ], fill=background_color + "f0")  # Added transparency

            # Composite the background onto the main image
            img = Image.alpha_composite(img.convert('RGBA'), background)
            draw = ImageDraw.Draw(img)

            # Draw the number with slight shadow for depth
            shadow_offset = 1
            draw.text(
                (number_position[0] + shadow_offset, number_position[1] + shadow_offset),
                text,
                fill="#00000022",  # Very light shadow
                font=font,
                anchor="mm"
            )

            # Draw main number
            draw.text(
                number_position,
                text,
                fill=font_color,
                font=font,
                anchor="mm"
            )

            # Add the current time to the chart
            now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
            timestamp_font = self._get_font(12)
            draw.text((600, img.height - 20), now_eastern, fill='black', font=timestamp_font)

            # Add a thin black border around the figure
            draw.rectangle([(0, 0), (img.width - 1, img.height - 1)], outline="black", width=1)

            # Convert back to RGB for saving
            img = img.convert('RGB')
            output_path = output_path or image_path
            img.save(output_path, quality=95)

            return output_path

        except Exception as e:
            self.logger.error(f"Error updating counter: {str(e)}")
            raise

    def _get_font(self, size):
        """Try to load a font from the available options"""
        for font_path in self.font_paths:
            try:
                return ImageFont.truetype(font_path, size)
            except IOError:
                continue

        self.logger.warning("Could not load any TrueType fonts, falling back to default")
        return ImageFont.load_default()


def get_last_incident_details():
    """Get the current days since the last incident"""
    # Search for the most recent MTP incident in the past year using exact timestamps
    # Note: Using 365 days to ensure we catch incidents even if they're older
    end_date = datetime.now(eastern).replace(hour=23, minute=59, second=59, microsecond=999999)
    start_date = end_date - timedelta(days=365)
    start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

    # Convert to UTC for API query
    start_str = start_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    end_str = end_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = f'type:{config.team_name} impact:"Malicious True Positive" created:>={start_str} created:<={end_str}'
    ticket = TicketHandler().get_tickets(query=query, size=1)

    if ticket:  # Check if any tickets were returned
        latest_incident_create_date_str = ticket[0].get('created')

        # Handle if the date is already a datetime object
        if isinstance(latest_incident_create_date_str, datetime):
            latest_incident_create_date = latest_incident_create_date_str
        else:
            latest_incident_create_date = datetime.fromisoformat(latest_incident_create_date_str.replace('Z', '+00:00'))

        latest_incident_create_date_eastern = latest_incident_create_date.astimezone(eastern)
        today_eastern = datetime.now(eastern)
        return (today_eastern.date() - latest_incident_create_date_eastern.date()).days, latest_incident_create_date_eastern.strftime('%-m/%-d/%Y'), ticket[0].get('id')
    else:
        return -1, None, None  # Always return a tuple


def make_chart():
    """Update the base image with the current days since last incident"""
    try:
        # Initialize the modifier
        modifier = CounterImageModifier()
        days_since_last_incident, last_incident_date, last_incident_id = get_last_incident_details()

        today_date = datetime.now().strftime('%m-%d-%Y')
        output_path = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Days Since Last Incident.png"
        modifier.update_counter(
            BASE_IMAGE_PATH,
            days_since_last_incident, last_incident_date, last_incident_id,
            output_path=output_path,
            font_size=50,
            font_color="green",
            background_color="#C3D3B8"  # Using hex code for lightgray
        )
    except Exception as e:
        import traceback
        print(f"Error: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    make_chart()
