import logging
import sys
from datetime import datetime, timezone

import pytesseract
import pytz
from PIL import Image, ImageDraw, ImageFont

import config
from xsoar import IncidentFetcher

eastern = pytz.timezone('US/Eastern')
config = config.get_config()


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

        self.number_position = (255, 155)

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

            draw.text((200, img.height - 30), f'X#{last_incident_id} was declared as an incident on {last_incident_date}', fill='black', font_size=14)

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
            draw.text((600, img.height - 20), now_eastern, fill='black', font_size=12)

            # Add a thin black border around the figure
            draw.rectangle([(0, 0), (img.width - 1, img.height - 1)], outline="black", width=1)

            # Convert back to RGB for saving
            img = img.convert('RGB')
            output_path = output_path or image_path
            img.save(output_path, quality=95)

            self.logger.info(f"Successfully updated counter to {days_since_last_incident}")
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
    query = f'type:{config.ticket_type_prefix} impact:Confirmed'
    period = {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": 1}

    ticket = IncidentFetcher().get_tickets(query=query, period=period, size=1)
    if ticket:  # Check if any tickets were returned
        latest_incident_create_date_str = ticket[0].get('created')
        latest_incident_create_date = datetime.fromisoformat(latest_incident_create_date_str.replace('Z', '+00:00'))
        today_utc = datetime.now(timezone.utc)  # Ensure both dates are timezone-aware
        return (today_utc - latest_incident_create_date).days, latest_incident_create_date.strftime('%-m/%-d/%Y'), ticket[0].get('id')
    else:
        return -1  # Or some other value to indicate no incidents found


def make_chart():
    """Update the base image with the current days since last incident"""
    # Initialize the modifier
    modifier = CounterImageModifier()
    days_since_last_incident, last_incident_date, last_incident_id = get_last_incident_details()

    try:
        modifier.update_counter(
            "web/static/images/base/days since last incident.jpg",
            days_since_last_incident, last_incident_date, last_incident_id,
            output_path="web/static/charts/Days Since Last Incident.jpg",
            font_size=50,
            font_color="green",
            background_color="#C3D3B8"  # Using hex code for lightgray
        )

    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    make_chart()
