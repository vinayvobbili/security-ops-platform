import logging
import sys

import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageDraw, ImageFont

import config
from incident_fetcher import IncidentFetcher

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

        self.number_position = (200, 115)  # Default position

    def update_counter(self, image_path, number, output_path=None, font_size=None, font_color=None, background_color=None):
        """Updated counter with improved styling and positioning"""
        try:
            img = Image.open(image_path)
            draw = ImageDraw.Draw(img)

            # Get optimized position
            number_position = self.number_position

            # Use custom or default styling
            font_size = font_size or self.default_font_size
            font_color = font_color or self.default_font_color
            background_color = background_color or self.default_background

            # Try to get Futura first, fall back to other fonts
            font = self._get_font(font_size)

            # Draw with slight transparency for better blending
            text = str(number)
            bbox = draw.textbbox(number_position, text, font=font, anchor="mm")
            padding = 8  # Reduced padding

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

            # Convert back to RGB for saving
            img = img.convert('RGB')
            output_path = output_path or image_path
            img.save(output_path, quality=95)

            self.logger.info(f"Successfully updated counter to {number}")
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

    def detect_number_position(self, image_path):
        """
        Detect the position of the number in the image using computer vision

        Args:
            image_path (str): Path to the image

        Returns:
            tuple: (x, y) coordinates of the detected number
        """
        # Read image using OpenCV
        img = cv2.imread(str(image_path))
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # Look for circular shapes (assuming the number is in a circle)
        circles = cv2.HoughCircles(
            gray,
            cv2.HOUGH_GRADIENT,
            dp=1,
            minDist=20,
            param1=50,
            param2=30,
            minRadius=20,
            maxRadius=40
        )

        if circles is not None:
            circles = np.uint16(np.around(circles))
            # Return center of first detected circle
            x, y = circles[0][0][0], circles[0][0][1]
            self.logger.info(f"Detected number position at coordinates: ({x}, {y})")
            return x, y

        # Fallback to default position if no circle detected
        self.logger.warning("No circle detected, using default position")
        return 165, 90

    def recognize_current_number(self, image_path):
        """
        Use OCR to recognize the current number in the image

        Args:
            image_path (str): Path to the image

        Returns:
            int: Recognized number, or 0 if recognition fails
        """
        try:
            # Convert to grayscale for better OCR
            img = Image.open(image_path).convert('L')

            # Use pytesseract to recognize text
            text = pytesseract.image_to_string(img, config='--psm 6 -c tessedit_char_whitelist=0123456789')

            # Extract first number found
            for word in text.split():
                if word.isdigit():
                    number = int(word)
                    self.logger.info(f"Successfully recognized number: {number}")
                    return number

        except Exception as e:
            self.logger.error(f"Error during number recognition: {str(e)}")

        self.logger.warning("Could not recognize number, defaulting to 0")
        return 0


def get_days_since_last_incident():
    """Get the current days since the last incident"""
    # Placeholder function, replace with actual logic
    query = f'-category:job type:{config.ticket_type_prefix} impact:Confirmed'
    period = {"byTo": "months", "toValue": None, "byFrom": "months", "fromValue": 1}
    tickets = IncidentFetcher().get_tickets(query=query, period=period)
    return 42


def make_chart():
    """Update the base image with the current days since last incident"""
    # Initialize the modifier
    modifier = CounterImageModifier()

    try:
        modifier.update_counter(
            "web/static/images/base/days since last incident.jpg",
            2,
            output_path="charts/Days Since Last Incident.jpg",
            font_size=50,
            font_color="green",
            background_color="#C3D3B8"  # Using hex code for lightgray
        )

    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    make_chart()
