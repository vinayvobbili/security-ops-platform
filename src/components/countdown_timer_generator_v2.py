"""Countdown Timer Generator Component - Circular Progress Arc Style.

Generates animated GIF countdown timers with circular progress arcs.
Inspired by https://stackoverflow.com/a/67168896 (License: CC BY-SA 4.0)

Uses OpenCV's cv2.ellipse with LINE_AA for anti-aliased, sharp circular arcs.

Dependencies:
    - opencv-python-headless
    - numpy
    - Pillow (PIL)
    - pytz
"""

import logging
import os
from datetime import datetime
from io import BytesIO

import cv2
import numpy as np
import pytz
from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)


def generate_countdown_timer_gif(deadline_str: str, title: str = "Time to Respond") -> BytesIO:
    """Generate an animated countdown timer GIF with circular progress arcs.

    Args:
        deadline_str: ISO 8601 timestamp (e.g., 2025-11-11T15:00:00-05:00)
        title: Optional title text (currently unused in implementation)

    Returns:
        BytesIO: Buffer containing the animated GIF

    Raises:
        ValueError: If deadline_str is invalid or cannot be parsed
        Exception: For other errors during GIF generation
    """
    eastern = pytz.timezone('US/Eastern')

    # Parse deadline
    try:
        deadline = datetime.fromisoformat(deadline_str.replace('Z', '+00:00'))
        if deadline.tzinfo is None:
            deadline = eastern.localize(deadline)
    except (ValueError, AttributeError) as parse_err:
        raise ValueError(f'Invalid deadline format: {parse_err}') from parse_err

    # Calculate time remaining from now
    now = datetime.now(eastern)
    time_remaining = deadline - now
    total_seconds_remaining = int(time_remaining.total_seconds())

    # Determine if expired
    is_expired = total_seconds_remaining <= 0

    # Image dimensions
    img_width, img_height = 500, 140

    # Load fonts
    number_font, label_font = _load_fonts()

    # Dynamic color scheme based on urgency
    hours_remaining = total_seconds_remaining / 3600

    # Determine colors based on urgency
    if is_expired or hours_remaining < 1:
        progress_color = (220, 53, 69)  # Red
    elif hours_remaining < 2:
        progress_color = (255, 133, 27)  # Orange
    else:
        progress_color = (40, 167, 69)  # Green

    def draw_circular_progress(img_array, center_x, center_y, radius, width, progress, color):
        """Draw anti-aliased circular progress arc using OpenCV.

        Args:
            img_array: numpy array of the image (height, width, 3) - RGB format
            center_x, center_y: Center of the circle
            radius: Radius of the circle
            width: Line width
            progress: Progress from 0.0 to 1.0
            color: RGB tuple
        """
        # Background circle (light gray)
        cv2.ellipse(
            img_array,
            (center_x, center_y),
            (radius, radius),
            0,  # angle
            0,  # startAngle
            360,  # endAngle
            (230, 230, 230),  # color
            width,
            cv2.LINE_AA  # Anti-aliased line - this is the key for sharpness!
        )

        # Progress arc (deplete clockwise as time counts down)
        if progress > 0:
            angle_degrees = 360 * progress
            # Start from top (-90°) and fill the remaining arc clockwise
            # cv2.ellipse draws counter-clockwise, so we reverse the angles
            cv2.ellipse(
                img_array,
                (center_x, center_y),
                (radius, radius),
                -90,  # rotation (start from top)
                360 - angle_degrees,  # startAngle (what's left)
                360,  # endAngle (top)
                color,  # RGB color
                width,
                cv2.LINE_AA  # Anti-aliased line
            )

    def create_frame(seconds_offset):
        """Create a single frame of the countdown timer."""
        # Calculate time for this frame
        current_total = max(0, total_seconds_remaining - seconds_offset)
        hours = (current_total % 86400) // 3600
        minutes = (current_total % 3600) // 60
        seconds = current_total % 60

        # Create numpy array (height, width, channels) - RGB format
        img_array = np.full((img_height, img_width, 3), 255, dtype=np.uint8)

        # Time units: (value, label, max_value)
        time_units = [
            (hours, "HOURS", 24),
            (minutes, "MINUTES", 60),
            (seconds, "SECONDS", 60)
        ]

        # Circle parameters
        circle_diameter = 110
        circle_radius = circle_diameter // 2
        arc_width = 10
        spacing = 20

        # Calculate positions
        total_width = (circle_diameter * 3) + (spacing * 2)
        start_x = (img_width - total_width) // 2
        center_y = img_height // 2

        # Draw circular progress arcs using OpenCV
        for idx, (value, label, max_val) in enumerate(time_units):
            center_x = start_x + (idx * (circle_diameter + spacing)) + circle_radius

            # Calculate progress (0.0 to 1.0)
            progress = value / max_val if max_val > 0 else 0

            # Draw circular progress arc with anti-aliasing
            draw_circular_progress(img_array, center_x, center_y, circle_radius, arc_width, progress, progress_color)

        # Convert numpy array to PIL Image for text drawing
        img = Image.fromarray(img_array)
        draw = ImageDraw.Draw(img)

        # Draw text on the image
        for idx, (value, label, max_val) in enumerate(time_units):
            center_x = start_x + (idx * (circle_diameter + spacing)) + circle_radius

            # Draw number
            num_text = f"{value:02d}"
            num_bbox = draw.textbbox((0, 0), num_text, font=number_font)
            num_width = num_bbox[2] - num_bbox[0]
            num_height = num_bbox[3] - num_bbox[1]
            num_x = center_x - num_width // 2
            num_y = center_y - num_height // 2 - 8

            # Number shadow
            draw.text((num_x + 2, num_y + 2), num_text, fill=(200, 200, 200), font=number_font)
            draw.text((num_x, num_y), num_text, fill=progress_color, font=number_font)

            # Draw label
            lbl_bbox = draw.textbbox((0, 0), label, font=label_font)
            lbl_width = lbl_bbox[2] - lbl_bbox[0]
            lbl_x = center_x - lbl_width // 2
            lbl_y = num_y + num_height + 16

            # Label shadow
            draw.text((lbl_x + 1, lbl_y + 1), label, fill=(200, 200, 200), font=label_font)
            draw.text((lbl_x, lbl_y), label, fill=(100, 100, 100), font=label_font)

        return img

    # Generate frames
    frames = []
    num_frames = 60 if not is_expired else 1

    for i in range(num_frames):
        frames.append(create_frame(i))

    # Save as animated GIF
    img_buffer = BytesIO()
    frames[0].save(
        img_buffer,
        format='GIF',
        save_all=True,
        append_images=frames[1:],
        duration=1000,
        loop=0
    )
    img_buffer.seek(0)

    return img_buffer


def _load_fonts():
    """Load fonts for the countdown timer."""
    home_dir = os.path.expanduser("~")
    font_paths = [
        f"{home_dir}/.fonts/Roboto-Medium.ttf",
        f"{home_dir}/.fonts/Roboto-Regular.ttf",
        "/usr/share/fonts/truetype/msttcorefonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "Arial.ttf",
    ]

    number_font = None
    label_font = None

    for font_path in font_paths:
        try:
            number_font = ImageFont.truetype(font_path, 48)
            label_font = ImageFont.truetype(font_path, 12)
            break
        except (OSError, IOError):
            continue

    if number_font is None:
        number_font = ImageFont.load_default()
        label_font = ImageFont.load_default()

    return number_font, label_font


def generate_error_timer_gif(error_message: str = "Error generating timer") -> BytesIO:
    """Generate an error GIF when countdown timer generation fails."""
    img = Image.new('RGB', (500, 140), color=(220, 53, 69))
    draw = ImageDraw.Draw(img)

    try:
        error_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 16)
    except (OSError, IOError):
        error_font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), error_message, font=error_font)
    text_width = bbox[2] - bbox[0]
    draw.text(((500 - text_width) // 2, 60), error_message, fill=(255, 255, 255), font=error_font)

    img_buffer = BytesIO()
    img.save(img_buffer, format='GIF')
    img_buffer.seek(0)

    return img_buffer


def main():
    """Standalone test for countdown timer generator."""
    from pathlib import Path
    from datetime import timedelta

    print("=" * 60)
    print("Countdown Timer Generator V2 - Circular Progress Arc Style")
    print("=" * 60)

    # Set up output directory
    project_root = Path(__file__).parent.parent.parent
    output_dir = project_root / "data" / "transient" / "test_output" / "countdown_timers_v2"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nOutput directory: {output_dir}")
    print(f"(Relative path: data/transient/test_output/countdown_timers_v2)\n")

    eastern = pytz.timezone('US/Eastern')
    now = datetime.now(eastern)

    # Test 1: 3 hours (Green)
    print("[Test 1] Generating 3-hour timer (GREEN)...")
    try:
        buffer = generate_countdown_timer_gif((now + timedelta(hours=3)).isoformat())
        with open(output_dir / "timer_3h.gif", 'wb') as f:
            f.write(buffer.read())
        print("✓ Success!")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 2: 1.5 hours (Orange)
    print("\n[Test 2] Generating 1.5-hour timer (ORANGE)...")
    try:
        buffer = generate_countdown_timer_gif((now + timedelta(hours=1, minutes=30)).isoformat())
        with open(output_dir / "timer_1h30m.gif", 'wb') as f:
            f.write(buffer.read())
        print("✓ Success!")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 3: 30 minutes (Red)
    print("\n[Test 3] Generating 30-minute timer (RED)...")
    try:
        buffer = generate_countdown_timer_gif((now + timedelta(minutes=30)).isoformat())
        with open(output_dir / "timer_30m.gif", 'wb') as f:
            f.write(buffer.read())
        print("✓ Success!")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 4: Expired
    print("\n[Test 4] Generating expired timer...")
    try:
        buffer = generate_countdown_timer_gif((now - timedelta(hours=1)).isoformat())
        with open(output_dir / "timer_expired.gif", 'wb') as f:
            f.write(buffer.read())
        print("✓ Success!")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 5: Error
    print("\n[Test 5] Generating error timer...")
    try:
        buffer = generate_error_timer_gif()
        with open(output_dir / "timer_error.gif", 'wb') as f:
            f.write(buffer.read())
        print("✓ Success!")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Create HTML viewer
    print("\n[Bonus] Creating HTML viewer...")
    timestamp = datetime.now(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Countdown Timer V2 - Circular Progress Arc Style</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 40px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        h1 {{ text-align: center; color: #333; }}
        .timer-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(520px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }}
        .timer-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .timer-card h2 {{ margin-top: 0; color: #555; font-size: 18px; }}
        .timer-card img {{
            width: 100%;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        .timer-card p {{ color: #666; font-size: 14px; margin: 10px 0 0 0; }}
    </style>
</head>
<body>
    <h1>🕐 Countdown Timer V2 - Circular Progress Arc Style</h1>
    <p style="text-align: center; color: #666;">
        Generated: {timestamp}<br>
        <strong>Using OpenCV cv2.ellipse with LINE_AA anti-aliasing</strong><br>
        Inspired by <a href="https://stackoverflow.com/a/67168896">Stack Overflow Answer</a> (CC BY-SA 4.0)
    </p>
    <div class="timer-grid">
        <div class="timer-card">
            <h2>Test 1: 3 Hours (GREEN)</h2>
            <img src="timer_3h.gif" alt="3 Hours">
            <p>Sharp, anti-aliased circular progress arcs show time remaining</p>
        </div>
        <div class="timer-card">
            <h2>Test 2: 1.5 Hours (ORANGE)</h2>
            <img src="timer_1h30m.gif" alt="1.5 Hours">
            <p>Medium urgency color scheme</p>
        </div>
        <div class="timer-card">
            <h2>Test 3: 30 Minutes (RED)</h2>
            <img src="timer_30m.gif" alt="30 Minutes">
            <p>High urgency - less than 1 hour</p>
        </div>
        <div class="timer-card">
            <h2>Test 4: Expired</h2>
            <img src="timer_expired.gif" alt="Expired">
            <p>Static display when deadline passed</p>
        </div>
        <div class="timer-card">
            <h2>Test 5: Error Display</h2>
            <img src="timer_error.gif" alt="Error">
            <p>Fallback when generation fails</p>
        </div>
    </div>
</body>
</html>
"""

    with open(output_dir / "view_timers.html", 'w') as f:
        f.write(html)
    print("✓ HTML viewer created!")

    print("\n" + "=" * 60)
    print(f"Complete! View in browser:")
    print(f"  open {output_dir / 'view_timers.html'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
