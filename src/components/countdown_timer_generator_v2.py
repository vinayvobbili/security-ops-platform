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

# Image rendering constants
IMAGE_WIDTH = 500
IMAGE_HEIGHT = 140
SCALE_FACTOR = 2
FRAME_COUNT = 60

# Circle sizing (base values, scaled by SCALE_FACTOR during rendering)
CIRCLE_DIAMETER_BASE = 110
ARC_WIDTH_BASE = 10
CIRCLE_SPACING_BASE = 20

# Font sizing (base values, scaled by SCALE_FACTOR during rendering)
NUMBER_FONT_SIZE_BASE = 48
LABEL_FONT_SIZE_BASE = 12

# Text positioning offsets (base values, scaled by SCALE_FACTOR during rendering)
NUMBER_VERTICAL_OFFSET = 8
LABEL_VERTICAL_OFFSET = 16
SHADOW_OFFSET_BASE = 1

# Color scheme (RGB tuples)
COLOR_RED_URGENT = (220, 53, 69)
COLOR_ORANGE_WARNING = (200, 100, 20)
COLOR_GREEN_SAFE = (20, 120, 40)
COLOR_BACKGROUND_CIRCLE = (230, 230, 230)
COLOR_SHADOW = (220, 220, 220)
COLOR_BLACK = (0, 0, 0)
COLOR_WHITE = (255, 255, 255)

# Time calculations
SECONDS_PER_DAY = 86400
SECONDS_PER_HOUR = 3600
SECONDS_PER_MINUTE = 60

# Urgency thresholds (hours)
URGENT_THRESHOLD_HOURS = 1
WARNING_THRESHOLD_HOURS = 2


def generate_countdown_timer_gif(deadline_str: str) -> BytesIO:
    """Generate an animated countdown timer GIF with circular progress arcs.

    Args:
        deadline_str: ISO 8601 timestamp (e.g., 2025-11-11T15:00:00-05:00)

    Returns:
        BytesIO: Buffer containing the animated GIF

    Raises:
        ValueError: If deadline_str is invalid or cannot be parsed
        Exception: For other errors during GIF generation
    """
    logger.debug(f"Generating countdown timer GIF for deadline: {deadline_str}")
    eastern = pytz.timezone('US/Eastern')

    # Parse deadline
    try:
        deadline = datetime.fromisoformat(deadline_str.replace('Z', '+00:00'))
        if deadline.tzinfo is None:
            deadline = eastern.localize(deadline)
        logger.debug(f"Parsed deadline: {deadline.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    except (ValueError, AttributeError) as parse_err:
        logger.error(f"Failed to parse deadline '{deadline_str}': {parse_err}")
        raise ValueError(f'Invalid deadline format: {parse_err}') from parse_err

    # Calculate time remaining from now
    now = datetime.now(eastern)
    time_remaining = deadline - now
    total_seconds_remaining = int(time_remaining.total_seconds())
    logger.debug(f"Current time: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    logger.debug(f"Time remaining: {total_seconds_remaining}s ({total_seconds_remaining // SECONDS_PER_HOUR}h {(total_seconds_remaining % SECONDS_PER_HOUR) // SECONDS_PER_MINUTE}m {total_seconds_remaining % SECONDS_PER_MINUTE}s)")

    # Determine if expired
    is_expired = total_seconds_remaining <= 0
    if is_expired:
        logger.info("Timer expired - generating static frame")

    # Get current wall-clock second for animation synchronization
    current_second = now.second
    logger.debug(f"Wall-clock second at generation: {current_second:02d}")

    # Image dimensions (will render at 2x for sharpness, then scale down)
    render_width, render_height = IMAGE_WIDTH * SCALE_FACTOR, IMAGE_HEIGHT * SCALE_FACTOR

    # Load fonts (at 2x scale for sharpness)
    number_font, label_font = _load_fonts(scale_factor=SCALE_FACTOR)

    # Dynamic color scheme based on urgency
    hours_remaining = total_seconds_remaining / SECONDS_PER_HOUR

    # Determine colors based on urgency
    if is_expired or hours_remaining < URGENT_THRESHOLD_HOURS:
        progress_color = COLOR_RED_URGENT
        color_name = "red (urgent)"
    elif hours_remaining < WARNING_THRESHOLD_HOURS:
        progress_color = COLOR_ORANGE_WARNING
        color_name = "orange (warning)"
    else:
        progress_color = COLOR_GREEN_SAFE
        color_name = "green (safe)"
    logger.debug(f"Urgency color: {color_name} ({hours_remaining:.2f}h remaining)")

    def draw_circular_progress(img_array, center_x, center_y, radius, width, progress, color):
        """Draw anti-aliased circular progress arc using OpenCV.

        Args:
            img_array: numpy array of the image (height, width, 3) - RGB format
            center_x: X coordinate of circle center
            center_y: Y coordinate of circle center
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
            COLOR_BACKGROUND_CIRCLE,
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
        """Create a single frame of the countdown timer.

        Frames are generated to start at the current wall-clock second,
        making the animation appear synchronized with real time.
        """
        # Calculate time for this frame
        current_total = max(0, total_seconds_remaining - seconds_offset)
        hours = (current_total % SECONDS_PER_DAY) // SECONDS_PER_HOUR
        minutes = (current_total % SECONDS_PER_HOUR) // SECONDS_PER_MINUTE
        seconds = current_total % SECONDS_PER_MINUTE

        # Create numpy array at 2x resolution for sharpness (height, width, channels) - RGB format
        img_array = np.full((render_height, render_width, 3), COLOR_WHITE[0], dtype=np.uint8)

        # Time units: (value, label, max_value)
        time_units = [
            (hours, "HOURS", 24),
            (minutes, "MINUTES", SECONDS_PER_MINUTE),
            (seconds, "SECONDS", SECONDS_PER_MINUTE)
        ]

        # Circle parameters (scaled for high-res rendering)
        circle_diameter = CIRCLE_DIAMETER_BASE * SCALE_FACTOR
        circle_radius = circle_diameter // 2
        arc_width = ARC_WIDTH_BASE * SCALE_FACTOR
        spacing = CIRCLE_SPACING_BASE * SCALE_FACTOR

        # Calculate positions
        total_width = (circle_diameter * 3) + (spacing * 2)
        start_x = (render_width - total_width) // 2
        center_y = render_height // 2

        # Draw circular progress arcs using OpenCV
        for idx, (value, label, max_val) in enumerate(time_units):
            center_x = start_x + (idx * (circle_diameter + spacing)) + circle_radius

            # Calculate progress (0.0 to 1.0)
            progress = value / max_val if max_val > 0 else 0

            # Draw circular progress arc with antialiasing
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
            num_y = center_y - num_height // 2 - (NUMBER_VERTICAL_OFFSET * SCALE_FACTOR)

            # Number shadow (subtle, scaled)
            shadow_offset = SHADOW_OFFSET_BASE * SCALE_FACTOR
            draw.text((num_x + shadow_offset, num_y + shadow_offset), num_text, fill=COLOR_SHADOW, font=number_font)
            draw.text((num_x, num_y), num_text, fill=progress_color, font=number_font)

            # Draw label
            lbl_bbox = draw.textbbox((0, 0), label, font=label_font)
            lbl_width = lbl_bbox[2] - lbl_bbox[0]
            lbl_x = center_x - lbl_width // 2
            lbl_y = num_y + num_height + (LABEL_VERTICAL_OFFSET * SCALE_FACTOR)

            # Label shadow (subtle, scaled)
            draw.text((lbl_x + shadow_offset, lbl_y + shadow_offset), label, fill=COLOR_SHADOW, font=label_font)
            draw.text((lbl_x, lbl_y), label, fill=COLOR_BLACK, font=label_font)

        # Scale down to final size using high-quality resampling for sharpness
        img = img.resize((IMAGE_WIDTH, IMAGE_HEIGHT), Image.Resampling.LANCZOS)

        return img

    # Generate frames starting at current wall-clock second for visual synchronization
    frames = []
    num_frames = FRAME_COUNT if not is_expired else 1

    if not is_expired:
        # Calculate offset to make frame 0 start at current_second
        # We want: (total_seconds_remaining - offset) % 60 == current_second
        natural_start_second = total_seconds_remaining % SECONDS_PER_MINUTE
        offset_needed = (natural_start_second - current_second) % SECONDS_PER_MINUTE
        logger.debug(f"Frame sync calculation: natural_start={natural_start_second:02d}, current={current_second:02d}, offset={offset_needed}")

        # Generate frames with the calculated offset so animation starts at current second
        logger.debug(f"Generating {num_frames} frames...")
        for i in range(num_frames):
            frames.append(create_frame(offset_needed + i))
    else:
        # Expired - just one frame
        frames.append(create_frame(0))

    # Save as animated GIF
    logger.debug(f"Saving {len(frames)} frames as animated GIF...")
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
    logger.info(f"Generated countdown timer GIF: {len(frames)} frames, {img_buffer.getbuffer().nbytes} bytes")

    return img_buffer


def _load_fonts(scale_factor=1):
    """Load fonts for the countdown timer.

    Args:
        scale_factor: Multiplier for font sizes (for supersampling)
    """
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
            number_font = ImageFont.truetype(font_path, NUMBER_FONT_SIZE_BASE * scale_factor)
            label_font = ImageFont.truetype(font_path, LABEL_FONT_SIZE_BASE * scale_factor)
            logger.debug(f"Loaded font: {font_path}")
            break
        except (OSError, IOError):
            continue

    if number_font is None:
        logger.warning("No TrueType fonts found, using default font")
        number_font = ImageFont.load_default()
        label_font = ImageFont.load_default()

    return number_font, label_font


def generate_error_timer_gif(error_message: str = "Error generating timer") -> BytesIO:
    """Generate an error GIF when countdown timer generation fails."""
    logger.warning(f"Generating error timer with message: {error_message}")
    img = Image.new('RGB', (IMAGE_WIDTH, IMAGE_HEIGHT), color=COLOR_RED_URGENT)
    draw = ImageDraw.Draw(img)

    try:
        error_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 16)
    except (OSError, IOError):
        error_font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), error_message, font=error_font)
    text_width = bbox[2] - bbox[0]
    draw.text(((IMAGE_WIDTH - text_width) // 2, 60), error_message, fill=COLOR_WHITE, font=error_font)

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
    print(f"[Test 1] Generating 3-hour timer (GREEN)...")
    try:
        buffer = generate_countdown_timer_gif((now + timedelta(hours=3)).isoformat())
        with open(output_dir / "timer_3h.gif", 'wb') as f:
            f.write(buffer.read())
        print(f"✓ Success! (Started at wall-clock second :{now.second:02d})")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 2: 1.5 hours (Orange)
    print(f"\n[Test 2] Generating 1.5-hour timer (ORANGE)...")
    try:
        buffer = generate_countdown_timer_gif((now + timedelta(hours=1, minutes=30)).isoformat())
        with open(output_dir / "timer_1h30m.gif", 'wb') as f:
            f.write(buffer.read())
        print(f"✓ Success! (Started at wall-clock second :{now.second:02d})")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 3: 30 minutes (Red)
    print(f"\n[Test 3] Generating 30-minute timer (RED)...")
    try:
        buffer = generate_countdown_timer_gif((now + timedelta(minutes=30)).isoformat())
        with open(output_dir / "timer_30m.gif", 'wb') as f:
            f.write(buffer.read())
        print(f"✓ Success! (Started at wall-clock second :{now.second:02d})")
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
        .info-box {{
            background: #e8f4fd;
            border-left: 4px solid #0066cc;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <h1>🕐 Countdown Timer V2 - Circular Progress Arc Style</h1>
    <p style="text-align: center; color: #666;">
        Generated: {timestamp}<br>
        <strong>Using OpenCV cv2.ellipse with LINE_AA anti-aliasing</strong><br>
        Inspired by <a href="https://stackoverflow.com/a/67168896">Stack Overflow Answer</a> (CC BY-SA 4.0)
    </p>
    <div class="info-box">
        <strong>✨ Wall-Clock Synchronization:</strong> Countdown timers start at the <strong>current wall-clock second</strong> when generated!
        <br><br>
        Each GIF animation begins at whatever second it was created and counts down naturally,
        properly rolling through minutes. Run the test multiple times to see different starting seconds and minute rollovers.
    </div>
    <div class="timer-grid">
        <div class="timer-card">
            <h2>Test 1: 3 Hours (GREEN)</h2>
            <img src="timer_3h.gif" alt="3 Hours">
            <p>Sharp, anti-aliased circular progress arcs</p>
        </div>
        <div class="timer-card">
            <h2>Test 2: 1.5 Hours (ORANGE)</h2>
            <img src="timer_1h30m.gif" alt="1.5 Hours">
            <p>Medium urgency color scheme</p>
        </div>
        <div class="timer-card">
            <h2>Test 3: 30 Minutes (RED)</h2>
            <img src="timer_30m.gif" alt="30 Minutes">
            <p>High urgency - less than 1 hour remaining</p>
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
