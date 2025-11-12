"""Countdown Timer Generator Component.

Generates animated GIF countdown timers for use in emails and web pages.
The timer displays hours, minutes, and seconds in a visually appealing format
with color-coded urgency levels.
"""

import logging
import os
from datetime import datetime
from io import BytesIO

import pytz
from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)


def generate_countdown_timer_gif(deadline_str: str) -> BytesIO:
    """Generate an animated countdown timer GIF.

    Creates a 60-second animated GIF that counts down in real-time.
    Each time the GIF is requested, it's generated fresh from the current time.

    Args:
        deadline_str: ISO 8601 timestamp (e.g., 2025-11-11T15:00:00-05:00)

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

    # Image dimensions - compact and email-friendly
    img_width, img_height = 480, 120

    # Load fonts
    number_font, label_font = _load_fonts()

    # Dynamic color scheme based on time remaining
    page_bg_color = (255, 255, 255)  # Pure white background

    # Calculate hours remaining for color determination
    hours_remaining = total_seconds_remaining / 3600

    # Determine colors based on time remaining
    # Green: 2-4 hours | Orange: 1-2 hours | Red: < 1 hour
    if is_expired:
        # Expired - Red
        circle_border_color = (220, 53, 69)
        number_color = (220, 53, 69)
        label_color = (220, 53, 69)
        last_circle_bg = (220, 53, 69)
    elif hours_remaining < 1:
        # Red: < 1 hour
        circle_border_color = (220, 53, 69)
        number_color = (220, 53, 69)
        label_color = (220, 53, 69)
        last_circle_bg = (220, 53, 69)
    elif hours_remaining < 2:
        # Orange: 1-2 hours
        circle_border_color = (255, 133, 27)
        number_color = (255, 133, 27)
        label_color = (255, 133, 27)
        last_circle_bg = (255, 133, 27)
    else:
        # Green: 2-4 hours
        circle_border_color = (40, 167, 69)
        number_color = (40, 167, 69)
        label_color = (40, 167, 69)
        last_circle_bg = (40, 167, 69)

    circle_bg_color = (255, 255, 255)  # White circle background
    last_circle_number = (255, 255, 255)  # White text
    last_circle_label = (255, 255, 255)  # White text

    def draw_circular_progress_arc(draw_obj, center, radius, width, progress_percent, color, bg_color=(240, 240, 240)):
        """Draw a circular progress arc similar to Stack Overflow example.

        Args:
            draw_obj: PIL ImageDraw object
            center: Tuple (x, y) for center of circle
            radius: Radius of the circle
            width: Width of the arc line
            progress_percent: Progress from 0-100 (100 = full circle)
            color: RGB color tuple for the progress arc
            bg_color: RGB color tuple for background circle
        """
        # Calculate bounding box for the circle
        x, y = center
        bbox = [x - radius, y - radius, x + radius, y + radius]

        # Draw background circle (light gray)
        draw_obj.ellipse(bbox, outline=bg_color, width=width)

        # Draw progress arc (starts at top, goes clockwise)
        # PIL arc: 0° is at 3 o'clock, goes counter-clockwise
        # We want to start at 12 o'clock (270° in PIL terms) and go clockwise
        if progress_percent > 0:
            # Convert progress to angle (starts at top, goes clockwise)
            end_angle = 270 - (360 * progress_percent / 100)  # Clockwise from top
            start_angle = 270  # Top position

            # PIL draws counter-clockwise, so we need to swap and adjust
            draw_obj.arc(bbox, start=end_angle, end=start_angle, fill=color, width=width)

    def create_frame(seconds_offset):
        """Create a single frame of the countdown timer with circular progress arcs.

        Args:
            seconds_offset: Number of seconds to subtract from current time
        """
        # Calculate time for this frame
        current_total = max(0, total_seconds_remaining - seconds_offset)

        hours = (current_total % 86400) // 3600
        minutes = (current_total % 3600) // 60
        seconds = current_total % 60

        # Create image with RGBA mode for transparency effects
        img = Image.new('RGBA', (img_width, img_height), color=page_bg_color + (255,))
        draw = ImageDraw.Draw(img, 'RGBA')

        # Time parts with their actual values for progress calculation
        time_parts = [
            (f"{hours:02d}", "HOURS", hours, 24),  # (display, label, value, max)
            (f"{minutes:02d}", "MINUTES", minutes, 60),
            (f"{seconds:02d}", "SECONDS", seconds, 60)
        ]

        num_parts = len(time_parts)

        # Circle dimensions - larger for better visibility
        circle_diameter = 100
        circle_radius = circle_diameter // 2
        arc_width = 8  # Thicker arc for visibility
        spacing = 15  # Space between circles

        # Calculate total width and starting position
        total_width = (circle_diameter * num_parts) + (spacing * (num_parts - 1))
        start_x = (img_width - total_width) // 2
        center_y = img_height // 2

        # Draw each time unit with circular progress arc
        for i, (value, label, current_value, max_value) in enumerate(time_parts):
            # Calculate circle center
            circle_center_x = start_x + (i * (circle_diameter + spacing)) + circle_radius
            circle_center_y = center_y

            # Calculate progress percentage
            progress = (current_value / max_value) * 100 if max_value > 0 else 0

            # Draw circular progress arc
            draw_circular_progress_arc(
                draw,
                (circle_center_x, circle_center_y),
                circle_radius,
                arc_width,
                progress,
                circle_border_color,
                (230, 230, 230)  # Light gray background
            )

            # Draw the number (centered in circle, bigger than label)
            num_bbox = draw.textbbox((0, 0), value, font=number_font)
            num_width = num_bbox[2] - num_bbox[0]
            num_height = num_bbox[3] - num_bbox[1]
            num_x = circle_x + (circle_diameter - num_width) // 2
            num_y = circle_y + (circle_diameter - num_height) // 2 - 12  # Moved up slightly

            # Add subtle text shadow for depth
            shadow_offset_text = 1
            text_shadow_color = (0, 0, 0, 30) if is_last else (100, 100, 100, 50)
            draw.text((num_x + shadow_offset_text, num_y + shadow_offset_text),
                      value, fill=text_shadow_color, font=number_font)
            draw.text((num_x, num_y), value, fill=num_color, font=number_font)

            # Draw the label (centered below number with MORE spacing)
            lbl_bbox = draw.textbbox((0, 0), label, font=label_font)
            lbl_width = lbl_bbox[2] - lbl_bbox[0]
            lbl_x = circle_x + (circle_diameter - lbl_width) // 2
            lbl_y = num_y + num_height + 10  # Increased from 4 to 10 pixels

            # Add subtle label shadow
            draw.text((lbl_x + shadow_offset_text, lbl_y + shadow_offset_text),
                      label, fill=text_shadow_color, font=label_font)
            draw.text((lbl_x, lbl_y), label, fill=lbl_color, font=label_font)

        return img

    # Generate animated GIF frames
    frames = []
    num_frames = 60 if not is_expired else 1  # 60 seconds of animation, or 1 frame if expired

    for i in range(num_frames):
        frame = create_frame(i)
        # Convert RGBA to RGB for GIF compatibility (composite on white background)
        if frame.mode == 'RGBA':
            rgb_frame = Image.new('RGB', frame.size, (255, 255, 255))
            rgb_frame.paste(frame, mask=frame.split()[3])  # Use alpha channel as mask
            frames.append(rgb_frame)
        else:
            frames.append(frame)

    # Save as animated GIF
    img_buffer = BytesIO()
    frames[0].save(
        img_buffer,
        format='GIF',
        save_all=True,
        append_images=frames[1:],
        duration=1000,  # 1000ms = 1 second per frame
        loop=0  # Loop forever
    )
    img_buffer.seek(0)

    return img_buffer


def _load_fonts():
    """Load fonts for the countdown timer.

    Tries multiple font paths for cross-platform compatibility.
    Falls back to default font if none are found.

    Returns:
        tuple: (number_font, label_font)
    """
    home_dir = os.path.expanduser("~")
    font_paths = [
        f"{home_dir}/.fonts/Roboto-Medium.ttf",  # Roboto Medium (user installed)
        f"{home_dir}/.fonts/Roboto-Regular.ttf",  # Roboto Regular (user installed)
        "/usr/share/fonts/truetype/msttcorefonts/Arial.ttf",  # Linux (Ubuntu with msttcorefonts)
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux (DejaVu fallback)
        "/System/Library/Fonts/Helvetica.ttc",  # macOS
        "Arial.ttf",  # Windows
    ]

    number_font = None
    label_font = None

    for font_path in font_paths:
        try:
            number_font = ImageFont.truetype(font_path, 42)
            label_font = ImageFont.truetype(font_path, 11)
            break
        except (OSError, IOError):
            continue

    # Fallback to default if no fonts found
    if number_font is None:
        number_font = ImageFont.load_default()
        label_font = ImageFont.load_default()

    return number_font, label_font


def generate_error_timer_gif(error_message: str = "Error generating timer") -> BytesIO:
    """Generate an error GIF when countdown timer generation fails.

    Args:
        error_message: Error message to display

    Returns:
        BytesIO: Buffer containing the error GIF
    """
    img = Image.new('RGB', (480, 120), color=(220, 53, 69))
    draw = ImageDraw.Draw(img)

    try:
        error_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 16)
    except (OSError, IOError):
        error_font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), error_message, font=error_font)
    text_width = bbox[2] - bbox[0]
    draw.text(((480 - text_width) // 2, 50), error_message, fill=(255, 255, 255), font=error_font)

    img_buffer = BytesIO()
    img.save(img_buffer, format='GIF')
    img_buffer.seek(0)

    return img_buffer


def main():
    """Standalone test for countdown timer generator.

    Generates test GIFs and saves them to data/transient/test_output/countdown_timers
    for easy visual inspection.
    """
    from pathlib import Path
    from datetime import timedelta

    print("=" * 60)
    print("Countdown Timer Generator - Standalone Test")
    print("=" * 60)

    # Set up output directory in project structure
    # Get project root (4 levels up from this file: src/components/countdown_timer_generator_v1.py)
    project_root = Path(__file__).parent.parent.parent
    output_dir = project_root / "data" / "transient" / "test_output" / "countdown_timers"

    # Create directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nOutput directory: {output_dir}")
    print(f"(Relative path: data/transient/test_output/countdown_timers)\n")

    eastern = pytz.timezone('US/Eastern')
    now = datetime.now(eastern)

    # Test 1: Timer with 3 hours remaining (Green)
    print("[Test 1] Generating timer with 3 hours remaining (GREEN)...")
    deadline_3h = (now + timedelta(hours=3)).isoformat()
    try:
        buffer_3h = generate_countdown_timer_gif(deadline_3h)
        output_path_3h = output_dir / "countdown_timer_3h.gif"
        with open(output_path_3h, 'wb') as f:
            f.write(buffer_3h.read())
        print(f"✓ Success! Saved to: {output_path_3h.name}")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 2: Timer with 1.5 hours remaining (Orange)
    print("\n[Test 2] Generating timer with 1.5 hours remaining (ORANGE)...")
    deadline_1h30m = (now + timedelta(hours=1, minutes=30)).isoformat()
    try:
        buffer_1h30m = generate_countdown_timer_gif(deadline_1h30m)
        output_path_1h30m = output_dir / "countdown_timer_1h30m.gif"
        with open(output_path_1h30m, 'wb') as f:
            f.write(buffer_1h30m.read())
        print(f"✓ Success! Saved to: {output_path_1h30m.name}")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 3: Timer with 30 minutes remaining (Red)
    print("\n[Test 3] Generating timer with 30 minutes remaining (RED)...")
    deadline_30m = (now + timedelta(minutes=30)).isoformat()
    try:
        buffer_30m = generate_countdown_timer_gif(deadline_30m)
        output_path_30m = output_dir / "countdown_timer_30m.gif"
        with open(output_path_30m, 'wb') as f:
            f.write(buffer_30m.read())
        print(f"✓ Success! Saved to: {output_path_30m.name}")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 4: Expired timer
    print("\n[Test 4] Generating expired timer (EXPIRED - RED)...")
    deadline_expired = (now - timedelta(hours=1)).isoformat()
    try:
        buffer_expired = generate_countdown_timer_gif(deadline_expired)
        output_path_expired = output_dir / "countdown_timer_expired.gif"
        with open(output_path_expired, 'wb') as f:
            f.write(buffer_expired.read())
        print(f"✓ Success! Saved to: {output_path_expired.name}")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 5: Error timer
    print("\n[Test 5] Generating error timer...")
    try:
        buffer_error = generate_error_timer_gif("Test Error Message")
        output_path_error = output_dir / "countdown_timer_error.gif"
        with open(output_path_error, 'wb') as f:
            f.write(buffer_error.read())
        print(f"✓ Success! Saved to: {output_path_error.name}")
    except Exception as exc:
        print(f"✗ Failed: {exc}")

    # Test 6: Invalid deadline format (should raise ValueError)
    print("\n[Test 6] Testing invalid deadline format (should fail)...")
    try:
        generate_countdown_timer_gif("invalid-date-format")
        print("✗ Test failed - should have raised ValueError")
    except ValueError as ve:
        print(f"✓ Success! Correctly raised ValueError: {ve}")
    except Exception as exc:
        print(f"✗ Unexpected error: {exc}")

    # Create HTML viewer for the GIFs
    print("\n[Bonus] Creating HTML viewer for animated GIFs...")
    timestamp = datetime.now(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Countdown Timer Test Results</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 40px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            text-align: center;
        }}
        .timer-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }}
        .timer-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .timer-card h2 {{
            margin-top: 0;
            color: #555;
            font-size: 18px;
        }}
        .timer-card img {{
            width: 100%;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        .timer-card p {{
            color: #666;
            font-size: 14px;
            margin: 10px 0 0 0;
        }}
        .success {{
            color: #28a745;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <h1>🕐 Countdown Timer Generator - Test Results</h1>
    <p style="text-align: center; color: #666;">
        Generated at: {timestamp}<br>
        All timers are animated and will count down in real-time!
    </p>

    <div class="timer-grid">
        <div class="timer-card">
            <h2>Test 1: 3 Hours Remaining (GREEN)</h2>
            <img src="countdown_timer_3h.gif" alt="3 Hours Timer">
            <p>Color scheme for long deadlines (2-4 hours remaining)</p>
        </div>

        <div class="timer-card">
            <h2>Test 2: 1.5 Hours Remaining (ORANGE)</h2>
            <img src="countdown_timer_1h30m.gif" alt="1.5 Hours Timer">
            <p>Color scheme for medium urgency (1-2 hours remaining)</p>
        </div>

        <div class="timer-card">
            <h2>Test 3: 30 Minutes Remaining (RED)</h2>
            <img src="countdown_timer_30m.gif" alt="30 Minutes Timer">
            <p>Color scheme for high urgency (less than 1 hour remaining)</p>
        </div>

        <div class="timer-card">
            <h2>Test 4: Expired Timer (RED)</h2>
            <img src="countdown_timer_expired.gif" alt="Expired Timer">
            <p>Display when deadline has passed</p>
        </div>

        <div class="timer-card">
            <h2>Test 5: Error Display</h2>
            <img src="countdown_timer_error.gif" alt="Error Timer">
            <p>Fallback error display when generation fails</p>
        </div>
    </div>

    <p style="text-align: center; margin-top: 40px; color: #999; font-size: 12px;">
        Note: Each animated timer runs for 60 seconds, showing real-time countdown.
    </p>
</body>
</html>
"""

    html_path = output_dir / "view_timers.html"
    with open(html_path, 'w') as f:
        f.write(html_content)
    print(f"✓ HTML viewer created: {html_path.name}")

    print("\n" + "=" * 60)
    print(f"Test complete! All GIFs saved to:")
    print(f"  {output_dir}")
    print(f"\n🌐 View animated GIFs in browser:")
    print(f"  open {html_path}  # macOS")
    print(f"\nOr view individual files:")
    print(f"  open {output_dir}  # Opens folder")
    print("=" * 60)


if __name__ == "__main__":
    main()
