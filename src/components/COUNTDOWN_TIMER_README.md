# Countdown Timer Generator - Deployment Notes

## Overview

Two versions of the countdown timer generator:

### V1 - Original Style (`countdown_timer_generator.py`)
- Static circles with solid borders
- Numbers and labels
- Works on all systems

### V2 - Circular Progress Arc Style (`countdown_timer_generator_v2.py`) ⭐ Recommended
- Circular progress arcs (like Stack Overflow example)
- Much cleaner, more modern look
- Optional OpenCV for anti-aliased sharp arcs

## VM Deployment

### Required Packages (Already Installed)
```bash
PIL (Pillow)  # Image manipulation
pytz          # Timezone handling
```

### Optional Package (For Best Quality)
```bash
pip install opencv-python-headless
```

**Benefits of OpenCV:**
- LINE_AA anti-aliasing for super sharp, smooth arcs
- Professional quality like the Stack Overflow example
- File size: ~38MB
- No GUI dependencies (headless version)

**Without OpenCV:**
- Graceful fallback to PIL arc drawing
- Still works fine, just slightly less sharp
- Arcs may look a bit pixelated on close inspection

## Testing

```bash
# Test V2 (will show if OpenCV is available)
PYTHONPATH=. python src/components/countdown_timer_generator_v2.py

# Check output
open data/transient/test_output/countdown_timers_v2/view_timers.html
```

## Integration with Web Server

Update `web/web_server.py`:

```python
# Change import from:
from src.components import countdown_timer_generator_v1

# To:
from src.components import countdown_timer_generator_v2 as countdown_timer_generator

# Or explicitly:
from src.components.countdown_timer_generator_v2 import generate_countdown_timer_gif, generate_error_timer_gif
```

## Recommendation

✅ **Deploy V2 to production**
- Start without OpenCV (PIL fallback)
- Monitor quality
- If arcs look pixelated, install opencv-python-headless on VM
- Zero code changes needed - automatic detection

## Example Output

V2 generates countdown timers with:
- Circular progress arcs showing time remaining
- Color-coded urgency (Green → Orange → Red)
- Clean, minimalist design
- 60-second animated GIF (or static if expired)

See: `data/transient/test_output/countdown_timers_v2/view_timers.html`
