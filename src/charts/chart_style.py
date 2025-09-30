# Centralized Matplotlib styling for all charts
# This avoids referencing fonts that may not exist on headless/Linux servers
# and prevents repeated rcParams mutations + findfont warnings.

import matplotlib

_APPLIED = False

def apply_chart_style():
    global _APPLIED
    if _APPLIED:
        return
    matplotlib.rcParams.update({
        # Use only fonts that ship with matplotlib or are broadly available
        "font.family": "DejaVu Sans",
        "font.sans-serif": [
            "DejaVu Sans",
            "Liberation Sans",
            "Nimbus Sans",
            "sans-serif"
        ],
        # Ensure minus signs render correctly
        "axes.unicode_minus": False,
    })
    _APPLIED = True

