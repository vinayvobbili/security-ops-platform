import os
from datetime import datetime
from pathlib import Path

def make_dir_for_todays_charts(charts_dir_path: Path):
    """
    Create today's charts directory if it doesn't exist.
    Args:
        charts_dir_path (Path): Base path for charts directory.
    """
    today_date = datetime.now().strftime('%m-%d-%Y')
    charts_dir = charts_dir_path / today_date
    os.makedirs(charts_dir, exist_ok=True)
    return charts_dir

