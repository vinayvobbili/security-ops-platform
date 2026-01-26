import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


def cleanup_old_transient_data(retention_days: int = 30) -> dict:
    """
    Remove transient data folders older than the specified retention period.

    Cleans up:
    - data/transient/secOps/ (daily SecOps data ~500MB/day)
    - web/static/charts/ (daily chart images ~300MB/day)

    Args:
        retention_days: Number of days to retain data (default: 30)

    Returns:
        dict with cleanup statistics
    """
    root_dir = Path(__file__).parent.parent.parent
    cleanup_dirs = [
        root_dir / "data" / "transient" / "secOps",
        root_dir / "web" / "static" / "charts",
    ]

    cutoff_time = datetime.now() - timedelta(days=retention_days)
    stats = {"deleted": 0, "freed_bytes": 0, "errors": 0}

    for cleanup_dir in cleanup_dirs:
        if not cleanup_dir.exists():
            logger.warning(f"Cleanup directory does not exist: {cleanup_dir}")
            continue

        logger.info(f"Cleaning up old folders in {cleanup_dir} (retention: {retention_days} days)")

        for folder in cleanup_dir.iterdir():
            if not folder.is_dir():
                continue

            try:
                folder_mtime = datetime.fromtimestamp(folder.stat().st_mtime)
                if folder_mtime < cutoff_time:
                    # Calculate size before deletion
                    folder_size = sum(f.stat().st_size for f in folder.rglob('*') if f.is_file())
                    shutil.rmtree(folder)
                    stats["deleted"] += 1
                    stats["freed_bytes"] += folder_size
                    logger.debug(f"Deleted: {folder.name} ({folder_size / 1024 / 1024:.1f} MB)")
            except Exception as e:
                stats["errors"] += 1
                logger.error(f"Failed to delete {folder}: {e}")

    freed_mb = stats["freed_bytes"] / 1024 / 1024
    logger.info(f"Cleanup complete: deleted {stats['deleted']} folders, freed {freed_mb:.1f} MB, errors: {stats['errors']}")
    return stats


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

