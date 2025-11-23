"""APT Names Handler for Web Dashboard."""

import logging
import os
from typing import Dict, Any, List

from src.components import apt_names_fetcher

logger = logging.getLogger(__name__)


def get_apt_workbook_info(base_dir: str) -> Dict[str, Any]:
    """Get APT workbook summary (region sheets only).

    Args:
        base_dir: Base directory of the web application

    Returns:
        APT workbook information
    """
    logger.info("Getting APT workbook info")
    file_path = os.path.join(base_dir, '../data/transient/de/APTAKAcleaned.xlsx')
    file_path = os.path.abspath(file_path)
    return apt_names_fetcher.get_workbook_info(file_path)


def get_apt_other_names(
    common_name: str,
    base_dir: str,
    should_include_metadata: bool = False
) -> Dict[str, Any]:
    """Get other names for a given APT common name.

    Args:
        common_name: APT common name to search for
        base_dir: Base directory of the web application
        should_include_metadata: Whether to include metadata in results

    Returns:
        APT other names information
    """
    logger.info(f"Getting APT other names for: {common_name}")
    file_path = os.path.join(base_dir, '../data/transient/de/APTAKAcleaned.xlsx')
    file_path = os.path.abspath(file_path)

    return apt_names_fetcher.get_other_names_for_common_name(
        common_name,
        file_path,
        should_include_metadata
    )


def get_all_apt_names(base_dir: str) -> List[str]:
    """Get all APT names for dropdown.

    Args:
        base_dir: Base directory of the web application

    Returns:
        List of all APT names

    Raises:
        Exception: If error loading APT names
    """
    logger.info("Loading all APT names")
    file_path = os.path.join(base_dir, '../data/transient/de/APTAKAcleaned.xlsx')
    file_path = os.path.abspath(file_path)

    return apt_names_fetcher.get_all_apt_names(file_path)
