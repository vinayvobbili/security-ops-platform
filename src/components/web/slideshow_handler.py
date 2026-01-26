"""Slideshow/Image Management Handler for Web Dashboard."""

import logging
import os
from datetime import datetime
from typing import List

import pytz

logger = logging.getLogger(__name__)


def get_image_files(static_folder: str, eastern: pytz.tzinfo.BaseTzInfo) -> List[str]:
    """Retrieves a list of image files from the static and charts directories.

    Args:
        static_folder: Path to the Flask static folder
        eastern: Pytz timezone object for US/Eastern

    Returns:
        List of image file paths relative to static folder
    """
    today_date = datetime.now(eastern).strftime('%m-%d-%Y')
    image_order = [
        "images/Company Logo.png",
        "images/IR Welcome.png",
        f"charts/{today_date}/Threatcon Level.png",
        f"charts/{today_date}/Days Since Last Incident.png",
        "images/IR Metrics by Peanuts.jpg",
        f"charts/{today_date}/Aging Tickets.png",
        f"charts/{today_date}/Inflow Yesterday.png",
        f"charts/{today_date}/Inflow Past 12 Months - Impact Only.png",
        f"charts/{today_date}/Inflow Past 12 Months - Ticket Type Only.png",
        f"charts/{today_date}/Outflow.png",
        f"charts/{today_date}/SLA Breaches.png",
        f"charts/{today_date}/MTTR MTTC.png",
        f"charts/{today_date}/Heat Map.png",
        f"charts/{today_date}/CrowdStrike Detection Efficacy-Week.png",
        f"charts/{today_date}/QR Rule Efficacy-Week.png",
        f"charts/{today_date}/Vectra Volume.png",
        "images/Threat Hunting Intro.png",
        f"charts/{today_date}/Threat Tippers.png",
        f"charts/{today_date}/DE Stories.png",
        f"charts/{today_date}/RE Stories.png",
        "images/End of presentation.jpg",
        "images/Feedback Email.png",
        "images/Thanks.png"
    ]

    image_files = []
    for image_path in image_order:
        full_path = os.path.join(static_folder, image_path)
        if os.path.exists(full_path):
            image_files.append(image_path)
        else:
            logger.warning(f"File not found: {full_path}")

    return image_files
