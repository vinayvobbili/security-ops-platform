"""Scheduled monthly Brand-Protection report.

On the 1st of each month, roll up the prior month's findings ledger into the
report workbook and post a summary (plus the xlsx) to the Domain Monitoring
Webex room.
"""

import logging
import tempfile
from datetime import datetime

from .config import EASTERN_TZ, WEB_BASE_URL, ALERT_ROOM_ID_PROD, get_webex_api, set_active_room_id
from .findings_ledger import monthly_rollup
from .export import build_monthly_report_workbook

logger = logging.getLogger(__name__)


def _prior_month() -> str:
    """Return the previous calendar month as YYYY-MM (Eastern)."""
    now = datetime.now(EASTERN_TZ)
    year, month = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
    return f"{year:04d}-{month:02d}"


def post_monthly_report(room_id: str | None = None, month: str | None = None) -> None:
    """Generate the monthly report and post it to the Domain Monitoring room.

    Defaults to the prior calendar month (the natural 1st-of-month run). Posts a
    KPI summary with a link to the report page and attaches the xlsx; if no
    findings were recorded for the month, posts a short note instead.
    """
    month = month or _prior_month()
    room_id = room_id or ALERT_ROOM_ID_PROD
    set_active_room_id(room_id)

    rollup = monthly_rollup(month)
    webex_api = get_webex_api()
    pretty = datetime.strptime(month, "%Y-%m").strftime("%B %Y")
    report_url = f"{WEB_BASE_URL}/domain-monitoring/reports"

    if not rollup.get("total_findings"):
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"🛡️ **Brand Protection Report — {pretty}**\n\nNo domains were recorded for this period.",
        )
        logger.info(f"Monthly report for {month}: no findings, posted note")
        return

    top_brands = ", ".join(f"{b} ({c})" for b, c in list(rollup["by_brand"].items())[:5]) or "—"
    summary = (
        f"🛡️ **Domain Monitoring & Brand Protection Report — {pretty}** 🛡️\n\n"
        f"- 🔎 **{rollup['total_findings']}** domains reviewed\n"
        f"- 🚫 **{rollup['takedowns']}** takedowns raised\n"
        f"- 👁️ **{rollup['monitoring']}** under monitoring\n"
        f"- 🏷️ **{len(rollup['by_brand'])}** brands impersonated — {top_brands}\n"
        f"- 🗑️ **{rollup['irrelevant']}** triaged as irrelevant\n\n"
        f"📊 Full report: {report_url}"
    )

    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx", dir="/tmp")
        tmp_path = tmp.name
        tmp.close()
        build_monthly_report_workbook(rollup, tmp_path, month)
        webex_api.messages.create(roomId=room_id, markdown=summary, files=[tmp_path])
        logger.info(f"Posted monthly report for {month} with xlsx attachment")
    except Exception as e:
        # Fall back to a text-only post so the summary still lands.
        logger.error(f"Could not attach monthly xlsx ({e}); posting summary only")
        webex_api.messages.create(roomId=room_id, markdown=summary)
