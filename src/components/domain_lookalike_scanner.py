"""Domain Lookalike Scanner - orchestrates scans and delivers results via Webex."""

import logging
import tempfile
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict

import pandas as pd

from services import domain_lookalike
from src.utils.excel_formatting import apply_professional_formatting
from src.utils.webex_utils import send_message_with_retry

logger = logging.getLogger(__name__)


class DomainLookalikeScanner:
    """Orchestrates domain lookalike scans with background execution and Webex delivery."""

    def __init__(self, webex_api):
        """Initialize scanner with Webex API instance.

        Args:
            webex_api: WebexAPI instance for sending messages
        """
        self.webex_api = webex_api

    def start_quick_scan(self, domain: str, room_id: str) -> str:
        """Start a quick scan (no DNS resolution) in background.

        Args:
            domain: Domain to scan for lookalikes
            room_id: Webex room ID for result delivery

        Returns:
            Acknowledgment message for immediate display
        """
        thread = threading.Thread(
            target=self._quick_scan_worker,
            args=(domain, room_id),
            daemon=True
        )
        thread.start()

        return (
            f"🔍 **Scanning lookalike domains for {domain}**\n\n"
            f"⚡ Showing all variations (registered + unregistered)\n"
            f"⏱️ This takes 10-30 seconds\n"
            f"💬 Results will appear here shortly!"
        )

    def start_full_scan(self, domain: str, room_id: str) -> str:
        """Start a full scan (with DNS resolution) in background.

        Args:
            domain: Domain to scan for lookalikes
            room_id: Webex room ID for result delivery

        Returns:
            Acknowledgment message for immediate display
        """
        thread = threading.Thread(
            target=self._full_scan_worker,
            args=(domain, room_id),
            daemon=True
        )
        thread.start()

        return (
            f"🚀 **Registered-only scan started for {domain}**\n\n"
            f"🎯 Filtering to show only registered lookalike domains\n"
            f"⏳ Takes 5-15 minutes (scanning thousands of variations)\n"
            f"🅿️ Will also check if registered domains are parked vs. active\n"
            f"💬 I'll message you here when complete - feel free to work on other tasks!"
        )

    def _quick_scan_worker(self, domain: str, room_id: str) -> None:
        """Background worker for quick scans."""
        logger.info(f"Quick scan worker started for domain: {domain}, room_id: {room_id}")
        start_time = time.time()

        try:
            result = domain_lookalike.get_domain_lookalikes(domain, False)
            duration = int(time.time() - start_time)

            if not result.get('success'):
                self._send_error(room_id, domain, result.get('error', 'Unknown error'))
                return

            if result['total_count'] == 0:
                self._send_message(
                    room_id,
                    f"✅ **Scan complete for {domain}**\n\n"
                    f"No lookalike domains found!\n"
                    f"⏱️ Scan completed in {duration} seconds"
                )
                return

            excel_path = self._generate_excel_file(result, domain, registered_only=False)
            total = result['total_count']
            registered = result['registered_count']

            self._send_message(
                room_id,
                f"✅ **Scan complete for {domain}**\n\n"
                f"📊 Found **{total}** lookalike domains\n"
                f"✅ Registered: **{registered}** | ⚪ Unregistered: **{total - registered}**\n"
                f"⏱️ Scan completed in {duration} seconds",
                files=[excel_path]
            )

        except Exception as e:
            logger.error(f"Quick scan worker error for {domain}: {e}", exc_info=True)
            self._send_error(room_id, domain, str(e), scan_type="Quick scan")

    def _full_scan_worker(self, domain: str, room_id: str) -> None:
        """Background worker for full DNS resolution scans."""
        logger.info(f"Full scan worker started for domain: {domain}, room_id: {room_id}")
        start_time = time.time()

        try:
            result = domain_lookalike.get_domain_lookalikes(domain, True)

            if not result.get('success'):
                self._send_error(room_id, domain, result.get('error', 'Unknown error'), scan_type="Full scan")
                return

            if result['registered_count'] == 0:
                duration_sec = int(time.time() - start_time)
                duration_str = str(timedelta(seconds=duration_sec))
                self._send_message(
                    room_id,
                    f"✅ **Full scan complete for {domain}**\n\n"
                    f"No registered lookalike domains found!\n"
                    f"⏱️ Scan completed in {duration_str}"
                )
                return

            # Check parking status for registered domains
            logger.info(f"Checking parking status for {result['registered_count']} registered domains")
            self._send_message(
                room_id,
                f"✅ DNS scan complete! Found **{result['registered_count']}** registered lookalike domains\n\n"
                f"🅿️ Now checking parking status for each domain (visiting each site to detect if parked/for-sale vs. active)...\n"
                f"⏳ This may take another minute or two - final report coming soon!"
            )
            result['domains'] = domain_lookalike.check_parking_batch(result['domains'])

            duration_sec = int(time.time() - start_time)
            duration_str = str(timedelta(seconds=duration_sec))

            excel_path = self._generate_excel_file(result, domain, registered_only=True)

            # Count parked domains
            parked_count = sum(1 for d in result['domains'] if d.get('parked') is True)

            self._send_message(
                room_id,
                f"🎯 **Full scan complete for {domain}**\n\n"
                f"⚠️ Found **{result['registered_count']}** registered lookalike domains\n"
                f"🅿️ Parked: **{parked_count}** | 🌐 Active: **{result['registered_count'] - parked_count}**\n"
                f"⏱️ Scan completed in {duration_str}",
                files=[excel_path]
            )

        except Exception as e:
            logger.error(f"Full scan worker error for {domain}: {e}", exc_info=True)
            self._send_error(room_id, domain, str(e), scan_type="Full scan")

    def _send_message(self, room_id: str, markdown: str, files: list = None) -> None:
        """Send message to Webex room."""
        send_message_with_retry(
            webex_api=self.webex_api,
            room_id=room_id,
            markdown=markdown,
            files=files
        )

    def _send_error(self, room_id: str, domain: str, error: str, scan_type: str = "Scan") -> None:
        """Send error message to Webex room."""
        try:
            self._send_message(
                room_id,
                f"❌ **{scan_type} failed for {domain}**\n\n"
                f"Error: {error}"
            )
        except Exception as e:
            logger.error(f"Failed to send error message: {e}")

    @staticmethod
    def _generate_excel_file(result: Dict[str, Any], domain: str, registered_only: bool = False) -> str:
        """Generate professionally formatted Excel file from scan results.

        Args:
            result: Scan result dictionary from domain_lookalike service
            domain: Original domain that was scanned
            registered_only: Whether this was a registered-only scan

        Returns:
            Path to generated Excel file
        """
        rows = []
        for d in result['domains']:
            if registered_only and not d['registered']:
                continue

            # Format parked status
            parked_value = d.get('parked')
            if parked_value is True:
                parked_str = 'Yes'
            elif parked_value is False:
                parked_str = 'No'
            else:
                parked_str = 'Unknown'

            row = {
                'Domain': d['domain'],
                'Registered': 'Yes' if d['registered'] else 'No',
                'Technique': d['fuzzer'],
                'DNS A Records': ', '.join(d['dns_a']) if d['dns_a'] else '',
                'DNS AAAA Records': ', '.join(d['dns_aaaa']) if d['dns_aaaa'] else '',
                'DNS MX Records': ', '.join(d['dns_mx']) if d['dns_mx'] else '',
                'DNS NS Records': ', '.join(d['dns_ns']) if d['dns_ns'] else '',
                'GeoIP': d['geoip']
            }

            # Add Parked column only for full scans (registered_only=True)
            if registered_only:
                row['Parked'] = parked_str

            rows.append(row)

        df = pd.DataFrame(rows)

        timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
        scan_type = 'registered' if registered_only else 'all'
        safe_domain = domain.replace('.', '_')
        filename = f"{safe_domain}_lookalikes_{scan_type}_{timestamp}.xlsx"

        with tempfile.NamedTemporaryFile(
            mode='wb',
            suffix='.xlsx',
            prefix=filename,
            delete=False
        ) as tmp:
            temp_path = tmp.name
            df.to_excel(temp_path, index=False, engine='openpyxl')

        column_widths = {
            'domain': 35,
            'registered': 12,
            'parked': 10,
            'technique': 20,
            'dns a records': 30,
            'dns aaaa records': 30,
            'dns mx records': 40,
            'dns ns records': 40,
            'geoip': 20
        }

        wrap_columns = {
            'dns a records',
            'dns aaaa records',
            'dns mx records',
            'dns ns records'
        }

        apply_professional_formatting(
            temp_path,
            column_widths=column_widths,
            wrap_columns=wrap_columns
        )

        logger.info(f"Generated Excel file: {temp_path}")
        return temp_path
