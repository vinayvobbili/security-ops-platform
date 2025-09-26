import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Iterable, Union

from tqdm import tqdm

from my_config import get_config
from services.xsoar import TicketHandler

CONFIG = get_config()
log = logging.getLogger(__name__)

# Simple alias / minimal shape hint (keep lightweight; avoid over-engineering)
Ticket = Dict[str, Any]

# Simple adjustable lookback window. Set to 9 for quick local tests; keep 90 in normal runs.
LOOKBACK_DAYS = 90  # Change manually when needed.


class TicketCache:
    """Handles caching and data preparation for XSOAR tickets.

    Simplicity focused: derives fields in a single pass; avoids over-engineering.
    Normalizes ticket 'type' values by removing any leading 'METCIRT' prefix.

    Lookback window is controlled by module-level LOOKBACK_DAYS for easy manual
    adjustment (test vs prod) without touching broader config plumbing.
    """

    def __init__(self):
        self.ticket_handler = TicketHandler()
        self.root_directory = Path(__file__).parent.parent.parent

    # ---------------------------- Internal Helpers (Simple + Reusable) ----------------------------
    @staticmethod
    def _parse_date(raw: Optional[str]) -> Optional[datetime]:
        """Parse an ISO-ish timestamp (with optional trailing Z). Return None if invalid.
        Keep intentionally small + forgiving (trusted environment per AGENTS.md)."""
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw.replace('Z', '+00:00'))
        except ValueError:
            # Fallback: try common millisecond format without manual timezone (assume UTC if 'Z')
            try:
                if raw.endswith('Z'):
                    return datetime.strptime(raw, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None

    @staticmethod
    def _age_category(age_days: Optional[int]) -> str:
        if age_days is None:
            return 'all'
        if age_days <= 7:
            return 'le7'
        if age_days <= 30:
            return 'le30'
        return 'gt30'

    @staticmethod
    def _clean_owner_name(owner: str) -> str:
        if not owner or owner == 'Unknown':
            return owner
        return owner[:-12] if owner.endswith('@company.com') else owner

    @staticmethod
    def _clean_type_name(ticket_type: str) -> str:
        if not ticket_type or ticket_type == 'Unknown':
            return ticket_type
        import re
        cleaned = re.sub(r'^METCIRT[_\-\s]*', '', ticket_type, flags=re.IGNORECASE) if ticket_type.startswith('METCIRT') else ticket_type
        return cleaned.strip()

    @staticmethod
    def _format_date_for_display(date_str: Optional[str]) -> str:
        if not date_str:
            return ''
        try:
            d = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return f"{d.month:02d}/{d.day:02d}"
        except Exception:
            return date_str

    @staticmethod
    def _format_age_display(age_days: Optional[int]) -> str:
        if age_days is None:
            return ''
        return f"{age_days}d"

    @staticmethod
    def _extract_duration(time_obj: Optional[Dict[str, Any]]) -> Optional[int]:
        if isinstance(time_obj, dict):
            return time_obj.get('totalDuration')
        return None

    @staticmethod
    def _extract_breach_status(time_obj: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(time_obj, dict):
            return False
        return bool(time_obj.get('breachTriggered') in (True, 'true'))

    @staticmethod
    def _format_duration(seconds: Optional[int]) -> str:
        if not seconds or seconds <= 0:
            return '0:00'
        return f"{seconds // 60}:{seconds % 60:02d}"

    @staticmethod
    def _extract_chart_date(date_str: Optional[str]) -> Optional[str]:
        dt = TicketCache._parse_date(date_str)
        return dt.strftime('%Y-%m-%d') if dt else None

    @staticmethod
    def _resolution_bucket(resolution_days: Optional[int], is_open: bool) -> str:
        """Map numeric resolution time (in days) to a discrete bucket for UI filtering.
        Buckets:
          open   -> ticket still open (no resolution yet)
          lt7    -> resolved in <7 days
          lt14   -> resolved in 7-13 days
          lt30   -> resolved in 14-29 days
          gt30   -> resolved in >=30 days
          unknown-> malformed / missing closed timestamp even though status implies closed
        """
        if is_open:
            return 'open'
        if resolution_days is None:
            return 'unknown'
        if resolution_days < 7:
            return 'lt7'
        if resolution_days < 14:
            return 'lt14'
        if resolution_days < 30:
            return 'lt30'
        return 'gt30'

    # ---------------------------- Core Pipeline ----------------------------
    def generate(self, lookback_days=90) -> None:
        """Fetch tickets for the past N days (default: LOOKBACK_DAYS), derive fields, cache raw + UI data.

        Args:
            lookback_days: Optional integer override for lookback days (e.g. 9 for faster tests). If None, uses LOOKBACK_DAYS.
        """
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=lookback_days)
        query = (
            f"created:>={start_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"created:<={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"type:{CONFIG.team_name} -closeReason:Duplicate"
        )

        print(f"🔍 Fetching tickets from XSOAR for past {lookback_days} days...")
        raw_tickets: Union[List[Ticket], Iterable[Ticket], None] = self.ticket_handler.get_tickets(query)  # type: ignore[attr-defined]
        tickets: List[Ticket] = [] if raw_tickets is None else [t for t in raw_tickets if isinstance(t, dict)]  # type: ignore[union-attr]
        log.info(f"Fetched {len(tickets)} tickets (lookback={lookback_days}d) from prod for caching")

        current_time = datetime.now(timezone.utc)
        print(f"⚙️  Processing {len(tickets)} tickets...")
        for t in tqdm(tickets, desc="Processing tickets", unit="ticket"):
            try:
                # Determine source type: prefer rawType (authoritative) then fallback to existing type
                source_type = t.get('rawType') or t.get('type')
                if isinstance(source_type, str):
                    t['type'] = self._clean_type_name(source_type)
                else:
                    t['type'] = 'Unknown'

                # Authoritative extraction: affected_country MUST always come from CustomFields.affectedCountry
                custom_fields = t.get('CustomFields')
                if isinstance(custom_fields, dict):
                    t['affected_country'] = custom_fields.get('affectedCountry') or 'Unknown'
                    # Optional: region is secondary; only set if present (non-breaking)
                    region_val = custom_fields.get('affectedRegion') or custom_fields.get('affected_region')
                    if region_val:
                        t['affected_region'] = region_val
                else:
                    t['affected_country'] = 'Unknown'

                created_dt = self._parse_date(t.get('created'))
                closed_dt = self._parse_date(t.get('closed'))
                is_open_flag = t.get('status', 0) in (0, 1)

                age_days = (current_time - created_dt).days if (created_dt and is_open_flag) else None
                days_since_creation = (current_time - created_dt).days if created_dt else None
                resolution_time_days = (closed_dt - created_dt).days if (created_dt and closed_dt) else None
                created_days_ago = (current_time - created_dt).days if created_dt else None

                resolution_bucket = self._resolution_bucket(resolution_time_days, is_open_flag)
                t.update({
                    'is_open': is_open_flag,
                    'age_days': age_days,
                    'days_since_creation': days_since_creation,
                    'resolution_time_days': resolution_time_days,
                    'resolution_bucket': resolution_bucket,
                    'has_resolution_time': resolution_time_days is not None,
                    'age_category': self._age_category(age_days),
                    'created_days_ago': created_days_ago,
                })
            except Exception as e:  # Trusted env: keep fallback simple
                log.warning(f"Derivation failed for ticket {t.get('id', 'unknown')}: {e}")
                t.setdefault('type', 'Unknown')
                t.setdefault('is_open', t.get('status', 0) in (0, 1))
                t.setdefault('age_days', None)
                t.setdefault('days_since_creation', None)
                t.setdefault('resolution_time_days', None)
                t.setdefault('resolution_bucket', 'unknown')
                t.setdefault('has_resolution_time', False)
                t.setdefault('age_category', 'all')
                t.setdefault('created_days_ago', None)
                t.setdefault('affected_country', 'Unknown')

        # Persist raw enriched tickets
        print("💾 Saving raw ticket data ...")
        today_date = datetime.now().strftime('%m-%d-%Y')
        charts_dir = self.root_directory / 'web' / 'static' / 'charts' / today_date
        charts_dir.mkdir(parents=True, exist_ok=True)

        # Stable filenames retained for dashboard compatibility
        raw_path = charts_dir / 'past_90_days_tickets_raw.json'
        with open(raw_path, 'w') as f:
            json.dump(tickets, f, indent=4)
        log.info(f"Cached {len(tickets)} raw tickets (lookback={lookback_days}d) to {raw_path}")

        print("📊 Generating UI data ...")
        ui_data = self.prep_data_for_UI(tickets)
        ui_path = charts_dir / 'past_90_days_tickets.json'
        with open(ui_path, 'w') as f:
            json.dump(ui_data, f, indent=2)
        log.info(f"Generated UI data with {len(ui_data)} tickets to {ui_path}")
        print("✅ Ticket caching completed successfully!")

    # ---------------------------- UI Prep ----------------------------
    def prep_data_for_UI(self, raw_tickets: List[Ticket]) -> List[Ticket]:
        ui_data: List[Ticket] = []
        for t in tqdm(raw_tickets, desc="Preparing UI data", unit="ticket"):
            try:
                tid = t.get('id')
                if not tid:
                    continue

                ttr_seconds = self._extract_duration(t.get('timetorespond'))
                ttc_seconds = self._extract_duration(t.get('timetocontain'))

                # Ensure resolution_time_days key exists (added per request)
                t.setdefault('resolution_time_days', None)
                t.setdefault('resolution_bucket', 'unknown')
                t.setdefault('has_resolution_time', t.get('resolution_time_days') is not None)

                # Legacy fallback (should be unnecessary after authoritative set in generate)
                if 'affected_country' not in t:
                    cf = t.get('CustomFields')
                    if isinstance(cf, dict):
                        t['affected_country'] = cf.get('affectedCountry') or 'Unknown'
                    else:
                        t['affected_country'] = 'Unknown'
                if 'affected_region' not in t:
                    cf = t.get('CustomFields')
                    if isinstance(cf, dict):
                        region_val = cf.get('affectedRegion') or cf.get('affected_region')
                        if region_val:
                            t['affected_region'] = region_val

                status_val = t.get('status', 0)
                ui_ticket: Ticket = {
                    'id': tid,
                    'name': t.get('name', f'Ticket {tid}'),
                    'type': t.get('type', 'Unknown'),
                    'type_display': t.get('type', 'Unknown'),
                    'status': status_val,
                    'status_display': {0: 'Pending', 1: 'Active', 2: 'Closed'}.get(status_val, 'Unknown'),
                    'severity': t.get('severity', 0),
                    'severity_display': {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}.get(t.get('severity', 0), 'Unknown'),
                    'impact': t.get('impact', 'Unknown'),
                    'affected_country': t.get('affected_country', 'Unknown'),
                    'affected_region': t.get('affected_region', 'Unknown'),
                    'owner': t.get('owner', 'Unknown'),
                    'owner_display': self._clean_owner_name(t.get('owner', 'Unknown')),
                    'created': t.get('created', ''),
                    'created_display': self._format_date_for_display(t.get('created')),
                    'closed': t.get('closed', ''),
                    'closed_display': self._format_date_for_display(t.get('closed')),
                    'automation_level': t.get('automation_level', 'Unknown'),
                    'age': t.get('age_days'),
                    'age_display': self._format_age_display(t.get('age_days')),
                    'is_open': t.get('is_open', status_val in (0, 1)),
                    'days_since_creation': t.get('days_since_creation'),
                    'created_days_ago': t.get('created_days_ago'),
                    'resolution_time_days': t.get('resolution_time_days'),
                    'resolution_bucket': t.get('resolution_bucket'),
                    'has_resolution_time': t.get('has_resolution_time'),
                    'ttr_seconds': ttr_seconds,
                    'ttr_display': self._format_duration(ttr_seconds),
                    'ttr_breach': self._extract_breach_status(t.get('timetorespond')),
                    'ttc_seconds': ttc_seconds,
                    'ttc_display': self._format_duration(ttc_seconds),
                    'ttc_breach': self._extract_breach_status(t.get('timetocontain')),
                    'has_host': bool(t.get('hostname') and t.get('hostname').strip() and t.get('hostname') != 'Unknown'),
                    'has_owner': bool(t.get('owner') and t.get('owner').strip()),
                    'has_ttr': bool(ttr_seconds),
                    'has_ttc': bool(ttc_seconds),
                    'chart_date': self._extract_chart_date(t.get('created')),
                    'age_category': t.get('age_category', 'all'),
                }
                ui_data.append(ui_ticket)
            except Exception as e:  # Simplicity: skip malformed
                log.warning(f"UI flatten failed for ticket {t.get('id', 'unknown')}: {e}")
                continue

        log.info(f"Prepared flattened UI data: {len(ui_data)} tickets from {len(raw_tickets)} raw tickets")
        return ui_data


def main():
    log.info("Starting ticket caching process")
    TicketCache().generate(lookback_days=9)
    log.info("Ticket caching process completed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()
