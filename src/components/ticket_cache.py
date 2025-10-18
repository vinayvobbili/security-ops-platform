import json
import logging
import pprint
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Iterable, Union
from zoneinfo import ZoneInfo

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
    """Simple ticket caching: fetch raw data from XSOAR, process for UI, save both versions.

    Process:
    1. Fetch raw data from XSOAR
    2. Process data for UI:
       2.1 Extract system fields (id, name, type, status, etc.)
       2.2 Extract custom fields from CustomFields object
       2.3 Calculate derived fields (age, resolution time, display formats)
       2.4 Apply transformations (remove METCIRT, @company.com, etc.)
    3. Save both raw and processed versions
    """

    def __init__(self):
        self.ticket_handler = TicketHandler()
        self.root_directory = Path(__file__).parent.parent.parent

    # System fields we want to extract
    SYSTEM_FIELDS = {
        'id': 'id',
        'name': 'name',
        'type': 'type',
        'status': 'status',
        'severity': 'severity',
        'owner': 'owner',
        'created': 'created',
        'closed': 'closed',
    }

    # Custom fields we want to extract from CustomFields
    CUSTOM_FIELDS = {
        'affected_country': 'affectedcountry',
        'affected_region': 'affectedregion',
        'impact': 'impact',
        'automation_level': 'automationlevel',
        'hostname': 'hostname',
        'username': 'username',
    }

    # Calculated fields we compute from other fields
    CALCULATED_FIELDS = {
        'is_open': 'status in (0, 1)',  # Pending or Active status
        'currently_aging_days': '(current_time - created).days if open else None',  # Days since creation for open tickets
        'days_since_creation': '(current_time - created).days',  # Total days since creation
        'resolution_time_days': '(closed - created).days if both exist',  # Days to resolve
        'resolution_bucket': 'categorical grouping of resolution_time_days',  # open, lt7, lt14, lt30, gt30
        'has_resolution_time': 'resolution_time_days is not None',  # Boolean flag
        'age_category': 'categorical grouping of currently_aging_days',  # le7, le30, gt30, all
        'created_days_ago': 'alias for days_since_creation',  # Legacy field name
        'status_display': 'human readable status names',  # Pending/Active/Closed
        'severity_display': 'human readable severity names',  # Low/Medium/High/Critical
        'created_display': 'MM/DD formatted creation date',  # Display format
        'closed_display': 'MM/DD formatted close date',  # Display format
        'has_breached_response_sla': 'timetorespond.breachTriggered boolean',  # Response SLA breach flag
        'has_breached_containment_sla': 'timetocontain.breachTriggered boolean',  # Containment SLA breach flag
        'time_to_respond_secs': 'timetorespond.totalDuration in seconds',  # Response time in seconds
        'time_to_contain_secs': 'timetocontain.totalDuration in seconds',  # Containment time in seconds
        'has_hostname': 'hostname field is not None/empty',  # Boolean flag for hostname presence
    }

    # ---------------------------- Data Transformations ----------------------------
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
    def _age_category(currently_aging_days: Optional[int]) -> str:
        if currently_aging_days is None:
            return 'all'
        if currently_aging_days <= 7:
            return 'le7'
        if currently_aging_days <= 30:
            return 'le30'
        return 'gt30'

    @staticmethod
    def _clean_owner_name(owner: str) -> str:
        """Remove @company.com suffix from owner names."""
        if not owner or owner == 'Unknown':
            return owner
        return owner.replace('@company.com', '')

    @staticmethod
    def _clean_type_name(ticket_type: str) -> str:
        """Remove METCIRT prefix from ticket types."""
        if not ticket_type or ticket_type == 'Unknown':
            return ticket_type
        import re
        return re.sub(r'^METCIRT[_\-\s]*', '', ticket_type, flags=re.IGNORECASE).strip()

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
    @classmethod
    def generate(cls, lookback_days=90) -> None:
        """Simple 3-step process: fetch, process, save."""

        # Create an instance for this operation
        instance = cls()

        # Step 1: Fetch raw data from XSOAR
        raw_tickets = instance._fetch_raw_tickets(lookback_days)

        # Step 2: Process for UI (flatten and transform)
        ui_tickets = instance._process_for_ui(raw_tickets)

        # Step 3: Save both versions
        instance._save_tickets(raw_tickets, ui_tickets)

        #

    def _fetch_raw_tickets(self, lookback_days: int) -> List[Ticket]:
        """Step 1: Fetch raw tickets from XSOAR."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=lookback_days)
        query = (
            f"created:>={start_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"created:<={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"type:{CONFIG.team_name} -closeReason:Duplicate"
        )

        print(f"🔍 Fetching tickets from XSOAR for past {lookback_days} days...")
        raw_tickets: Union[List[Ticket], Iterable[Ticket], None] = self.ticket_handler.get_tickets(query, paginate=True)
        tickets: List[Ticket] = [] if raw_tickets is None else [t for t in raw_tickets if isinstance(t, dict)]
        log.info(f"Fetched {len(tickets)} tickets (lookback={lookback_days}d) from XSOAR")
        return tickets

    def _process_for_ui(self, raw_tickets: List[Ticket]) -> List[Ticket]:
        """Step 2: Process raw tickets into flattened UI format."""
        ui_tickets = []
        current_time = datetime.now(timezone.utc)

        print(f"⚙️ Processing {len(raw_tickets)} tickets for UI...")
        for ticket in tqdm(raw_tickets, desc="Processing tickets", unit="ticket"):
            try:
                ui_ticket = self._flatten_ticket(ticket, current_time)
                ui_tickets.append(ui_ticket)
            except Exception as e:
                log.warning(f"Failed to process ticket {ticket.get('id', 'unknown')}: {e}")
                continue

        log.info(f"Processed {len(ui_tickets)} tickets for UI")
        return ui_tickets

    def _flatten_ticket(self, ticket: Ticket, current_time: datetime) -> Ticket:
        """Convert a raw ticket to flattened UI format."""
        # Extract system fields
        ui_ticket = {}
        for ui_field, system_field in self.SYSTEM_FIELDS.items():
            ui_ticket[ui_field] = ticket.get(system_field, 'Unknown' if ui_field in ['name', 'owner'] else 0)

        # Extract custom fields
        custom_fields = ticket.get('CustomFields', {})
        for ui_field, custom_field in self.CUSTOM_FIELDS.items():
            ui_ticket[ui_field] = custom_fields.get(custom_field, 'Unknown')

        # Extract SLA timing objects for computed fields (from CustomFields)
        ui_ticket['_timetorespond'] = custom_fields.get('timetorespond', {})
        ui_ticket['_timetocontain'] = custom_fields.get('timetocontain', {})

        # Apply transformations
        ui_ticket['type'] = self._clean_type_name(ui_ticket.get('type', 'Unknown'))
        ui_ticket['owner'] = self._clean_owner_name(ui_ticket.get('owner', 'Unknown'))

        # Add computed fields
        self._add_computed_fields(ui_ticket, current_time)

        # Remove temporary SLA objects (they're only needed for computation)
        ui_ticket.pop('_timetorespond', None)
        ui_ticket.pop('_timetocontain', None)

        return ui_ticket

    def _add_computed_fields(self, ticket: Ticket, current_time: datetime) -> None:
        """Add computed fields like age, resolution time, etc."""
        created_dt = self._parse_date(ticket.get('created'))
        closed_dt = self._parse_date(ticket.get('closed'))
        status = ticket.get('status', 0)
        is_open = status in (0, 1)

        # Age and timing calculations
        currently_aging_days = (current_time - created_dt).days if (created_dt and is_open) else None
        days_since_creation = (current_time - created_dt).days if created_dt else None
        resolution_time_days = (closed_dt - created_dt).days if (created_dt and closed_dt) else None

        # Extract SLA timing data
        timetorespond = ticket.get('_timetorespond', {})
        timetocontain = ticket.get('_timetocontain', {})

        # Add all computed fields
        ticket.update({
            'is_open': is_open,
            'currently_aging_days': currently_aging_days,
            'days_since_creation': days_since_creation,
            'resolution_time_days': resolution_time_days,
            'resolution_bucket': self._resolution_bucket(resolution_time_days, is_open),
            'has_resolution_time': resolution_time_days is not None,
            'age_category': self._age_category(currently_aging_days),
            'created_days_ago': days_since_creation,
            # SLA fields
            'has_breached_response_sla': bool(timetorespond.get('breachTriggered', False)),
            'has_breached_containment_sla': bool(timetocontain.get('breachTriggered', False)),
            'time_to_respond_secs': timetorespond.get('totalDuration', 0),
            'time_to_contain_secs': timetocontain.get('totalDuration', 0),
            # Hostname presence
            'has_hostname': bool(ticket.get('hostname') and ticket['hostname'].strip() and ticket['hostname'] != 'Unknown'),
            # Display fields
            'status_display': {0: 'Pending', 1: 'Active', 2: 'Closed'}.get(status, 'Unknown'),
            'severity_display': {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}.get(ticket.get('severity', 0), 'Unknown'),
            'created_display': self._format_date_for_display(ticket.get('created')),
            'closed_display': self._format_date_for_display(ticket.get('closed')),
        })

    def _save_tickets(self, raw_tickets: List[Ticket], ui_tickets: List[Ticket]) -> None:
        """Step 3: Save both raw and UI ticket data."""
        today_date = datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y')
        charts_dir = self.root_directory / 'web' / 'static' / 'charts' / today_date
        charts_dir.mkdir(parents=True, exist_ok=True)

        # Save raw tickets
        print("💾 Saving raw ticket data...")
        raw_path = charts_dir / 'past_90_days_tickets_raw.json'
        with open(raw_path, 'w') as f:
            json.dump(raw_tickets, f, indent=4)
        log.info(f"Saved {len(raw_tickets)} raw tickets to {raw_path}")

        # Save UI tickets with metadata
        print("📊 Saving UI ticket data...")
        ui_path = charts_dir / 'past_90_days_tickets.json'
        ui_data_with_metadata = {
            'data': ui_tickets,
            'data_generated_at': datetime.now(ZoneInfo("America/New_York")).isoformat(),
            'total_count': len(ui_tickets)
        }
        with open(ui_path, 'w') as f:
            json.dump(ui_data_with_metadata, f, indent=2)
        log.info(f"Saved {len(ui_tickets)} UI tickets to {ui_path}")

        print("✅ Ticket caching completed successfully!")


def main():
    log.info("Starting ticket caching process")
    cache = TicketCache()
    cache.generate(lookback_days=90)

    # Pretty print first 3 tickets for visual inspection
    ui_path = cache.root_directory / 'web' / 'static' / 'charts' / datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y') / 'past_90_days_tickets.json'
    if ui_path.exists():
        with open(ui_path, 'r') as f:
            cached_data = json.load(f)

        # Extract tickets from new format (with metadata) or old format (just array)
        if isinstance(cached_data, dict) and 'data' in cached_data:
            tickets = cached_data['data']
            print(f"\n📊 Data generated at: {cached_data.get('data_generated_at', 'Unknown')}")
            print(f"📦 Total tickets: {cached_data.get('total_count', len(tickets))}")
        else:
            tickets = cached_data  # Old format fallback

        print("\n" + "=" * 80)
        print("SAMPLE UI TICKETS (first 3 for inspection):")
        print("=" * 80)
        pp = pprint.PrettyPrinter(indent=2, width=100)
        for i, ticket in enumerate(tickets[:3], 1):
            print(f"\n--- Ticket #{i} ---")
            pp.pprint(ticket)
        print("=" * 80)

    log.info("Ticket caching process completed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()
