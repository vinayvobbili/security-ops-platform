"""Ticket cache component for XSOAR data.

Fetches tickets from XSOAR, processes for UI consumption, and caches locally.
Runs in trusted environment - minimal defensive coding per AGENTS.md.
"""
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from zoneinfo import ZoneInfo

from tqdm import tqdm

from my_config import get_config
from services.xsoar import TicketHandler, XsoarEnvironment

CONFIG = get_config()
log = logging.getLogger(__name__)

Ticket = Dict[str, Any]
LOOKBACK_DAYS = 90
# Configurable worker count via env var (default: 25)
# Reduced from 100->50->25 to avoid API rate limiting
MAX_WORKERS = int(os.getenv('TICKET_ENRICHMENT_WORKERS', '25'))


# Field mappings for ticket extraction
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

CUSTOM_FIELDS = {
    'affected_country': 'affectedcountry',
    'affected_region': 'affectedregion',
    'impact': 'impact',
    'automation_level': 'automationlevel',
    'hostname': 'hostname',
    'username': 'username',
}

# Status and severity display mappings
STATUS_DISPLAY = {0: 'Pending', 1: 'Active', 2: 'Closed'}
SEVERITY_DISPLAY = {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}


# ---------------------------- Utility Functions ----------------------------

def parse_date(raw: Optional[Union[str, int, datetime]]) -> Optional[datetime]:
    """Parse date from various formats: datetime object, Unix timestamp, or ISO string.

    Returns timezone-aware datetime or None. Handles XSOAR's mixed date formats.
    Trusted environment - minimal error handling.
    """
    if not raw:
        return None

    # Already parsed datetime
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)

    # Unix timestamp (milliseconds or seconds)
    if isinstance(raw, (int, float)):
        if raw == 0:
            return None
        timestamp = raw / 1000 if raw > 10 ** 10 else raw
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    # ISO string
    if isinstance(raw, str):
        return datetime.fromisoformat(raw.replace('Z', '+00:00'))

    return None


def age_category(days: Optional[int]) -> str:
    """Categorize ticket age into buckets: le7, le30, gt30, all."""
    if days is None:
        return 'all'
    if days <= 7:
        return 'le7'
    if days <= 30:
        return 'le30'
    return 'gt30'


def resolution_bucket(days: Optional[int], is_open: bool) -> str:
    """Categorize resolution time: open, lt7, lt14, lt30, gt30, unknown."""
    if is_open:
        return 'open'
    if days is None:
        return 'unknown'
    if days < 7:
        return 'lt7'
    if days < 14:
        return 'lt14'
    if days < 30:
        return 'lt30'
    return 'gt30'


def clean_owner_name(owner: str) -> str:
    """Remove @company.com domain from owner email."""
    if not owner or owner == 'Unknown':
        return owner
    return owner.replace('@company.com', '')


def clean_type_name(ticket_type: str) -> str:
    """Remove METCIRT prefix from ticket types."""
    if not ticket_type or ticket_type == 'Unknown':
        return ticket_type
    return re.sub(r'^METCIRT[_\-\s]*', '', ticket_type, flags=re.IGNORECASE).strip()


def format_date_display(date_obj: Optional[Union[str, datetime]]) -> str:
    """Format date as MM/DD for UI display."""
    if not date_obj:
        return ''
    if isinstance(date_obj, datetime):
        return f"{date_obj.month:02d}/{date_obj.day:02d}"
    if isinstance(date_obj, str):
        dt = parse_date(date_obj)
        return f"{dt.month:02d}/{dt.day:02d}" if dt else ''
    return str(date_obj)


def json_serializer(obj: Any) -> str:
    """Serialize datetime objects to ISO format for JSON."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


# ---------------------------- Main Class ----------------------------

class TicketCache:
    """Cache XSOAR tickets locally with UI processing.

    Three-step pipeline:
    1. Fetch raw tickets from XSOAR (with notes enrichment)
    2. Process for UI (flatten structure, compute derived fields)
    3. Save both raw and processed versions
    """

    def __init__(self):
        self.ticket_handler = TicketHandler(XsoarEnvironment.PROD)
        self.root_directory = Path(__file__).parent.parent.parent
        log.debug(f"Initialized TicketCache with root: {self.root_directory}")

    @classmethod
    def generate(cls, lookback_days: int = 90) -> None:
        """Run complete ticket caching pipeline."""
        try:
            log.info(f"Starting ticket cache generation (lookback={lookback_days}d)")
            instance = cls()

            # Three-step pipeline
            raw_tickets = instance._fetch_raw_tickets(lookback_days)
            ui_tickets = instance._process_for_ui(raw_tickets)
            instance._save_tickets(raw_tickets, ui_tickets)

            log.info("Ticket cache generation complete")
        except Exception as e:
            log.error(f"Ticket cache generation failed: {e}", exc_info=True)
            raise

    def _fetch_raw_tickets(self, lookback_days: int) -> List[Ticket]:
        """Fetch tickets from XSOAR and enrich with notes in parallel."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=lookback_days)
        query = (
            f"created:>={start_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"created:<={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"type:{CONFIG.team_name} -closeReason:Duplicate"
        )

        log.debug(f"XSOAR query: {query}")
        print(f"🔍 Fetching tickets from XSOAR for past {lookback_days} days...")

        raw_tickets = self.ticket_handler.get_tickets(query, paginate=True)
        tickets = [] if raw_tickets is None else [t for t in raw_tickets if isinstance(t, dict)]
        log.info(f"Fetched {len(tickets)} tickets from XSOAR")

        if not tickets:
            log.warning("No tickets fetched from XSOAR")
            return []

        # Parallel notes enrichment
        return self._enrich_with_notes(tickets)

    def _enrich_with_notes(self, tickets: List[Ticket]) -> List[Ticket]:
        """Enrich tickets with user notes in parallel.

        Uses as_completed() for efficient iteration. Timeout after 10 minutes.
        Individual futures timeout after 90s to prevent indefinite hangs.
        """
        from concurrent.futures import as_completed, TimeoutError as FuturesTimeoutError

        start_time = time.time()
        print(f"📝 Enriching {len(tickets)} tickets with notes (workers={MAX_WORKERS})...")
        print(f"⏱️  Max wait time: 10 minutes (90s timeout per ticket)")

        enriched = []
        failed_count = 0
        future_start_times = {}

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit all tasks and track submission time
            log.debug(f"Submitting {len(tickets)} tasks to {MAX_WORKERS} workers...")
            futures = {}
            for ticket in tickets:
                future = executor.submit(self._fetch_notes_for_ticket, ticket)
                futures[future] = ticket
                future_start_times[future] = time.time()
            log.debug(f"All tasks submitted. Waiting for completions...")

            # Process with as_completed and 10-minute total timeout
            # With 100 workers and 90s per-future timeout, worst case is ~8 minutes
            completed = set()
            last_straggler_report = time.time()

            try:
                for future in tqdm(as_completed(futures.keys(), timeout=600),
                                  total=len(tickets), desc="Fetching notes", unit="ticket"):
                    completed.add(future)
                    ticket = futures[future]
                    elapsed_time = time.time() - future_start_times[future]
                    remaining_count = len(tickets) - len(completed)

                    # Report stragglers every 10 seconds when <10 tickets remain
                    if 0 < remaining_count < 10:
                        if time.time() - last_straggler_report > 10:
                            remaining_futures = set(futures.keys()) - completed
                            pending_ids = [futures[f].get('id', 'unknown') for f in remaining_futures]
                            log.info(f"⏳ {remaining_count} stragglers remaining: {pending_ids}")
                            last_straggler_report = time.time()

                    try:
                        # Timeout individual futures after 90s to prevent indefinite hangs
                        result = future.result(timeout=90)
                        enriched.append(result)
                        if not result.get('notes'):
                            failed_count += 1

                    except TimeoutError:
                        log.error(f"Ticket {ticket.get('id', 'unknown')} timed out after {elapsed_time:.1f}s")
                        ticket['notes'] = []
                        enriched.append(ticket)
                        failed_count += 1
                        future.cancel()  # Try to cancel the stuck future

                    except Exception as e:
                        log.warning(f"Failed ticket {ticket.get('id', 'unknown')}: {e}")
                        ticket['notes'] = []
                        enriched.append(ticket)
                        failed_count += 1

            except FuturesTimeoutError:
                # Timeout after 10 minutes - add remaining tickets
                remaining = set(futures.keys()) - completed
                log.error(f"TIMEOUT after 600s: {len(remaining)}/{len(tickets)} tickets didn't complete")
                log.error(f"Remaining ticket IDs: {[futures[f].get('id', 'unknown') for f in remaining]}")
                for future in remaining:
                    ticket = futures[future]
                    ticket['notes'] = []
                    enriched.append(ticket)
                    failed_count += 1
                    future.cancel()  # Try to cancel stuck futures

        elapsed = time.time() - start_time
        success_count = len(enriched) - failed_count
        log.info(f"Enriched {len(enriched)} tickets in {elapsed:.1f}s "
                f"({success_count} success, {failed_count} failed)")

        if failed_count > len(enriched) * 0.1:
            failure_pct = (failed_count / len(enriched)) * 100
            log.error(f"HIGH FAILURE RATE: {failure_pct:.1f}% ({failed_count}/{len(enriched)}) "
                     f"- Check API rate limits or network issues")

        return enriched

    def _fetch_notes_for_ticket(self, ticket: Ticket) -> Ticket:
        """Fetch user notes for a single ticket.

        Simple wrapper - HTTP client already handles timeouts and retries.
        """
        ticket_id = ticket.get('id')
        if not ticket_id:
            ticket['notes'] = []
            return ticket

        try:
            # Debug: log when we START fetching (to verify workers are running)
            log.debug(f"START fetching notes for ticket {ticket_id}")
            notes = self.ticket_handler.get_user_notes(ticket_id)
            ticket['notes'] = notes if notes else []
            if not notes:
                log.debug(f"Ticket {ticket_id}: API returned empty/null notes")
            log.debug(f"DONE fetching notes for ticket {ticket_id}")
        except Exception as e:
            # Log error type for debugging high failure rates
            error_type = type(e).__name__
            error_msg = str(e)
            if '429' in error_msg or 'Too Many Requests' in error_msg:
                log.warning(f"Ticket {ticket_id}: Rate limited")
            elif 'timeout' in error_msg.lower():
                log.warning(f"Ticket {ticket_id}: Timeout ({error_type})")
            else:
                log.warning(f"Ticket {ticket_id}: {error_type} - {error_msg[:100]}")
            ticket['notes'] = []

        return ticket

    def _process_for_ui(self, raw_tickets: List[Ticket]) -> List[Ticket]:
        """Process raw tickets into flattened UI format with computed fields."""
        print(f"⚙️ Processing {len(raw_tickets)} tickets for UI...")
        log.debug("Starting UI processing pipeline")

        ui_tickets = []
        current_time = datetime.now(timezone.utc)

        for ticket in tqdm(raw_tickets, desc="Processing tickets", unit="ticket"):
            try:
                ui_ticket = self._flatten_ticket(ticket, current_time)
                ui_tickets.append(ui_ticket)
            except Exception as e:
                ticket_id = ticket.get('id', 'unknown')
                log.warning(f"Failed to process ticket {ticket_id}: {e}")

        log.info(f"Processed {len(ui_tickets)}/{len(raw_tickets)} tickets successfully")
        return ui_tickets

    def _flatten_ticket(self, ticket: Ticket, current_time: datetime) -> Ticket:
        """Flatten ticket structure: extract fields, apply transforms, compute derived fields."""
        ui_ticket = {}

        # Extract system fields
        for ui_field, sys_field in SYSTEM_FIELDS.items():
            default = 'Unknown' if ui_field in ('name', 'owner') else 0
            ui_ticket[ui_field] = ticket.get(sys_field, default)

        # Extract custom fields
        custom_fields = ticket.get('CustomFields', {})
        for ui_field, custom_field in CUSTOM_FIELDS.items():
            ui_ticket[ui_field] = custom_fields.get(custom_field, 'Unknown')

        # Extract SLA timing for computed fields
        ui_ticket['_timetorespond'] = custom_fields.get('timetorespond', {})
        ui_ticket['_timetocontain'] = custom_fields.get('timetocontain', {})

        # Apply name transformations
        ui_ticket['type'] = clean_type_name(ui_ticket['type'])
        ui_ticket['owner'] = clean_owner_name(ui_ticket['owner'])

        # Add computed fields
        self._add_computed_fields(ui_ticket, current_time)

        # Add notes
        ui_ticket['notes'] = ticket.get('notes', [])

        # Clean up temporary fields
        ui_ticket.pop('_timetorespond', None)
        ui_ticket.pop('_timetocontain', None)

        return ui_ticket

    @staticmethod
    def _add_computed_fields(ticket: Ticket, current_time: datetime) -> None:
        """Compute derived fields: age, resolution time, SLA status, display formats."""
        # Parse dates
        created_dt = parse_date(ticket.get('created'))
        closed_dt = parse_date(ticket.get('closed'))

        # Convert status/severity to int (XSOAR sometimes returns strings)
        status = int(ticket.get('status', 0))
        severity = int(ticket.get('severity', 0))
        is_open = status in (0, 1)

        log.debug(f"Computing fields for ticket {ticket.get('id')}: "
                  f"status={status}, severity={severity}, created={created_dt}")

        # Time calculations
        currently_aging_days = (current_time - created_dt).days if (created_dt and is_open) else None
        days_since_creation = (current_time - created_dt).days if created_dt else None
        resolution_time_days = (closed_dt - created_dt).days if (created_dt and closed_dt) else None

        # SLA data
        timetorespond = ticket.get('_timetorespond', {})
        timetocontain = ticket.get('_timetocontain', {})

        # Update ticket with all computed fields
        ticket.update({
            # Status and timing
            'is_open': is_open,
            'currently_aging_days': currently_aging_days,
            'days_since_creation': days_since_creation,
            'created_days_ago': days_since_creation,
            'resolution_time_days': resolution_time_days,
            'has_resolution_time': resolution_time_days is not None,

            # Categories
            'age_category': age_category(currently_aging_days),
            'resolution_bucket': resolution_bucket(resolution_time_days, is_open),

            # SLA breach flags
            'has_breached_response_sla': bool(timetorespond.get('breachTriggered')),
            'has_breached_containment_sla': bool(timetocontain.get('breachTriggered')),
            'time_to_respond_secs': timetorespond.get('totalDuration', 0),
            'time_to_contain_secs': timetocontain.get('totalDuration', 0),

            # Host presence
            'has_hostname': bool(ticket.get('hostname') and
                                 ticket['hostname'].strip() and
                                 ticket['hostname'] != 'Unknown'),

            # Display formats
            'status_display': STATUS_DISPLAY.get(status, 'Unknown'),
            'severity_display': SEVERITY_DISPLAY.get(severity, 'Unknown'),
            'created_display': format_date_display(ticket.get('created')),
            'closed_display': format_date_display(ticket.get('closed')),
        })

    def _save_tickets(self, raw_tickets: List[Ticket], ui_tickets: List[Ticket]) -> None:
        """Save both raw and UI-processed tickets to JSON files.

        Uses atomic writes: saves to temp files first, then renames to final location.
        This prevents corrupting the cache if the process fails mid-write.
        """
        today = datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y')
        output_dir = self.root_directory / 'data' / 'transient' / 'secOps' / today
        output_dir.mkdir(parents=True, exist_ok=True)

        log.info(f"Saving tickets to {output_dir}")

        # Define final paths
        raw_path = output_dir / 'past_90_days_tickets_raw.json'
        ui_path = output_dir / 'past_90_days_tickets.json'

        # Define temp paths (write here first)
        raw_temp_path = output_dir / 'past_90_days_tickets_raw.json.tmp'
        ui_temp_path = output_dir / 'past_90_days_tickets.json.tmp'

        try:
            # Save raw tickets to temp file
            print("💾 Saving raw ticket data...")
            with open(raw_temp_path, 'w') as f:
                json.dump(raw_tickets, f, indent=4, default=json_serializer)
            log.info(f"Saved {len(raw_tickets)} raw tickets to temp file")

            # Save UI tickets with metadata to temp file
            print("📊 Saving UI ticket data...")
            ui_data = {
                'data': ui_tickets,
                'data_generated_at': datetime.now(ZoneInfo("America/New_York")).isoformat(),
                'total_count': len(ui_tickets)
            }
            with open(ui_temp_path, 'w') as f:
                json.dump(ui_data, f, indent=2, default=json_serializer)
            log.info(f"Saved {len(ui_tickets)} UI tickets to temp file")

            # Atomic rename: only now replace the old files
            raw_temp_path.replace(raw_path)
            ui_temp_path.replace(ui_path)
            log.info(f"Atomically replaced cache files in {output_dir}")

            print("✅ Ticket caching completed successfully!")

        except Exception as e:
            # Clean up temp files on failure
            log.error(f"Failed to save tickets: {e}")
            if raw_temp_path.exists():
                raw_temp_path.unlink()
                log.debug("Cleaned up temp raw file")
            if ui_temp_path.exists():
                ui_temp_path.unlink()
                log.debug("Cleaned up temp UI file")
            raise


# ---------------------------- CLI Entry Point ----------------------------

def main():
    """CLI entry point with visual output."""
    log.info("Starting ticket caching process")
    cache = TicketCache()
    cache.generate(lookback_days=10)

    # Display sample tickets
    today = datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y')
    ui_path = cache.root_directory / 'data' / 'transient' / 'secOps' / today / 'past_90_days_tickets.json'

    if ui_path.exists():
        with open(ui_path, 'r') as f:
            cached_data = json.load(f)

        tickets = cached_data.get('data', cached_data)
        print(f"\n📊 Data generated at: {cached_data.get('data_generated_at', 'Unknown')}")
        print(f"📦 Total tickets: {cached_data.get('total_count', len(tickets))}")

        # print("\n" + "=" * 80)
        # print("SAMPLE UI TICKETS (first 3 for inspection):")
        # print("=" * 80)
        # pp = pprint.PrettyPrinter(indent=2, width=100)
        # for i, ticket in enumerate(tickets[:3], 1):
        #     print(f"\n--- Ticket #{i} ---")
        #     pp.pprint(ticket)
        # print("=" * 80)

    log.info("Ticket caching process completed")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    main()
