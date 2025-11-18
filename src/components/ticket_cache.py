"""Ticket cache component for XSOAR data.

Fetches tickets from XSOAR, processes for UI consumption, and caches locally.
Runs in trusted environment - minimal defensive coding per AGENTS.md.
"""
import json
import logging
import os
import re
import sys
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
# Configurable worker count via env var
# Default: 5 for slow VM networks (empirically proven to prevent API rate limiting)
# Tested: 10 workers = 52% failure rate, 5 workers = expected 75-90% success rate
# Use TICKET_ENRICHMENT_WORKERS=25 for fast networks (local dev)
# Use TICKET_ENRICHMENT_WORKERS=10 for faster processing if you accept 50% note loss
MAX_WORKERS = int(os.getenv('TICKET_ENRICHMENT_WORKERS', '5'))

# Configurable individual ticket timeout
# Default: 300s (5 min) for slow VM networks to allow completion
# Use TICKET_ENRICHMENT_TIMEOUT=90 for fast networks (local dev)
# Longer timeout = fewer timeouts = higher success rate
TICKET_TIMEOUT = int(os.getenv('TICKET_ENRICHMENT_TIMEOUT', '300'))

# Skip note enrichment for performance (default: False - enrichment enabled)
# Set SKIP_NOTE_ENRICHMENT=true to skip notes for faster processing
# Note: Enrichment is slow on VMs but will complete if given enough time
SKIP_NOTE_ENRICHMENT = os.getenv('SKIP_NOTE_ENRICHMENT', 'false').lower() in ('true', '1', 'yes')


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
        log.debug("TicketCache.__init__() called - creating ticket handler...")
        try:
            self.ticket_handler = TicketHandler(XsoarEnvironment.PROD)
            log.debug(f"TicketHandler created successfully: {type(self.ticket_handler)}")
        except Exception as e:
            log.error(f"Failed to create TicketHandler: {type(e).__name__}: {e}")
            raise

        self.root_directory = Path(__file__).parent.parent.parent
        log.debug(f"Initialized TicketCache with root: {self.root_directory}")
        log.debug(f"Root directory exists: {self.root_directory.exists()}, is_dir: {self.root_directory.is_dir()}")

    @classmethod
    def generate(cls, lookback_days: int = 90) -> None:
        """Run complete ticket caching pipeline."""
        log.debug("="*80)
        log.debug(f"TicketCache.generate() ENTRY - lookback_days={lookback_days}")
        log.debug("="*80)
        try:
            log.info(f"Starting ticket cache generation (lookback={lookback_days}d)")
            log.info(f"Configuration: Workers={MAX_WORKERS}, Timeout={TICKET_TIMEOUT}s, "
                    f"SkipNotes={SKIP_NOTE_ENRICHMENT}")
            log.debug(f"Pipeline will run: fetch -> process -> save")

            log.debug("Creating TicketCache instance...")
            instance = cls()
            log.debug(f"TicketCache instance created: {instance}")

            # Three-step pipeline
            log.debug("="*60)
            log.debug("STEP 1/3: Fetching raw tickets from XSOAR...")
            log.debug("="*60)
            step1_start = time.time()
            raw_tickets = instance._fetch_raw_tickets(lookback_days)
            step1_duration = time.time() - step1_start
            log.debug(f"STEP 1/3 Complete: Fetched {len(raw_tickets)} raw tickets in {step1_duration:.2f}s")
            log.debug(f"Raw tickets type: {type(raw_tickets)}, len: {len(raw_tickets)}")

            log.debug("="*60)
            log.debug("STEP 2/3: Processing tickets for UI...")
            log.debug("="*60)
            step2_start = time.time()
            ui_tickets = instance._process_for_ui(raw_tickets)
            step2_duration = time.time() - step2_start
            log.debug(f"STEP 2/3 Complete: Processed {len(ui_tickets)} UI tickets in {step2_duration:.2f}s")
            log.debug(f"UI tickets type: {type(ui_tickets)}, len: {len(ui_tickets)}")

            log.debug("="*60)
            log.debug("STEP 3/3: Saving tickets to disk...")
            log.debug("="*60)
            step3_start = time.time()
            instance._save_tickets(raw_tickets, ui_tickets)
            step3_duration = time.time() - step3_start
            log.debug(f"STEP 3/3 Complete: Tickets saved successfully in {step3_duration:.2f}s")

            total_duration = step1_duration + step2_duration + step3_duration
            log.info(f"Ticket cache generation complete - Total time: {total_duration:.2f}s")
            log.debug(f"Time breakdown - Fetch: {step1_duration:.2f}s, Process: {step2_duration:.2f}s, Save: {step3_duration:.2f}s")
        except Exception as e:
            log.error(f"Ticket cache generation failed: {e}", exc_info=True)
            log.debug(f"Failure details - Exception type: {type(e).__name__}")
            log.debug(f"Exception args: {e.args}")
            log.debug(f"Exception __dict__: {e.__dict__ if hasattr(e, '__dict__') else 'N/A'}")
            raise
        finally:
            log.debug("="*80)
            log.debug("TicketCache.generate() EXIT")
            log.debug("="*80)

    def _fetch_raw_tickets(self, lookback_days: int) -> List[Ticket]:
        """Fetch tickets from XSOAR and enrich with notes in parallel."""
        log.debug("_fetch_raw_tickets() ENTRY")
        log.debug(f"Calculating date range for lookback_days={lookback_days}")
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=lookback_days)
        log.debug(f"Date range: {start_date} to {end_date}")
        log.debug(f"Timezone info - start: {start_date.tzinfo}, end: {end_date.tzinfo}")

        query = (
            f"created:>={start_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"created:<={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"type:{CONFIG.team_name} -closeReason:Duplicate"
        )

        log.debug(f"XSOAR query: {query}")
        log.debug(f"Team name filter: {CONFIG.team_name}")
        log.debug(f"Paginate: True")
        print(f"🔍 Fetching tickets from XSOAR for past {lookback_days} days...")

        log.debug("Calling ticket_handler.get_tickets()...")
        log.debug(f"ticket_handler type: {type(self.ticket_handler)}")
        log.debug(f"ticket_handler attributes: {dir(self.ticket_handler)}")

        try:
            fetch_start = time.time()
            raw_tickets = self.ticket_handler.get_tickets(query, paginate=True)
            fetch_duration = time.time() - fetch_start
            log.debug(f"ticket_handler.get_tickets() completed in {fetch_duration:.2f}s")
            log.debug(f"ticket_handler.get_tickets() returned: {type(raw_tickets)}")
            log.debug(f"raw_tickets is None: {raw_tickets is None}")
            if raw_tickets is not None:
                log.debug(f"raw_tickets length: {len(raw_tickets) if hasattr(raw_tickets, '__len__') else 'N/A'}")
        except Exception as e:
            log.error(f"ticket_handler.get_tickets() raised exception: {type(e).__name__}: {e}")
            log.debug(f"Exception details: {e.args}")
            raise

        tickets = [] if raw_tickets is None else [t for t in raw_tickets if isinstance(t, dict)]
        log.info(f"Fetched {len(tickets)} tickets from XSOAR")
        log.debug(f"Filtered out {len(raw_tickets or []) - len(tickets)} non-dict entries")

        if not tickets:
            log.warning("No tickets fetched from XSOAR")
            log.debug(f"Raw response was: {type(raw_tickets)}, is None: {raw_tickets is None}")
            if raw_tickets is not None and len(raw_tickets) > 0:
                log.debug(f"First non-dict entry: {raw_tickets[0] if len(raw_tickets) > 0 else 'N/A'}")
            return []

        log.debug(f"Sample ticket IDs: {[t.get('id', 'NO_ID') for t in tickets[:5]]}")
        log.debug(f"Sample ticket keys (first ticket): {list(tickets[0].keys()) if tickets else 'N/A'}")

        # Parallel notes enrichment (optional - can be disabled for performance)
        if SKIP_NOTE_ENRICHMENT:
            log.info("⏭️  Skipping note enrichment (SKIP_NOTE_ENRICHMENT=true)")
            print("⏭️  Skipping note enrichment for faster processing...")
            # Add empty notes to all tickets
            for ticket in tickets:
                ticket['notes'] = []
            log.debug("_fetch_raw_tickets() EXIT (notes skipped)")
            return tickets
        else:
            log.debug("Calling _enrich_with_notes()...")
            enriched = self._enrich_with_notes(tickets)
            log.debug(f"_enrich_with_notes() returned {len(enriched)} tickets")
            log.debug("_fetch_raw_tickets() EXIT")
            return enriched

    def _enrich_with_notes(self, tickets: List[Ticket]) -> List[Ticket]:
        """Enrich tickets with user notes in parallel.

        Uses as_completed() for efficient iteration. No overall timeout.
        Individual futures timeout after TICKET_TIMEOUT seconds to prevent indefinite hangs.
        Default: 180s for slow networks, configurable via TICKET_ENRICHMENT_TIMEOUT env var.
        """
        from concurrent.futures import as_completed

        log.debug("="*60)
        log.debug("_enrich_with_notes() ENTRY")
        log.debug("="*60)
        log.debug(f"Starting note enrichment for {len(tickets)} tickets")
        log.debug(f"Worker count: {MAX_WORKERS}, Individual timeout: {TICKET_TIMEOUT}s")
        log.debug(f"MAX_WORKERS env var: {os.getenv('TICKET_ENRICHMENT_WORKERS', '5')}")
        log.debug(f"TICKET_TIMEOUT env var: {os.getenv('TICKET_ENRICHMENT_TIMEOUT', '300')}")

        start_time = time.time()
        print(f"📝 Enriching {len(tickets)} tickets with notes (workers={MAX_WORKERS})...")
        print(f"⏱️  Individual ticket timeout: {TICKET_TIMEOUT}s (no overall job timeout)")

        enriched = []
        failed_count = 0
        future_start_times = {}

        log.debug("Initializing ThreadPoolExecutor...")
        log.debug(f"System info - CPU count: {os.cpu_count()}")

        try:
            executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
            log.debug(f"ThreadPoolExecutor created successfully: {executor}")
        except Exception as e:
            log.error(f"Failed to create ThreadPoolExecutor: {type(e).__name__}: {e}")
            raise

        with executor:
            # Submit all tasks and track submission time
            log.debug(f"Submitting {len(tickets)} tasks to {MAX_WORKERS} workers...")
            submission_start = time.time()
            futures = {}
            for i, ticket in enumerate(tickets):
                future = executor.submit(self._fetch_notes_for_ticket, ticket)
                futures[future] = ticket
                future_start_times[future] = time.time()
                if (i + 1) % 100 == 0:
                    log.debug(f"Submitted {i + 1}/{len(tickets)} tasks...")
            submission_time = time.time() - submission_start
            log.debug(f"All {len(tickets)} tasks submitted in {submission_time:.2f}s. Waiting for completions...")

            # Process with as_completed - no overall timeout, will run until all complete
            # Individual futures have TICKET_TIMEOUT (default 180s) to prevent indefinite hangs
            completed = set()
            last_straggler_report = time.time()
            processing_start = time.time()

            log.debug("Entering as_completed() processing loop...")
            log.debug(f"Total futures to process: {len(futures)}")
            log.debug(f"tqdm disabled: {not sys.stdout.isatty()}, sys.stdout.isatty(): {sys.stdout.isatty()}")

            try:
                log.debug("Creating as_completed() iterator...")
                for future in tqdm(as_completed(futures.keys()),
                                  total=len(tickets), desc="Fetching notes", unit="ticket", disable=not sys.stdout.isatty()):
                    completed.add(future)
                    ticket = futures[future]
                    elapsed_time = time.time() - future_start_times[future]
                    remaining_count = len(tickets) - len(completed)

                    # Log progress every 50 tickets
                    if len(completed) % 50 == 0:
                        current_rate = len(completed) / (time.time() - processing_start)
                        log.debug(f"Progress: {len(completed)}/{len(tickets)} tickets processed, {failed_count} failed so far")
                        log.debug(f"Processing rate: {current_rate:.2f} tickets/sec")

                    # Log every 10th completion for detailed tracking
                    if len(completed) % 10 == 0:
                        log.debug(f"Completed {len(completed)}/{len(tickets)}, last ticket: {ticket.get('id', 'unknown')}")

                    # Report stragglers every 10 seconds when <10 tickets remain
                    if 0 < remaining_count < 10:
                        if time.time() - last_straggler_report > 10:
                            remaining_futures = set(futures.keys()) - completed
                            pending_ids = [futures[f].get('id', 'unknown') for f in remaining_futures]
                            log.info(f"⏳ {remaining_count} stragglers remaining: {pending_ids}")
                            last_straggler_report = time.time()

                    try:
                        # Timeout individual futures to prevent indefinite hangs
                        log.debug(f"Waiting for result from ticket {ticket.get('id', 'unknown')}...")
                        result = future.result(timeout=TICKET_TIMEOUT)
                        enriched.append(result)
                        if not result.get('notes'):
                            failed_count += 1
                            log.debug(f"Ticket {ticket.get('id', 'unknown')}: No notes returned")
                        else:
                            log.debug(f"Ticket {ticket.get('id', 'unknown')}: {len(result['notes'])} notes fetched")

                    except TimeoutError:
                        log.error(f"Ticket {ticket.get('id', 'unknown')} timed out after {elapsed_time:.1f}s")
                        log.debug(f"Timeout occurred at {time.time() - processing_start:.1f}s into processing phase")
                        ticket['notes'] = []
                        enriched.append(ticket)
                        failed_count += 1
                        future.cancel()  # Try to cancel the stuck future

                    except Exception as e:
                        log.warning(f"Failed ticket {ticket.get('id', 'unknown')}: {e}")
                        log.debug(f"Exception details: {type(e).__name__}: {str(e)}")
                        ticket['notes'] = []
                        enriched.append(ticket)
                        failed_count += 1

            except Exception as e:
                # Handle any unexpected errors during iteration
                log.error(f"Unexpected error during note enrichment: {e}", exc_info=True)
                log.debug(f"Error type: {type(e).__name__}, Error details: {str(e)}")
                log.debug(f"Error occurred at {time.time() - processing_start:.1f}s into processing phase")
                remaining = set(futures.keys()) - completed
                log.error(f"Processing stopped: {len(remaining)}/{len(tickets)} tickets didn't complete")
                log.error(f"Remaining ticket IDs: {[futures[f].get('id', 'unknown') for f in remaining]}")
                log.debug(f"Completed count: {len(completed)}, Enriched count: {len(enriched)}, Failed count: {failed_count}")
                log.debug(f"Exception args: {e.args}")
                log.debug(f"Exception __dict__: {e.__dict__ if hasattr(e, '__dict__') else 'N/A'}")

                log.debug("Adding remaining tickets with empty notes...")
                for future in remaining:
                    ticket = futures[future]
                    ticket['notes'] = []
                    enriched.append(ticket)
                    failed_count += 1
                    future.cancel()  # Try to cancel stuck futures
                log.debug(f"Added {len(remaining)} remaining tickets to enriched list")
                raise  # Re-raise to propagate the error

        elapsed = time.time() - start_time
        processing_time = time.time() - processing_start
        success_count = len(enriched) - failed_count
        log.info(f"Enriched {len(enriched)} tickets in {elapsed:.1f}s "
                f"({success_count} success, {failed_count} failed)")
        log.debug(f"Time breakdown - Submission: {submission_time:.2f}s, Processing: {processing_time:.2f}s")
        log.debug(f"Overall rate: {len(enriched) / elapsed:.2f} tickets/sec")

        if failed_count > len(enriched) * 0.1:
            failure_pct = (failed_count / len(enriched)) * 100
            log.error(f"HIGH FAILURE RATE: {failure_pct:.1f}% ({failed_count}/{len(enriched)}) "
                     f"- Check API rate limits or network issues")
            log.debug(f"Failure threshold: {len(enriched) * 0.1:.1f} tickets (10%)")

        log.debug(f"Returning {len(enriched)} enriched tickets")
        log.debug("="*60)
        log.debug("_enrich_with_notes() EXIT")
        log.debug("="*60)
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
        log.debug(f"Processing {len(raw_tickets)} tickets at {datetime.now(timezone.utc)}")

        ui_tickets = []
        current_time = datetime.now(timezone.utc)
        processing_errors = []

        for i, ticket in enumerate(tqdm(raw_tickets, desc="Processing tickets", unit="ticket", disable=not sys.stdout.isatty())):
            try:
                ui_ticket = self._flatten_ticket(ticket, current_time)
                ui_tickets.append(ui_ticket)

                # Log every 100th ticket
                if (i + 1) % 100 == 0:
                    log.debug(f"Processed {i + 1}/{len(raw_tickets)} tickets")
            except Exception as e:
                ticket_id = ticket.get('id', 'unknown')
                error_msg = f"Failed to process ticket {ticket_id}: {type(e).__name__}: {e}"
                log.warning(error_msg)
                log.debug(f"Ticket data: {ticket}")
                processing_errors.append(error_msg)

        log.info(f"Processed {len(ui_tickets)}/{len(raw_tickets)} tickets successfully")
        if processing_errors:
            log.debug(f"Processing errors summary: {len(processing_errors)} failures")
            log.debug(f"First few errors: {processing_errors[:5]}")

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
        log.debug("Starting ticket save operation")
        today = datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y')
        log.debug(f"Today's date (ET): {today}")

        output_dir = self.root_directory / 'data' / 'transient' / 'secOps' / today
        log.debug(f"Output directory path: {output_dir}")

        log.debug(f"Creating output directory if needed...")
        output_dir.mkdir(parents=True, exist_ok=True)
        log.debug(f"Output directory exists: {output_dir.exists()}, is dir: {output_dir.is_dir()}")

        log.info(f"Saving tickets to {output_dir}")
        log.debug(f"Will save {len(raw_tickets)} raw tickets and {len(ui_tickets)} UI tickets")

        # Define final paths
        raw_path = output_dir / 'past_90_days_tickets_raw.json'
        ui_path = output_dir / 'past_90_days_tickets.json'

        # Define temp paths (write here first)
        raw_temp_path = output_dir / 'past_90_days_tickets_raw.json.tmp'
        ui_temp_path = output_dir / 'past_90_days_tickets.json.tmp'

        try:
            # Save raw tickets to temp file
            print("💾 Saving raw ticket data...")
            log.debug(f"Writing raw tickets to temp file: {raw_temp_path}")
            with open(raw_temp_path, 'w') as f:
                json.dump(raw_tickets, f, indent=4, default=json_serializer)
            raw_size = raw_temp_path.stat().st_size
            log.info(f"Saved {len(raw_tickets)} raw tickets to temp file ({raw_size:,} bytes)")
            log.debug(f"Raw temp file exists: {raw_temp_path.exists()}")

            # Save UI tickets with metadata to temp file
            print("📊 Saving UI ticket data...")
            log.debug(f"Preparing UI data with metadata...")
            ui_data = {
                'data': ui_tickets,
                'data_generated_at': datetime.now(ZoneInfo("America/New_York")).isoformat(),
                'total_count': len(ui_tickets)
            }
            log.debug(f"Writing UI tickets to temp file: {ui_temp_path}")
            with open(ui_temp_path, 'w') as f:
                json.dump(ui_data, f, indent=2, default=json_serializer)
            ui_size = ui_temp_path.stat().st_size
            log.info(f"Saved {len(ui_tickets)} UI tickets to temp file ({ui_size:,} bytes)")
            log.debug(f"UI temp file exists: {ui_temp_path.exists()}")

            # Atomic rename: only now replace the old files
            log.debug(f"Performing atomic rename: {raw_temp_path} -> {raw_path}")
            raw_temp_path.replace(raw_path)
            log.debug(f"Raw file renamed successfully. Exists at final path: {raw_path.exists()}")

            log.debug(f"Performing atomic rename: {ui_temp_path} -> {ui_path}")
            ui_temp_path.replace(ui_path)
            log.debug(f"UI file renamed successfully. Exists at final path: {ui_path.exists()}")

            log.info(f"Atomically replaced cache files in {output_dir}")
            log.debug(f"Final files - Raw: {raw_path.stat().st_size:,} bytes, UI: {ui_path.stat().st_size:,} bytes")

            print("✅ Ticket caching completed successfully!")

        except Exception as e:
            # Clean up temp files on failure
            log.error(f"Failed to save tickets: {e}")
            log.debug(f"Save failure details - Exception: {type(e).__name__}: {str(e)}")
            log.debug(f"Temp files status - Raw exists: {raw_temp_path.exists()}, UI exists: {ui_temp_path.exists()}")

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
    # Allow overriding lookback days via env var
    lookback = int(os.getenv('LOOKBACK_DAYS', '90'))

    print(f"\n{'='*60}")
    print("Ticket Cache Configuration")
    print(f"{'='*60}")
    print(f"Lookback Days: {lookback}")
    print(f"Page Size: {TicketHandler.DEFAULT_PAGE_SIZE}")
    print(f"Read Timeout: {TicketHandler.READ_TIMEOUT}s")
    print(f"Skip Notes: {SKIP_NOTE_ENRICHMENT}")
    if not SKIP_NOTE_ENRICHMENT:
        print(f"Workers: {MAX_WORKERS}")
        print(f"Note Timeout: {TICKET_TIMEOUT}s")
    print(f"{'='*60}\n")

    log.info("Starting ticket caching process")
    TicketCache.generate(lookback_days=lookback)

    # Display sample tickets
    today = datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y')
    root_directory = Path(__file__).parent.parent.parent
    ui_path = root_directory / 'data' / 'transient' / 'secOps' / today / 'past_90_days_tickets.json'

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
