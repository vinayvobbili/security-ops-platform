"""Ticket cache component for XSOAR data.

Fetches tickets from XSOAR, processes for UI consumption, and caches locally.
Runs in trusted environment - minimal defensive coding per AGENTS.md.
"""
import json
import logging
import os
import random
import re
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
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
# Configurable worker count via env var (default: 100, range: 10-200)
DEFAULT_MAX_WORKERS = int(os.getenv('TICKET_ENRICHMENT_WORKERS', '100'))


# ---------------------------- Metrics Tracking ----------------------------

class EnrichmentMetrics:
    """Thread-safe metrics tracker for ticket enrichment monitoring."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.rate_limited_requests = 0
        self.retry_counts = defaultdict(int)  # Count of retries per attempt number
        self.total_retry_wait_time = 0.0  # Total time spent waiting on retries
        self.start_time = None
        self.end_time = None

    def record_success(self):
        """Record a successful ticket enrichment."""
        with self._lock:
            self.total_requests += 1
            self.successful_requests += 1

    def record_failure(self):
        """Record a failed ticket enrichment."""
        with self._lock:
            self.total_requests += 1
            self.failed_requests += 1

    def record_rate_limit(self, attempt: int, wait_time: float):
        """Record a rate limit event with retry attempt number and wait time."""
        with self._lock:
            self.rate_limited_requests += 1
            self.retry_counts[attempt] += 1
            self.total_retry_wait_time += wait_time

    def start(self):
        """Mark the start of enrichment."""
        self.start_time = time.time()

    def end(self):
        """Mark the end of enrichment."""
        self.end_time = time.time()

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        with self._lock:
            elapsed = (self.end_time - self.start_time) if self.start_time and self.end_time else 0
            rate_limit_rate = (self.rate_limited_requests / self.total_requests * 100) if self.total_requests > 0 else 0
            success_rate = (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
            throughput = self.total_requests / elapsed if elapsed > 0 else 0

            return {
                'total_requests': self.total_requests,
                'successful': self.successful_requests,
                'failed': self.failed_requests,
                'rate_limited': self.rate_limited_requests,
                'rate_limit_percentage': rate_limit_rate,
                'success_rate': success_rate,
                'retry_breakdown': dict(self.retry_counts),
                'total_retry_wait_time': self.total_retry_wait_time,
                'elapsed_time': elapsed,
                'throughput_per_sec': throughput
            }

    def print_summary(self, max_workers: int):
        """Print formatted metrics summary."""
        summary = self.get_summary()

        print("\n" + "=" * 80)
        print("📊 TICKET ENRICHMENT METRICS")
        print("=" * 80)
        print(f"Workers:              {max_workers}")
        print(f"Total Requests:       {summary['total_requests']}")
        print(f"✅ Successful:        {summary['successful']} ({summary['success_rate']:.1f}%)")
        print(f"❌ Failed:            {summary['failed']}")
        print(f"⏱️  Total Time:        {summary['elapsed_time']:.1f}s ({summary['elapsed_time'] / 60:.1f}m)")
        print(f"⚡ Throughput:        {summary['throughput_per_sec']:.2f} tickets/sec")
        print()
        print(f"🚦 Rate Limited:      {summary['rate_limited']} requests ({summary['rate_limit_percentage']:.2f}%)")

        if summary['retry_breakdown']:
            print(f"   Retry Breakdown:")
            for attempt, count in sorted(summary['retry_breakdown'].items()):
                print(f"     - Attempt {attempt}: {count} retries")

        if summary['total_retry_wait_time'] > 0:
            avg_wait = summary['total_retry_wait_time'] / summary['rate_limited'] if summary['rate_limited'] > 0 else 0
            print(f"   Total Wait Time:   {summary['total_retry_wait_time']:.1f}s ({summary['total_retry_wait_time'] / 60:.1f}m)")
            print(f"   Avg Wait/Retry:    {avg_wait:.1f}s")

        # Performance recommendations
        print()
        if summary['rate_limit_percentage'] > 15:
            print("⚠️  HIGH RATE LIMITING - Consider reducing TICKET_ENRICHMENT_WORKERS")
            recommended = max(10, int(max_workers * 0.7))
            print(f"   Recommended: export TICKET_ENRICHMENT_WORKERS={recommended}")
        elif summary['rate_limit_percentage'] < 3 and max_workers < 150:
            print("✅ LOW RATE LIMITING - You can safely increase TICKET_ENRICHMENT_WORKERS")
            recommended = min(200, int(max_workers * 1.3))
            print(f"   Recommended: export TICKET_ENRICHMENT_WORKERS={recommended}")
        else:
            print("✅ RATE LIMITING WITHIN ACCEPTABLE RANGE")

        print("=" * 80)

    def save_to_file(self, output_dir: Path, max_workers: int):
        """Save metrics to JSON file for historical tracking."""
        summary = self.get_summary()
        summary['max_workers'] = max_workers
        summary['timestamp'] = datetime.now(timezone.utc).isoformat()

        metrics_file = output_dir / 'enrichment_metrics.json'
        try:
            # Load existing metrics if file exists
            if metrics_file.exists():
                with open(metrics_file, 'r') as f:
                    history = json.load(f)
                    if not isinstance(history, list):
                        history = [history]  # Convert old format
            else:
                history = []

            # Append new metrics
            history.append(summary)

            # Keep only last 30 runs
            history = history[-30:]

            # Save updated history
            with open(metrics_file, 'w') as f:
                json.dump(history, f, indent=2)

            log.debug(f"Saved enrichment metrics to {metrics_file}")
        except Exception as e:
            log.warning(f"Failed to save metrics: {e}")


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
            raw_tickets, metrics = instance._fetch_raw_tickets(lookback_days)
            ui_tickets = instance._process_for_ui(raw_tickets)
            instance._save_tickets(raw_tickets, ui_tickets, metrics)

            log.info("Ticket cache generation complete")
        except Exception as e:
            log.error(f"Ticket cache generation failed: {e}", exc_info=True)
            raise

    def _fetch_raw_tickets(self, lookback_days: int) -> tuple[List[Ticket], EnrichmentMetrics]:
        """Fetch tickets from XSOAR and enrich with notes in parallel.

        Returns:
            Tuple of (enriched_tickets, metrics)
        """
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
            return [], EnrichmentMetrics()  # Return empty metrics

        # Parallel notes enrichment
        return self._enrich_with_notes(tickets)

    def _enrich_with_notes(self, tickets: List[Ticket]) -> tuple[List[Ticket], EnrichmentMetrics]:
        """Enrich tickets with user notes in parallel.

        Returns:
            Tuple of (enriched_tickets, metrics)
        """
        # Conservative worker count to balance throughput vs rate limiting
        # Default 100 workers = 2x improvement with lower rate limit risk
        # Override with: export TICKET_ENRICHMENT_WORKERS=75 (or 50, 125, etc.)
        max_workers = max(10, min(200, DEFAULT_MAX_WORKERS))  # Clamp to safe range
        timeout_per_ticket = 60  # seconds - increased from 30s to handle network congestion

        # Initialize metrics tracking
        metrics = EnrichmentMetrics()
        metrics.start()

        print(f"📝 Enriching {len(tickets)} tickets with notes (parallel, workers={max_workers})...")
        log.debug(f"Starting parallel notes enrichment with {max_workers} workers")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._fetch_notes_for_ticket, ticket, metrics): ticket
                for ticket in tickets
            }

            enriched = []
            failed = 0
            completed_futures = set()

            # Calculate overall timeout: worst case = all tickets timeout at max (60s each)
            # With 100 workers, max tickets per worker = ceil(7645/100) = 77
            # Worst case: 77 tickets × 60s = 4620s (~77 min), add 50% buffer = 6930s (~115 min)
            tickets_per_worker = (len(tickets) + max_workers - 1) // max_workers
            overall_timeout = tickets_per_worker * timeout_per_ticket * 1.5
            log.debug(f"Overall enrichment timeout: {overall_timeout:.0f}s ({overall_timeout / 60:.1f}m) "
                      f"[{tickets_per_worker} tickets/worker max]")

            try:
                for future in tqdm(as_completed(futures, timeout=overall_timeout), total=len(tickets),
                                   desc="Fetching notes", unit="ticket"):
                    completed_futures.add(future)
                    try:
                        enriched.append(future.result(timeout=timeout_per_ticket))
                    except Exception as e:
                        failed += 1
                        ticket = futures[future]
                        ticket_id = ticket.get('id', 'unknown')
                        log.error(f"Failed to enrich ticket {ticket_id}: {e}")
                        ticket['notes'] = []
                        enriched.append(ticket)
            except TimeoutError:
                # Overall timeout reached - add remaining tickets with empty notes
                log.error(f"Overall enrichment timeout reached after {overall_timeout:.0f}s")
                for future, ticket in futures.items():
                    if future not in completed_futures:
                        failed += 1
                        ticket_id = ticket.get('id', 'unknown')
                        log.warning(f"Ticket {ticket_id} did not complete - adding with empty notes")
                        ticket['notes'] = []
                        enriched.append(ticket)

        # End metrics tracking and display summary
        metrics.end()
        log.info(f"Enriched {len(enriched)} tickets ({failed} failed)")
        metrics.print_summary(max_workers)

        return enriched, metrics

    def _fetch_notes_for_ticket(self, ticket: Ticket, metrics: EnrichmentMetrics, max_retries: int = 3) -> Ticket:
        """Fetch user notes for a single ticket with retry on rate limit."""
        ticket_id = ticket.get('id')
        if not ticket_id:
            ticket['notes'] = []
            metrics.record_failure()
            return ticket

        for attempt in range(max_retries):
            try:
                ticket['notes'] = self.ticket_handler.get_user_notes(ticket_id)
                log.debug(f"Fetched {len(ticket['notes'])} notes for ticket {ticket_id}")
                metrics.record_success()
                return ticket
            except Exception as e:
                error_msg = str(e)

                # Rate limit handling with exponential backoff + jitter
                # Jitter prevents thundering herd when many workers retry simultaneously
                if '429' in error_msg or 'Too Many Requests' in error_msg:
                    if attempt < max_retries - 1:
                        base_wait = (2 ** attempt) * 2
                        jitter = random.uniform(0, base_wait * 0.5)  # Add 0-50% jitter
                        wait_time = base_wait + jitter

                        # Record rate limit event
                        metrics.record_rate_limit(attempt, wait_time)

                        log.debug(f"Rate limited ticket {ticket_id}, waiting {wait_time:.1f}s")
                        time.sleep(wait_time)
                        continue
                    log.warning(f"Rate limit exceeded for ticket {ticket_id} after {max_retries} attempts")
                else:
                    log.warning(f"Failed to fetch notes for ticket {ticket_id}: {e}")

                ticket['notes'] = []
                metrics.record_failure()
                return ticket

        ticket['notes'] = []
        metrics.record_failure()
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

    def _save_tickets(self, raw_tickets: List[Ticket], ui_tickets: List[Ticket],
                      metrics: EnrichmentMetrics) -> None:
        """Save both raw and UI-processed tickets to JSON files, plus enrichment metrics."""
        today = datetime.now(ZoneInfo("America/New_York")).strftime('%m-%d-%Y')
        output_dir = self.root_directory / 'data' / 'transient' / 'secOps' / today
        output_dir.mkdir(parents=True, exist_ok=True)

        log.info(f"Saving tickets to {output_dir}")

        # Save raw tickets
        print("💾 Saving raw ticket data...")
        raw_path = output_dir / 'past_90_days_tickets_raw.json'
        with open(raw_path, 'w') as f:
            json.dump(raw_tickets, f, indent=4, default=json_serializer)
        log.info(f"Saved {len(raw_tickets)} raw tickets to {raw_path}")

        # Save UI tickets with metadata
        print("📊 Saving UI ticket data...")
        ui_data = {
            'data': ui_tickets,
            'data_generated_at': datetime.now(ZoneInfo("America/New_York")).isoformat(),
            'total_count': len(ui_tickets)
        }

        ui_path = output_dir / 'past_90_days_tickets.json'
        with open(ui_path, 'w') as f:
            json.dump(ui_data, f, indent=2, default=json_serializer)
        log.info(f"Saved {len(ui_tickets)} UI tickets to {ui_path}")

        # Save enrichment metrics for historical tracking
        print("📈 Saving enrichment metrics...")
        max_workers = max(10, min(200, DEFAULT_MAX_WORKERS))
        metrics.save_to_file(output_dir, max_workers)

        print("✅ Ticket caching completed successfully!")


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
